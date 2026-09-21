"""
Linux platform adapter.

Handles:
- systemd service management
- POSIX permissions (chmod, chown)
- UFW/nftables firewall
- Linux user/group management
- journald logging
- Paths: /etc, /var/lib, /var/log, /run
"""
import logging
import os
import shutil
import socket
import subprocess

from vnc_remote_secure.core.processes import run_cmd
from vnc_remote_secure.platform.base import PlatformAdapter

logger = logging.getLogger(__name__)


class LinuxAdapter(PlatformAdapter):
    """Linux-specific platform operations."""

    def get_platform_info(self):
        return {
            'platform': 'linux',
            'service_manager': 'systemd',
            'firewall': 'ufw or nftables',
            'config_dir': '/etc/vnc-remote-secure',
            'data_dir': '/var/lib/vnc-remote-secure',
            'log_dir': '/var/log/vnc-remote-secure',
            'run_dir': '/run/vnc-remote-secure',
            'default_vnc_port': 5901,
            'default_health_port': 8080,
            'default_webterm_shell': '/bin/bash',
        }

    def remove_service(self, service_name):
        """Stop and remove a systemd service."""
        from vnc_remote_secure.platform.linux.services import _check_unit_name
        _check_unit_name(service_name)
        run_cmd(['systemctl', 'stop', service_name], check=False)
        run_cmd(['systemctl', 'disable', service_name], check=False)
        unit_path = f'/etc/systemd/system/{service_name}.service'
        if os.path.exists(unit_path):
            os.remove(unit_path)
            run_cmd(['systemctl', 'daemon-reload'], check=False)
        return True

    def remove_firewall_rule(self, rule_name):
        """Remove UFW rules carrying the ``rule_name`` comment.

        ``ufw delete`` does not accept a rule name — it needs the
        full rule spec or a number. Rules installed by
        ``install_firewall_rule`` are tagged with a comment, so the
        matching rules are located via ``ufw status numbered`` and
        deleted highest-first (numbers shift on each delete).
        """
        status = run_cmd(
            ['ufw', 'status', 'numbered'],
            capture_output=True, text=True,
        )
        if status.returncode != 0:
            return False
        import re
        nums = [
            int(m.group(1)) for m in re.finditer(
                r'\[\s*(\d+)\].*' + re.escape(rule_name), status.stdout)
        ]
        ok = True
        for n in sorted(nums, reverse=True):
            res = run_cmd(
                ['ufw', '--force', 'delete', str(n)],
                capture_output=True,
            )
            ok = ok and res.returncode == 0
        return ok

    def install_firewall_rule(self, port, protocol='tcp', rule_name=None):
        """Allow ``port``/``protocol`` through UFW.

        The rule is tagged with ``comment 'vnc-remote'`` (or
        ``rule_name``) so ``remove_firewall_rule`` can find and
        delete it deterministically — bare ``ufw delete <name>`` is
        not valid UFW syntax. Returns ``True`` on success.
        """
        comment = rule_name or 'vnc-remote'
        result = run_cmd(
            ['ufw', 'allow', f'{port}/{protocol}', 'comment', comment],
            capture_output=True
        )
        return result.returncode == 0

    def create_runtime_user(self, username):
        """Create a Linux user.

        Delegates to ``platform.linux.users`` so the idempotent
        semantics (already-existing user -> True) live in one place.
        """
        from vnc_remote_secure.platform.linux.users import (
            create_runtime_user as _create,
        )
        return _create(username)

    def remove_runtime_user(self, username):
        """Remove a Linux user."""
        from vnc_remote_secure.platform.linux.users import (
            remove_runtime_user as _remove,
        )
        return _remove(username)

    # ---- Service-specific platform operations ----

    def get_lan_ips(self):
        """Return LAN IP addresses, filtering out virtual/loopback adapters."""
        ips = []
        # UDP socket trick for primary LAN IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(('8.8.8.8', 80))
            primary_ip = s.getsockname()[0]
            s.close()
            if primary_ip and not primary_ip.startswith('127.'):
                ips.append(primary_ip)
        except Exception as e:
            logger.debug("LAN IP detection via UDP socket failed: %s", e)
        # Parse 'ip addr' output
        try:
            result = subprocess.run(
                ['ip', 'addr'],
                capture_output=True, text=True, timeout=10, check=False
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    # 'ip addr' lines look like: "inet 10.0.0.5/24 brd ..."
                    # The address token is the token immediately after 'inet'.
                    if len(parts) >= 2 and parts[0] == 'inet':
                        ip = parts[1].split('/')[0]
                        if ip and not ip.startswith('127.') and ip not in ips:
                            ips.append(ip)
        except Exception as e:
            logger.debug("LAN IP detection via 'ip addr' failed: %s", e)
        # Filter virtual adapter ranges
        virtual_ranges = [f'172.{i}.' for i in range(16, 32)]
        virtual_ranges += ['192.168.56.', '192.168.96.', '192.168.204.']
        ips = [ip for ip in ips if not any(ip.startswith(r) for r in virtual_ranges)]
        # Deduplicate preserving order
        seen = set()
        return [ip for ip in ips if not (ip in seen or seen.add(ip))]

    def start_vnc_server(self, display, geometry, depth, password):
        """Start TigerVNC/vncserver. Returns subprocess.Popen.

        The VNC password is written to a protected file (0o600) and
        passed via ``-PasswordFile`` rather than on the command line,
        to avoid exposing it in ``/proc/<pid>/cmdline``.
        """
        exe = shutil.which('tigervncserver') or shutil.which('vncserver')
        if not exe:
            from vnc_remote_secure.core.exceptions import ServiceError
            raise ServiceError("VNC server binary not found on PATH")
        cmd = [exe, display, '-geometry', geometry, '-depth', str(depth)]
        # TigerVNC's wrapper daemonizes by default: it forks Xvnc and
        # exits, so the PID the service manager records dies instantly
        # and the real Xvnc escapes start/stop/status tracking. `-fg`
        # keeps the wrapper in the foreground as Xvnc's parent, which
        # restores correct PID lifecycle management.
        if os.path.basename(exe).startswith('tigervncserver'):
            cmd.append('-fg')
        # ADR-0002: when nginx is the single entry point the RFB port
        # must not listen on all interfaces — direct RFB is only
        # reachable through the loopback websockify bridge. Without
        # nginx (development/direct-access mode) the port stays open
        # for native VNC clients. UFW is only a secondary control: it
        # may not even be installed.
        try:
            from vnc_remote_secure.core.config import get_config
            if get_config().get('nginx_enabled'):
                cmd.extend(['-localhost', 'yes'])
        except Exception:  # noqa: BLE001 - config lookup is best-effort
            pass
        if password:
            passwd_file = self._write_vnc_password_file(password)
            cmd.extend(['-PasswordFile', passwd_file])
        # The RFB server is an external binary that needs none of our
        # credentials — strip secret env vars like the service manager
        # does for websockify (password travels via -PasswordFile).
        child_env = None
        try:
            from vnc_remote_secure.security.redaction import SECRET_VARS
            child_env = {k: v for k, v in os.environ.items()
                         if k not in SECRET_VARS}
        except Exception:  # noqa: BLE001 - env filtering is best-effort
            child_env = None
        return subprocess.Popen(cmd, env=child_env)

    @staticmethod
    def _write_vnc_password_file(password):
        """Write a VNC password to a protected file (0o600).

        TigerVNC expects the password file in the ``vncpasswd``
        format: the 8-byte-padded password DES-encrypted under the
        fixed VNC key (not the password as its own key). We use the
        bundled ``d3des`` implementation to produce the same format.

        The file lives under the canonical run directory (cleaned by
        uninstall) rather than a fresh ``/tmp`` mkstemp on every
        start — the previous behaviour accumulated credential files
        that were never deleted.
        """
        import os
        import tempfile

        from vnc_remote_secure.vendor.d3des import encrypt_vnc_password
        # The file must contain the classic vncpasswd obfuscation:
        # the padded password DES-encrypted under the fixed VNC key.
        encrypted = encrypt_vnc_password(password)
        try:
            from vnc_remote_secure.core.paths import get_run_dir
            base = get_run_dir()
        except Exception:  # noqa: BLE001
            base = tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, 'vnc_passwd.pwd')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, encrypted)
        finally:
            os.close(fd)
        return path

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        """Return ffmpeg input args for PulseAudio/ALSA capture."""
        if not device:
            try:
                result = subprocess.run(
                    ["pactl", "get-default-source"],
                    capture_output=True, text=True, timeout=5
                )
                default_source = result.stdout.strip()
                if default_source:
                    device = f"{default_source}.monitor"
            except Exception as e:
                logger.debug("PulseAudio default source detection failed: %s", e)
        if device:
            input_args = ["-f", "pulse", "-i", device]
        else:
            input_args = ["-f", "alsa", "-i", "default"]
        return input_args

    def list_audio_devices(self, ffmpeg):
        """List PulseAudio/ALSA capture devices."""
        try:
            result = subprocess.run(
                ["pactl", "list", "short", "sources"],
                capture_output=True, text=True, timeout=10
            )
            logger.info("PulseAudio sources:")
            for line in result.stdout.strip().split("\n"):
                if line:
                    logger.info("  %s", line)
        except FileNotFoundError:
            logger.info("pactl not found, trying ALSA...")
            try:
                result = subprocess.run(
                    ["arecord", "-l"],
                    capture_output=True, text=True, timeout=10
                )
                logger.info("%s", result.stdout)
            except FileNotFoundError:
                logger.warning("arecord not found either")

    def create_gamepad_injector(self):
        """Return a LinuxInputInjector (or None if evdev unavailable)."""
        try:
            from vnc_remote_secure.platform.linux.gamepad import LinuxInputInjector
            return LinuxInputInjector()
        except Exception as e:
            logger.debug("Linux gamepad injector unavailable: %s", e)
            return None
