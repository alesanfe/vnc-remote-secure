"""
Windows platform adapter.

Handles:
- Windows Services
- Windows Firewall (NetFirewall cmdlets)
- ACL permissions (icacls, Set-Acl)
- Local/service account management
- Event Log integration
- Paths: ProgramFiles, ProgramData
"""
import contextlib
import logging
import os
import socket
import subprocess

from vnc_remote_secure.core.processes import run_cmd
from vnc_remote_secure.platform.base import PlatformAdapter
from vnc_remote_secure.platform.windows._powershell import run_powershell

logger = logging.getLogger(__name__)


def _merge_ini_overrides(lines, overrides):
    """Apply ``key=value`` overrides to an UltraVNC ini's ``[admin]`` section.

    Credential keys (``passwd``/``passwd2``) are rewritten in EVERY
    section — a stale ``passwd`` left in [ultravnc]/[poll] would remain
    a working default credential. Structural keys are [admin]-only.
    """
    credential_keys = {'passwd', 'passwd2'}

    def _safe(v):
        # A CR/LF in an override value would inject extra lines into
        # the ini — strip them (values are single-line by definition).
        return str(v).replace('\r', '').replace('\n', '')

    out = []
    seen = set()
    in_admin = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            in_admin = stripped == '[admin]'
            out.append(line)
            continue
        if '=' in line:
            key_name = line.split('=', 1)[0].strip()
            if key_name in credential_keys and key_name in overrides:
                out.append(f'{key_name}={_safe(overrides[key_name])}')
                seen.add(key_name)
                continue
            if in_admin and key_name in overrides:
                out.append(f'{key_name}={_safe(overrides[key_name])}')
                seen.add(key_name)
                continue
        out.append(line)
    missing = [k for k in overrides if k not in seen]
    if missing:
        # Create the [admin] section when absent — a truncated/empty
        # ini must not abort the write.
        if not any(ln.strip() == '[admin]' for ln in out):
            out.append('[admin]')
        idx = next(
            i for i, line in enumerate(out)
            if line.strip() == '[admin]') + 1
        for key_name in missing:
            out.insert(idx, f'{key_name}={_safe(overrides[key_name])}')
            idx += 1
    return out


class WindowsAdapter(PlatformAdapter):
    """Windows-specific platform operations."""

    def get_platform_info(self):
        """Get platform info."""
        return {
            'platform': 'windows',
            'service_manager': 'Windows Services',
            'firewall': 'Windows Firewall (NetFirewall)',
            'config_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'config'),
            'data_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'data'),
            'log_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'logs'),
            'run_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'run'),
            'default_vnc_port': 5900,
            'default_health_port': 8090,
            'default_webterm_shell': 'cmd.exe',
        }

    def _run_powershell(self, script):
        """Run a PowerShell command and return result."""
        return run_powershell(script)

    def remove_service(self, service_name):
        """Remove a Windows Service using sc.exe (the supported path)."""
        from vnc_remote_secure.platform.windows.permissions import (
            _ps_escape,
        )
        # Stop the service first (ignore errors if it isn't running).
        self._run_powershell(
            f"Stop-Service -Name '{_ps_escape(service_name)}' "
            "-Force -ErrorAction SilentlyContinue"
        )
        # sc.exe delete is the documented way to remove a service.
        result = run_cmd(
            ['sc.exe', 'delete', service_name],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    def remove_firewall_rule(self, rule_name):
        """Remove a Windows Firewall rule."""
        from vnc_remote_secure.platform.windows.permissions import (
            _ps_escape,
        )
        ps_script = (
            f"Remove-NetFirewallRule -DisplayName '{_ps_escape(rule_name)}*' "
            # No matching rule is not an error — removal is idempotent,
            # matching firewall.remove_firewall_rule.
            "-ErrorAction SilentlyContinue")
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def install_firewall_rule(self, port, protocol='tcp', rule_name=None):
        """Create a Windows Firewall rule allowing ``port``/``protocol``.

        The rule is named ``VncRemoteSecure-{port}-{protocol}`` so it can
        be removed deterministically via ``remove_firewall_rule``.
        Returns ``True`` on success.
        """
        from vnc_remote_secure.platform.windows.permissions import (
            _ps_escape,
        )
        # Coerce/validate before interpolation: these values land inside
        # a PowerShell command string.
        port = int(port)
        protocol = 'TCP' if str(protocol).lower() == 'tcp' else 'UDP'
        name = _ps_escape(
            rule_name or f'VncRemoteSecure-{port}-{protocol.lower()}')
        # Scope to Private,Domain like firewall.configure_firewall —
        # an unscoped rule applies on Public networks too, which is
        # not what a LAN-only remote-access tool should open.
        ps_script = (
            f"New-NetFirewallRule -DisplayName '{name}' "
            f"-Direction Inbound -Protocol {protocol} "
            f"-LocalPort {port} -Action Allow "
            # SilentlyContinue for idempotency — re-running against an
            # existing rule must report success, matching
            # firewall.configure_firewall.
            "-Profile Private,Domain -ErrorAction SilentlyContinue"
        )
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def create_runtime_user(self, username):
        """Create a restricted local Windows user (idempotent).

        Delegates to :func:`permissions.create_restricted_user` so the
        account is created without interactive logon rights (removed
        from the Users group) — runtime users exist for service
        isolation, not for console access.
        """
        from vnc_remote_secure.platform.windows.permissions import (
            create_restricted_user,
        )
        return create_restricted_user(username)

    def remove_runtime_user(self, username):
        r"""Remove a local Windows user and best-effort delete the profile.

        ``Remove-LocalUser`` only removes the account; the user profile
        directory (``C:\\Users\\<name>``) is left behind. We attempt to
        remove it via ``Remove-Item`` so the cleanup matches Linux's
        ``userdel -r`` semantics. Failures to delete the profile are
        logged but do not fail the operation.
        """
        log = logging.getLogger(__name__)
        # Refuse to remove accounts we did not create: TEMP_USER comes
        # from the environment, so a misconfiguration naming a builtin
        # (Administrator, SYSTEM) would otherwise reach Remove-LocalUser.
        from vnc_remote_secure.core.constants import (
            RESERVED_USERNAMES,
            WINDOWS_BUILTIN_USERNAMES,
        )
        if username in WINDOWS_BUILTIN_USERNAMES \
                or username.lower() in {u.lower() for u in RESERVED_USERNAMES}:
            log.warning(
                "Refusing to remove reserved/builtin user %s", username)
            return False
        from vnc_remote_secure.platform.windows.permissions import (
            _ps_escape,
        )
        ps_script = (
            f"Remove-LocalUser -Name '{_ps_escape(username)}' "
            "-ErrorAction SilentlyContinue"
        )
        result = self._run_powershell(ps_script)
        # Best-effort profile removal (matches Linux ``userdel -r``).
        profile_path = f"C:\\Users\\{username}"
        try:
            import shutil
            if os.path.isdir(profile_path):
                shutil.rmtree(profile_path, ignore_errors=True)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            log.debug("Could not remove profile %s: %s", profile_path, exc)
        return result.returncode == 0

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
        # PowerShell Get-NetIPAddress for physical adapters
        try:
            ps_cmd = (
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object { $_.IPAddress -ne '127.0.0.1' -and "
                "$_.IPAddress -notlike '169.254.*' -and "
                "$_.IPAddress -notmatch '^172\\.(1[6-9]|2[0-9]|3[01])\\.' -and "
                "$_.IPAddress -notlike '192.168.56.*' -and "
                "$_.IPAddress -notlike '192.168.96.*' -and "
                "$_.IPAddress -notlike '192.168.204.*' } | "
                "Select-Object -ExpandProperty IPAddress -Unique"
            )
            result = run_cmd(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=10, check=False
            )
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and line not in ips and not line.startswith('127.'):
                    ips.append(line)
        except Exception as e:
            logger.debug("LAN IP detection via PowerShell failed: %s", e)
        # Filter virtual adapter ranges
        virtual_ranges = [f'172.{i}.' for i in range(16, 32)]
        virtual_ranges += ['192.168.56.', '192.168.96.', '192.168.204.']
        ips = [ip for ip in ips if not any(ip.startswith(r) for r in virtual_ranges)]
        # Deduplicate preserving order
        seen = set()
        return [ip for ip in ips if not (ip in seen or seen.add(ip))]

    def start_vnc_server(self, display, geometry, depth, password):
        """Start UltraVNC winvnc.exe with the requested parameters.

        UltraVNC does NOT accept TigerVNC-style command-line flags — it
        has no ``-passwordfile``, ``-geometry``, ``-depth``, or ``:N``
        display argument. In file-settings mode (``UseRegistry=0``) it
        reads ``ultravnc.ini`` from the directory containing
        winvnc.exe, so the effective settings (DES-encrypted RFB
        password, RFB/HTTP ports, unattended accept) are rendered into
        that file before launch. ``geometry``/``depth`` are ignored:
        UltraVNC shares the console session at its native resolution.

        Note: The VNC process currently runs under the current user's
        context, not under the restricted runtime user. Full process
        impersonation (CreateProcessAsUser) is a planned enhancement
        (see ADR-0007). The restricted runtime user is created by the
        installer and secret files (config.env, TLS keys) get owner-only
        ACLs, but the VNC process itself is not yet sandboxed to that
        user.
        """
        from vnc_remote_secure.core.exceptions import ServiceError
        from vnc_remote_secure.platform.windows.installer import _find_ultravnc
        exe = _find_ultravnc()
        if not exe:
            raise ServiceError(
                "UltraVNC winvnc.exe not found. Run 'vnc-remote install' to "
                "provision it automatically, or install UltraVNC manually and "
                "set ULTRAVNC_PATH in your .env file."
            )
        try:
            self._write_ultravnc_ini(exe, password)
        except OSError as e:
            # Non-fatal: winvnc launches with whatever settings are in
            # the existing ini (e.g. a Program Files install dir the
            # current user cannot write).
            logger.warning(
                "Could not write ultravnc.ini next to %s: %s — "
                "starting with the existing settings", exe, e)
        # winvnc is an external binary that needs none of our
        # credentials — strip secret env vars like the service manager
        # does for websockify (the password travels via ultravnc.ini).
        try:
            from vnc_remote_secure.security.redaction import (
                sanitized_child_env,
            )
            child_env = sanitized_child_env()
        except Exception:  # noqa: BLE001 - import broken entirely
            child_env = {'PATH': os.environ.get('PATH', '')}
        return subprocess.Popen([exe], env=child_env)

    @staticmethod
    def _write_ultravnc_ini(exe, password):
        """Render ``ultravnc.ini`` next to the resolved winvnc.exe.

        Updates only the keys the app manages inside the ``[admin]``
        section — the DES-encrypted RFB password (same legacy DES the
        wire protocol uses), the RFB/HTTP ports from config, and
        ``QueryAccept=0`` so unattended connections are not gated on a
        console-side prompt. Any other existing keys are preserved.
        """
        from vnc_remote_secure.core.config import get_config
        from vnc_remote_secure.vendor.d3des import encrypt_vnc_password

        ini_path = os.path.join(os.path.dirname(exe), 'ultravnc.ini')
        from vnc_remote_secure.core.constants import (
            DEFAULT_VNC_HTTP_PORT,
            DEFAULT_VNC_PORT,
        )
        config = get_config()
        overrides = {
            'UseRegistry': '0',
            'SocketConnect': '1',
            'HTTPConnect': '1',
            'AllowLoopback': '1',
            'AuthRequired': '1',
            'QueryAccept': '0',
            'PortNumber': str(config.get('vnc_port', DEFAULT_VNC_PORT)),
            'HTTPPortNumber': str(config.get(
                'vnc_http_port', DEFAULT_VNC_HTTP_PORT)),
        }
        # ADR-0002 parity with TigerVNC ``-localhost yes``: when nginx
        # is the single entry point the RFB port must not listen on all
        # interfaces — the loopback websockify bridge still works.
        # Without nginx the port stays open for native VNC clients.
        if config.get('nginx_enabled'):
            overrides['LoopbackOnly'] = '1'
        if password:
            # ultravnc.ini ``passwd`` uses the classic vncpasswd
            # format (8-byte padded password, fixed-key DES). UltraVNC
            # reads it via GetPrivateProfileStruct(), which requires a
            # trailing checksum byte = sum(data) & 0xFF appended to the
            # hex string — without it the API fails and winvnc reports
            # "no valid password enabled".
            blob = encrypt_vnc_password(password)
            hex_pass = blob.hex().upper() + f'{sum(blob) & 0xFF:02X}'
            overrides['passwd'] = hex_pass
            # passwd2 is UltraVNC's view-only password. Setting it
            # equal to passwd is deliberate: a *different* stale
            # passwd2 left in the ini would still authenticate a
            # view-only login (credential bypass for viewing), and
            # per-session view-only is enforced at the control-channel
            # layer, not in RFB (see services/novnc.py).
            overrides['passwd2'] = hex_pass

        try:
            with open(ini_path, encoding='utf-8', errors='replace') as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = ['[admin]']
        if not any(line.strip() == '[admin]' for line in lines):
            lines.insert(0, '[admin]')

        out = _merge_ini_overrides(lines, overrides)
        # Atomic write: a truncated ultravnc.ini would leave winvnc
        # running with corrupted/partial settings (including a stale
        # or missing password).
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(ini_path) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as fh:
                fh.write('\n'.join(out) + '\n')
            os.replace(tmp, ini_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        """Return ffmpeg input args for DirectShow capture."""
        if not device:
            device = "audio=Stereo Mix (Realtek High Definition Audio)"
        return ["-f", "dshow", "-i", device]

    def list_audio_devices(self, ffmpeg):
        """List DirectShow audio capture devices."""
        try:
            result = run_cmd(
                ["ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy"],
                capture_output=True, text=True, timeout=10
            )
            # ffmpeg outputs device list to stderr
            logger.info("%s", result.stderr)
        except Exception:
            logger.exception("Error listing devices:")

    def create_gamepad_injector(self):
        """Return a WindowsInputInjector (or None if unavailable)."""
        try:
            from vnc_remote_secure.platform.windows.gamepad import WindowsInputInjector
            return WindowsInputInjector()
        except Exception as e:
            logger.debug("Windows gamepad injector unavailable: %s", e)
            return None
