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

    def install_service(self, service_definition):
        """Install a systemd unit file and reload daemon."""
        unit_path = service_definition.get('unit_path')
        unit_content = service_definition.get('unit_content')
        if unit_path and unit_content:
            with open(unit_path, 'w') as f:
                f.write(unit_content)
            subprocess.run(['systemctl', 'daemon-reload'], check=False)
            return True
        return False

    def remove_service(self, service_name):
        """Stop and remove a systemd service."""
        subprocess.run(['systemctl', 'stop', service_name], check=False)
        subprocess.run(['systemctl', 'disable', service_name], check=False)
        unit_path = f'/etc/systemd/system/{service_name}.service'
        if os.path.exists(unit_path):
            os.remove(unit_path)
            subprocess.run(['systemctl', 'daemon-reload'], check=False)
        return True

    def start_service(self, service_name):
        """Start a systemd service."""
        result = subprocess.run(['systemctl', 'start', service_name])
        return result.returncode == 0

    def stop_service(self, service_name):
        """Stop a systemd service."""
        result = subprocess.run(['systemctl', 'stop', service_name])
        return result.returncode == 0

    def service_status(self, service_name):
        """Get systemd service status."""
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True, text=True
        )
        running = result.stdout.strip() == 'active'
        result2 = subprocess.run(
            ['systemctl', 'is-enabled', service_name],
            capture_output=True, text=True
        )
        enabled = result2.stdout.strip() == 'enabled'
        return {'running': running, 'enabled': enabled}

    def configure_firewall(self, port, protocol='tcp', direction='inbound', action='allow'):
        """Configure UFW firewall rule."""
        if direction != 'inbound':
            return False
        ufw_action = 'allow' if action == 'allow' else 'deny'
        result = subprocess.run(
            ['ufw', ufw_action, f'{port}/{protocol}'],
            capture_output=True
        )
        return result.returncode == 0

    def remove_firewall_rule(self, rule_name):
        """Remove a UFW rule."""
        result = subprocess.run(
            ['ufw', 'delete', rule_name],
            capture_output=True
        )
        return result.returncode == 0

    def create_runtime_user(self, username):
        """Create a Linux user."""
        result = subprocess.run(
            ['useradd', '-r', '-s', '/usr/sbin/nologin', username],
            capture_output=True
        )
        return result.returncode == 0

    def remove_runtime_user(self, username):
        """Remove a Linux user."""
        result = subprocess.run(
            ['userdel', '-r', username],
            capture_output=True
        )
        return result.returncode == 0

    def configure_permissions(self, path, owner, mode=None):
        """Set POSIX permissions on a path."""
        if mode is not None:
            os.chmod(path, mode)
        if ':' in owner:
            user, group = owner.split(':')
            shutil.chown(path, user, group)
        else:
            shutil.chown(path, owner)
        return True

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
                    for part in parts:
                        if part.startswith('inet') and '/' in part:
                            ip = part.split('/')[0].replace('inet', '').strip()
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
        """Start TigerVNC/vncserver. Returns subprocess.Popen."""
        exe = shutil.which('tigervncserver') or shutil.which('vncserver')
        if not exe:
            from vnc_remote_secure.core.exceptions import ServiceError
            raise ServiceError("VNC server binary not found on PATH")
        cmd = [exe, display, '-geometry', geometry, '-depth', str(depth)]
        if password:
            cmd.extend(['-password', password])
        return subprocess.Popen(cmd)

    def stop_vnc_process(self, pid):
        """Stop a VNC process by PID using kill."""
        subprocess.run(['kill', '-TERM', str(pid)], capture_output=True)

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
