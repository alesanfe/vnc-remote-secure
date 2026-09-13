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
import logging
import os
import shutil
import socket
import subprocess

from vnc_remote_secure.platform.base import PlatformAdapter

logger = logging.getLogger(__name__)


class WindowsAdapter(PlatformAdapter):
    """Windows-specific platform operations."""

    def get_platform_info(self):
        return {
            'platform': 'windows',
            'service_manager': 'Windows Services',
            'firewall': 'Windows Firewall (NetFirewall)',
            'config_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'config'),
            'data_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'data'),
            'log_dir': os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'VncRemoteSecure', 'logs'),
            'default_vnc_port': 5900,
            'default_health_port': 8090,
            'default_webterm_shell': 'cmd.exe',
        }

    def _run_powershell(self, script):
        """Run a PowerShell command and return result."""
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', script],
            capture_output=True, text=True
        )
        return result

    def install_service(self, service_definition):
        """Install a Windows Service."""
        service_name = service_definition.get('service_name')
        binary_path = service_definition.get('binary_path')
        if not service_name or not binary_path:
            return False
        ps_script = f"New-Service -Name '{service_name}' -BinaryPathName '{binary_path}' -StartupType Automatic"
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def remove_service(self, service_name):
        """Remove a Windows Service."""
        ps_script = f"Stop-Service -Name '{service_name}' -Force; (Get-Service -Name '{service_name}').Delete()"
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def start_service(self, service_name):
        """Start a Windows Service."""
        result = self._run_powershell(f"Start-Service -Name '{service_name}'")
        return result.returncode == 0

    def stop_service(self, service_name):
        """Stop a Windows Service."""
        result = self._run_powershell(f"Stop-Service -Name '{service_name}' -Force")
        return result.returncode == 0

    def service_status(self, service_name):
        """Get Windows Service status."""
        result = self._run_powershell(
            f"(Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue).Status"
        )
        running = result.stdout.strip().lower() == 'running'
        return {'running': running, 'enabled': True}

    def configure_firewall(self, port, protocol='tcp', direction='inbound', action='allow'):
        """Configure Windows Firewall rule."""
        rule_name = f'VncRemoteSecure-{port}-{protocol}'
        ps_action = 'Allow' if action == 'allow' else 'Block'
        ps_direction = 'Inbound' if direction == 'inbound' else 'Outbound'
        ps_script = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction {ps_direction} -Protocol {protocol.upper()} "
            f"-LocalPort {port} -Action {ps_action} -Profile Private,Domain"
        )
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def remove_firewall_rule(self, rule_name):
        """Remove a Windows Firewall rule."""
        ps_script = f"Remove-NetFirewallRule -DisplayName '{rule_name}*'"
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def create_runtime_user(self, username):
        """Create a local Windows user."""
        ps_script = f"New-LocalUser -Name '{username}' -NoPassword -Description 'VNC Remote Secure runtime user'"
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def remove_runtime_user(self, username):
        """Remove a local Windows user."""
        ps_script = f"Remove-LocalUser -Name '{username}' -ErrorAction SilentlyContinue"
        result = self._run_powershell(ps_script)
        return result.returncode == 0

    def configure_permissions(self, path, owner, mode=None):
        """Set ACL permissions on a path using icacls."""
        # Use icacls for ACL management
        result = subprocess.run(
            ['icacls', path, '/grant', f'{owner}:(OI)(CI)F', '/T'],
            capture_output=True
        )
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
                "$_.IPAddress -notlike '172.*' -and "
                "$_.IPAddress -notlike '192.168.56.*' -and "
                "$_.IPAddress -notlike '192.168.96.*' -and "
                "$_.IPAddress -notlike '192.168.204.*' } | "
                "Select-Object -ExpandProperty IPAddress -Unique"
            )
            result = subprocess.run(
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
        """Start UltraVNC winvnc.exe. Returns subprocess.Popen.

        Note: The VNC process currently runs under the current user's
        context, not under the restricted runtime user. Full process
        impersonation (CreateProcessAsUser) is a planned enhancement
        (see ADR-0007). The restricted user is created and ACLs are
        applied to the data directory, but the VNC process itself is
        not yet sandboxed to that user.
        """
        exe = shutil.which('winvnc')
        if not exe:
            from vnc_remote_secure.core.exceptions import ServiceError
            raise ServiceError("UltraVNC winvnc.exe not found on PATH")
        return subprocess.Popen([exe])

    def stop_vnc_process(self, pid):
        """Stop a VNC process by PID using taskkill."""
        subprocess.run(['taskkill', '/PID', str(pid), '/F'],
                       capture_output=True)

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        """Return ffmpeg input args for DirectShow capture."""
        if not device:
            device = "audio=Stereo Mix (Realtek High Definition Audio)"
        return ["-f", "dshow", "-i", device]

    def list_audio_devices(self, ffmpeg):
        """List DirectShow audio capture devices."""
        try:
            result = subprocess.run(
                ["ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy"],
                capture_output=True, text=True, timeout=10
            )
            # ffmpeg outputs device list to stderr
            logger.info("%s", result.stderr)
        except Exception as e:
            logger.error("Error listing devices: %s", e)

    def create_gamepad_injector(self):
        """Return a WindowsInputInjector (or None if unavailable)."""
        try:
            from vnc_remote_secure.platform.windows.gamepad import WindowsInputInjector
            return WindowsInputInjector()
        except Exception as e:
            logger.debug("Windows gamepad injector unavailable: %s", e)
            return None
