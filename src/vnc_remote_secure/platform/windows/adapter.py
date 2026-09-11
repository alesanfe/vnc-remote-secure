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
import os
import subprocess

from vnc_remote_secure.platform.base import PlatformAdapter


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
