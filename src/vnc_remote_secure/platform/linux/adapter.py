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
import os
import shutil
import subprocess

from vnc_remote_secure.platform.base import PlatformAdapter


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
