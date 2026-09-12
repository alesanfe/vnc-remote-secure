"""
Platform adapter base class.

Defines the interface that platform-specific adapters must implement.
The business logic calls these methods without knowing whether
the implementation uses systemd, Windows Services, POSIX permissions,
ACLs, UFW, or Windows Firewall.
"""


class PlatformAdapter:
    """Abstract base class for platform-specific operations."""

    def install_service(self, service_definition):
        """Install a system service."""
        raise NotImplementedError

    def remove_service(self, service_name):
        """Remove a system service."""
        raise NotImplementedError

    def start_service(self, service_name):
        """Start a system service."""
        raise NotImplementedError

    def stop_service(self, service_name):
        """Stop a system service."""
        raise NotImplementedError

    def service_status(self, service_name):
        """Get service status. Returns dict with 'running', 'enabled'."""
        raise NotImplementedError

    def configure_firewall(self, port, protocol='tcp', direction='inbound', action='allow'):
        """Configure a firewall rule."""
        raise NotImplementedError

    def remove_firewall_rule(self, rule_name):
        """Remove a firewall rule."""
        raise NotImplementedError

    def create_runtime_user(self, username):
        """Create a runtime user for service isolation."""
        raise NotImplementedError

    def remove_runtime_user(self, username):
        """Remove a runtime user."""
        raise NotImplementedError

    def configure_permissions(self, path, owner, mode=None):
        """Set permissions on a path."""
        raise NotImplementedError

    def get_platform_info(self):
        """Return platform information dict."""
        raise NotImplementedError

    # ---- Service-specific platform operations ----

    def get_lan_ips(self):
        """Return a list of LAN IP addresses (excluding virtual/loopback)."""
        raise NotImplementedError

    def start_vnc_server(self, display, geometry, depth, password):
        """Start the platform VNC server.

        Returns a process object (with a ``pid`` attribute) on success, or
        raises :class:`ServiceError` if the server binary is missing or fails
        to start.
        """
        raise NotImplementedError

    def stop_vnc_process(self, pid):
        """Stop a VNC process by PID."""
        raise NotImplementedError

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        """Return ffmpeg input args for audio capture on this platform."""
        raise NotImplementedError

    def list_audio_devices(self, ffmpeg):
        """List available audio capture devices (platform-specific)."""
        raise NotImplementedError

    def create_gamepad_injector(self):
        """Return a platform-specific gamepad injector instance (or None)."""
        raise NotImplementedError


def get_adapter():
    """Detect platform and return the appropriate adapter instance."""
    import platform
    system = platform.system().lower()
    if system == 'windows':
        from vnc_remote_secure.platform.windows.adapter import WindowsAdapter
        return WindowsAdapter()
    else:
        from vnc_remote_secure.platform.linux.adapter import LinuxAdapter
        return LinuxAdapter()
