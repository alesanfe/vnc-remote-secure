"""
Platform adapter base class.

Defines the interface that platform-specific adapters must implement.
The business logic calls these methods without knowing whether
the implementation uses systemd, Windows Services, POSIX permissions,
ACLs, UFW, or Windows Firewall.
"""


class PlatformAdapter:
    """Abstract base class for platform-specific operations."""

    def remove_service(self, service_name):
        """Remove a system service."""
        raise NotImplementedError

    def remove_firewall_rule(self, rule_name):
        """Remove a firewall rule."""
        raise NotImplementedError

    def install_firewall_rule(self, port, protocol='tcp', rule_name=None):
        """Install a firewall rule allowing ``port``/``protocol``.

        Concrete adapters should create a named rule so ``remove_firewall_rule``
        can delete it deterministically. Returns ``True`` on success.
        """
        raise NotImplementedError

    def create_runtime_user(self, username):
        """Create a runtime user for service isolation."""
        raise NotImplementedError

    def remove_runtime_user(self, username):
        """Remove a runtime user."""
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
