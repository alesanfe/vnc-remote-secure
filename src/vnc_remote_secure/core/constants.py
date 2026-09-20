"""Project-wide constants.

Platform-aware defaults (VNC port, health port, web terminal shell) are
derived from the platform adapter via :func:`get_platform_defaults`.
Tests can monkeypatch :func:`get_platform_defaults` to override detection.
"""
import logging
import platform

from vnc_remote_secure import __version__ as APP_VERSION

__all__ = ['APP_NAME', 'APP_VERSION', 'get_platform_defaults']

logger = logging.getLogger(__name__)

APP_NAME = "VNC Remote Secure"


def get_platform_defaults():
    """Return platform-specific defaults via the platform adapter.

    This indirection keeps ``core/constants.py`` free of direct
    ``platform.system()`` calls at import time and allows tests to
    monkeypatch the detection. Falls back to a conservative default
    when the adapter cannot be loaded (e.g. during early import).
    """
    try:
        from vnc_remote_secure.platform.base import get_adapter
        info = get_adapter().get_platform_info()
        return {
            'vnc_port': info.get('default_vnc_port', 5901),
            'health_port': info.get('default_health_port', 8080),
            'webterm_shell': info.get('default_webterm_shell', '/bin/bash'),
        }
    except (ImportError, AttributeError, NotImplementedError) as exc:
        logger.warning("Platform adapter unavailable, using fallback: %s", exc)
        is_win = platform.system() == 'Windows'
        return {
            'vnc_port': 5900 if is_win else 5901,
            'health_port': 8090 if is_win else 8080,
            'webterm_shell': 'cmd.exe' if is_win else '/bin/bash',
        }


_platform_defaults = get_platform_defaults()

# Port defaults (platform-aware via the adapter)
DEFAULT_VNC_PORT = _platform_defaults['vnc_port']
DEFAULT_VNC_HTTP_PORT = 5800
DEFAULT_NOVNC_PORT = 6080
DEFAULT_TTYD_PORT = 5000
DEFAULT_HEALTH_PORT = _platform_defaults['health_port']

# Web Terminal username default (platform-aware: current user on Linux, admin on Windows)
import getpass

DEFAULT_TTYD_USERNAME = getpass.getuser() if platform.system() != 'Windows' else 'admin'
DEFAULT_LANDING_PORT = 8000
DEFAULT_USER_UI_PORT = 8081
DEFAULT_NOVNC_WS_PORT = 5700  # loopback websockify bridge (NOVNC_WS_PORT)
DEFAULT_AUDIO_STREAM_PORT = 7777
DEFAULT_GAMEPAD_PORT = 7788
DEFAULT_NGINX_HTTP_PORT = 80
DEFAULT_NGINX_HTTPS_PORT = 443

# TigerVNC binds its RFB port at 5900 + display number regardless of an
# explicit VNC_PORT — the adapter launches ``vncserver :N`` without
# -rfbport, so probes must derive the port from the display.
TIGERVNC_BASE_PORT = 5900

# VNC display defaults
DEFAULT_VNC_GEOMETRY = "1280x720"
DEFAULT_VNC_DEPTH = 24
DEFAULT_VNC_DISPLAY = ":1"

# Web Terminal
DEFAULT_WEBTERM_SHELL = _platform_defaults['webterm_shell']

# Timeouts and limits (centralized to avoid magic numbers in services)
DEFAULT_CMD_TIMEOUT = 30
DEFAULT_MAX_OUTPUT = 1024 * 1024  # 1 MiB
DEFAULT_PING_INTERVAL = 20
DEFAULT_PING_TIMEOUT = 60

# Session timeouts — single source of truth for the fallbacks used
# when SESSION_IDLE_TIMEOUT / SESSION_MAX_LIFETIME are unset. These
# match the schema defaults and .env.example shipped values.
DEFAULT_SESSION_IDLE_TIMEOUT = 1800   # 30 minutes
DEFAULT_SESSION_MAX_LIFETIME = 28800  # 8 hours
DEFAULT_SESSION_SAMESITE = 'Lax'      # SESSION_SAMESITE cookie attribute

# Security
MIN_PASSWORD_LENGTH = 8
WEAK_PASSWORDS = {"changeme", "admin123", "password", "YourStrongPassword123", "12345678"}
WEAK_PASSWORD_PATTERNS = (
    "password", "123456", "qwerty", "changeme", "admin", "root",
    "user", "yourstrongpassword", "letmein", "welcome",
)
RESERVED_USERNAMES = {"root", "pi", "admin", "daemon", "bin", "sys", "nobody", "www-data"}
# Windows built-in accounts that must never be modified through the UI.
WINDOWS_BUILTIN_USERNAMES = {
    "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount",
}

# Secure bind address default (127.0.0.1; opt-in to 0.0.0.0 for LAN)
DEFAULT_BIND_HOST = "127.0.0.1"
