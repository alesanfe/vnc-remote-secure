"""Project-wide constants.

Platform-aware defaults (VNC port, health port, web terminal shell) are
derived from the platform adapter via :func:`get_platform_defaults`.
Tests can override the detection by calling :func:`set_platform_override`
or by monkeypatching :func:`get_platform_defaults`.
"""
import logging
import platform

logger = logging.getLogger(__name__)

APP_NAME = "VNC Remote Secure"
APP_VERSION = "0.2.0"

# Module-level override that tests can set via :func:`set_platform_override`.
# When ``None``, defaults are resolved from the platform adapter.
_platform_override = None


def get_platform_defaults():
    """Return platform-specific defaults via the platform adapter.

    This indirection keeps ``core/constants.py`` free of direct
    ``platform.system()`` calls at import time and allows tests to
    monkeypatch the detection. Falls back to a conservative default
    when the adapter cannot be loaded (e.g. during early import).
    """
    if _platform_override is not None:
        return _platform_override
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


def set_platform_override(platform_name=None):
    """Override platform defaults for testing.

    Pass ``'windows'`` or ``'linux'`` to force the corresponding defaults,
    or ``None`` to restore automatic detection.
    """
    global _platform_override, DEFAULT_VNC_PORT, DEFAULT_HEALTH_PORT, DEFAULT_WEBTERM_SHELL
    if platform_name is None:
        _platform_override = None
    elif platform_name == 'windows':
        _platform_override = {
            'vnc_port': 5900,
            'health_port': 8090,
            'webterm_shell': 'cmd.exe',
        }
    elif platform_name == 'linux':
        _platform_override = {
            'vnc_port': 5901,
            'health_port': 8080,
            'webterm_shell': '/bin/bash',
        }
    else:
        raise ValueError(f"Unknown platform: {platform_name}")
    DEFAULT_VNC_PORT = _platform_override['vnc_port'] if _platform_override else get_platform_defaults()['vnc_port']
    DEFAULT_HEALTH_PORT = _platform_override['health_port'] if _platform_override else get_platform_defaults()['health_port']
    DEFAULT_WEBTERM_SHELL = _platform_override['webterm_shell'] if _platform_override else get_platform_defaults()['webterm_shell']


_platform_defaults = get_platform_defaults()

# Port defaults (platform-aware via the adapter)
DEFAULT_VNC_PORT = _platform_defaults['vnc_port']
DEFAULT_VNC_HTTP_PORT = 5800
DEFAULT_NOVNC_PORT = 6080
DEFAULT_TTYD_PORT = 5000
DEFAULT_HEALTH_PORT = _platform_defaults['health_port']

# Terminal username default (platform-aware: current user on Linux, admin on Windows)
import getpass
DEFAULT_TTYD_USERNAME = getpass.getuser() if platform.system() != 'Windows' else 'admin'
DEFAULT_LANDING_PORT = 8000
DEFAULT_USER_UI_PORT = 8081
DEFAULT_AUDIO_STREAM_PORT = 7777
DEFAULT_GAMEPAD_PORT = 7788

# VNC display defaults
DEFAULT_VNC_GEOMETRY = "1280x720"
DEFAULT_VNC_DEPTH = 24
DEFAULT_VNC_DISPLAY = ":1"

# Web terminal
DEFAULT_WEBTERM_SHELL = _platform_defaults['webterm_shell']

# Timeouts and limits (centralized to avoid magic numbers in services)
DEFAULT_CMD_TIMEOUT = 30
DEFAULT_MAX_OUTPUT = 1024 * 1024  # 1 MiB
DEFAULT_PING_INTERVAL = 20
DEFAULT_PING_TIMEOUT = 60

# Security
MIN_PASSWORD_LENGTH = 8
WEAK_PASSWORDS = {"changeme", "admin123", "password", "YourStrongPassword123", "12345678"}
RESERVED_USERNAMES = {"root", "pi", "admin", "daemon", "bin", "sys", "nobody", "www-data"}

# Secure bind address default (localhost; opt-in to 0.0.0.0 for LAN)
DEFAULT_BIND_HOST = "127.0.0.1"
