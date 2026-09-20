"""Platform detection utilities."""
import platform


def detect_platform():
    """Return 'linux', 'windows', or 'macos'."""
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    elif system == 'darwin':
        return 'macos'
    else:
        return 'linux'


def is_windows():
    return detect_platform() == 'windows'


def is_linux():
    return detect_platform() == 'linux'
