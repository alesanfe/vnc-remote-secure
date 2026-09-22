"""Platform detection utilities."""
import platform


def detect_platform():
    """Return 'linux', 'windows', or 'macos'."""
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    if system == 'darwin':
        return 'macos'
    return 'linux'


def is_windows():
    """Is windows."""
    return detect_platform() == 'windows'


def is_linux():
    """Is linux."""
    return detect_platform() == 'linux'
