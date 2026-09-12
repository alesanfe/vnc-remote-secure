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


def is_macos():
    return detect_platform() == 'macos'


def get_architecture():
    """Return architecture string."""
    machine = platform.machine().lower()
    if machine in ('x86_64', 'amd64'):
        return 'x86_64'
    elif machine in ('arm64', 'aarch64'):
        return 'arm64'
    elif machine in ('armv7l', 'armhf'):
        return 'armv7'
    return machine


def get_platform_info():
    """Return a dict with platform, architecture, and OS release info."""
    return {
        'platform': detect_platform(),
        'architecture': get_architecture(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'node': platform.node(),
        'python_version': platform.python_version(),
    }
