"""Path resolution utilities for VNC Remote Secure.

Provides platform-aware directory locations for configuration, data,
logs, runtime state, and SSL certificates. On Linux the standard FHS
locations (``/etc``, ``/var/lib``, ``/var/log``, ``/run``) are used; on
Windows everything lives under ``%ProgramData%``.
"""
import os
import sys

from vnc_remote_secure.platform.detection import is_windows

_APP_DIR_NAME = 'vnc-remote-secure'
_APP_DIR_NAME_WIN = 'VncRemoteSecure'


def find_project_root():
    """Find the project root by searching upward for ``.env.example``.

    Falls back to the package's grandparent directory when no marker
    file is found.
    """
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        if os.path.exists(os.path.join(current, '.env')):
            return current
        current = os.path.dirname(current)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _win_base():
    """Return the Windows ProgramData base directory."""
    return os.environ.get('ProgramData', r'C:\ProgramData')


def get_config_dir():
    """Return the configuration directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'config')
    return os.path.join('/etc', _APP_DIR_NAME)


def get_data_dir():
    """Return the data directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'data')
    return os.path.join('/var/lib', _APP_DIR_NAME)


def get_log_dir():
    """Return the log directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'logs')
    return os.path.join('/var/log', _APP_DIR_NAME)


def get_run_dir():
    """Return the runtime state directory for the current platform.

    On Windows there is no ``/run`` equivalent, so a ``run`` subdirectory
    of the data directory is used instead.
    """
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'run')
    return os.path.join('/run', _APP_DIR_NAME)


def get_ssl_dir():
    """Return the SSL certificate directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'ssl')
    return os.path.join(get_data_dir(), 'ssl')


def ensure_dirs():
    """Create all standard directories if they do not already exist."""
    for path in (get_config_dir(), get_data_dir(), get_log_dir(),
                 get_run_dir(), get_ssl_dir()):
        os.makedirs(path, exist_ok=True)
