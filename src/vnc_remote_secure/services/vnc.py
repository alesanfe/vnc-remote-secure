"""VNC server management for VNC Remote Secure.

Starts and stops a VNC server (TigerVNC on Linux, UltraVNC on Windows)
for a given display and reports its status. The actual process
management is delegated to platform-specific binaries via the platform
adapter.
"""
import getpass
import platform

from vnc_remote_secure.core.constants import (
    DEFAULT_VNC_DEPTH,
    DEFAULT_VNC_GEOMETRY,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.core.exceptions import ServiceError
from vnc_remote_secure.core.processes import find_process, is_port_available
from vnc_remote_secure.core.sessions import create_session, destroy_session
from vnc_remote_secure.platform.base import get_adapter


def _vnc_port(display):
    """Convert a display number to a TCP port (DEFAULT_VNC_PORT + display)."""
    base = DEFAULT_VNC_PORT
    if display is None:
        return base
    num = int(str(display).lstrip(':'))
    return base + num


def start_vnc(display=':1', geometry=DEFAULT_VNC_GEOMETRY,
              depth=DEFAULT_VNC_DEPTH, password=None):
    """Start a VNC server for ``display``.

    Args:
        display: Display number (e.g. ``:1`` or ``1``).
        geometry: Desktop resolution (e.g. ``1280x720``).
        depth: Color depth (e.g. ``24``).
        password: VNC password. Required by the server for authentication.

    Returns:
        The subprocess.Popen instance (or PID on Windows) on success.

    Raises:
        ServiceError: if the server binary is missing or fails to start.
    """
    display_str = str(display)
    if not display_str.startswith(':'):
        display_str = f':{display_str}'
    port = _vnc_port(display_str)

    if not is_port_available(port):
        raise ServiceError(f"VNC server already running on {display_str} (port {port})")

    adapter = get_adapter()
    proc = adapter.start_vnc_server(display_str, geometry, depth, password)
    username = getpass.getuser()
    if hasattr(proc, 'pid'):
        create_session(username, display_str, proc.pid)
        # Windows adapter contract: return PID; Linux: return Popen
        if platform.system() == 'Windows':
            return proc.pid
        return proc
    return proc


def stop_vnc(display=':1'):
    """Stop the VNC server for ``display``.

    Returns ``True`` if the server was stopped (or was not running).
    """
    display_str = str(display)
    if not display_str.startswith(':'):
        display_str = f':{display_str}'
    port = _vnc_port(display_str)
    pid = find_process(port)
    if pid:
        adapter = get_adapter()
        adapter.stop_vnc_process(pid)
    destroy_session(display_str)
    return True


def vnc_status(display=':1'):
    """Return a dict describing the VNC server status for ``display``."""
    display_str = str(display)
    if not display_str.startswith(':'):
        display_str = f':{display_str}'
    port = _vnc_port(display_str)
    listening = not is_port_available(port)
    return {
        'display': display_str,
        'port': port,
        'running': listening,
        'pid': find_process(port),
    }
