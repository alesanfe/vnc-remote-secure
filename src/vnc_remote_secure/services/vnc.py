"""VNC server management for VNC Remote Secure.

Starts and stops a VNC server (TigerVNC on Linux, UltraVNC on Windows)
for a given display and reports its status. The actual process
management is delegated to platform-specific binaries.
"""
import os
import shutil
import subprocess

from vnc_remote_secure.core.constants import DEFAULT_VNC_DEPTH, DEFAULT_VNC_GEOMETRY
from vnc_remote_secure.core.exceptions import ServiceError
from vnc_remote_secure.core.processes import find_process, is_port_available
from vnc_remote_secure.core.sessions import create_session, destroy_session
from vnc_remote_secure.platform.detection import is_windows


def _vnc_port(display):
    """Convert a display number to a TCP port (5900 + display)."""
    if display is None:
        return 5900
    num = int(str(display).lstrip(':'))
    return 5900 + num


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

    if is_windows():
        exe = shutil.which('winvnc')
        if not exe:
            raise ServiceError("UltraVNC winvnc.exe not found on PATH")
        proc = subprocess.Popen([exe])
        create_session(os.environ.get('USERNAME', 'unknown'), display_str, proc.pid)
        return proc.pid
    else:
        exe = shutil.which('tigervncserver') or shutil.which('vncserver')
        if not exe:
            raise ServiceError("VNC server binary not found on PATH")
        cmd = [exe, display_str, '-geometry', geometry, '-depth', str(depth)]
        if password:
            cmd.extend(['-password', password])
        proc = subprocess.Popen(cmd)
        create_session(os.environ.get('USER', 'unknown'), display_str, proc.pid)
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
        if is_windows():
            subprocess.run(['taskkill', '/PID', str(pid), '/F'],
                           capture_output=True)
        else:
            subprocess.run(['kill', '-TERM', str(pid)], capture_output=True)
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
