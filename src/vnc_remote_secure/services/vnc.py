"""VNC server management for VNC Remote Secure.

Starts and stops a VNC server (TigerVNC on Linux, UltraVNC on Windows)
for a given display and reports its status. The actual process
management is delegated to platform-specific binaries via the platform
adapter.

The base VNC port is read from the ``VNC_PORT`` environment variable
(falling back to ``DEFAULT_VNC_PORT``) so the service honors the
operator's configured port, not just the compile-time default.
"""
import platform

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_VNC_DEPTH,
    DEFAULT_VNC_GEOMETRY,
)
from vnc_remote_secure.core.exceptions import ServiceError
from vnc_remote_secure.core.processes import is_port_available
from vnc_remote_secure.platform.base import get_adapter

# Load .env and platform defaults before any env reads.
load_env_file()


def _vnc_base_port():
    """Return the configured base VNC port — delegates to
    ``core.portal.vnc_base_port`` (single derivation for services and
    engine read models)."""
    from vnc_remote_secure.core.portal import vnc_base_port
    return vnc_base_port()


def _vnc_port(display):
    """Return the RFB port a ``vncserver :N`` display binds — delegates
    to ``core.portal.vnc_display_port`` (TigerVNC 5900+N convention)."""
    from vnc_remote_secure.core.portal import vnc_display_port
    return vnc_display_port(display)


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
    if platform.system() == 'Windows':
        # UltraVNC shares the console session on the configured
        # VNC_PORT; the ``:N`` display offset is a TigerVNC-ism the
        # Windows adapter does not apply.
        port = _vnc_base_port()
    else:
        port = _vnc_port(display_str)

    if not is_port_available(port):
        raise ServiceError(f"VNC server already running on {display_str} (port {port})")

    # VNC legacy DES auth uses only the first 8 bytes of the password.
    # Warn (but do not reject) when a longer password is supplied so the
    # operator is aware of the protocol limitation.
    if password and len(password) > 8:
        import logging
        logging.getLogger(__name__).warning(
            "VNC password is %d characters long; legacy DES auth only uses "
            "the first 8 characters. Consider a shorter, strong password.",
            len(password),
        )
    elif not password:
        # No -PasswordFile / ini passwd → the RFB server accepts
        # unauthenticated connections from whoever can reach the port
        # (loopback at minimum). get_config() normally enforces
        # VNC_PASSWORD, so warn loudly on the direct-call path.
        import logging
        logging.getLogger(__name__).warning(
            "Starting VNC server WITHOUT a password — RFB accepts "
            "unauthenticated connections. Set VNC_PASSWORD.")

    adapter = get_adapter()
    proc = adapter.start_vnc_server(display_str, geometry, depth, password)
    if hasattr(proc, 'pid'):
        # Windows adapter contract: return PID; Linux: return Popen
        if platform.system() == 'Windows':
            return proc.pid
        return proc
    return proc
