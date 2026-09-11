"""Session management for VNC Remote Secure.

Tracks VNC display sessions in a simple in-memory registry. Each
session maps a display number (e.g. ``:1``) to the owning user and the
process PID. A JSON file under the runtime directory can be used for
persistence across restarts.
"""
import json
import os
import time

from vnc_remote_secure.core.paths import get_run_dir

_SESSIONS = {}
_SESSION_FILE = 'sessions.json'


def _session_path():
    return os.path.join(get_run_dir(), _SESSION_FILE)


def _load_sessions():
    """Load persisted sessions from disk into the in-memory registry."""
    global _SESSIONS
    path = _session_path()
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                _SESSIONS = json.load(f)
        except (OSError, ValueError):
            _SESSIONS = {}
    return _SESSIONS


def _save_sessions():
    """Persist the in-memory session registry to disk."""
    path = _session_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(_SESSIONS, f, indent=2)
    except OSError:
        pass


def create_session(user, display, pid=None):
    """Register a new VNC session.

    Args:
        user: The username owning the session.
        display: The display number (e.g. ``:1`` or ``1``).
        pid: Optional process ID of the VNC server.

    Returns:
        The created session dictionary.
    """
    if not display:
        display = ':1'
    if not display.startswith(':'):
        display = f':{display}'
    session = {
        'user': user,
        'display': display,
        'pid': pid,
        'created_at': time.time(),
    }
    _SESSIONS[display] = session
    _save_sessions()
    return session


def destroy_session(display):
    """Remove a session from the registry.

    Returns the removed session dict, or ``None`` if it did not exist.
    """
    if display and not display.startswith(':'):
        display = f':{display}'
    session = _SESSIONS.pop(display, None)
    if session is not None:
        _save_sessions()
    return session


def list_sessions():
    """Return a list of all known sessions."""
    _load_sessions()
    return list(_SESSIONS.values())


def get_session(display):
    """Return the session dict for ``display`` or ``None``."""
    if display and not display.startswith(':'):
        display = f':{display}'
    return _SESSIONS.get(display)
