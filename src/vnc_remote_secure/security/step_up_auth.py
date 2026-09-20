"""Step-up authentication for sensitive actions.

Certain actions require a recent authentication, not just a valid
session. This module tracks when each user last authenticated and
provides helpers to enforce step-up auth for sensitive actions.

Sensitive actions that require step-up auth (the enforced set — see
``SENSITIVE_ACTIONS``):
- Opening a terminal (WebSocket open).
- Creating an admin user.
- Deleting an admin user.

Other sensitive operations (disabling TLS, changing the security
profile, rotating secrets, modifying the firewall, creating a support
session) are CLI-only surfaces where the operator already holds a
local shell — a web-session step-up has no enforcement point there.

Usage:
    from vnc_remote_secure.security.step_up_auth import (
        record_auth_time,
        needs_step_up,
    )

    # After successful login or MFA:
    record_auth_time(username)

    # Before a sensitive action:
    if needs_step_up(username, max_age_seconds=300):
        return error_json('Re-authentication required', 403)
"""
import logging
import threading
import time
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# Actions that require step-up authentication. This set contains only
# actions that actually have a runtime enforcement point — every entry
# has a ``require_step_up`` call site:
#   open_terminal  -> services/terminal.py WebSocket open
#   create_admin   -> web/routes/users.py /create_user, /api/users POST
#   delete_admin   -> web/routes/users.py /delete_user, /api/users DELETE
#
# The remaining sensitive operations (disable_tls, change_profile,
# rotate_secrets, modify_firewall, view_audit_log, session creation)
# are CLI-only: the operator already holds a local shell, so a web
# session step-up has no enforcement surface there. ``file_transfer``
# has no implementation at all.
SENSITIVE_ACTIONS: Set[str] = {
    'open_terminal',
    'create_admin',
    'delete_admin',
}


class StepUpAuthManager:
    """Tracks recent authentication times for step-up auth."""

    _NS = 'step_up_auth_times'

    def __init__(self, default_max_age: int = 300):
        """Initialize the manager.

        Auth times live in the shared-state backend so a login
        recorded by the user-UI process satisfies step-up checks in
        the terminal process — a purely in-memory dict would make
        every cross-process sensitive action report "never
        authenticated" and reject (the F-018 class of bug).

        Args:
            default_max_age: Default max age (seconds) for step-up auth
                validity. Actions requiring step-up auth must have been
                authenticated within this window.
        """
        self._auth_times: Dict[str, float] = {}  # process-local cache
        self._lock = threading.Lock()
        self.default_max_age = default_max_age

    def _backend_get(self, username: str) -> Optional[float]:
        """Read the auth time from the shared backend."""
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            val = get_backend().get(self._NS, username)
            return float(val) if val is not None else None
        except Exception:  # noqa: BLE001 - backend must not break auth
            return self._auth_times.get(username)

    def record_auth_time(self, username: str, auth_time: Optional[float] = None):
        """Record that a user has authenticated.

        Args:
            username: The user who authenticated.
            auth_time: Timestamp of authentication (default: now).
        """
        ts = auth_time or time.time()
        with self._lock:
            self._auth_times[username] = ts
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            # TTL 24h — auth records are useless past any session lifetime.
            get_backend().set_ttl(self._NS, username, ts, 86400)
        except Exception:  # noqa: BLE001
            pass
        logger.debug('Step-up auth recorded for user: %s', username)

    def needs_step_up(self, username: str, max_age: Optional[int] = None) -> bool:
        """Check if a user needs to re-authenticate.

        Args:
            username: The user to check.
            max_age: Max age in seconds (default: self.default_max_age).

        Returns:
            True if the user needs to re-authenticate (or has never
            authenticated), False if they have a recent authentication.
        """
        age = max_age if max_age is not None else self.default_max_age
        last_auth = self._backend_get(username)
        if last_auth is None:
            return True  # Never authenticated
        return (time.time() - last_auth) > age

    def get_auth_age(self, username: str) -> Optional[float]:
        """Return the age (seconds) of the last authentication.

        Returns None if the user has never authenticated.
        """
        last_auth = self._backend_get(username)
        if last_auth is None:
            return None
        return time.time() - last_auth

    def clear(self, username: Optional[str] = None):
        """Clear auth time for a user (or all users if None)."""
        with self._lock:
            if username:
                self._auth_times.pop(username, None)
            else:
                self._auth_times.clear()
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            backend = get_backend()
            if username:
                backend.delete(self._NS, username)
            else:
                for key in backend.list_keys(self._NS):
                    backend.delete(self._NS, key)
        except Exception:  # noqa: BLE001
            pass

    def cleanup(self, max_age: int = 3600):
        """Remove stale auth records older than max_age."""
        with self._lock:
            cutoff = time.time() - max_age
            stale = [u for u, t in self._auth_times.items() if t < cutoff]
            for u in stale:
                del self._auth_times[u]


# Global singleton.
_manager: Optional[StepUpAuthManager] = None


def get_step_up_manager() -> StepUpAuthManager:
    """Return the process-wide step-up auth manager."""
    global _manager
    if _manager is None:
        _manager = StepUpAuthManager()
    return _manager


def record_auth_time(username: str, auth_time: Optional[float] = None):
    """Record that a user has authenticated (convenience function)."""
    get_step_up_manager().record_auth_time(username, auth_time)


def needs_step_up(username: str, max_age: Optional[int] = None) -> bool:
    """Check if a user needs step-up auth (convenience function)."""
    return get_step_up_manager().needs_step_up(username, max_age)


def require_step_up(username: str, action: str,
                    max_age: Optional[int] = None) -> Optional[str]:
    """Check if a sensitive action requires step-up auth.

    Args:
        username: The user performing the action.
        action: The action being performed (must be in SENSITIVE_ACTIONS).
        max_age: Max age for step-up auth validity.

    Returns:
        None if the action is allowed, or an error message if
        step-up auth is required.
    """
    if action not in SENSITIVE_ACTIONS:
        return None  # Not a sensitive action

    if needs_step_up(username, max_age):
        logger.warning(
            'Step-up auth required for user %s on action %s', username, action
        )
        return (
            f'Re-authentication required for action: {action}. '
            f'Please log in again or provide MFA.'
        )
    return None
