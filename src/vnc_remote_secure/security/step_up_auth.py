"""Step-up authentication for sensitive actions.

Certain actions require a recent authentication, not just a valid
session. This module tracks when each user last authenticated and
provides a decorator/helper to enforce step-up auth for sensitive
actions.

Sensitive actions that require step-up auth:
- Opening a terminal.
- Transferring files.
- Creating an admin user.
- Disabling TLS.
- Changing the security profile.
- Creating a support session.
- Querying sensitive information.

Usage:
    from vnc_remote_secure.security.step_up_auth import (
        requires_step_up,
        record_auth_time,
        needs_step_up,
    )

    # After successful login or MFA:
    record_auth_time(username)

    # Before a sensitive action:
    if needs_step_up(username, max_age_seconds=300):
        return error_json('Re-authentication required', 403)

    # Or as a decorator (for Flask routes):
    @requires_step_up(max_age_seconds=300)
    def sensitive_route():
        ...
"""
import logging
import threading
import time
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# Actions that require step-up authentication.
SENSITIVE_ACTIONS: Set[str] = {
    'open_terminal',
    'file_transfer',
    'create_admin',
    'disable_tls',
    'change_profile',
    'create_support_session',
    'query_sensitive_info',
    'rotate_secrets',
    'modify_firewall',
    'view_audit_log',
}


class StepUpAuthManager:
    """Tracks recent authentication times for step-up auth."""

    def __init__(self, default_max_age: int = 300):
        """Initialize the manager.

        Args:
            default_max_age: Default max age (seconds) for step-up auth
                validity. Actions requiring step-up auth must have been
                authenticated within this window.
        """
        self._auth_times: Dict[str, float] = {}  # username -> last auth timestamp
        self._lock = threading.Lock()
        self.default_max_age = default_max_age

    def record_auth_time(self, username: str, auth_time: Optional[float] = None):
        """Record that a user has authenticated.

        Args:
            username: The user who authenticated.
            auth_time: Timestamp of authentication (default: now).
        """
        with self._lock:
            self._auth_times[username] = auth_time or time.time()
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
        with self._lock:
            last_auth = self._auth_times.get(username)
            if last_auth is None:
                return True  # Never authenticated
            return (time.time() - last_auth) > age

    def get_auth_age(self, username: str) -> Optional[float]:
        """Return the age (seconds) of the last authentication.

        Returns None if the user has never authenticated.
        """
        with self._lock:
            last_auth = self._auth_times.get(username)
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
