"""Rate limiting for authentication endpoints.

Implements a sliding-window rate limiter to prevent brute-force
attacks. Tracks failed attempts per IP address and per username, with
progressive delays and temporary lockouts.

State is stored via the shared-state backend (``security.shared_state``)
so that rate limiting works correctly across multiple processes when
the SQLite backend is enabled. The default in-memory backend preserves
the previous single-process behaviour.
"""
import os
import time

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.security.shared_state import get_backend

# Default limits (configurable via env vars)
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_SECONDS = 900  # 15 minutes
DEFAULT_WINDOW_SECONDS = 600   # 10 minutes

# Shared-state namespaces.
_NS_ATTEMPTS = 'rate_limit_attempts'
_NS_LOCKOUTS = 'rate_limit_lockouts'


class RateLimiter:
    """Sliding-window rate limiter for auth attempts.

    Tracks failed login attempts per key (IP or username) and
    temporarily locks out after exceeding the threshold.
    """

    def __init__(
        self,
        max_attempts: int = None,
        lockout_seconds: int = None,
        window_seconds: int = None,
    ):
        load_env_file()
        self.max_attempts = max_attempts or int(
            os.environ.get('AUTH_MAX_ATTEMPTS', str(DEFAULT_MAX_ATTEMPTS))
        )
        self.lockout_seconds = lockout_seconds or int(
            os.environ.get('AUTH_LOCKOUT_SECONDS', str(DEFAULT_LOCKOUT_SECONDS))
        )
        self.window_seconds = window_seconds or int(
            os.environ.get('AUTH_WINDOW_SECONDS', str(DEFAULT_WINDOW_SECONDS))
        )

    # Each failed attempt is stored as its own TTL'd record keyed
    # ``<key>\x00<ts>\x00<rand>`` — insert-only, so recording a failure
    # is atomic across processes (the previous list read-modify-write
    # could lose a failure when two service processes raced). The
    # embedded timestamp lets readers apply THEIR OWN window — a
    # record's TTL only controls storage cleanup.
    _SEP = '\x00'

    def _attempt_keys(self, key: str) -> list:
        """Return the unexpired attempt-record keys for ``key``."""
        return get_backend().list_keys(
            _NS_ATTEMPTS, prefix=key + self._SEP)

    def _attempt_count(self, key: str) -> int:
        now = time.time()
        count = 0
        for k in self._attempt_keys(key):
            parts = k.split(self._SEP)
            try:
                ts = float(parts[1])
            except (IndexError, ValueError):
                continue
            if ts > now - self.window_seconds:
                count += 1
        return count

    def _clear_attempts(self, key: str):
        backend = get_backend()
        for k in self._attempt_keys(key):
            backend.delete(_NS_ATTEMPTS, k)

    def is_locked(self, key: str) -> bool:
        """Check if a key (IP or username) is currently locked out."""
        backend = get_backend()
        locked_until = backend.get(_NS_LOCKOUTS, key)
        if locked_until is None:
            return False
        now = time.time()
        if now < locked_until:
            return True
        # Lockout expired — clean up.
        backend.delete(_NS_LOCKOUTS, key)
        self._clear_attempts(key)
        return False

    def get_lockout_remaining(self, key: str) -> int:
        """Return remaining lockout seconds (0 if not locked)."""
        backend = get_backend()
        locked_until = backend.get(_NS_LOCKOUTS, key) or 0
        remaining = int(locked_until - time.time())
        return max(0, remaining)

    def record_failure(self, key: str):
        """Record a failed attempt. Locks out if threshold exceeded."""
        import secrets as _secrets
        backend = get_backend()
        now = time.time()
        # Insert-only attempt record with sliding-window TTL. No read-
        # modify-write, so concurrent failures across processes can
        # never be lost (each insert is an independent row).
        record_key = f'{key}{self._SEP}{now}{self._SEP}{_secrets.token_hex(4)}'
        backend.set_ttl(_NS_ATTEMPTS, record_key, True, self.window_seconds)
        if self._attempt_count(key) >= self.max_attempts:
            backend.set_ttl(_NS_LOCKOUTS, key, now + self.lockout_seconds,
                            self.lockout_seconds)

    def record_success(self, key: str):
        """Clear attempt history on successful auth."""
        backend = get_backend()
        self._clear_attempts(key)
        backend.delete(_NS_LOCKOUTS, key)

    def remaining_attempts(self, key: str) -> int:
        """Return how many attempts remain before lockout."""
        return max(0, self.max_attempts - self._attempt_count(key))


# Global singleton (process-wide)
_auth_limiter = None


def get_auth_limiter() -> RateLimiter:
    """Return the process-wide auth rate limiter."""
    global _auth_limiter
    if _auth_limiter is None:
        _auth_limiter = RateLimiter()
    return _auth_limiter


# ---------------------------------------------------------------------------
# General IP-based rate limiting (for non-auth endpoints like user management)
# ---------------------------------------------------------------------------
# This is a simple sliding-window limiter keyed by IP. For auth-specific
# limiting with lockouts, use RateLimiter above.

_NS_GENERAL = 'rate_limit_general'

DEFAULT_MAX_REQUESTS = 5
# Distinct name from the auth limiter's DEFAULT_WINDOW_SECONDS above —
# reusing the same constant name silently overwrote the 10-minute auth
# window with this 5-minute value (module constants resolve at call
# time, so RateLimiter read the last assignment).
DEFAULT_GENERAL_WINDOW_SECONDS = 300  # 5 minutes


_GENERAL_SEP = '\x00'


def _general_attempt_keys(ip):
    """Return the unexpired attempt-record keys for ``ip``."""
    return get_backend().list_keys(_NS_GENERAL, prefix=ip + _GENERAL_SEP)


def _general_attempt_count(ip, window_seconds):
    """Count attempt records newer than the caller's window.

    The record key embeds the insertion timestamp — the TTL is only
    storage hygiene, the caller's own window decides what counts.
    """
    now = time.time()
    count = 0
    for k in _general_attempt_keys(ip):
        parts = k.split(_GENERAL_SEP)
        try:
            ts = float(parts[1])
        except (IndexError, ValueError):
            continue
        if ts > now - window_seconds:
            count += 1
    return count


def check_rate_limit(ip, max_requests=DEFAULT_MAX_REQUESTS,
                     window_seconds=DEFAULT_GENERAL_WINDOW_SECONDS):
    """Check whether ``ip`` is within the allowed request rate.

    Records the current attempt and returns ``True`` if allowed,
    ``False`` if rate-limited. Attempts are stored as individual
    TTL'd records (insert-only) so concurrent requests across
    processes cannot lose updates — the previous list read-modify-
    write raced under multi-process deployments.
    """
    import secrets as _secrets
    backend = get_backend()
    if _general_attempt_count(ip, window_seconds) >= max_requests:
        return False
    record_key = (
        f'{ip}{_GENERAL_SEP}{time.time()}{_GENERAL_SEP}'
        f'{_secrets.token_hex(4)}')
    backend.set_ttl(_NS_GENERAL, record_key, True, window_seconds)
    return True


def reset_rate_limit(ip):
    """Clear the rate-limit history for ``ip``."""
    backend = get_backend()
    for k in _general_attempt_keys(ip):
        backend.delete(_NS_GENERAL, k)
    return True


def get_rate_limit_info(ip, window_seconds=DEFAULT_GENERAL_WINDOW_SECONDS):
    """Return a dict with current attempt count and remaining allowance."""
    return {
        'ip': ip,
        'attempts': _general_attempt_count(ip, window_seconds),
        'window_seconds': window_seconds,
    }
