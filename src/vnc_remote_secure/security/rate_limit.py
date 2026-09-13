"""Rate limiting for authentication endpoints.

Implements a simple in-memory sliding-window rate limiter to prevent
brute-force attacks. Tracks failed attempts per IP address and per
username, with progressive delays and temporary lockouts.
"""
import os
import time
from collections import defaultdict
from threading import Lock

from vnc_remote_secure.core.config import load_env_file

# Default limits (configurable via env vars)
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_SECONDS = 900  # 15 minutes
DEFAULT_WINDOW_SECONDS = 600   # 10 minutes


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
        self._attempts: dict = defaultdict(list)
        self._lockouts: dict = {}
        self._lock = Lock()

    def _prune(self, key: str, now: float):
        """Remove expired entries from the sliding window."""
        cutoff = now - self.window_seconds
        self._attempts[key] = [
            t for t in self._attempts[key] if t > cutoff
        ]

    def is_locked(self, key: str) -> bool:
        """Check if a key (IP or username) is currently locked out."""
        with self._lock:
            now = time.time()
            locked_until = self._lockouts.get(key)
            if locked_until and now < locked_until:
                return True
            if locked_until and now >= locked_until:
                del self._lockouts[key]
                self._attempts[key] = []
            return False

    def get_lockout_remaining(self, key: str) -> int:
        """Return remaining lockout seconds (0 if not locked)."""
        with self._lock:
            locked_until = self._lockouts.get(key, 0)
            remaining = int(locked_until - time.time())
            return max(0, remaining)

    def record_failure(self, key: str):
        """Record a failed attempt. Locks out if threshold exceeded."""
        with self._lock:
            now = time.time()
            self._prune(key, now)
            self._attempts[key].append(now)
            if len(self._attempts[key]) >= self.max_attempts:
                self._lockouts[key] = now + self.lockout_seconds

    def record_success(self, key: str):
        """Clear attempt history on successful auth."""
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)

    def remaining_attempts(self, key: str) -> int:
        """Return how many attempts remain before lockout."""
        with self._lock:
            now = time.time()
            self._prune(key, now)
            return max(0, self.max_attempts - len(self._attempts[key]))


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

_general_store: dict = defaultdict(list)

DEFAULT_MAX_REQUESTS = 5
DEFAULT_WINDOW_SECONDS = 300  # 5 minutes


def check_rate_limit(ip, max_requests=DEFAULT_MAX_REQUESTS,
                     window_seconds=DEFAULT_WINDOW_SECONDS):
    """Check whether ``ip`` is within the allowed request rate.

    Records the current attempt and returns ``True`` if allowed,
    ``False`` if rate-limited.
    """
    now = time.time()
    cutoff = now - window_seconds
    _general_store[ip] = [t for t in _general_store[ip] if t > cutoff]
    if len(_general_store[ip]) >= max_requests:
        return False
    _general_store[ip].append(now)
    return True


def reset_rate_limit(ip):
    """Clear the rate-limit history for ``ip``."""
    _general_store.pop(ip, None)
    return True


def get_rate_limit_info(ip, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Return a dict with current attempt count and remaining allowance."""
    now = time.time()
    cutoff = now - window_seconds
    recent = [t for t in _general_store.get(ip, []) if t > cutoff]
    return {
        'ip': ip,
        'attempts': len(recent),
        'window_seconds': window_seconds,
    }
