"""Rate limiting for VNC Remote Secure.

A simple in-memory sliding-window rate limiter keyed by client IP.
Suitable for single-process deployments; for multi-process setups a
shared backend (e.g. Redis) would be required.
"""
import time
from collections import defaultdict

# Default limits.
DEFAULT_MAX_REQUESTS = 5
DEFAULT_WINDOW_SECONDS = 300  # 5 minutes

# In-memory store: ip -> list of request timestamps.
_store = defaultdict(list)


def check_rate_limit(ip, max_requests=DEFAULT_MAX_REQUESTS,
                     window_seconds=DEFAULT_WINDOW_SECONDS):
    """Check whether ``ip`` is within the allowed request rate.

    Records the current attempt and returns ``True`` if the request is
    allowed (under the limit) or ``False`` if the limit has been
    exceeded.

    Args:
        ip: Client IP address.
        max_requests: Maximum allowed requests within the window.
        window_seconds: Sliding window length in seconds.

    Returns:
        ``True`` if the request is allowed, ``False`` if rate-limited.
    """
    now = time.time()
    cutoff = now - window_seconds
    # Prune old entries.
    _store[ip] = [t for t in _store[ip] if t > cutoff]
    if len(_store[ip]) >= max_requests:
        return False
    _store[ip].append(now)
    return True


def reset_rate_limit(ip):
    """Clear the rate-limit history for ``ip``."""
    _store.pop(ip, None)
    return True


def get_rate_limit_info(ip, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Return a dict with current attempt count and remaining allowance.

    Does **not** record a new attempt; use :func:`check_rate_limit` for
    that.
    """
    now = time.time()
    cutoff = now - window_seconds
    recent = [t for t in _store.get(ip, []) if t > cutoff]
    return {
        'ip': ip,
        'attempts': len(recent),
        'window_seconds': window_seconds,
    }
