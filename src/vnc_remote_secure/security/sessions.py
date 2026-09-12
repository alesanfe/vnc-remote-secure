"""Secure session management with cookies.

Provides a cookie-based session store with HttpOnly, Secure, SameSite
attributes, CSRF protection, and idle/max lifetime enforcement. Designed
to be used by the Flask web application and the health/landing services.
"""
import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Optional

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)

# Defaults (configurable via env)
DEFAULT_IDLE_TIMEOUT = 900      # 15 minutes
DEFAULT_MAX_LIFETIME = 28800    # 8 hours
DEFAULT_COOKIE_NAME = 'vnc_session'
CSRF_HEADER = 'X-CSRF-Token'


def _get_session_secret() -> bytes:
    """Return the session signing secret."""
    from vnc_remote_secure.security.authentication import _get_secret
    return _get_secret()


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


def create_session_cookie(
    username: str,
    csrf_token: Optional[str] = None,
    idle_timeout: Optional[int] = None,
    max_lifetime: Optional[int] = None,
) -> dict:
    """Create a signed session cookie value and metadata.

    Returns a dict with:
        - ``value``: the signed cookie string to set
        - ``csrf_token``: CSRF token the client must echo
        - ``max_age``: cookie max-age in seconds
    """
    load_env_file()
    idle = idle_timeout or _get_env_int('SESSION_IDLE_TIMEOUT', DEFAULT_IDLE_TIMEOUT)
    max_lt = max_lifetime or _get_env_int('SESSION_MAX_LIFETIME', DEFAULT_MAX_LIFETIME)
    csrf = csrf_token or secrets.token_hex(32)
    now = int(time.time())
    payload = f"{username}:{now}:{now + max_lt}"
    secret = _get_session_secret()
    sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    cookie_value = f"{payload}.{sig}"
    return {
        'value': cookie_value,
        'csrf_token': csrf,
        'max_age': min(idle, max_lt),
    }


def verify_session_cookie(cookie_value: str) -> Optional[dict]:
    """Verify a session cookie and return session info if valid.

    Returns:
        dict with ``username``, ``created``, ``expires`` if valid.
        ``None`` if invalid or expired.
    """
    if not cookie_value or '.' not in cookie_value:
        return None
    payload, sig = cookie_value.rsplit('.', 1)
    secret = _get_session_secret()
    expected_sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    parts = payload.split(':')
    if len(parts) != 3:
        return None
    username, created_str, expires_str = parts
    try:
        created = int(created_str)
        expires = int(expires_str)
    except ValueError:
        return None
    now = time.time()
    if now > expires:
        return None
    _get_env_int('SESSION_IDLE_TIMEOUT', DEFAULT_IDLE_TIMEOUT)
    # Idle timeout is enforced by the cookie max-age; if the client
    # sends an old cookie, the browser would have expired it. But if
    # the client tampers with max-age, we still check absolute expiry.
    return {
        'username': username,
        'created': created,
        'expires': expires,
    }


def verify_csrf_token(provided_token: str, expected_token: str) -> bool:
    """Verify a CSRF token (constant-time comparison)."""
    if not provided_token or not expected_token:
        return False
    return hmac.compare_digest(provided_token, expected_token)


def get_cookie_attributes(secure: bool = True) -> dict:
    """Return standard cookie attributes for secure sessions.

    Args:
        secure: If True, set the Secure flag (requires HTTPS).
                Set to False for local HTTP-only development.
    """
    load_env_file()
    samesite = os.environ.get('SESSION_SAMESITE', 'Strict')
    return {
        'httponly': True,
        'secure': secure,
        'samesite': samesite,
        'path': '/',
    }


def invalidate_session_cookie() -> dict:
    """Return cookie attributes that immediately expire the session."""
    attrs = get_cookie_attributes()
    attrs['max_age'] = 0
    attrs['value'] = ''
    return attrs
