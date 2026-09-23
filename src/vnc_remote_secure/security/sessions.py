"""Secure session management with cookies.

Provides a cookie-based session store with HttpOnly, Secure, SameSite
attributes, CSRF protection, and idle/max lifetime enforcement. Designed
to be used by the Flask web application and the health/landing services.

Token signing is delegated to ``security.token_signing`` so that
persistent session cookies and ephemeral access tokens share a single
signing mechanism while remaining type-separated (a cookie cannot be
replayed as an ephemeral token).
"""
import logging
import os
import secrets
import time

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_SESSION,
    sign_token,
    verify_token,
)

logger = logging.getLogger(__name__)

# Defaults (configurable via env) — canonical values live in
# core.constants so every consumer resolves the same fallback.
from vnc_remote_secure.core.constants import (
    DEFAULT_SESSION_IDLE_TIMEOUT,
    DEFAULT_SESSION_MAX_LIFETIME,
)

DEFAULT_IDLE_TIMEOUT = DEFAULT_SESSION_IDLE_TIMEOUT
DEFAULT_MAX_LIFETIME = DEFAULT_SESSION_MAX_LIFETIME
DEFAULT_COOKIE_NAME = 'vnc_session'
CSRF_HEADER = 'X-CSRF-Token'


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


def create_session_cookie(
    username: str,
    csrf_token: str | None = None,
    idle_timeout: int | None = None,
    max_lifetime: int | None = None,
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
    # Payload v2: username:created:last_seen:expires. ``last_seen`` is
    # refreshed by refresh_session_cookie() on each authenticated
    # request, making SESSION_IDLE_TIMEOUT a true sliding window while
    # ``expires`` remains the absolute cap.
    payload = f"{username}:{now}:{now}:{now + max_lt}"
    cookie_value = sign_token(TOKEN_TYPE_SESSION, payload)
    return {
        'value': cookie_value,
        'csrf_token': csrf,
        'max_age': min(idle, max_lt),
    }


def verify_session_cookie(cookie_value: str) -> dict | None:
    """Verify a session cookie and return session info if valid.

    Returns:
        dict with ``username``, ``created``, ``expires`` if valid.
        ``None`` if invalid or expired.
    """
    payload = verify_token(TOKEN_TYPE_SESSION, cookie_value)
    if payload is None:
        return None
    parts = payload.split(':')
    # v2: username:created:last_seen:expires. Legacy v1
    # (username:created:expires) is accepted with last_seen=created.
    if len(parts) == 4:
        username, created_str, last_seen_str, expires_str = parts
    elif len(parts) == 3:
        username, created_str, expires_str = parts
        last_seen_str = created_str
    else:
        return None
    try:
        created = int(created_str)
        last_seen = int(last_seen_str)
        expires = int(expires_str)
    except ValueError:
        return None
    now = time.time()
    if now > expires:
        return None
    # Enforce idle timeout server-side against ``last_seen`` — a
    # sliding window refreshed on each authenticated request. The
    # cookie ``max_age`` is a client-side hint; a client that tampers
    # with it cannot extend the session past the signed values.
    idle = _get_env_int('SESSION_IDLE_TIMEOUT', DEFAULT_IDLE_TIMEOUT)
    if now - last_seen > idle:
        return None
    return {
        'username': username,
        'created': created,
        'last_seen': last_seen,
        'expires': expires,
    }


_NS_OPERATOR_EPOCH = 'operator_session_epoch'


def bump_operator_epoch() -> None:
    """Invalidate every operator session issued so far.

    Records the current time as the operator-session epoch in shared
    state; ``check_authenticated`` rejects any session whose
    ``created`` predates it. Called after sensitive credential
    changes (rotating the UI password must not leave live sessions).
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().set_ttl(
            _NS_OPERATOR_EPOCH, 'all', time.time(),
            _get_env_int('SESSION_MAX_LIFETIME', 86400) + 86400)
    except Exception:  # noqa: BLE001 - best-effort; rotation already
        logger.debug("Could not bump operator session epoch")
        pass


def operator_session_epoch() -> float:
    """Return the operator-session epoch (0 when never bumped)."""
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        val = get_backend().get(_NS_OPERATOR_EPOCH, 'all')
        return float(val) if val else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def session_revocation_key(cookie_value: str) -> str | None:
    """Return a revocation key stable across cookie refreshes.

    ``refresh_session_cookie`` re-signs the cookie every refresh window,
    so the exact signed string is not a usable revocation key — marking
    it would leave the refreshed (current) cookie valid. The
    ``username:created`` pair is invariant across refreshes and unique
    per login, so revocations keyed on it cover every re-issued value.
    """
    session = verify_session_cookie(cookie_value)
    if session is None:
        return None
    return f"{session['username']}:{session['created']}"


def refresh_session_cookie(cookie_value: str,
                           refresh_grace: int = 60) -> str | None:
    """Return a re-signed cookie with an updated ``last_seen``.

    Callers that can emit ``Set-Cookie`` should attach the returned
    value to authenticated responses so SESSION_IDLE_TIMEOUT measures
    inactivity, not age since login. ``refresh_grace`` avoids re-signing
    on every request — the cookie is only refreshed when ``last_seen``
    is older than the grace period.

    Returns ``None`` when the cookie is invalid/expired.
    """
    session = verify_session_cookie(cookie_value)
    if session is None:
        return None
    now = time.time()
    if now - session.get('last_seen', session['created']) < refresh_grace:
        return None  # still fresh — no need to re-issue
    payload = (f"{session['username']}:{session['created']}:"
               f"{int(now)}:{session['expires']}")
    return sign_token(TOKEN_TYPE_SESSION, payload)


def get_cookie_attributes(secure: bool = True) -> dict:
    """Return standard cookie attributes for secure sessions.

    Args:
        secure: If True, set the Secure flag (requires HTTPS).
                Set to False for local HTTP-only development.
    """
    load_env_file()
    # Whitelist: the value lands verbatim in the Set-Cookie header —
    # a crafted SESSION_SAMESITE containing ';' or CRLF would inject
    # extra attributes or split the response.
    from vnc_remote_secure.core.config import resolve_samesite
    samesite = resolve_samesite()
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
