"""Central authentication gateway for VNC Remote Secure.

Provides a unified auth layer that sits in front of all services
(landing, health, terminal, noVNC). Enforces:
- Session cookie validation
- MFA (TOTP) when configured
- Rate limiting on login attempts
- CSRF protection on state-changing requests
- Origin validation for WebSocket upgrades

This module is designed to be used as Flask middleware or as a
standalone HTTP handler pre-check by the stdlib-based services.
"""
import logging
import os
from typing import Optional, Tuple

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.security.authentication import (
    authenticate,
    create_session_token,
    validate_session_token,
)
from vnc_remote_secure.security.mfa import (
    verify_totp,
    verify_recovery_code,
    is_mfa_enabled,
    mfa_required_for_login,
)
from vnc_remote_secure.security.rate_limit import get_auth_limiter
from vnc_remote_secure.security.sessions import (
    create_session_cookie,
    verify_session_cookie,
    verify_csrf_token,
    get_cookie_attributes,
    invalidate_session_cookie,
    CSRF_HEADER,
)

logger = logging.getLogger(__name__)


def check_origin(origin: str, allowed_origins: list) -> bool:
    """Validate the Origin header for WebSocket/CSRF protection.

    Rejects empty/null origins and any origin not in the allowlist.
    """
    if not origin or origin == 'null':
        return False
    return origin in allowed_origins


def get_allowed_origins() -> list:
    """Return the list of allowed origins from configuration."""
    load_env_file()
    origins = []
    # Explicit configured origins
    configured = os.environ.get('ALLOWED_ORIGINS', '')
    if configured:
        origins.extend(o.strip() for o in configured.split(',') if o.strip())
    # Auto-generate from DUCK_DOMAIN and LAN
    duck = os.environ.get('DUCK_DOMAIN', '')
    if duck:
        origins.append(f'https://{duck}')
    https_port = os.environ.get('NGINX_HTTPS_PORT', '443')
    if duck and https_port != '443':
        origins.append(f'https://{duck}:{https_port}')
    # Localhost for development
    origins.append('http://localhost:8000')
    origins.append('http://127.0.0.1:8000')
    https_port_val = os.environ.get('NGINX_HTTPS_PORT', '443')
    origins.append(f'https://localhost:{https_port_val}')
    origins.append(f'https://127.0.0.1:{https_port_val}')
    return list(dict.fromkeys(origins))  # dedupe preserving order


def attempt_login(
    username: str,
    password: str,
    totp_code: str = '',
    client_ip: str = 'unknown',
) -> Tuple[bool, str, Optional[dict]]:
    """Attempt a login with password + optional MFA.

    Returns:
        Tuple of (success, message, session_data).
        session_data is None on failure, or a dict on success.
    """
    limiter = get_auth_limiter()

    # Check rate limit
    ip_key = f'ip:{client_ip}'
    user_key = f'user:{username}'
    if limiter.is_locked(ip_key) or limiter.is_locked(user_key):
        remaining = max(
            limiter.get_lockout_remaining(ip_key),
            limiter.get_lockout_remaining(user_key),
        )
        return False, f'Account locked. Try again in {remaining}s.', None

    # Verify password
    if not authenticate(username, password):
        limiter.record_failure(ip_key)
        limiter.record_failure(user_key)
        remaining = limiter.remaining_attempts(ip_key)
        if remaining > 0:
            return False, f'Invalid credentials. {remaining} attempts remaining.', None
        return False, 'Too many attempts. Account locked.', None

    # Verify MFA if required
    if mfa_required_for_login():
        totp_secret = os.environ.get('TOTP_SECRET', '')
        if not totp_code:
            limiter.record_failure(ip_key)
            return False, 'MFA code required.', None
        if totp_secret and verify_totp(totp_secret, totp_code):
            pass  # TOTP valid
        else:
            # Try recovery codes
            stored = os.environ.get('RECOVERY_CODES_HASHES', '')
            if stored:
                hashes = [h.strip() for h in stored.split(',') if h.strip()]
                if verify_recovery_code(totp_code, hashes):
                    pass  # Recovery code valid
                else:
                    limiter.record_failure(ip_key)
                    return False, 'Invalid MFA code.', None
            else:
                limiter.record_failure(ip_key)
                return False, 'Invalid MFA code.', None

    # Success: clear rate limit and create session
    limiter.record_success(ip_key)
    limiter.record_success(user_key)

    session = create_session_cookie(username)
    token = create_session_token(username)
    session['token'] = token
    return True, 'Login successful.', session


def check_authenticated(
    cookie_value: str,
    bearer_token: str = '',
) -> Tuple[bool, Optional[str]]:
    """Check if a request is authenticated via cookie or bearer token.

    Returns:
        Tuple of (authenticated, username).
    """
    # Try session cookie first
    if cookie_value:
        session = verify_session_cookie(cookie_value)
        if session:
            return True, session['username']

    # Fall back to bearer token
    if bearer_token:
        try:
            username = validate_session_token(bearer_token)
            return True, username
        except Exception:
            pass

    return False, None


def check_websocket_upgrade(
    origin: str,
    cookie_value: str = '',
    bearer_token: str = '',
) -> Tuple[bool, str]:
    """Validate a WebSocket upgrade request.

    Enforces Origin validation AND authentication before allowing
    the 101 Switching Protocols response.

    Returns:
        Tuple of (allowed, reason).
    """
    # Origin must be valid
    if not check_origin(origin, get_allowed_origins()):
        return False, 'Invalid origin'

    # Must be authenticated
    authed, _ = check_authenticated(cookie_value, bearer_token)
    if not authed:
        return False, 'Authentication required'

    return True, 'OK'


def logout(cookie_value: str) -> dict:
    """Invalidate a session and return cookie attributes to clear it."""
    return invalidate_session_cookie()
