"""Authentication utilities for VNC Remote Secure.

Provides username/password authentication backed by environment-configured
credentials, plus session-token creation and validation using HMAC-signed
tokens. Tokens are stateless and expire after a configurable lifetime.
"""
import hashlib
import hmac
import os
import secrets
import time

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.exceptions import SecurityError
from vnc_remote_secure.security.credentials import verify_password

# Default session token lifetime in seconds (30 minutes).
DEFAULT_TOKEN_LIFETIME = 1800


_cached_secret = None


def _get_secret():
    """Return the signing secret, generating one if not configured.

    When no secret is configured in the environment a random one is
    generated and cached for the lifetime of the process so that tokens
    remain valid across calls.
    """
    global _cached_secret
    load_env_file()
    secret = os.environ.get('AUTH_SECRET') or os.environ.get('FLASK_SECRET_KEY')
    if secret:
        return secret.encode('utf-8')
    if _cached_secret is None:
        _cached_secret = secrets.token_hex(32)
    return _cached_secret.encode('utf-8')


def authenticate(username, password):
    """Authenticate a user against environment-configured credentials.

    The expected credentials are ``TTYD_USERNAME`` and ``TTYD_PASSWD``
    (or ``USER_UI_PASSWORD`` for the management UI). Comparison is done
    in constant time to prevent timing attacks.

    Returns:
        ``True`` if the credentials match, ``False`` otherwise.
    """
    load_env_file()
    from vnc_remote_secure.core.constants import DEFAULT_TTYD_USERNAME
    expected_user = os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME)
    # Support both plain-text and hashed passwords.
    stored_password = os.environ.get('TTYD_PASSWD') or os.environ.get('USER_UI_PASSWORD', '')
    if not stored_password:
        return False
    user_ok = hmac.compare_digest(str(username), expected_user)
    if not user_ok:
        return False
    # If the stored value looks like a werkzeug hash, use verify_password.
    if stored_password.startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
        return verify_password(password, stored_password)
    return hmac.compare_digest(str(password), stored_password)


def create_session_token(username, lifetime=DEFAULT_TOKEN_LIFETIME):
    """Create a signed session token for ``username``.

    The token format is ``payload.signature`` where payload is a
    base64url-encoded JSON-like string ``username:expiry``.
    """
    expiry = int(time.time()) + lifetime
    payload = f"{username}:{expiry}"
    secret = _get_secret()
    signature = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def validate_session_token(token):
    """Validate a session token and return the username if valid.

    Returns:
        The username string if the token is valid and not expired.

    Raises:
        SecurityError: if the token is malformed, expired, or has an
            invalid signature.
    """
    if not token or '.' not in token:
        raise SecurityError("Invalid token format")
    payload, signature = token.rsplit('.', 1)
    secret = _get_secret()
    expected_sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise SecurityError("Invalid token signature")
    if ':' not in payload:
        raise SecurityError("Invalid token payload")
    username, expiry_str = payload.rsplit(':', 1)
    try:
        expiry = int(expiry_str)
    except ValueError:
        raise SecurityError("Invalid token expiry")
    if time.time() > expiry:
        raise SecurityError("Token expired")
    return username


def create_web_session(flask_session, username, csrf_token_bytes=32):
    """Populate a Flask session dict with the canonical session fields.

    This helper centralizes the session model shared by the Flask UI
    (``web/routes/users.py``) and the legacy Bash-stack UI
    (``lib/web/user_ui_app.py``) so both use the same keys, CSRF token
    length, and signed-token semantics.

    Args:
        flask_session: The Flask ``session`` proxy (or any dict-like
            object that supports item assignment).
        username: The authenticated username to store.
        csrf_token_bytes: Length of the CSRF token in bytes (default 32).

    Returns:
        The signed session token string (also stored under the ``token``
        key in the session).
    """
    token = create_session_token(username)
    flask_session['user'] = username
    flask_session['token'] = token
    flask_session['login_time'] = time.time()
    flask_session['csrf_token'] = secrets.token_hex(csrf_token_bytes)
    return token
