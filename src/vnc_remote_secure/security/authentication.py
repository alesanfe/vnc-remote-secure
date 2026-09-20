"""Authentication utilities for VNC Remote Secure.

Provides username/password authentication backed by environment-configured
credentials, plus session-token creation and validation using HMAC-signed
tokens. Tokens are stateless and expire after a configurable lifetime.

Token signing is delegated to ``security.token_signing`` so that all
signed tokens (bearer, session cookie, ephemeral) share a single
signing mechanism while remaining type-separated.
"""
import hmac
import logging
import os
import secrets
import time

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.exceptions import SecurityError
from vnc_remote_secure.security.credentials import verify_password
from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_BEARER,
    sign_token,
    verify_token,
)

logger = logging.getLogger(__name__)

# Default session token lifetime in seconds (30 minutes).
DEFAULT_TOKEN_LIFETIME = 1800


_cached_secret = None


def _secret_file_path():
    """Return the path to the persisted auto-generated secret."""
    import os

    from vnc_remote_secure.core.paths import get_run_dir
    return os.path.join(get_run_dir(), 'auth_secret.key')


def _get_secret():
    """Return the signing secret, generating and persisting one if not configured.

    When no secret is configured in the environment a random one is
    generated and persisted to the runtime directory so it remains
    stable across process restarts. This is essential for ephemeral
    session tokens to remain valid across CLI invocations.
    """
    global _cached_secret
    load_env_file()
    secret = os.environ.get('AUTH_SECRET') or os.environ.get('FLASK_SECRET_KEY')
    if secret:
        return secret.encode('utf-8')
    if _cached_secret is None:
        # Try to load a previously persisted secret.
        path = _secret_file_path()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                _cached_secret = f.read().strip()
            # Keys written before the ACL hardening existed may still
            # be world-readable — re-restrict on load (once per process,
            # guarded by _cached_secret).
            if _cached_secret:
                try:
                    from vnc_remote_secure.security.certificates import _restrict_key_permissions
                    _restrict_key_permissions(path, writable=True)
                except Exception:  # noqa: BLE001
                    pass
        except (OSError, IOError) as exc:
            logger.debug("Could not read persisted auth secret at %s: %s", path, exc, exc_info=True)
        if not _cached_secret:
            _cached_secret = secrets.token_hex(32)
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                # Atomic write: a truncated secret would invalidate
                # every issued token and break the deployment.
                import tempfile
                fd, tmp = tempfile.mkstemp(
                    dir=os.path.dirname(path), suffix='.tmp')
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        f.write(_cached_secret)
                    os.replace(tmp, path)
                except BaseException:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
                # The file signs every bearer/session/ephemeral token —
                # it must be owner-only like a private key, or any
                # local user can forge valid sessions.
                try:
                    from vnc_remote_secure.security.certificates import _restrict_key_permissions
                    _restrict_key_permissions(path, writable=True)
                except Exception:  # noqa: BLE001
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
            except OSError as exc:
                logger.warning("Could not persist auth secret at %s: %s", path, exc, exc_info=True)
    return _cached_secret.encode('utf-8')


def authenticate(username, password):
    """Authenticate a user against environment-configured credentials.

    The management-UI login uses ``USER_UI_USERNAME``/
    ``USER_UI_PASSWORD`` when set; the terminal credentials
    (``TTYD_USERNAME``/``TTYD_PASSWD``) act as a shared-admin fallback
    so a single-credential deployment still works. Comparison is done
    in constant time to prevent timing attacks.

    Returns:
        ``True`` if the credentials match, ``False`` otherwise.
    """
    load_env_file()
    from vnc_remote_secure.core.constants import DEFAULT_TTYD_USERNAME
    expected_user = os.environ.get(
        'USER_UI_USERNAME',
        os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME))
    # Support both plain-text and hashed passwords. USER_UI_PASSWORD
    # (the UI's own credential) takes precedence over the shared
    # terminal password — when both are set, the operator's dedicated
    # UI password is the one that must work.
    stored_password = os.environ.get('USER_UI_PASSWORD') or os.environ.get('TTYD_PASSWD', '')
    if not stored_password:
        # Persisted auto-generated credential fallback: get_config()
        # generates TTYD_PASSWD into <run_dir>/generated_credentials.env
        # — a process that did not run get_config() would otherwise
        # reject a perfectly valid login.
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )
            stored_password = _load_generated_credential('TTYD_PASSWD')
        except Exception:  # noqa: BLE001 - fallback is best-effort
            stored_password = ''
    if not stored_password:
        return False
    # compare_digest on str rejects non-ASCII — a UTF-8 username or
    # password (legit or fuzzed) must fail cleanly, not crash with
    # TypeError. Encode to bytes so the compare is constant-time AND
    # charset-agnostic.
    user_ok = hmac.compare_digest(
        str(username).encode('utf-8', 'replace'),
        expected_user.encode('utf-8', 'replace'))
    # Exactly one expensive verification per attempt regardless of
    # outcome — a fast path (early return on unknown user, or the
    # near-instant plaintext compare) would leak via timing whether
    # the username is valid.
    dummy = ('pbkdf2:sha256:600000$dummysalt$'
             + '0' * 64)
    if stored_password.startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
        target = stored_password if user_ok else dummy
        pw_ok = verify_password(password, target) and user_ok
    else:
        # Plain-text store: the compare itself is constant-time, but
        # run the dummy verify too so every attempt costs one pbkdf2
        # (same as the hashed-storage path).
        pw_ok = hmac.compare_digest(
            str(password).encode('utf-8', 'replace'),
            stored_password.encode('utf-8', 'replace'))
        verify_password(str(password), dummy)
    return user_ok and pw_ok


def create_session_token(username, lifetime=DEFAULT_TOKEN_LIFETIME):
    """Create a signed session token for ``username``.

    The token format is ``bearer:<payload>.<signature>`` where payload
    is ``username:expiry``. The type tag ensures bearer tokens cannot
    be replayed as session cookies or ephemeral tokens.
    """
    expiry = int(time.time()) + lifetime
    payload = f"{username}:{expiry}"
    return sign_token(TOKEN_TYPE_BEARER, payload)


def validate_session_token(token):
    """Validate a session token and return the username if valid.

    Returns:
        The username string if the token is valid and not expired.

    Raises:
        SecurityError: if the token is malformed, expired, or has an
            invalid signature.
    """
    payload = verify_token(TOKEN_TYPE_BEARER, token)
    if payload is None:
        raise SecurityError("Invalid token format")
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

    This helper centralizes the session model used by the Flask UI
    (``web/routes/users.py``) so it uses consistent keys, CSRF token
    length, and signed-token semantics.

    The token lifetime honours ``SESSION_MAX_LIFETIME`` from the
    environment (default 28800 seconds / 8 hours) so operator policy
    is enforced rather than the hard-coded ``DEFAULT_TOKEN_LIFETIME``.

    Args:
        flask_session: The Flask ``session`` proxy (or any dict-like
            object that supports item assignment).
        username: The authenticated username to store.
        csrf_token_bytes: Length of the CSRF token in bytes (default 32).

    Returns:
        The signed session token string (also stored under the ``token``
        key in the session).
    """
    import os

    from vnc_remote_secure.core.constants import DEFAULT_SESSION_MAX_LIFETIME
    lifetime = int(os.environ.get(
        'SESSION_MAX_LIFETIME', str(DEFAULT_SESSION_MAX_LIFETIME)))
    # The value stored in session['token'] is validated by
    # verify_session_cookie() (TOKEN_TYPE_SESSION, payload
    # "user:created:last_seen:expires") via check_authenticated — a
    # bearer-type token from create_session_token() would be rejected
    # there, so the session-cookie signer must be used here.
    from vnc_remote_secure.security.sessions import create_session_cookie
    token = create_session_cookie(
        username, max_lifetime=lifetime)['value']
    flask_session['user'] = username
    flask_session['token'] = token
    flask_session['login_time'] = time.time()
    flask_session['csrf_token'] = secrets.token_hex(csrf_token_bytes)
    return token
