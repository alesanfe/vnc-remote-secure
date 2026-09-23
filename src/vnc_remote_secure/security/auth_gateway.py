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

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.exceptions import SecurityError
from vnc_remote_secure.security.authentication import (
    authenticate,
    create_session_token,
    validate_session_token,
)
from vnc_remote_secure.security.mfa import (
    mfa_required_for_login,
    verify_recovery_code,
    verify_totp,
)
from vnc_remote_secure.security.rate_limit import get_auth_limiter
from vnc_remote_secure.security.sessions import (
    create_session_cookie,
    verify_session_cookie,
)

logger = logging.getLogger(__name__)


def _audit(event, user, ip, result, detail):
    """Write an audit log entry (best-effort, never raises)."""
    try:
        from vnc_remote_secure.security.audit import audit_log
        audit_log(event, user=user, ip=ip, result=result, detail=detail)
    except (ImportError, OSError):
        pass


def _inc_auth_counter(result: str):
    """Increment the ``vnc_remote_auth_attempts_total`` counter (best-effort)."""
    try:
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_auth_attempts_total', labels=result)
    except (ImportError, KeyError):
        pass


# Shared-state namespace for consumed recovery-code hashes. Unlike the
# RECOVERY_CODES_HASHES env var (which requires a writable .env to
# shrink), this record is durable on every deployment.
_NS_USED_RECOVERY = 'mfa_used_recovery_codes'


def _claim_recovery_code(code_hash: str) -> bool:
    """Atomically claim a recovery-code hash (single-use, 30-day TTL).

    Returns ``True`` when this caller consumed the code. Returns
    ``False`` when the hash was already claimed — check-then-set would
    race across service processes, so the claim is a single atomic
    ``INSERT OR IGNORE`` against the shared-state backend.

    On backend failure the claim FAILS CLOSED: an open claim would let
    a one-time recovery code be replayed across processes (a degraded
    per-process memory backend sees nothing of the other side). A
    denied legitimate login is recoverable; a replayed code is not.
    """
    if not code_hash:
        return False
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        return bool(get_backend().set_if_absent(
            _NS_USED_RECOVERY, code_hash, True, 30 * 86400))
    except Exception:  # noqa: BLE001 - fail closed
        logger.exception(
            "Recovery-code claim backend unavailable — denying")
        return False


def check_origin(origin: str, allowed_origins: list) -> bool:
    """Validate the Origin header for WebSocket/CSRF protection.

    Rejects empty/null origins and any origin not in the allowlist.
    Origins whose host is listed in ``ALLOWED_LAN_IPS`` are accepted
    regardless of scheme/port — previously only the terminal applied
    this exception, so LAN clients got 403 on noVNC/audio/gamepad.
    """
    if not origin or origin == 'null':
        return False
    if origin in allowed_origins:
        return True
    try:
        from urllib.parse import urlparse
        host = urlparse(origin).hostname or ''
        lan_ips = [ip.strip() for ip in
                   os.environ.get('ALLOWED_LAN_IPS', '').split(',')
                   if ip.strip()]
        return bool(host and host in lan_ips)
    except Exception:
        return False


def get_allowed_origins() -> list:
    """Return the list of allowed origins from configuration."""
    load_env_file()
    from vnc_remote_secure.core.constants import (
        DEFAULT_HEALTH_PORT,
        DEFAULT_LANDING_PORT,
        DEFAULT_NGINX_HTTPS_PORT,
        DEFAULT_NOVNC_PORT,
        DEFAULT_TTYD_PORT,
        DEFAULT_USER_UI_PORT,
    )
    default_https = str(DEFAULT_NGINX_HTTPS_PORT)
    origins: list = []
    # Explicit configured origins
    configured = os.environ.get('ALLOWED_ORIGINS', '')
    if configured:
        origins.extend(o.strip() for o in configured.split(',') if o.strip())
    # Auto-generate from DUCK_DOMAIN and LAN. Bare 'mysub' becomes
    # 'mysub.duckdns.org' — the origin a browser actually sends.
    try:
        from vnc_remote_secure.core.config import normalize_duck_domain
        duck = normalize_duck_domain(os.environ.get('DUCK_DOMAIN', ''))
    except ImportError:
        duck = os.environ.get('DUCK_DOMAIN', '').strip()
    if duck:
        origins.append(f'https://{duck}')
    https_port = os.environ.get('NGINX_HTTPS_PORT', default_https)
    if duck and https_port != default_https:
        origins.append(f'https://{duck}:{https_port}')
    # Localhost for development (use configured ports, not hardcoded).
    # Every browser-facing local service port must be an allowed origin
    # so direct (non-nginx) access works: the noVNC page on NOVNC_PORT
    # upgrades to /websockify with Origin http://127.0.0.1:<NOVNC_PORT>.
    local_ports = {
        os.environ.get('LANDING_PORT', str(DEFAULT_LANDING_PORT)),
        os.environ.get('NOVNC_PORT', str(DEFAULT_NOVNC_PORT)),
        os.environ.get('TTYD_PORT', str(DEFAULT_TTYD_PORT)),
        os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT)),
        os.environ.get('USER_UI_PORT', str(DEFAULT_USER_UI_PORT)),
    }
    for port in sorted(local_ports):
        for host in ('localhost', '127.0.0.1'):
            # Both schemes: direct service access is plain HTTP when
            # no certs exist and HTTPS when they do.
            origins.append(f'http://{host}:{port}')
            origins.append(f'https://{host}:{port}')
    origins.append(f'https://localhost:{https_port}')
    origins.append(f'https://127.0.0.1:{https_port}')
    # LAN addresses of this host: on LAN-facing deployments
    # (trusted-lan/private-overlay) remote clients reach nginx via a
    # LAN IP — their Origin is https://<lan-ip>, which must be allowed
    # or every WebSocket upgrade gets rejected even though the
    # deployment is intentionally LAN-facing.
    try:
        from vnc_remote_secure.platform.base import get_adapter
        # On Windows (no nginx) the landing portal itself is the public
        # entry — a plain-HTTP LAN deployment produces Origin
        # http://<lan-ip>:<LANDING_PORT>, which must be allowed or
        # every WebSocket upgrade is rejected there.
        landing_port = os.environ.get(
            'LANDING_PORT', str(DEFAULT_LANDING_PORT))
        for ip in get_adapter().get_lan_ips():
            origins.append(f'https://{ip}')
            if https_port != default_https:
                origins.append(f'https://{ip}:{https_port}')
            origins.append(f'http://{ip}:{landing_port}')
            origins.append(f'https://{ip}:{landing_port}')
    except Exception:  # noqa: BLE001 - best-effort LAN discovery
        logger.debug("LAN IP discovery failed for allowed origins",
                     exc_info=True)
    return list(dict.fromkeys(origins))  # dedupe preserving order


def attempt_login(
    username: str,
    password: str,
    totp_code: str = '',
    client_ip: str = 'unknown',
) -> tuple[bool, str, dict | None]:
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
        _audit('login', username, client_ip, 'failure', f'Account locked ({remaining}s remaining)')
        _inc_auth_counter('locked')
        return False, f'Account locked. Try again in {remaining}s.', None

    # Verify password
    if not authenticate(username, password):
        limiter.record_failure(ip_key)
        limiter.record_failure(user_key)
        remaining = limiter.remaining_attempts(ip_key)
        if remaining > 0:
            _audit('login', username, client_ip, 'failure', f'Invalid credentials ({remaining} left)')
            _inc_auth_counter('failure')
            return False, f'Invalid credentials. {remaining} attempts remaining.', None
        _audit('login', username, client_ip, 'failure', 'Too many attempts, locked')
        _inc_auth_counter('locked')
        return False, 'Too many attempts. Account locked.', None

    # Verify MFA if required
    if mfa_required_for_login():
        totp_secret = os.environ.get('TOTP_SECRET', '')
        if not totp_code:
            limiter.record_failure(ip_key)
            _audit('login', username, client_ip, 'failure', 'MFA code required')
            _inc_auth_counter('mfa_required')
            return False, 'MFA code required.', None
        if totp_secret and verify_totp(totp_secret, totp_code):
            pass  # TOTP valid
        else:
            # Try recovery codes — SINGLE USE: a successfully matched
            # hash is marked consumed in the shared-state backend (which
            # survives restarts and unwritable .env deployments) and also
            # removed from RECOVERY_CODES_HASHES in .env when possible.
            stored = os.environ.get('RECOVERY_CODES_HASHES', '')
            if stored:
                hashes = [h.strip() for h in stored.split(',') if h.strip()]
                from vnc_remote_secure.security.mfa import hash_recovery_code
                candidate_hash = hash_recovery_code(totp_code) if totp_code else ''
                if verify_recovery_code(totp_code, hashes):
                    # Single-use claim is atomic: a concurrent login
                    # presenting the same code loses the race and is
                    # rejected even across service processes. The
                    # shared-state record is durable when .env cannot
                    # be rewritten (e.g. systemd unit without write
                    # access to /opt).
                    if not _claim_recovery_code(candidate_hash):
                        limiter.record_failure(ip_key)
                        limiter.record_failure(user_key)
                        _audit('login', username, client_ip, 'failure',
                               'Recovery code already used')
                        _inc_auth_counter('mfa_failure')
                        return False, 'Invalid MFA code.', None
                    used = candidate_hash
                    remaining_hashes = [h for h in hashes if h != used]
                    try:
                        from vnc_remote_secure.core.config import set_env_persistent
                        set_env_persistent(
                            'RECOVERY_CODES_HASHES',
                            ','.join(remaining_hashes))
                    except Exception:  # noqa: BLE001
                        logger.warning(
                            "Could not persist recovery-code removal; "
                            "shared-state single-use record still enforced")
                    _audit('login', username, client_ip, 'success',
                           'Recovery code consumed')
                else:
                    limiter.record_failure(ip_key)
                    limiter.record_failure(user_key)
                    _audit('login', username, client_ip, 'failure', 'Invalid MFA code')
                    _inc_auth_counter('mfa_failure')
                    return False, 'Invalid MFA code.', None
            else:
                limiter.record_failure(ip_key)
                limiter.record_failure(user_key)
                _audit('login', username, client_ip, 'failure', 'Invalid MFA code')
                _inc_auth_counter('mfa_failure')
                return False, 'Invalid MFA code.', None

    # Success: clear rate limit and create session
    limiter.record_success(ip_key)
    limiter.record_success(user_key)

    session = create_session_cookie(username)
    token = create_session_token(username)
    session['token'] = token
    _audit('login', username, client_ip, 'success', 'Login successful')
    _inc_auth_counter('success')
    # Record auth time for step-up auth (sensitive actions require recent login).
    try:
        from vnc_remote_secure.security.step_up_auth import record_auth_time
        record_auth_time(username)
    except (ImportError, OSError):
        logger.debug("Failed to record auth time", exc_info=True)
    return True, 'Login successful.', session


def check_authenticated(
    cookie_value: str,
    bearer_token: str = '',
) -> tuple[bool, str | None]:
    """Check if a request is authenticated via cookie or bearer token.

    Returns:
        Tuple of (authenticated, username).
    """
    # Revoked sessions (logout, admin revoke) must not authenticate —
    # the shared-state marker survives across processes.
    from vnc_remote_secure.security.websocket_registry import is_revoked_shared

    # Try session cookie first
    if cookie_value:
        if is_revoked_shared(cookie_value):
            return False, None
        session = verify_session_cookie(cookie_value)
        if session:
            # The signed cookie string is re-issued on every refresh,
            # so revocation is keyed on the stable username:created
            # pair — check that too or a logged-out session's current
            # (refreshed) cookie would keep working.
            stable = f"{session['username']}:{session['created']}"
            if is_revoked_shared(stable):
                return False, None
            # Global operator epoch: a credential rotation bumps it —
            # every session issued before the change is revoked.
            from vnc_remote_secure.security.sessions import (
                operator_session_epoch)
            if session['created'] < operator_session_epoch():
                return False, None
            return True, session['username']

    # Fall back to bearer token
    if bearer_token:
        if is_revoked_shared(bearer_token):
            return False, None
        try:
            username = validate_session_token(bearer_token)
            return True, username
        except (SecurityError, ValueError):
            logger.debug("Bearer token validation failed", exc_info=True)

    return False, None


def is_client_locked(client_ip: str) -> bool:
    """Return True when ``client_ip`` is locked out in ANY limiter namespace.

    The login flow records failures under ``ip:{addr}``, WebSocket
    rejections under ``ws:{addr}``, and the basic-auth helpers use the
    bare address — every surface must consult all three or a lockout on
    one auth path leaves the others open to the same credential.
    """
    limiter = get_auth_limiter()
    return (limiter.is_locked(client_ip)
            or limiter.is_locked(f'ip:{client_ip}')
            or limiter.is_locked(f'ws:{client_ip}'))


def _metric_reject(reason: str) -> None:
    """Emit a WS/HTTP auth-rejection counter (best-effort).

    Labels are limited to a small fixed reason set — no IP, token or
    user (high-cardinality by design).
    """
    try:
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_auth_rejections_total',
                    f'reason={reason}')
    except Exception:  # noqa: BLE001
        pass


def authorize_request(
    cookie_value: str = '',
    bearer_token: str = '',
    ephemeral_cookie: str = '',
    resource: str = '',
    required_permission: str = '',
    client_ip: str = '',
) -> tuple[bool, str, str | None]:
    """Unified credential→session→permission→rate-limit decision.

    This is THE single token-credential enforcement tree — every
    token-based surface (noVNC, websockify relay, audio, gamepad) must
    resolve credentials through it so that fixes apply everywhere.
    Basic-auth surfaces are a different credential type and live in
    http_auth, but share :func:`is_client_locked`.

    Resolution order:
      1. Activated ephemeral session (``vnc_ephemeral`` cookie /
         internal token) → ``check_session_permission`` when a
         required_permission is given.
      2. Ephemeral Bearer token → ``check_permission`` (per-action,
         enforces the permission and single-use semantics).
      3. Operator session (``vnc_session`` cookie or session Bearer) →
         ``check_authenticated`` — not permission-bound.

    Rate limiting: a locked IP is rejected up front; final failures
    record a failure, final successes record a success — matching the
    semantics the individual surfaces implemented by hand.

    Returns:
        Tuple of (allowed, reason, session_identity). The identity is
        the resolved session key usable for WebSocket registration and
        revocation (internal ephemeral token, session cookie, or
        bearer), or None when not allowed.
    """
    limiter = get_auth_limiter() if client_ip else None
    if limiter is not None and is_client_locked(client_ip):
        _metric_reject('rate_limited')
        return False, 'Rate limited', None

    # 1. Activated ephemeral session (internal token cookie).
    if ephemeral_cookie:
        allowed, reason = _authorize_ephemeral_cookie(
            ephemeral_cookie, required_permission, resource, client_ip)
        if allowed:
            return True, reason, ephemeral_cookie
        # A stale ephemeral cookie must not block a separately valid
        # credential — only reject when it is the sole credential.
        if not cookie_value and not bearer_token:
            if limiter is not None:
                limiter.record_failure(client_ip)
            _metric_reject('ephemeral_invalid')
            return False, reason, None

    if not cookie_value and not bearer_token:
        _metric_reject('missing_credentials')
        return False, 'Authentication required', None

    # 2. Ephemeral Bearer token (per-action authorization).
    if bearer_token and required_permission:
        from vnc_remote_secure.security.ephemeral_sessions import (
            check_permission,
        )
        if check_permission(
                bearer_token, required_permission,
                resource=resource or None,
                client_ip=client_ip or None):
            return True, 'OK', bearer_token

    # 3. Operator session (cookie or session bearer).
    allowed, _user = check_authenticated(cookie_value, bearer_token)
    if allowed:
        if limiter is not None:
            limiter.record_success(client_ip)
        return True, 'OK', cookie_value or bearer_token
    if limiter is not None:
        limiter.record_failure(client_ip)
    _metric_reject('invalid_session')
    return False, 'Invalid or expired session', None


def _authorize_ephemeral_cookie(
    ephemeral_cookie: str,
    required_permission: str,
    resource: str,
    client_ip: str,
) -> tuple[bool, str]:
    """Authorize an activated ephemeral session cookie."""
    from vnc_remote_secure.security.ephemeral_sessions import (
        check_session_permission,
    )
    if required_permission:
        if check_session_permission(
                ephemeral_cookie, required_permission,
                resource=resource or None,
                client_ip=client_ip or None):
            return True, 'OK'
        return False, 'Invalid or expired session'
    if check_session_permission(
            ephemeral_cookie, 'view',
            client_ip=client_ip or None):
        return True, 'OK'
    return False, 'Invalid or expired session'


def check_websocket_upgrade(
    origin: str,
    cookie_value: str = '',
    bearer_token: str = '',
    resource: str = '',
    required_permission: str = '',
    client_ip: str = '',
    ephemeral_cookie: str = '',
) -> tuple[bool, str]:
    """Validate a WebSocket upgrade request.

    Enforces Origin validation AND authentication AND authorization
    before allowing the 101 Switching Protocols response.

    Args:
        origin: Origin header value.
        cookie_value: Session cookie value.
        bearer_token: Bearer token (alternative to cookie).
        resource: The resource being accessed ('desktop', 'terminal').
        required_permission: Permission required (e.g. 'desktop:view',
            'terminal:use'). Applies to ephemeral bearer tokens only —
            a full operator session (cookie or session bearer) is not
            permission-bound and passes on authentication alone.

    Returns:
        Tuple of (allowed, reason).
    """
    limiter = get_auth_limiter()

    # A locked IP is rejected before any other check — otherwise a
    # brute-force lockout would not actually block subsequent valid
    # upgrades from the same address.
    if client_ip and is_client_locked(client_ip):
        return False, 'Rate limited'

    def _reject(reason: str, category: str = 'invalid') -> tuple[bool, str]:
        # Count rejected upgrades against the same limiter as auth
        # attempts — otherwise the WebSocket endpoint becomes a
        # lockout-free credential oracle.
        if client_ip:
            limiter.record_failure(f'ws:{client_ip}')
        _metric_reject(category)
        return False, reason

    # Origin must be valid
    if not check_origin(origin, get_allowed_origins()):
        return _reject('Invalid origin', 'bad_origin')

    # Activated ephemeral session (vnc_ephemeral cookie → internal
    # token). Unified through authorize_request's resolution — when it
    # fails, a separately valid credential may still authenticate, so
    # only reject when the ephemeral cookie is the sole credential.
    if ephemeral_cookie and required_permission:
        from vnc_remote_secure.security.ephemeral_sessions import (
            check_session_permission,
        )
        if check_session_permission(
                ephemeral_cookie, required_permission,
                resource=resource or None,
                client_ip=client_ip or None):
            return True, 'OK'
        if not cookie_value and not bearer_token:
            return _reject('Invalid or expired session',
                           'ephemeral_invalid')

    # If a required permission is specified, the bearer token is an
    # ephemeral session token — validate it against the session store.
    if required_permission and bearer_token:
        from vnc_remote_secure.security.ephemeral_sessions import (
            check_permission,
            is_session_expired,
            is_session_revoked,
        )
        from vnc_remote_secure.security.token_signing import (
            TOKEN_TYPE_EPHEMERAL,
            verify_token,
        )
        # A bearer that is NOT an ephemeral token (e.g. a regular
        # session bearer token) must fall through to standard auth —
        # otherwise valid operator tokens are rejected whenever a
        # required_permission is configured (noVNC applies the same
        # ephemeral-then-standard order).
        if verify_token(TOKEN_TYPE_EPHEMERAL, bearer_token):
            if is_session_revoked(bearer_token):
                return _reject('Session revoked', 'revoked')
            if is_session_expired(bearer_token):
                return _reject('Session expired', 'expired')
            if not check_permission(
                    bearer_token, required_permission, resource=resource,
                    client_ip=client_ip or None):
                return _reject(f'Permission denied: {required_permission}',
                               'permission_denied')
            return True, 'OK'

    # Standard authentication (cookie or session token)
    authed, _ = check_authenticated(cookie_value, bearer_token)
    if not authed:
        return _reject('Authentication required', 'auth_failed')

    return True, 'OK'


def register_websocket_connection(
    session_id: str,
    close_callback,
    resource: str = '',
    client_ip: str = '',
) -> str:
    """Register a WebSocket connection for immediate revocation.

    After a successful check_websocket_upgrade, the WebSocket handler
    should call this function to register the connection. When the
    session is revoked, the close_callback will be invoked to close
    the WebSocket immediately.

    Args:
        session_id: The session ID (signed token or internal token).
        close_callback: A callable that closes the WebSocket. Must
            return True on success.
        resource: The resource being accessed (e.g. 'desktop',
            'terminal').
        client_ip: Peer IP for the per-IP connection cap.

    Returns:
        A connection ID for later unregister.
    """
    from vnc_remote_secure.security.websocket_registry import register_connection
    # Resolve signed token to internal token so revoke_session
    # (which uses the internal token) can find the connection.
    internal_id = _resolve_session_id(session_id)
    return register_connection(
        internal_id, close_callback, resource,
        client_ip=client_ip) or ''


def _resolve_session_id(session_id: str) -> str:
    """Resolve a signed token to a stable internal session key.

    Ephemeral signed tokens resolve to their internal session token.
    Persistent session cookies resolve to the ``username:created``
    revocation key so a logout kills every re-issued (refreshed)
    cookie value and its live WebSocket connections — the raw signed
    string changes on every refresh.
    """
    try:
        from vnc_remote_secure.security.ephemeral_sessions import (
            verify_ephemeral_token,
        )
        payload = verify_ephemeral_token(session_id)
        if payload:
            return payload['session_token']
    except (ImportError, ValueError):
        logger.debug("Failed to resolve ephemeral session token", exc_info=True)
    try:
        from vnc_remote_secure.security.sessions import (
            session_revocation_key,
        )
        key = session_revocation_key(session_id)
        if key:
            return key
    except (ImportError, ValueError):
        logger.debug("Failed to resolve session cookie key", exc_info=True)
    return session_id


def unregister_websocket_connection(conn_id: str):
    """Unregister a WebSocket connection (on normal close)."""
    from vnc_remote_secure.security.websocket_registry import unregister_connection
    unregister_connection(conn_id)


def check_permission_for_action(
    bearer_token: str,
    permission: str,
    client_ip: str = '',
) -> tuple[bool, str]:
    """Check if a token has a specific permission for an action.

    This is the per-action authorization check that must be called
    BEFORE performing any sensitive operation (keyboard input, clipboard
    paste, file transfer, terminal open, user management, etc.).

    Returns:
        Tuple of (allowed, reason).
    """
    from vnc_remote_secure.security.ephemeral_sessions import (
        check_permission,
        is_session_expired,
        is_session_revoked,
    )
    if not bearer_token:
        return False, 'No token provided'
    if is_session_revoked(bearer_token):
        return False, 'Session revoked'
    if is_session_expired(bearer_token):
        return False, 'Session expired'
    if not check_permission(
            bearer_token, permission, client_ip=client_ip or None):
        return False, f'Permission denied: {permission}'
    return True, 'OK'


def revoke_session_live(token: str) -> bool:
    """Revoke a session and propagate to all active WebSocket connections.

    This marks the token as revoked so that:
    - New WebSocket upgrades with this token are rejected.
    - Per-action checks on existing connections fail.
    - The next heartbeat/check on an existing connection disconnects it.
    """
    from vnc_remote_secure.security.ephemeral_sessions import revoke_session
    return revoke_session(token)
