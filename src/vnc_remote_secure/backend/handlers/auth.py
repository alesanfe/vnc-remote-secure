"""Operator auth handlers: login, passkeys ceremonies, logout, step-up."""
import base64
import logging
import time

from vnc_remote_secure.backend.handlers.common import (
    _MAX_BODY,
    _err,
    _ok,
    _public_gate,
    _read_typed_body,
)
from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.security.http_auth import cookie_value

logger = logging.getLogger(__name__)


def _get_auth_methods(handler, query):
    """GET /auth/methods — which login ceremonies the login page may
    offer. Public by design: nothing sensitive is disclosed."""
    passkey = True
    try:
        from vnc_remote_secure.engine.infrastructure import stores
        passkey = stores.webauthn_gate_error() is None
    except Exception:  # noqa: BLE001 - unavailable
        passkey = False
    from vnc_remote_secure.security.mfa import mfa_required_for_login
    mfa = False
    try:
        mfa = mfa_required_for_login()
    except Exception:  # noqa: BLE001 - unavailable
        mfa = False
    _ok(handler, {'password': True, 'passkey': passkey, 'mfa': mfa})


def _queue_operator_service_cookie(handler, username: str) -> dict | None:
    """Mint ``vnc_session`` — the raw HMAC operator cookie the remote
    services (terminal, noVNC, audio, gamepad) verify. Without it a
    SPA-logged-in operator could not open the desktop or terminal.
    Cookies are host-scoped, so a value set by the landing service is
    sent to the sibling services on their own ports.

    Returns the parsed session record (sid/created/expires) so the
    caller can key the auth-policy context by it."""
    import ssl as _ssl

    from vnc_remote_secure.core.constants import (
        DEFAULT_SESSION_IDLE_TIMEOUT,
        DEFAULT_SESSION_MAX_LIFETIME,
    )
    from vnc_remote_secure.security.sessions import (
        _get_env_int,
        create_session_cookie,
    )
    lifetime = _get_env_int('SESSION_MAX_LIFETIME',
                            DEFAULT_SESSION_MAX_LIFETIME)
    token = create_session_cookie(username, max_lifetime=lifetime)['value']
    max_age = min(_get_env_int('SESSION_IDLE_TIMEOUT',
                               DEFAULT_SESSION_IDLE_TIMEOUT),
                  lifetime)
    # Same Secure convention as the share-link cookie: only when the
    # request actually arrived over TLS (direct socket or trusted
    # X-Forwarded-Proto behind nginx).
    trusted = env_flag('TRUSTED_PROXY', 'false')
    is_tls = ((trusted and
               handler.headers.get('X-Forwarded-Proto', '') == 'https')
              or getattr(handler, 'is_tls', None) is True
              or isinstance(getattr(handler, 'connection', None),
                            _ssl.SSLSocket))
    secure = ' Secure;' if is_tls else ''
    handler._queue_cookie(
        f'vnc_session={token};{secure} HttpOnly; Path=/; '
        f'SameSite=Strict; Max-Age={max_age}')
    try:
        from vnc_remote_secure.security.sessions import verify_session_cookie
        return verify_session_cookie(token)
    except Exception:  # noqa: BLE001 - context record is advisory
        return None


def _finish_operator_login(handler, username: str,
                           auth_method: str) -> None:
    """Mint the operator session + CSRF nonce and answer /login.

    ``auth_method`` is the VERIFIED ceremony ('password',
    'password+totp', 'password+recovery', 'webauthn') — it lands in
    the shared auth context so auth_policy.evaluate (e.g. the
    terminal's open_terminal check) can enforce MFA/phishing
    requirements across processes."""
    handler._portal_sid = handler._issue_op_session(username)
    sess = _queue_operator_service_cookie(handler, username)
    try:
        if sess and sess.get('sid'):
            from vnc_remote_secure.security.auth_policy import record_auth_context
            record_auth_context(sess['sid'], {
                'username': username,
                'auth_method': auth_method,
                'authenticated_at': int(time.time()),
                'mfa': '+totp' in auth_method
                       or '+recovery' in auth_method,
                'phishing_resistant': auth_method == 'webauthn',
                'user_verified': auth_method == 'webauthn',
            }, stable_id=f"{username}:{sess.get('created')}",
                expires_at=sess.get('expires'))
    except Exception:  # noqa: BLE001 - policy context is advisory
        pass
    _ok(handler, {
        'operator': {
            'username': username,
            'role': 'admin' if username == 'admin' else None,
        },
        'csrf_token': handler._csrf_token(),
        'auth_method': auth_method,
    })


def _post_auth_login(handler, query):
    """POST /auth/login — password login for the SPA. Verifies through
    the same path as Basic auth (store → env bootstrap, lockout,
    audit), then mints the vnc_op cookie."""
    if not _public_gate(handler):
        return
    from vnc_remote_secure.backend.schemas import LoginRequest
    body, error = _read_typed_body(handler, LoginRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    username = body.username
    password = body.password
    cred = base64.b64encode(
        f'{username}:{password}'.encode()).decode()
    from vnc_remote_secure.security.http_auth import (
        authenticate_landing,
        client_ip_from,
    )
    client_ip = client_ip_from(handler.headers, handler.peer_ip())
    ok, operator = authenticate_landing(
        f'Basic {cred}', client_ip=client_ip)
    from vnc_remote_secure.security.audit import audit_event
    if not ok or operator is None:
        audit_event('operator_login', user=username,
                    result='failure')
        _err(handler, 'Invalid credentials', 401)
        return
    # Second factor — MFA_REQUIRED + TOTP_SECRET must actually gate
    # the password path, not just exist as configuration.
    from vnc_remote_secure.security.mfa import mfa_required_for_login
    mfa_method = None
    if mfa_required_for_login():
        totp = body.totp
        if not totp or not totp.strip():
            audit_event('operator_login', user=username,
                        detail='mfa required', result='failure')
            handler.send_json_error(
                'MFA code required', 401, code='MFA_REQUIRED')
            return
        from vnc_remote_secure.security.auth_gateway import verify_login_mfa
        mfa_ok, mfa_msg, mfa_method = verify_login_mfa(
            username, totp.strip()[:32], client_ip=client_ip)
        if not mfa_ok:
            _err(handler, mfa_msg or 'Invalid MFA code', 401)
            return
    # Maintenance mode: valid credentials clear the lockout but no
    # new session is issued to non-admin accounts — parity with
    # auth_gateway.attempt_login.
    from vnc_remote_secure.security.maintenance import maintenance_login_allowed
    if not maintenance_login_allowed(username):
        audit_event('operator_login', user=username,
                    detail='maintenance mode', result='failure')
        _err(handler, 'System under maintenance. Try again later.',
             503)
        return
    audit_event('operator_login', user=username,
                detail='method=password' + (
                    f'+{mfa_method}' if mfa_method else ''),
                result='success')
    _finish_operator_login(
        handler, operator.get('username', username),
        'password' + (f'+{mfa_method}' if mfa_method else ''))


def _post_auth_passkey_begin(handler, query):
    """POST /auth/passkey/begin — WebAuthn assertion options.
    Same response for unknown user and no-credential accounts —
    no enumeration through the ceremony."""
    if not _public_gate(handler):
        return
    from vnc_remote_secure.engine.infrastructure import stores
    gate = stores.webauthn_gate_error()
    if gate:
        _err(handler, gate, 503)
        return
    from vnc_remote_secure.backend.schemas import PasskeyAuthBeginRequest
    body, error = _read_typed_body(
        handler, PasskeyAuthBeginRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    username = body.username
    if not username.strip():
        _err(handler, 'username is required', 400)
        return
    from vnc_remote_secure.engine.application.passkeys import rp_id
    from vnc_remote_secure.security.webauthn import begin_authentication
    options = begin_authentication(username.strip()[:128], rp_id())
    from vnc_remote_secure.security.audit import audit_event
    if options is None:
        audit_event('passkey_auth_begin', user=username,
                    result='failure')
        _err(handler, 'Passkey authentication unavailable', 404)
        return
    audit_event('passkey_auth_begin', user=username,
                result='success')
    _ok(handler, {'options': options})


def _post_auth_passkey_complete(handler, query):
    """POST /auth/passkey/complete — verify the assertion and mint
    the operator session (a passkey ceremony is a fresh auth)."""
    if not _public_gate(handler):
        return
    from vnc_remote_secure.engine.infrastructure import stores
    gate = stores.webauthn_gate_error()
    if gate:
        _err(handler, gate, 503)
        return
    from vnc_remote_secure.backend.schemas import (
        PasskeyAuthCompleteRequest,
    )
    body, error = _read_typed_body(
        handler, PasskeyAuthCompleteRequest, limit=_MAX_BODY)
    if error:
        _err(handler, *error)
        return
    username = body.username
    credential = body.credential
    from vnc_remote_secure.engine.application.passkeys import (
        rp_id,
        webauthn_origin,
    )
    from vnc_remote_secure.security.webauthn import complete_authentication
    result = complete_authentication(
        username.strip()[:128], credential, rp_id(), webauthn_origin())
    from vnc_remote_secure.security.audit import audit_event
    if not result.ok:
        audit_event('operator_login', user=username,
                    detail='method=webauthn', result='failure')
        _err(handler, result.message, 401)
        return
    audit_event('operator_login', user=username,
                detail='method=webauthn', result='success')
    _finish_operator_login(handler, username.strip()[:128], 'webauthn')


def _post_logout(handler, query):
    """POST /api/v1/logout — revoke this operator session.

    Revokes the ``vnc_op`` sid server-side (shared state — the cookie
    stops working even if copied), then expires both session cookies
    and every CSRF token minted for them. Idempotent: an already
    revoked session still gets expired cookies. ``no-store`` keeps
    the response out of caches.

    Basic auth is stateless — a browser that still holds the
    credentials silently re-authenticates on the next request. This
    endpoint protects the *session artifact*: a stolen ``vnc_op`` or
    ``vnc_csrf`` cookie dies here even while the password remains
    valid.
    """
    # The sid arrives via _portal_sid (gate-resolved session) or is
    # parsed from the vnc_op cookie being revoked — covering the case
    # where the gate authenticated via Basic while the browser still
    # holds a stale cookie.
    sid = getattr(handler, '_portal_sid', '')
    raw = cookie_value(handler.headers.get('Cookie', ''), 'vnc_op')
    parts = raw.split('.')
    cookie_sid, cookie_exp = '', 0
    if len(parts) == 4:
        cookie_sid = parts[0]
        try:
            cookie_exp = int(parts[2])
        except ValueError:
            cookie_exp = 0
    # Revoke each sid with ITS OWN validity horizon — the gate sid
    # gets a fresh TTL, the cookie sid gets the expiry it carries.
    now = int(time.time())
    for target_sid, exp in ((sid, now + handler._OP_SESSION_TTL),
                            (cookie_sid, cookie_exp)):
        if target_sid:
            try:
                handler._revoke_op_session(
                    target_sid, exp or now + handler._OP_SESSION_TTL)
            except Exception:  # noqa: BLE001 - best-effort
                pass
    from vnc_remote_secure.security.audit import audit_event
    audit_event('portal_logout',
                user=handler._api_operator.get('username', 'unknown'))
    # Drop the auth-policy context recorded at login — the vnc_session
    # sid dies with the session, its assurance record must too.
    try:
        from vnc_remote_secure.security.auth_policy import drop_auth_context_for_cookie
        drop_auth_context_for_cookie(
            cookie_value(
                handler.headers.get('Cookie', ''), 'vnc_session'))
    except Exception:  # noqa: BLE001 - best-effort
        pass
    # Cancel any pending session cookies this request minted, then
    # expire both explicitly.
    handler.__dict__['_pending_cookies'] = []
    handler._queue_cookie(
        'vnc_op=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict')
    handler._queue_cookie(
        'vnc_csrf=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict')
    handler._queue_cookie(
        'vnc_session=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict')
    _ok(handler, {'logged_out': True})


def _post_step_up(handler, query):
    """POST /api/v1/step-up — re-authenticate the operator's password
    for a recent-auth grant (step-up) without minting a new session.

    The grant is recorded in shared state; routes flagged
    ``step_up=True`` in ``_ROUTES`` check it via ``needs_step_up``.
    """
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import StepUpRequest
    body, error = _read_typed_body(handler, StepUpRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    password = body.password
    username = operator.get('username', '')
    from vnc_remote_secure.security.audit import audit_event
    verified = None
    try:
        from vnc_remote_secure.security.operator_users import (
            load_store,
            verify,
        )
        if username in load_store():
            verified = verify(username, password)
    except Exception:  # noqa: BLE001 - store unreadable -> env path
        verified = None
    if verified is None:
        # Env bootstrap admin: re-check through the same code path as
        # Basic auth so the password policy is identical.
        import base64 as _b64

        from vnc_remote_secure.security.http_auth import check_landing_auth
        cred = _b64.b64encode(
            f'{username}:{password}'.encode()).decode()
        if check_landing_auth(f'Basic {cred}'):
            verified = operator
    if verified is None:
        audit_event('step_up_denied', user=username)
        _err(handler, 'Re-authentication failed', 403)
        return
    from vnc_remote_secure.security.step_up_auth import record_auth_time
    record_auth_time(username)
    # Refresh the auth-policy context too — without it the step-up
    # clears step_up_auth's clock but evaluate() still reads the
    # stale ``authenticated_at`` recorded at login and fails
    # max_auth_age policies.
    try:
        from vnc_remote_secure.security.auth_policy import (
            session_id_for_cookie,
            update_auth_context,
        )
        sid = session_id_for_cookie(
            cookie_value(
                handler.headers.get('Cookie', ''), 'vnc_session'))
        if sid:
            update_auth_context(sid, authenticated_at=int(time.time()))
    except Exception:  # noqa: BLE001 - advisory record
        pass
    # Operation-bound grant: the wizard sends the catalog operation id
    # (+resource) so the grant is tied to THAT action on THAT target
    # and consumed once — not a blank 5-minute cheque.
    bound = None
    operation = getattr(body, 'operation', '') or ''
    if operation:
        from vnc_remote_secure.engine.domain.operations import (
            OPERATIONS,
            step_up_bound_operations,
        )
        if operation not in step_up_bound_operations() \
                and operation not in OPERATIONS:
            _err(handler, f'Unknown operation: {operation}', 400)
            return
        resource = getattr(body, 'resource', '') or ''
        op_sid = cookie_value(
            handler.headers.get('Cookie', ''), 'vnc_op')
        from vnc_remote_secure.security.step_up_auth import (
            GRANT_TTL_SECONDS,
            grant_step_up,
        )
        grant_step_up(username, operation, resource, sid=op_sid)
        bound = {'operation': operation, 'resource': resource or None,
                 'expires_in': GRANT_TTL_SECONDS}
    audit_event('step_up_granted', user=username,
                detail=f'op={operation}' if operation else '')
    _ok(handler, {'stepped_up': True, 'expires_in': 300,
                  'bound': bound})
