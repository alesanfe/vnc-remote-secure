"""User management route handler for the web UI.

Provides login/logout, user CRUD and WebAuthn/passkey endpoints.
Authentication is backed by
:mod:`vnc_remote_secure.security.authentication` and rate-limited via
:mod:`vnc_remote_secure.security.rate_limit`.
"""
import logging
import os
import secrets

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from vnc_remote_secure.core.constants import (
    RESERVED_USERNAMES,
)
from vnc_remote_secure.core.errors import json_error
from vnc_remote_secure.core.validation import sanitize_input
from vnc_remote_secure.security.auth_gateway import check_authenticated
from vnc_remote_secure.security.authentication import (
    create_web_session,
)
from vnc_remote_secure.security.rate_limit import check_rate_limit

logger = logging.getLogger(__name__)


def _require_session():
    """Validate the current session via the auth gateway.

    Returns ``(username, response)``. When ``response`` is not ``None``
    the caller must return it (redirect or error). When ``response`` is
    ``None``, ``username`` is the authenticated user.
    """
    token = session.get('token', '')
    from vnc_remote_secure.security.http_auth import extract_bearer_token
    bearer = extract_bearer_token(
        request.headers.get('Authorization', ''))
    authenticated, username = check_authenticated(token, bearer)
    if not authenticated:
        session.clear()
        if request.path.startswith('/api/') or request.is_json:
            return None, json_error('Authentication required', 401)
        return None, redirect(url_for('users.login'))
    return username, None


def _require_permission(permission: str, actor: str):
    """Enforce an operator-store permission on an admin action.

    Returns a JSON error response when the authenticated operator's
    role lacks ``permission`` (a viewer must not create system users
    even with a valid session); ``None`` when allowed. The built-in
    env-authenticated operator resolves to ``admin`` (all perms).
    """
    from vnc_remote_secure.security.operator_users import has_permission
    if has_permission(actor, permission):
        return None
    from vnc_remote_secure.security.audit import audit_event
    audit_event('operator_permission_denied', user=actor,
              ip=_client_ip(), result='failure',
              detail=f'required={permission}')
    return json_error('Insufficient role for this action', 403)


def _enforce_auth_policy(operation: str):
    """Enforce the declarative auth-assurance policy for *operation*.

    Evaluates the Flask session's recorded auth properties against
    ``AUTH_POLICIES[operation]``; returns a JSON error when the
    decision denies, else ``None``. Audit-only evaluations (dev
    profile, non-enforced properties) never block but are logged.
    """
    from vnc_remote_secure.security.auth_policy import evaluate
    ctx = {
        'username': session.get('user'),
        'auth_method': session.get('auth_method'),
        'mfa': session.get('mfa'),
        'phishing_resistant': session.get('phishing_resistant'),
        'user_verified': session.get('user_verified'),
        'authenticated_at': session.get('authenticated_at'),
    }
    decision = evaluate(operation, ctx)
    if not decision.allowed:
        return json_error(
            f'Authentication strength insufficient for '
            f'{operation} ({decision.reason_code})', 403)
    return None


users_bp = Blueprint('users', __name__)


def _create_runtime_user(username: str, password: str,
                         actor: str = '?') -> str | None:
    """Create a runtime user via the engine use case.

    Returns ``None`` on success or an error message string on failure.
    Reserved-name/password policy and the audit trail live in
    ``engine.application.system_users`` — the Flask surface only
    translates the result.
    """
    from vnc_remote_secure.engine.application.system_users import (
        create_system_user,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        create_system_user(actor, username, password)
    except UseCaseError as exc:
        if exc.detail in ('User creation failed',):
            logger.error("User creation failed: %s", username)
        return exc.detail
    return None


def _delete_runtime_user(username: str, actor: str = '?') -> str | None:
    """Delete a runtime user via the engine use case (reserved names
    and the current process account are refused there)."""
    from vnc_remote_secure.engine.application.system_users import (
        delete_system_user,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_system_user(actor, username)
    except UseCaseError as exc:
        if exc.detail in ('User deletion failed',):
            logger.error("User deletion failed: %s", username)
        return exc.detail
    return None


def _client_ip():
    """Return the request client IP.

    Respects ``X-Forwarded-For`` only when ``TRUSTED_PROXY=true`` (i.e.
    when the operator has confirmed the app sits behind a trusted reverse
    proxy). Otherwise the direct ``remote_addr`` is used to prevent
    spoofing. Delegates to ``http_auth.client_ip_from`` so the trusted
    hop is the LAST XFF entry (the one nginx appended), not the
    attacker-controlled first one.
    """
    from vnc_remote_secure.security.http_auth import client_ip_from
    return client_ip_from(request.headers, request.remote_addr) or 'unknown'


def _check_csrf():
    """Validate the CSRF token for state-changing requests.

    The token is stored in ``session['csrf_token']`` on login and must be
    supplied via the ``X-CSRF-Token`` header or a ``csrf_token`` form field.
    Returns ``True`` if the token matches.
    """
    expected = session.get('csrf_token')
    if not expected:
        return False
    sent = (
        request.headers.get('X-CSRF-Token')
        or request.form.get('csrf_token')
        or (request.get_json(silent=True) or {}).get('csrf_token')
    )
    if not sent:
        return False
    # compare_digest on str rejects non-ASCII — a fuzzed X-CSRF-Token
    # would crash the request with TypeError instead of failing closed.
    return secrets.compare_digest(
        str(sent).encode('utf-8', 'replace'),
        str(expected).encode('utf-8', 'replace'))


def _issue_session_response(username: str, auth_method: str = 'password',
                            user_verified: bool | None = None):
    """Create the authenticated session + cookies for *username*.

    Shared by the password login and the WebAuthn assertion path —
    both must produce identical session state (Flask session keys,
    ``vnc_session`` HMAC cookie, step-up auth time). ``auth_method``
    is the method that ACTUALLY verified (from ``attempt_login``'s
    result, not request fields): 'password', 'password+totp',
    'password+recovery', or 'webauthn'. Structured properties
    (``phishing_resistant``, ``mfa``) are recorded separately — a
    passkey's strength depends on the authenticator, so it is NOT
    equated with a maximum assurance level by fiat.
    """
    # Regenerate the session on privilege change: clear any
    # pre-login keys (attacker-fixated or stale) so the
    # authenticated session carries only fresh state.
    session.clear()
    token = create_web_session(session, username)
    import time as _t
    session['auth_method'] = auth_method
    session['mfa'] = '+' in auth_method or auth_method == 'webauthn'
    session['phishing_resistant'] = auth_method == 'webauthn'
    session['authenticated_at'] = _t.time()
    if user_verified is not None:
        # Ceremony-reported UV — password methods leave it unset
        # rather than implying True/False.
        session['user_verified'] = user_verified
    # Persist the auth context keyed by THIS session's stable id
    # (username:created — survives cookie refreshes, same key the
    # revocation layer uses). Keyed by username, a strong login would
    # overwrite a weaker concurrent session and elevate it.
    from vnc_remote_secure.security.auth_policy import record_auth_context, session_id_for_cookie
    sid = session_id_for_cookie(token)
    if sid:
        session['sid'] = sid
        from vnc_remote_secure.security.sessions import verify_session_cookie
        parsed = verify_session_cookie(token) or {}
        stable = (f"{parsed['username']}:{parsed['created']}"
                  if parsed.get('created') else None)
        record_auth_context(sid, {
            'username': username,
            'auth_method': auth_method,
            'mfa': session['mfa'],
            'phishing_resistant': session['phishing_resistant'],
            'user_verified': session.get('user_verified'),
            'authenticated_at': session['authenticated_at'],
        }, stable_id=stable,
           expires_at=parsed.get('expires'))
    from vnc_remote_secure.security.audit import audit_event
    audit_event('session_issued', user=username, ip=_client_ip(),
                result='success', detail=f'method={auth_method}')
    # Record auth time for step-up auth enforcement.
    from vnc_remote_secure.security.step_up_auth import record_auth_time
    record_auth_time(username)
    resp = redirect(url_for('users.users'))
    # Also issue the raw HMAC session token as the 'vnc_session'
    # cookie — the non-Flask services (noVNC, terminal, audio,
    # gamepad, landing) verify it via verify_session_cookie.
    # Flask's own session cookie was renamed 'vnc_flask_session'
    # to avoid colliding on the same name.
    from flask import current_app

    from vnc_remote_secure.core.constants import (
        DEFAULT_SESSION_IDLE_TIMEOUT,
        DEFAULT_SESSION_MAX_LIFETIME,
    )
    from vnc_remote_secure.security.sessions import (
        _get_env_int,
        get_cookie_attributes,
    )
    attrs = get_cookie_attributes(
        secure=current_app.config.get(
            'SESSION_COOKIE_SECURE', True))
    # Same max_age as create_session_cookie:
    # min(idle, max_lifetime) — the idle window, not the
    # absolute cap (PERMANENT_SESSION_LIFETIME may surface as
    # a timedelta under Flask, so read the env ints directly).
    max_age = min(
        _get_env_int('SESSION_IDLE_TIMEOUT',
                     DEFAULT_SESSION_IDLE_TIMEOUT),
        _get_env_int('SESSION_MAX_LIFETIME',
                     DEFAULT_SESSION_MAX_LIFETIME))
    resp.set_cookie(
        'vnc_session', token,
        max_age=max_age,
        httponly=True,
        secure=attrs['secure'],
        samesite=attrs['samesite'],
        path=attrs['path'])
    return resp


@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate a user and create a session.

    GET renders the login form; POST validates credentials, applies
    rate limiting, and stores a session token on success.
    """
    if request.method == 'POST':
        # CSRF protection: the login form must include the token rendered
        # in the GET response. This prevents login CSRF where an attacker
        # forces a victim to log into the attacker's account.
        expected = session.get('csrf_token')
        sent = request.form.get('csrf_token') or ''
        if not expected or not secrets.compare_digest(
                str(sent).encode('utf-8', 'replace'),
                str(expected).encode('utf-8', 'replace')):
            return render_template('login.html', error='Invalid request'), 400
        ip = _client_ip()
        if not check_rate_limit(ip):
            return json_error('Too many attempts. Try again later.', 429)
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()
        # attempt_login (auth_gateway) is the canonical login path: it
        # enforces per-IP and per-user lockouts, MFA/TOTP when
        # MFA_REQUIRED is set, recovery codes, audit events and auth
        # counters — none of which authenticate() alone performs.
        from vnc_remote_secure.security.auth_gateway import attempt_login
        from vnc_remote_secure.security.mfa import mfa_required_for_login
        ok, message, _data = attempt_login(
            username, password, totp_code=totp_code, client_ip=ip)
        if ok:
            return _issue_session_response(
                username,
                auth_method=(_data or {}).get('auth_method',
                                             'password'))
        return render_template(
            'login.html', error=message,
            mfa_required=mfa_required_for_login(),
            webauthn_enabled=_webauthn_gate() is None,
            csrf_token=session.get('csrf_token', '')), 401
    # Generate a CSRF token for the login form.
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    from vnc_remote_secure.security.mfa import mfa_required_for_login
    return render_template(
        'login.html', csrf_token=session['csrf_token'],
        webauthn_enabled=_webauthn_gate() is None,
        mfa_required=mfa_required_for_login())


@users_bp.route('/logout', methods=['POST'])
def logout():
    """Clear the session and redirect to login.

    POST is required to prevent CSRF attacks via simple GET links.
    A valid CSRF token (issued on login) must be supplied.
    """
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    # Revoke server-side: the auth token lives in session['token']
    # (validated via check_authenticated) — mark it in the shared
    # backend and force-close live WebSocket connections registered
    # under it. Without this a stolen/logged-out token stayed valid
    # until expiry.
    try:
        token = session.get('token', '')
        # The cookie is re-signed on every refresh, so the client's live
        # cookie value no longer equals session['token']. Revoke the
        # stable username:created key — it kills the current cookie and
        # every connection registered under the resolved session id.
        # Central coordinator: resolves cookie -> sid (v3, precise)
        # or legacy pair (v1/v2, group), marks revocation, drops the
        # auth context + index entry, closes WS conns, audits.
        from vnc_remote_secure.security.revocation import revoke_cookie
        for c in {t for t in (token,
                              request.cookies.get('vnc_session', ''))
                  if t}:
            revoke_cookie(c, reason='logout',
                          actor=session.get('username'))
    except Exception:  # noqa: BLE001 - logout must not fail on revoke
        pass
    session.clear()
    resp = redirect(url_for('users.login'))
    # Expire the raw HMAC session cookie too — the Flask session clear
    # does not touch it, and a surviving token would keep WS access
    # alive until expiry. Same for vnc_ephemeral: a share-link session
    # cookie must also be dropped on logout or "logout" is a no-op for
    # ephemeral users (the link itself stays valid server-side by
    # design — revoking it is the owner's choice, not the browser's).
    resp.set_cookie('vnc_session', '', max_age=0, httponly=True,
                    path='/')
    resp.set_cookie('vnc_ephemeral', '', max_age=0, httponly=True,
                    path='/')
    return resp


@users_bp.route('/users')
def users():
    """Render the user management page (requires authentication)."""
    _username, err = _require_session()
    if err is not None:
        return err
    # Provide the context variables the template expects — the OS
    # account enumeration lives in the engine use case.
    from vnc_remote_secure.engine.application.system_users import (
        list_system_users,
    )
    return render_template('users.html', users=list_system_users(),
                           csrf_token=session.get('csrf_token', ''),
                           webauthn_enabled=_webauthn_gate() is None,
                           RESERVED_USERNAMES=RESERVED_USERNAMES)


@users_bp.route('/create_user', methods=['POST'])
def create_user():
    """Create a system user via the platform adapter."""
    actor, err = _require_session()
    if err is not None:
        return err
    perm_err = _require_permission('admin_users', actor)
    if perm_err is not None:
        return perm_err
    # Step-up auth: creating users is a sensitive action.
    from vnc_remote_secure.security.step_up_auth import require_step_up
    step_up_err = require_step_up(actor, 'create_admin')
    if step_up_err:
        return json_error(step_up_err, 403)
    policy_err = _enforce_auth_policy('create_admin')
    if policy_err is not None:
        return policy_err
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    username = sanitize_input(request.form.get('username', ''))
    password = request.form.get('password', '')
    # The use case owns the policy + audit trail.
    err = _create_runtime_user(username, password, actor)
    if err is not None:
        return json_error(err, 400 if err != 'User creation failed' else 500)
    return redirect(url_for('users.users'))


@users_bp.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    """Delete a system user via the platform adapter."""
    actor, err = _require_session()
    if err is not None:
        return err
    perm_err = _require_permission('admin_users', actor)
    if perm_err is not None:
        return perm_err
    # Step-up auth: deleting users is a sensitive action.
    from vnc_remote_secure.security.step_up_auth import require_step_up
    step_up_err = require_step_up(actor, 'delete_admin')
    if step_up_err:
        return json_error(step_up_err, 403)
    policy_err = _enforce_auth_policy('delete_admin')
    if policy_err is not None:
        return policy_err
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    username = sanitize_input(username)
    # Reserved-name/self-deletion policy + audit live in the use case.
    del_err = _delete_runtime_user(username, actor)
    if del_err is not None:
        return json_error(del_err,
                          400 if del_err != 'User deletion failed' else 500)
    return redirect(url_for('users.users'))


def _api_users_get():
    """Handle GET /api/users — list non-system users via the engine
    use case (cross-platform, reserved names filtered)."""
    from vnc_remote_secure.engine.application.system_users import (
        list_system_users,
    )
    return jsonify({'users': list_system_users()})


def _api_users_post(req, sess, actor='?'):
    """Handle POST /api/users — create a user via the engine use case."""
    data = req.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error('Request body must be a JSON object', 400)
    username = sanitize_input(data.get('username', ''))
    password = data.get('password', '')
    err = _create_runtime_user(username, password, actor)
    if err is not None:
        return json_error(err, 400 if err != 'User creation failed' else 500)
    return jsonify({'status': 'created', 'username': username})


def _api_users_delete(req, sess, username, actor='?'):
    """Handle DELETE /api/users — remove a user via the engine use case."""
    err = _delete_runtime_user(username, actor)
    if err is not None:
        return json_error(err,
                          400 if err != 'User deletion failed' else 500)
    return jsonify({'status': 'deleted', 'username': username})


@users_bp.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def api_users():
    """JSON API for user management (requires authentication).

    GET returns the list of non-system users. POST creates a user via
    the platform adapter. DELETE removes a user via the platform adapter.
    State-changing methods require a valid CSRF token.
    """
    _user, err = _require_session()
    if err is not None:
        return err
    if not _user:
        # Authenticated but no resolvable username — fail closed.
        return json_error('Authentication required', 401)

    if request.method == 'GET':
        return _api_users_get()

    # POST and DELETE are state-changing: require CSRF protection.
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)

    # Permission gate: same as the HTML routes — without it an
    # authenticated-but-unprivileged session could manage users via
    # the API while the HTML path blocked it.
    perm_err = _require_permission('admin_users', _user)
    if perm_err:
        return perm_err

    # Step-up auth: user management is sensitive (same as the HTML
    # routes /create_user and /delete_user).
    from vnc_remote_secure.security.step_up_auth import require_step_up

    if request.method == 'POST':
        step_up_err = require_step_up(_user, 'create_admin')
        if step_up_err:
            return json_error(step_up_err, 403)
        data = request.get_json(silent=True)
        username = (sanitize_input((data or {}).get('username', ''))
                    if isinstance(data, dict) else '')
        return _api_users_post(request, session, _user)

    if request.method == 'DELETE':
        step_up_err = require_step_up(_user, 'delete_admin')
        if step_up_err:
            return json_error(step_up_err, 403)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error('Request body must be a JSON object', 400)
        username = sanitize_input(data.get('username', ''))
        return _api_users_delete(request, session, username, _user)

    return json_error('Method not allowed', 405)


# ------------------------------------------------------------------
# WebAuthn / passkey endpoints (opt-in: WEBAUTHN_ENABLED + the
# 'webauthn' package). Registration requires an authenticated
# session + step-up; assertion is the public login ceremony.
# ------------------------------------------------------------------

def _webauthn_rp_id() -> str:
    return (os.environ.get('WEBAUTHN_RP_ID', '').strip()
            or request.host.split(':')[0])


def _webauthn_origin() -> str:
    return (os.environ.get('WEBAUTHN_ORIGIN', '').strip()
            or request.url_root.rstrip('/'))


def _webauthn_rp_name() -> str:
    return (os.environ.get('WEBAUTHN_RP_NAME', '').strip()
            or 'VNC Remote Secure')


def _webauthn_gate():
    """503 when the feature is off, the library is missing, or the
    RP config is unsafe for this deployment."""
    from vnc_remote_secure.security.webauthn import rp_config_error, webauthn_available
    if not webauthn_available():
        return json_error('WebAuthn is not enabled', 503)
    cfg_err = rp_config_error()
    if cfg_err:
        return json_error(cfg_err, 503)
    return None


@users_bp.route('/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    """Start a passkey registration ceremony (auth + step-up)."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    actor, err = _require_session()
    if err is not None:
        return err
    from vnc_remote_secure.security.step_up_auth import require_step_up
    step_up_err = require_step_up(actor, 'webauthn_register')
    if step_up_err:
        return json_error(step_up_err, 403)
    policy_err = _enforce_auth_policy('webauthn_register')
    if policy_err is not None:
        return policy_err
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    from vnc_remote_secure.security.webauthn import begin_registration
    options = begin_registration(
        actor, actor, _webauthn_rp_id(), _webauthn_rp_name())
    return jsonify(options)


@users_bp.route('/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    """Finish a passkey registration ceremony."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    actor, err = _require_session()
    if err is not None:
        return err
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'credential' not in data:
        return json_error('Request body must contain a credential', 400)
    from vnc_remote_secure.security.webauthn import complete_registration
    ok, message = complete_registration(
        actor, data['credential'], _webauthn_rp_id(),
        _webauthn_origin(), name=str(data.get('name', ''))[:64])
    if not ok:
        return json_error(message, 400)
    return jsonify({'registered': True})


@users_bp.route('/webauthn/credentials', methods=['GET'])
def webauthn_credentials():
    """List the caller's registered passkeys."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    actor, err = _require_session()
    if err is not None:
        return err
    from vnc_remote_secure.security.webauthn import list_credentials
    return jsonify({'credentials': list_credentials(actor)})


@users_bp.route('/webauthn/credentials/<credential_id>',
                methods=['DELETE'])
def webauthn_delete_credential(credential_id):
    """Delete one of the caller's passkeys (step-up required)."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    actor, err = _require_session()
    if err is not None:
        return err
    from vnc_remote_secure.security.step_up_auth import require_step_up
    step_up_err = require_step_up(actor, 'webauthn_delete')
    if step_up_err:
        return json_error(step_up_err, 403)
    policy_err = _enforce_auth_policy('webauthn_delete')
    if policy_err is not None:
        return policy_err
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    from vnc_remote_secure.security.webauthn import delete_credential
    if not delete_credential(credential_id, actor):
        return json_error('Credential not found', 404)
    return jsonify({'deleted': True})


@users_bp.route('/webauthn/assert/begin', methods=['POST'])
def webauthn_assert_begin():
    """Start a passkey login ceremony (public, rate-limited)."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    ip = _client_ip()
    if not check_rate_limit(ip):
        return json_error('Too many attempts. Try again later.', 429)
    data = request.get_json(silent=True) or {}
    username = sanitize_input(str(data.get('username', '')))
    if not username:
        return json_error('username is required', 400)
    from vnc_remote_secure.security.webauthn import begin_authentication
    options = begin_authentication(username, _webauthn_rp_id())
    if options is None:
        # Same response whether the user or their passkeys exist —
        # no account enumeration through the ceremony.
        return json_error('Passkey authentication unavailable', 404)
    return jsonify(options)


@users_bp.route('/webauthn/assert/complete', methods=['POST'])
def webauthn_assert_complete():
    """Finish a passkey login ceremony and issue the session."""
    gate = _webauthn_gate()
    if gate is not None:
        return gate
    ip = _client_ip()
    if not check_rate_limit(ip):
        return json_error('Too many attempts. Try again later.', 429)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'credential' not in data:
        return json_error('Request body must contain a credential', 400)
    username = sanitize_input(str(data.get('username', '')))
    from vnc_remote_secure.security.webauthn import complete_authentication
    result = complete_authentication(
        username, data['credential'], _webauthn_rp_id(),
        _webauthn_origin())
    if not result.ok:
        return json_error(result.message, 401)
    return _issue_session_response(username, auth_method='webauthn',
                                   user_verified=result.user_verified)
