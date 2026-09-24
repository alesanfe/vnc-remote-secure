"""Versioned JSON API for the admin SPA (``/api/v1/*``).

Served by the landing handler. The portal-level auth gate has already
run for GETs (ephemeral cookie or operator Basic-auth); operator-only
routes additionally require ``handler._portal_operator`` — an
ephemeral share-link session is never an operator. Mutating routes
go through ``handler._operator_gate`` which re-authenticates the
Basic credential and enforces Origin + Sec-Fetch-Site CSRF checks.

Success responses use the ``{data, error, request_id}`` envelope;
errors reuse the canonical ``error_json`` body via ``send_json_error``.
"""
import hashlib
import hmac
import json
import logging
import re
import time
import uuid

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import cookie_value

logger = logging.getLogger(__name__)

_API_PREFIX = '/api/v1/'
_MAX_BODY = 16384

# Resources a share link may be bound to.
_RESOURCES = {'desktop', 'terminal', 'audio', 'gamepad'}

# Share-link permissions that grant administrative power — minting a
# link carrying any of these requires the operator to hold 'admin:*',
# otherwise an 'admin_sessions' operator could hand out admin links.
_ADMINISH_PERMS = {
    'admin', 'admin_users', 'admin_config', 'admin_secrets',
    'admin_audit',
}

# Strict input schema for POST /api/v1/sessions.
_SESSION_CREATE_KEYS = {
    'role', 'permissions', 'ttl_seconds', 'single_use', 'view_only',
    'no_terminal', 'max_uses', 'allowed_ip', 'resource',
}

# Per-scope rate limits: (max requests, window seconds). These sit on
# top of the auth layer — expensive endpoints (doctor, audit verify)
# get tight budgets so the API cannot be used to burn CPU/disk.
_RATE_LIMITS = {
    'sessions.create': (30, 60),
    'sessions.revoke': (60, 60),
    'sessions.revoke-all': (10, 60),
    'doctor': (6, 60),
    'audit': (60, 60),
    'audit.verify': (10, 60),
    'session.activate': (30, 60),
    'session.preview': (60, 60),
    # Operator management — destructive scopes get tighter budgets.
    'operators.create': (10, 60),
    'operators.update': (30, 60),
    'operators.delete': (10, 60),
    'operators.sessions_revoke': (30, 60),
    'default': (120, 60),
}
_RATE_NS = 'api_rate'


def _rate_limit(handler, scope: str) -> bool:
    """Fixed-window per-IP-per-scope limiter over the shared backend.

    Fails closed on backend errors for mutating scopes and open for
    reads — a redis/sqlite hiccup must not blind the operator, but a
    mutation flood must not sail through either.
    """
    from vnc_remote_secure.security.http_auth import client_ip_from
    ip = client_ip_from(handler.headers, handler.peer_ip()) or 'unknown'
    max_req, window = _RATE_LIMITS.get(scope, _RATE_LIMITS['default'])
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        bucket = int(time.time() // window)
        count = get_backend().increment(
            _RATE_NS, f'{scope}\x00{ip}\x00{bucket}', 1, window)
        allowed = int(count) <= max_req
    except Exception:  # noqa: BLE001 - degraded, not silent
        logger.warning('API rate limiter unavailable (scope=%s)', scope)
        allowed = scope not in ('sessions.create', 'sessions.revoke',
                                'sessions.revoke-all')
    if not allowed:
        _err(handler, 'Too many requests', 429)
    return allowed


def _csrf_token(sid: str, nonce: str) -> str:
    """CSRF token bound to the operator session id (``vnc_op``) AND
    the ``vnc_csrf`` nonce cookie.

    Binding to the sid means a nonce cookie copied between sessions
    cannot mint a usable token; binding to the nonce means the token
    dies when the cookie rotates (logout, step-up).
    """
    from vnc_remote_secure.security.authentication import _get_secret
    return hmac.new(_get_secret(), f'csrf:{sid}:{nonce}'.encode(),
                    hashlib.sha256).hexdigest()


def is_api_path(path: str) -> bool:
    """Return True when ``path`` is an /api/v1/* route."""
    return path.startswith(_API_PREFIX)


def _request_id() -> str:
    return uuid.uuid4().hex[:16]


def _ok(handler, data, status: int = 200) -> None:
    handler.send_json(
        {'data': data, 'error': None, 'request_id': _request_id()},
        status)


def _err(handler, message: str, status: int) -> None:
    handler.send_json_error(message, status)


def _operator(handler, permission: str | None = None):
    """Return the operator record or write the error and return None.

    Read endpoints rely on the identity resolved by the portal gate;
    ``_portal_operator`` is None for ephemeral share-link sessions.
    """
    operator = getattr(handler, '_portal_operator', None)
    if operator is None:
        _err(handler, 'Operator access required', 403)
        return None
    if permission:
        perms = set(operator.get('permissions') or [])
        if permission not in perms and 'admin:*' not in perms:
            from vnc_remote_secure.security.audit import audit_event
            audit_event('api_permission_denied',
                        user=operator.get('username', '?'),
                        detail=f'required={permission}')
            _err(handler, 'Insufficient role for this action', 403)
            return None
    return operator


def _read_json_body(handler, limit: int = _MAX_BODY):
    """Read a bounded JSON body; returns ``(payload, error)``."""
    try:
        length = int(handler.headers.get('Content-Length', 0))
    except ValueError:
        length = 0
    if not 0 < length <= limit:
        return None, ('Bad request', 400)
    try:
        payload = json.loads(handler.rfile.read(length))
    except (json.JSONDecodeError, ValueError):
        return None, ('Invalid JSON', 400)
    if not isinstance(payload, dict):
        return None, ('JSON object expected', 400)
    return payload, None


# ---------------------------------------------------------------------------
# Public serializers — whitelist field selection. Never serialize an
# internal object wholesale; the allowed keys ARE the response schema.
# ---------------------------------------------------------------------------

def session_to_api(s: dict) -> dict:
    """Ephemeral-session dict -> public shape. Never emits the raw
    session token or any server-side secret."""
    keys = ('token_id', 'role', 'permissions', 'expires_at',
            'single_use', 'view_only', 'no_terminal', 'allowed_ip',
            'created_by', 'created_at', 'used', 'revoked', 'resource',
            'max_uses', 'use_count')
    return {k: s.get(k) for k in keys if k in s}


def operator_to_api(u: dict) -> dict:
    keys = ('username', 'role', 'disabled', 'created_at', 'permissions')
    return {k: u.get(k) for k in keys if k in u}


def backup_to_api(path: str, st) -> dict:
    import os
    return {
        'name': os.path.basename(path),
        'size': st.st_size,
        'modified': st.st_mtime,
        'encrypted': path.endswith('.enc.tar.gz'),
    }


def audit_event_to_api(e: dict) -> dict:
    keys = ('seq', 'timestamp', 'event', 'user', 'result', 'detail')
    return {k: e.get(k) for k in keys if k in e}


def config_entry_to_api(e: dict) -> dict:
    # Values arrive already redacted by config_inspector._redact_value;
    # the whitelist keeps the contract explicit.
    keys = ('name', 'value', 'source')
    return {k: e.get(k) for k in keys if k in e}


def _external_base(handler) -> str | None:
    """Public nginx base from trusted forwarded headers, else None.

    Mirrors ``generate_landing_page``: the forwarded host lands inside
    URLs returned to the SPA, so it is constrained to a strict
    hostname set — a crafted X-Forwarded-Host must not become
    reflected markup.
    """
    if not env_flag('TRUSTED_PROXY', 'false'):
        return None
    fhost = handler.headers.get('X-Forwarded-Host')
    if not fhost:
        return None
    proto = handler.headers.get(
        'X-Forwarded-Proto', 'https').split(',')[0].strip()
    host = fhost.split(',')[0].strip()
    if re.fullmatch(r'[A-Za-z0-9.\-:\[\]]{1,253}', host) \
            and proto in ('http', 'https'):
        return f'{proto}://{host}'
    return None


def _protocol() -> str:
    try:
        from vnc_remote_secure.core.config import get_config
        from vnc_remote_secure.security.certificates import create_ssl_context
        cfg = get_config()
        return 'https' if create_ssl_context(
            cfg['ssl_cert'], cfg['ssl_key']) is not None else 'http'
    except Exception:  # noqa: BLE001 - fall back to plain http
        return 'http'


# ---------------------------------------------------------------------------
# GET endpoints
# ---------------------------------------------------------------------------

def _get_me(handler, query):
    operator = getattr(handler, '_portal_operator', None)
    _ok(handler, {
        'authenticated': True,
        'operator': ({
            'username': operator.get('username'),
            'role': operator.get('role'),
            'permissions': sorted(operator.get('permissions') or []),
        } if operator else None),
        'ephemeral': operator is None,
        # Session-bound CSRF token (HMAC of the vnc_csrf nonce) — the
        # SPA presents it as X-CSRF-Token on every mutation.
        'csrf_token': (handler._csrf_token() if operator else None),
    })


def _get_status(handler, query):
    # Intentionally NOT operator-gated: share-link sessions read
    # service states for the portal cards. _status_payload redacts
    # lan_ips/system metrics when _portal_operator is None.
    _ok(handler, handler._status_payload())


def _get_services(handler, query):
    from vnc_remote_secure.services.landing import _build_service_list
    services = _build_service_list(_protocol(), _external_base(handler))
    for svc in services:
        # Booleans/ints/urls only — the raw dict is already the same
        # data the portal page renders for any authenticated user.
        svc.pop('color', None)
    _ok(handler, {'services': services})


def _get_sessions(handler, query):
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        store = get_session_store()
        store._load_if_changed()
        _ok(handler, {'sessions': [
            session_to_api(s) for s in store.list_active()]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /sessions')
        _err(handler, 'Failed to list sessions', 500)


def _get_session_context(handler, query):
    """GET /api/v1/session-context — the share-link session's own
    minimal context (what an ephemeral client may know about itself).

    Separates ephemeral reads from the operator /status contract:
    this payload can never grow admin telemetry by accident.
    """
    operator = getattr(handler, '_portal_operator', None)
    if operator is not None:
        _ok(handler, {'ephemeral': False})
        return
    internal = cookie_value(
        handler.headers.get('Cookie', ''), 'vnc_ephemeral')
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        store = get_session_store()
        store._load_if_changed()
        sess = store.get(internal) if internal else None
    except Exception:  # noqa: BLE001 - fail closed
        sess = None
    if sess is None or getattr(sess, 'revoked', False):
        _ok(handler, {'ephemeral': True, 'active': False})
        return
    try:
        from vnc_remote_secure.security.maintenance import maintenance_active
        maintenance = maintenance_active()
    except Exception:  # noqa: BLE001
        maintenance = False
    _ok(handler, {
        'ephemeral': True,
        'active': True,
        'role': getattr(sess, 'role', ''),
        'permissions': sorted(getattr(sess, 'permissions', []) or []),
        'expires_at': getattr(sess, 'expires_at', None),
        'view_only': bool(getattr(sess, 'view_only', False)),
        'single_use': bool(getattr(sess, 'single_use', False)),
        'no_terminal': bool(getattr(sess, 'no_terminal', False)),
        'resource': getattr(sess, 'resource', None),
        'maintenance': maintenance,
    })


def _get_health(handler, query):
    try:
        from vnc_remote_secure.monitoring.health import get_all_health
        _ok(handler, get_all_health())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /health')
        _err(handler, 'Health status generation failed', 500)


def _get_posture(handler, query):
    try:
        from vnc_remote_secure.security.posture import calculate_posture
        _ok(handler, calculate_posture())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /security/posture')
        _err(handler, 'Posture calculation failed', 500)


def _get_doctor(handler, query):
    try:
        from vnc_remote_secure.core.doctor import run_doctor
        _ok(handler, run_doctor(as_json=True))
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /doctor')
        _err(handler, 'Doctor run failed', 500)


def _get_audit(handler, query):
    try:
        from vnc_remote_secure.security.audit import get_audit_entries
        try:
            limit = int((query.get('limit') or ['100'])[0])
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))
        event = (query.get('event') or [None])[0]
        # Cursor pagination: ``cursor`` is the seq of the last entry of
        # the previous page — opaque to the client, stable under
        # appends, no deep offsets.
        cursor = (query.get('cursor') or [None])[0]
        try:
            before_seq = int(cursor) if cursor else None
        except (TypeError, ValueError):
            _err(handler, 'Invalid cursor', 400)
            return
        entries = get_audit_entries(
            limit=limit + 1, event=event, before_seq=before_seq)
        has_more = len(entries) > limit
        entries = entries[:limit]
        next_cursor = (entries[-1].get('seq')
                       if has_more and entries else None)
        _ok(handler, {
            'entries': [audit_event_to_api(e) for e in entries],
            'next_cursor': next_cursor,
            'has_more': has_more,
        })
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit')
        _err(handler, 'Audit read failed', 500)


def _get_audit_verify(handler, query):
    try:
        from vnc_remote_secure.security.audit import verify_chain
        intact, message = verify_chain()
        _ok(handler, {'intact': intact, 'message': message})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit/verify')
        _err(handler, 'Audit verification failed', 500)


def _get_config(handler, query):
    try:
        from vnc_remote_secure.core.config_inspector import compute_effective_config
        _ok(handler, {'vars': [
            config_entry_to_api(e) for e in compute_effective_config()]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /config')
        _err(handler, 'Config inspection failed', 500)


def _get_backups(handler, query):
    try:
        from vnc_remote_secure.core.backup import list_backups
        items = []
        for path in list_backups():
            import os
            try:
                items.append(backup_to_api(path, os.stat(path)))
            except OSError:
                continue
        _ok(handler, {'backups': items})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /backups')
        _err(handler, 'Backup listing failed', 500)


def _get_operators(handler, query):
    try:
        from vnc_remote_secure.security.operator_users import get_permissions, list_users
        users = []
        for u in list_users():
            u['permissions'] = sorted(
                get_permissions(u['username']))
            users.append(operator_to_api(u))
        _ok(handler, {'operators': users})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /operators')
        _err(handler, 'Operator listing failed', 500)


def _get_maintenance(handler, query):
    try:
        from vnc_remote_secure.security.maintenance import maintenance_active, maintenance_info
        _ok(handler, {
            'active': maintenance_active(),
            'info': maintenance_info() or {},
        })
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /maintenance')
        _err(handler, 'Maintenance state read failed', 500)


# ---------------------------------------------------------------------------
# POST endpoints
# ---------------------------------------------------------------------------

def _valid_allowed_ip(value: str) -> bool:
    """Validate an IP, CIDR or the 'first-observed' marker."""
    if value == 'first-observed':
        return True
    import ipaddress
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _post_session_create(handler, query):
    """POST /api/v1/sessions — share-link creation for the wizard.
    Auth+CSRF+capability already ran in _dispatch; the operator is
    stashed on ``handler._api_operator``."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return

    # Strict schema: unknown keys are rejected, not ignored — a
    # misspelled flag must never silently produce a wider link.
    unknown_keys = set(payload) - _SESSION_CREATE_KEYS
    if unknown_keys:
        _err(handler, f'Unknown fields: {sorted(unknown_keys)}', 400)
        return

    from vnc_remote_secure.security.ephemeral_sessions import (
        ALL_PERMISSIONS,
        ROLES,
        expand_permissions,
        get_session_store,
    )

    role = payload.get('role', 'viewer')
    if not isinstance(role, str) or role not in ROLES:
        _err(handler, f'Unknown role: {role}', 400)
        return
    permissions = payload.get('permissions')
    if permissions is not None:
        if (not isinstance(permissions, list)
                or not all(type(p) is str for p in permissions)
                or len(permissions) > len(ALL_PERMISSIONS)):
            _err(handler, 'permissions must be a list of strings', 400)
            return
        permissions = set(permissions)
        unknown = permissions - ALL_PERMISSIONS
        if unknown:
            _err(handler,
                 f'Unknown permissions: {sorted(unknown)}', 400)
            return
        if not permissions:
            _err(handler, 'permissions must not be empty', 400)
            return
    ttl = payload.get('ttl_seconds', 1800)
    if type(ttl) is not int:  # noqa: E721 - bool is an int; reject it
        _err(handler, 'ttl_seconds must be an integer', 400)
        return
    if not 60 <= ttl <= 7 * 86400:
        _err(handler, 'ttl_seconds must be 60..604800', 400)
        return
    max_uses = payload.get('max_uses', 0)
    if type(max_uses) is not int:  # noqa: E721
        _err(handler, 'max_uses must be an integer', 400)
        return
    if not 0 <= max_uses <= 1000:
        _err(handler, 'max_uses must be 0..1000', 400)
        return
    for flag in ('single_use', 'view_only', 'no_terminal'):
        if type(payload.get(flag, False)) is not bool:  # noqa: E721
            _err(handler, f'{flag} must be a boolean', 400)
            return
    allowed_ip = payload.get('allowed_ip')
    if allowed_ip:
        if not isinstance(allowed_ip, str):
            _err(handler, 'allowed_ip must be a string', 400)
            return
        allowed_ip = allowed_ip.strip()
        if len(allowed_ip) > 64 or not _valid_allowed_ip(allowed_ip):
            _err(handler, 'allowed_ip is not a valid IP, CIDR, '
                          "or 'first-observed'", 400)
            return
    else:
        allowed_ip = None
    resource = payload.get('resource')
    if resource:
        if not isinstance(resource, str) or resource not in _RESOURCES:
            _err(handler,
                 f'resource must be one of {sorted(_RESOURCES)}', 400)
            return
    else:
        resource = None

    # Privilege delegation: a share link may only carry powers the
    # CREATING operator holds. Operator permissions are admin_* names
    # while share-link permissions are view/control/terminal/... — the
    # enforceable overlap is the admin-granting set: minting a link
    # with admin powers (administrator role or explicit admin_*)
    # requires 'admin:*'.
    requested = permissions if permissions is not None else ROLES[role]
    if expand_permissions(requested) & _ADMINISH_PERMS:
        op_perms = set(operator.get('permissions') or [])
        if 'admin:*' not in op_perms:
            from vnc_remote_secure.security.audit import audit_event
            audit_event('api_permission_denied',
                        user=operator.get('username', '?'),
                        detail='share-link with admin permissions')
            _err(handler,
                 'Admin-granting share links require admin:*', 403)
            return

    try:
        session, signed = get_session_store().create(
            expires_in=ttl,
            role=role,
            single_use=payload.get('single_use', False),
            view_only=payload.get('view_only', False),
            no_terminal=payload.get('no_terminal', False),
            allowed_ip=allowed_ip,
            created_by=operator.get('username', 'admin'),
            resource=resource,
            max_uses=max_uses,
            permissions=permissions,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        _err(handler, f'Session creation failed: {exc}', 500)
        return

    from vnc_remote_secure.cli.commands.session import _share_base_url
    base = _share_base_url()
    _ok(handler, {
        # Fragment-carried link: the token never reaches the server in
        # the URL, so it cannot leak via history, Referer, or logs.
        'url': f'{base}/share#t={signed}',
        'legacy_url': f'{base}/?session={signed}',
        'token_id': session.to_dict()['token_id'],
        'expires_at': session.expires_at,
        'role': session.role,
        'permissions': sorted(session.permissions),
        'single_use': session.single_use,
        'view_only': session.view_only,
        'no_terminal': session.no_terminal,
        'max_uses': session.max_uses,
        'resource': session.resource,
        'allowed_ip': session.allowed_ip,
    }, status=201)


def _post_session_revoke(handler, query):
    """POST /api/v1/sessions/revoke — revoke one share-link session."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    token_id = str(payload.get('token_id', '')).strip()
    if not token_id:
        _err(handler, 'token_id required', 400)
        return
    from vnc_remote_secure.security.ephemeral_sessions import revoke_session
    revoked = revoke_session(token_id)
    from vnc_remote_secure.security.audit import audit_event
    audit_event('portal_session_revoke',
                user=operator.get('username', 'unknown'),
                result='success' if revoked else 'failure',
                detail=f'token_id={token_id}')
    # Uniform 200 whether the token existed or not — the caller is
    # already authorized; distinguishing 404 would only help enumerate
    # live session ids.
    _ok(handler, {'revoked': bool(revoked)})


def _post_session_revoke_all(handler, query):
    """POST /api/v1/sessions/revoke-all — emergency kill-switch."""
    operator = handler._api_operator
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store, revoke_session
    store = get_session_store()
    store._load_if_changed()
    count = 0
    for s in list(store.list_active()):
        if revoke_session(s['token_id']):
            count += 1
    from vnc_remote_secure.security.audit import audit_event
    audit_event('portal_session_revoke_all',
                user=operator.get('username', 'unknown'),
                detail=f'count={count}')
    _ok(handler, {'revoked': count})


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
    for target_sid, exp in ((sid, cookie_exp),
                            (cookie_sid, cookie_exp)):
        if target_sid:
            try:
                handler._revoke_op_session(
                    target_sid,
                    exp or int(time.time()) + handler._OP_SESSION_TTL)
            except Exception:  # noqa: BLE001 - best-effort
                pass
    from vnc_remote_secure.security.audit import audit_event
    audit_event('portal_logout',
                user=handler._api_operator.get('username', 'unknown'))
    # Cancel any pending session cookies this request minted, then
    # expire both explicitly.
    handler.__dict__['_pending_cookies'] = []
    handler._queue_cookie(
        'vnc_op=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict')
    handler._queue_cookie(
        'vnc_csrf=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict')
    _ok(handler, {'logged_out': True})


# ---------------------------------------------------------------------------
# Operator management
# ---------------------------------------------------------------------------
# Schemas (strict — unknown keys rejected):
#   POST   /operators            {username, password, role, enabled?}
#   PATCH  /operators/{username} {role?, disabled?, password?}
#   DELETE /operators/{username}
#   POST   /operators/{username}/sessions/revoke-all  {}
_OPERATOR_CREATE_KEYS = {'username', 'password', 'role', 'enabled'}
_OPERATOR_PATCH_KEYS = {'role', 'disabled', 'password'}


def _operator_record(username: str):
    """Store record for *username* or None."""
    from vnc_remote_secure.security.operator_users import load_store
    return load_store().get(username)


def _uc_error_status(err) -> int:
    """Map a domain UseCaseError code to a public HTTP status."""
    from vnc_remote_secure.engine.domain.decision import (
        ERR_CONFLICT,
        ERR_LAST_ADMIN,
        ERR_NOT_FOUND,
        ERR_PERMISSION,
    )
    return {ERR_NOT_FOUND: 404, ERR_PERMISSION: 403,
            ERR_CONFLICT: 409, ERR_LAST_ADMIN: 409}.get(err.code, 400)


def _get_operator_detail(handler, query):
    username = handler._api_params['username']
    rec = _operator_record(username)
    if rec is None:
        _err(handler, 'Operator not found', 404)
        return
    from vnc_remote_secure.security.operator_users import get_permissions
    from vnc_remote_secure.security.webauthn import list_credentials
    data = operator_to_api({'username': username, **rec})
    data['permissions'] = sorted(get_permissions(username))
    data['passkey_count'] = len(list_credentials(username))
    _ok(handler, {'operator': data})


def _get_operator_passkeys(handler, query):
    """Public passkey view: opaque ref (sha256 prefix of the
    credential id), name, timestamps — never the credential id or
    public key."""
    import hashlib as _hashlib
    username = handler._api_params['username']
    if _operator_record(username) is None:
        _err(handler, 'Operator not found', 404)
        return
    from vnc_remote_secure.security.webauthn import list_credentials
    keys = [{
        'ref': _hashlib.sha256(c['credential_id'].encode()).hexdigest()[:16],
        'name': c.get('name', ''),
        'created_at': c.get('created_at', ''),
        'sign_count': c.get('sign_count', 0),
    } for c in list_credentials(username)]
    _ok(handler, {'passkeys': keys})


def _post_operator_create(handler, query):
    """POST /api/v1/operators — strict schema; a misspelled flag must
    never silently produce a wider account."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    unknown = set(payload) - _OPERATOR_CREATE_KEYS
    if unknown:
        _err(handler, f'Unknown fields: {sorted(unknown)}', 400)
        return
    username = payload.get('username')
    password = payload.get('password')
    role = payload.get('role', 'viewer')
    enabled = payload.get('enabled', True)
    if not isinstance(username, str):
        _err(handler, 'username must be a string', 400)
        return
    username = username.strip()
    if not isinstance(password, str) or not password:
        _err(handler, 'password required', 400)
        return
    if type(enabled) is not bool:  # noqa: E721
        _err(handler, 'enabled must be a boolean', 400)
        return
    from vnc_remote_secure.core.validation import ValidationError, validate_password
    from vnc_remote_secure.security.operator_users import _valid_username
    if not _valid_username(username):
        _err(handler,
             'username must be 1-64 chars of [a-zA-Z0-9._-@]', 400)
        return
    try:
        validate_password(password)
    except ValidationError as exc:
        _err(handler, str(exc), 400)
        return
    from vnc_remote_secure.engine.application.operators import create_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        rec = create_operator(
            operator.get('username', '?'),
            set(operator.get('permissions') or []),
            username, password, role, enabled)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {
        'operator': operator_to_api({'username': username, **rec}),
    }, status=201)


def _patch_operator(handler, query):
    """PATCH /api/v1/operators/{username} — role, disabled, password.
    Internal fields (hash, timestamps) are never settable."""
    operator = handler._api_operator
    username = handler._api_params['username']
    payload, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    unknown = set(payload) - _OPERATOR_PATCH_KEYS
    if unknown or not payload:
        _err(handler,
             f'Allowed fields: {sorted(_OPERATOR_PATCH_KEYS)}'
             + (f' (unknown: {sorted(unknown)})' if unknown else ''),
             400)
        return
    if _operator_record(username) is None:
        _err(handler, 'Operator not found', 404)
        return
    from vnc_remote_secure.engine.application.operators import update_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    kw: dict = {}
    if 'role' in payload:
        role = payload['role']
        if not isinstance(role, str):
            _err(handler, 'role must be a string', 400)
            return
        kw['role'] = role
    if 'disabled' in payload:
        disabled = payload['disabled']
        if type(disabled) is not bool:  # noqa: E721
            _err(handler, 'disabled must be a boolean', 400)
            return
        kw['disabled'] = disabled
    if 'password' in payload:
        password = payload['password']
        if not isinstance(password, str) or not password:
            _err(handler, 'password must be a non-empty string', 400)
            return
        from vnc_remote_secure.core.validation import ValidationError, validate_password
        try:
            validate_password(password)
        except ValidationError as exc:
            _err(handler, str(exc), 400)
            return
        kw['password'] = password
    try:
        result = update_operator(
            operator.get('username', '?'),
            set(operator.get('permissions') or []),
            username, **kw)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {
        'operator': operator_to_api(
            {'username': username, **result['record']}),
        'changed': result['changed'],
        'sessions_revoked': result['sessions_revoked'],
    })


def _delete_operator(handler, query):
    """DELETE /api/v1/operators/{username} — refuses the last viable
    administrator; live sessions die with the account."""
    operator = handler._api_operator
    username = handler._api_params['username']
    from vnc_remote_secure.engine.application.operators import delete_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_operator(operator.get('username', '?'), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'deleted': True})


def _post_operator_revoke_sessions(handler, query):
    """POST /api/v1/operators/{username}/sessions/revoke-all."""
    operator = handler._api_operator
    username = handler._api_params['username']
    from vnc_remote_secure.engine.application.operators import revoke_sessions
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        revoke_sessions(operator.get('username', '?'), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'revoked': True})


# ---------------------------------------------------------------------------
# Declarative route registry
# ---------------------------------------------------------------------------
# Single source of truth for the API contract. ``perm`` is the
# operator capability required (``None`` = any authenticated portal
# user, including ephemeral share-link sessions; the literal
# 'operator' = operator account, no specific capability). ``scope``
# selects the rate-limit budget; ``audit`` names the event a mutation
# must emit; ``resp`` names the public response schema the handler
# serializes through — declared here so a contract test can flag a
# mutation that forgets either.
from collections import namedtuple

_Route = namedtuple('_Route', 'fn perm scope audit resp')

_ROUTES = {
    ('GET', 'me'): _Route(
        _get_me, None, 'default', None, 'MeResponse'),
    ('GET', 'status'): _Route(
        _get_status, None, 'default', None, 'StatusResponse'),
    ('GET', 'session-context'): _Route(
        _get_session_context, None, 'default', None,
        'SessionContextResponse'),
    ('GET', 'services'): _Route(
        _get_services, 'operator', 'default', None, 'ServicesResponse'),
    ('GET', 'sessions'): _Route(
        _get_sessions, 'admin_sessions', 'default', None,
        'SessionPageResponse'),
    ('GET', 'health'): _Route(
        _get_health, 'operator', 'default', None, 'HealthResponse'),
    ('GET', 'security/posture'): _Route(
        _get_posture, 'operator', 'default', None, 'PostureResponse'),
    ('GET', 'doctor'): _Route(
        _get_doctor, 'operator', 'doctor', None, 'DoctorResponse'),
    ('GET', 'audit'): _Route(
        _get_audit, 'admin_audit', 'audit', None, 'AuditPageResponse'),
    ('GET', 'audit/verify'): _Route(
        _get_audit_verify, 'admin_audit', 'audit.verify', None,
        'AuditVerifyResponse'),
    ('GET', 'config'): _Route(
        _get_config, 'admin_config', 'default', None,
        'ConfigPageResponse'),
    ('GET', 'backups'): _Route(
        _get_backups, 'operator', 'default', None,
        'BackupPageResponse'),
    ('GET', 'operators'): _Route(
        _get_operators, 'admin_users', 'default', None,
        'OperatorPageResponse'),
    ('GET', 'maintenance'): _Route(
        _get_maintenance, 'operator', 'default', None,
        'MaintenanceResponse'),
    ('POST', 'sessions'): _Route(
        _post_session_create, 'admin_sessions', 'sessions.create',
        'portal_session_create', 'SessionCreatedResponse'),
    ('POST', 'sessions/revoke'): _Route(
        _post_session_revoke, 'admin_sessions', 'sessions.revoke',
        'portal_session_revoke', 'SessionRevokeResponse'),
    ('POST', 'sessions/revoke-all'): _Route(
        _post_session_revoke_all, 'admin_sessions', 'sessions.revoke-all',
        'portal_session_revoke_all', 'SessionRevokeResponse'),
    ('POST', 'logout'): _Route(
        _post_logout, 'operator', 'default', 'portal_logout',
        'LogoutResponse'),
    # Operator management — {username} is a path parameter resolved
    # by _dispatch into handler._api_params.
    ('GET', 'operators/{username}'): _Route(
        _get_operator_detail, 'admin_users', 'default', None,
        'OperatorResponse'),
    ('GET', 'operators/{username}/passkeys'): _Route(
        _get_operator_passkeys, 'admin_users', 'default', None,
        'PasskeyPageResponse'),
    ('POST', 'operators'): _Route(
        _post_operator_create, 'admin_users', 'operators.create',
        'operator_created', 'OperatorResponse'),
    ('PATCH', 'operators/{username}'): _Route(
        _patch_operator, 'admin_users', 'operators.update',
        'operator_updated', 'OperatorResponse'),
    ('DELETE', 'operators/{username}'): _Route(
        _delete_operator, 'admin_users', 'operators.delete',
        'operator_deleted', 'DeleteResponse'),
    ('POST', 'operators/{username}/sessions/revoke-all'): _Route(
        _post_operator_revoke_sessions, 'admin_users',
        'operators.sessions_revoke', 'operator_sessions_revoked',
        'SessionRevokeResponse'),
}

# Operator capabilities the registry may reference — anything else is
# a configuration bug a contract test catches.
_KNOWN_PERMS = {
    'operator', 'admin_sessions', 'admin_audit', 'admin_config',
    'admin_users', 'admin_secrets',
}


_TEMPLATE_ROUTES = None


def _template_routes():
    """Compile ``{name}`` path templates in _ROUTES to regexes once.

    Segments like ``operators/{username}`` match a single non-empty
    path segment; captured params are stashed on
    ``handler._api_params`` for the handler.
    """
    global _TEMPLATE_ROUTES
    if _TEMPLATE_ROUTES is None:
        import re
        compiled = []
        for (method, rel), spec in _ROUTES.items():
            if '{' not in rel:
                continue
            pattern = '/'.join(
                f'(?P<{seg[1:-1]}>[^/]+)'
                if seg.startswith('{') and seg.endswith('}')
                else re.escape(seg)
                for seg in rel.split('/'))
            compiled.append((method, re.compile(f'^{pattern}$'), spec))
        _TEMPLATE_ROUTES = compiled
    return _TEMPLATE_ROUTES


def _dispatch(handler, method: str, path: str, query: dict) -> bool:
    """Central dispatch: rate limit -> auth/capability -> handler.

    Returns True when the route was handled (response written), False
    when ``path`` matches no route.
    """
    rel = path[len(_API_PREFIX):]
    spec = _ROUTES.get((method, rel))
    params = {}
    if spec is None:
        for rmethod, regex, rspec in _template_routes():
            if rmethod != method:
                continue
            m = regex.match(rel)
            if m:
                spec, params = rspec, m.groupdict()
                break
    if spec is None:
        return False
    if not _rate_limit(handler, spec.scope):
        return True
    if method != 'GET':
        # _operator_gate runs operator auth + Origin + Sec-Fetch-Site
        # + the nonce-bound CSRF check + the capability check.
        perm = None if spec.perm == 'operator' else spec.perm
        operator = handler._operator_gate(perm)
        if operator is None:
            return True
        handler._api_operator = operator
    elif spec.perm is not None:
        cap = None if spec.perm == 'operator' else spec.perm
        if _operator(handler, cap) is None:
            return True
    handler._api_params = params
    spec.fn(handler, query)
    return True


def handle_get(handler, path: str, query: dict) -> bool:
    """Dispatch a GET under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'GET', path, query)


def handle_post(handler, path: str) -> bool:
    """Dispatch a POST under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'POST', path, {})


def handle_patch(handler, path: str) -> bool:
    """Dispatch a PATCH under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'PATCH', path, {})


def handle_delete(handler, path: str) -> bool:
    """Dispatch a DELETE under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'DELETE', path, {})
