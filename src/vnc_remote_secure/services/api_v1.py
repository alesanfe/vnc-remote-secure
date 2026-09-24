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


def _csrf_token(username: str) -> str:
    """CSRF token bound to the operator username and the deployment
    signing secret — a cross-site page cannot read or forge it."""
    from vnc_remote_secure.security.authentication import _get_secret
    return hmac.new(_get_secret(), f'csrf:{username}'.encode(),
                    hashlib.sha256).hexdigest()


def _check_csrf(handler, operator) -> bool:
    """Require ``X-CSRF-Token`` matching the operator's token.

    Basic auth rides on every same-origin request automatically, so
    Origin/Sec-Fetch-Site (checked in _operator_gate) plus this token
    give two independent CSRF layers — neither alone is guaranteed.
    """
    token = handler.headers.get('X-CSRF-Token', '')
    expected = _csrf_token(str(operator.get('username', '')))
    if not token or not hmac.compare_digest(token, expected):
        _err(handler, 'CSRF token missing or invalid', 403)
        return False
    return True


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

def _get_me(handler):
    operator = getattr(handler, '_portal_operator', None)
    _ok(handler, {
        'authenticated': True,
        'operator': ({
            'username': operator.get('username'),
            'role': operator.get('role'),
            'permissions': sorted(operator.get('permissions') or []),
        } if operator else None),
        'ephemeral': operator is None,
        # Double-submit CSRF token for SPA mutations — bound to the
        # operator username, required as X-CSRF-Token on POSTs.
        'csrf_token': (_csrf_token(str(operator.get('username', '')))
                       if operator else None),
    })


def _get_status(handler):
    _ok(handler, handler._status_payload())


def _get_services(handler):
    from vnc_remote_secure.services.landing import _build_service_list
    services = _build_service_list(_protocol(), _external_base(handler))
    for svc in services:
        # Booleans/ints/urls only — the raw dict is already the same
        # data the portal page renders for any authenticated user.
        svc.pop('color', None)
    _ok(handler, {'services': services})


def _get_sessions(handler):
    if _operator(handler, 'admin_sessions') is None:
        return
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        store = get_session_store()
        store._load_if_changed()
        _ok(handler, {'sessions': store.list_active()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /sessions')
        _err(handler, 'Failed to list sessions', 500)


def _get_health(handler):
    if _operator(handler) is None:
        return
    try:
        from vnc_remote_secure.monitoring.health import get_all_health
        _ok(handler, get_all_health())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /health')
        _err(handler, 'Health status generation failed', 500)


def _get_posture(handler):
    if _operator(handler) is None:
        return
    try:
        from vnc_remote_secure.security.posture import calculate_posture
        _ok(handler, calculate_posture())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /security/posture')
        _err(handler, 'Posture calculation failed', 500)


def _get_doctor(handler):
    if _operator(handler) is None:
        return
    try:
        from vnc_remote_secure.core.doctor import run_doctor
        _ok(handler, run_doctor(as_json=True))
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /doctor')
        _err(handler, 'Doctor run failed', 500)


def _audit_permitted(handler):
    return _operator(handler, 'admin_audit') is not None


def _get_audit(handler, query):
    if not _audit_permitted(handler):
        return
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
            'entries': entries,
            'next_cursor': next_cursor,
            'has_more': has_more,
        })
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit')
        _err(handler, 'Audit read failed', 500)


def _get_audit_verify(handler):
    if not _audit_permitted(handler):
        return
    try:
        from vnc_remote_secure.security.audit import verify_chain
        intact, message = verify_chain()
        _ok(handler, {'intact': intact, 'message': message})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit/verify')
        _err(handler, 'Audit verification failed', 500)


def _get_config(handler):
    if _operator(handler, 'admin_config') is None:
        return
    try:
        from vnc_remote_secure.core.config_inspector import compute_effective_config
        _ok(handler, {'vars': compute_effective_config()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /config')
        _err(handler, 'Config inspection failed', 500)


def _get_backups(handler):
    if _operator(handler) is None:
        return
    try:
        from vnc_remote_secure.core.backup import list_backups
        items = []
        for path in list_backups():
            import os
            try:
                st = os.stat(path)
                items.append({
                    'name': os.path.basename(path),
                    'size': st.st_size,
                    'modified': st.st_mtime,
                    'encrypted': path.endswith('.enc.tar.gz'),
                })
            except OSError:
                continue
        _ok(handler, {'backups': items})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /backups')
        _err(handler, 'Backup listing failed', 500)


def _get_operators(handler):
    if _operator(handler, 'admin_users') is None:
        return
    try:
        from vnc_remote_secure.security.operator_users import get_permissions, list_users
        users = []
        for u in list_users():
            u['permissions'] = sorted(
                get_permissions(u['username']))
            users.append(u)
        _ok(handler, {'operators': users})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /operators')
        _err(handler, 'Operator listing failed', 500)


def _get_maintenance(handler):
    if _operator(handler) is None:
        return
    try:
        from vnc_remote_secure.security.maintenance import maintenance_active, maintenance_info
        _ok(handler, {
            'active': maintenance_active(),
            'info': maintenance_info() or {},
        })
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /maintenance')
        _err(handler, 'Maintenance state read failed', 500)


# Route -> rate-limit scope. Dispatch applies it centrally so no
# handler can forget it.
_GET_SCOPES = {
    'doctor': 'doctor', 'audit': 'audit', 'audit/verify': 'audit.verify',
}
_POST_SCOPES = {
    'sessions': 'sessions.create', 'sessions/revoke': 'sessions.revoke',
    'sessions/revoke-all': 'sessions.revoke-all',
}


def handle_get(handler, path: str, query: dict) -> bool:
    """Dispatch a GET under /api/v1/. Returns True when handled."""
    routes = {
        'me': _get_me,
        'status': _get_status,
        'services': _get_services,
        'sessions': _get_sessions,
        'health': _get_health,
        'security/posture': _get_posture,
        'doctor': _get_doctor,
        'audit': lambda h: _get_audit(h, query),
        'audit/verify': _get_audit_verify,
        'config': _get_config,
        'backups': _get_backups,
        'operators': _get_operators,
        'maintenance': _get_maintenance,
    }
    rel = path[len(_API_PREFIX):]
    fn = routes.get(rel)
    if fn is None:
        return False
    if not _rate_limit(handler, _GET_SCOPES.get(rel, 'default')):
        return True
    fn(handler)
    return True


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


def _post_session_create(handler):
    """POST /api/v1/sessions — share-link creation for the wizard."""
    if not _rate_limit(handler, 'sessions.create'):
        return
    operator = handler._operator_gate('admin_sessions')
    if operator is None:
        return
    if not _check_csrf(handler, operator):
        return
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


def _post_session_revoke(handler):
    """POST /api/v1/sessions/revoke — revoke one share-link session."""
    if not _rate_limit(handler, 'sessions.revoke'):
        return
    operator = handler._operator_gate('admin_sessions')
    if operator is None:
        return
    if not _check_csrf(handler, operator):
        return
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
    _ok(handler, {'revoked': bool(revoked)},
        status=200 if revoked else 404)


def _post_session_revoke_all(handler):
    """POST /api/v1/sessions/revoke-all — emergency kill-switch."""
    if not _rate_limit(handler, 'sessions.revoke-all'):
        return
    operator = handler._operator_gate('admin_sessions')
    if operator is None:
        return
    if not _check_csrf(handler, operator):
        return
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


def handle_post(handler, path: str) -> bool:
    """Dispatch a POST under /api/v1/. Returns True when handled."""
    routes = {
        'sessions': _post_session_create,
        'sessions/revoke': _post_session_revoke,
        'sessions/revoke-all': _post_session_revoke_all,
    }
    rel = path[len(_API_PREFIX):]
    fn = routes.get(rel)
    if fn is None:
        return False
    if not _rate_limit(handler, _POST_SCOPES.get(rel, 'default')):
        return True
    fn(handler)
    return True
