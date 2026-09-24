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

# Resources a share link may be bound to (validation surface; the
# domain rule that requires admin:* for admin-granting links lives in
# engine.application.sessions.ADMINISH_PERMS).
_RESOURCES = {'desktop', 'terminal', 'audio', 'gamepad'}

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
    'passkeys.register': (10, 60),
    'passkeys.manage': (30, 60),
    'system_users.manage': (30, 60),
    'maintenance': (10, 60),
    # Step-up re-authentication — a password-verification oracle must
    # be throttled as hard as login itself.
    'stepup': (10, 60),
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
        from vnc_remote_secure.engine.application.sessions import (
            LIST_FILTERS,
            list_share_links,
        )
        from vnc_remote_secure.engine.domain.decision import UseCaseError
        status = (query.get('status') or ['active'])[0]
        try:
            sessions = list_share_links(status=status)
        except UseCaseError:
            _err(handler,
                 f'status must be one of {sorted(LIST_FILTERS)}', 400)
            return
        # Cursor pagination over the public token_id — stable under
        # concurrent creates/revokes, opaque, and never leaks ordering
        # by creation time or token value.
        try:
            limit = int((query.get('limit') or ['200'])[0])
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 500))
        cursor = (query.get('cursor') or [None])[0]
        items = sorted(
            (session_to_api(s) for s in sessions),
            key=lambda s: s.get('token_id') or '')
        if cursor:
            items = [s for s in items
                     if (s.get('token_id') or '') > cursor]
        has_more = len(items) > limit
        items = items[:limit]
        _ok(handler, {
            'sessions': items,
            'next_cursor': (items[-1]['token_id']
                            if has_more and items else None),
            'has_more': has_more,
        })
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
        # Cursor pagination: ``cursor`` is the seq of the last entry of
        # the previous page — opaque to the client, stable under
        # appends, no deep offsets.
        cursor = (query.get('cursor') or [None])[0]
        try:
            before_seq = int(cursor) if cursor else None
        except (TypeError, ValueError):
            _err(handler, 'Invalid cursor', 400)
            return
        # Bounded, whitelisted filter params — raw query values are
        # length-capped so a huge ?user= can't burn CPU on matching.
        def _flt(name: str) -> str | None:
            v = (query.get(name) or [None])[0]
            if v is None:
                return None
            v = v.strip()[:128]
            return v or None
        entries = get_audit_entries(
            limit=limit + 1, event=_flt('event'), before_seq=before_seq,
            user=_flt('user'), result=_flt('result'))
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
        from vnc_remote_secure.engine.application.maintenance import maintenance_status
        _ok(handler, maintenance_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /maintenance')
        _err(handler, 'Maintenance state read failed', 500)


def _post_maintenance(handler, query):
    """POST /api/v1/maintenance — toggle maintenance mode
    (admin:* + step-up). Optional immediate/scheduled drain of
    existing share links."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    allowed = {'active', 'reason', 'drain', 'drain_timeout'}
    unknown = set(payload) - allowed
    if unknown:
        _err(handler, f'Unknown fields: {sorted(unknown)}', 400)
        return
    active = payload.get('active')
    if type(active) is not bool:  # noqa: E721
        _err(handler, 'active must be a boolean', 400)
        return
    from vnc_remote_secure.engine.application.maintenance import set_maintenance
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        result = set_maintenance(
            operator.get('username', 'unknown'), active,
            reason=str(payload.get('reason', '')),
            drain=bool(payload.get('drain', False)),
            drain_timeout=int(payload.get('drain_timeout') or 0))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, result)


def _get_system_users(handler, query):
    """GET /api/v1/system-users — non-reserved OS accounts."""
    try:
        from vnc_remote_secure.engine.application.system_users import list_system_users
        _ok(handler, {'users': list_system_users()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /system-users')
        _err(handler, 'System user list failed', 500)


def _post_system_user_create(handler, query):
    """POST /api/v1/system-users — runtime OS account (step-up)."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    unknown = set(payload) - {'username', 'password'}
    if unknown:
        _err(handler, f'Unknown fields: {sorted(unknown)}', 400)
        return
    username = payload.get('username')
    password = payload.get('password')
    if not isinstance(username, str) or not username.strip():
        _err(handler, 'username is required', 400)
        return
    if not isinstance(password, str) or not password:
        _err(handler, 'password is required', 400)
        return
    from vnc_remote_secure.engine.application.system_users import create_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        result = create_system_user(
            operator.get('username', 'unknown'), username, password)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, result, status=201)


def _delete_system_user(handler, query):
    """DELETE /api/v1/system-users/{username} — step-up gated."""
    operator = handler._api_operator
    username = handler._api_params['username']
    from vnc_remote_secure.engine.application.system_users import delete_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_system_user(operator.get('username', 'unknown'), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'deleted': True})


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


def _parse_permissions_field(payload: dict):
    """``permissions`` → ``(set|None, error)``."""
    from vnc_remote_secure.security.ephemeral_sessions import ALL_PERMISSIONS
    permissions = payload.get('permissions')
    if permissions is None:
        return None, None
    if (not isinstance(permissions, list)
            or not all(type(p) is str for p in permissions)
            or len(permissions) > len(ALL_PERMISSIONS)):
        return None, ('permissions must be a list of strings', 400)
    permissions = set(permissions)
    unknown = permissions - ALL_PERMISSIONS
    if unknown:
        return None, (f'Unknown permissions: {sorted(unknown)}', 400)
    if not permissions:
        return None, ('permissions must not be empty', 400)
    return permissions, None


def _bounded_int(payload: dict, key: str, default: int,
                 lo: int, hi: int):
    """``key`` → ``(int, error)`` — strict int (bool rejected)."""
    value = payload.get(key, default)
    if type(value) is not int:  # noqa: E721 - bool is an int; reject it
        return None, (f'{key} must be an integer', 400)
    if not lo <= value <= hi:
        return None, (f'{key} must be {lo}..{hi}', 400)
    return value, None


def _bool_flags(payload: dict, keys) -> tuple | None:
    for flag in keys:
        if type(payload.get(flag, False)) is not bool:  # noqa: E721
            return (f'{flag} must be a boolean', 400)
    return None


def _parse_allowed_ip(payload: dict):
    """``allowed_ip`` → ``(str|None, error)``; 'first-observed' binds
    on first use, IP/CIDR is validated here."""
    allowed_ip = payload.get('allowed_ip')
    if not allowed_ip:
        return None, None
    if not isinstance(allowed_ip, str):
        return None, ('allowed_ip must be a string', 400)
    allowed_ip = allowed_ip.strip()
    if len(allowed_ip) > 64 or not _valid_allowed_ip(allowed_ip):
        return None, ("allowed_ip is not a valid IP, CIDR, "
                      "or 'first-observed'", 400)
    return allowed_ip, None


def _parse_resource_field(payload: dict):
    """``resource`` → ``(str|None, error)``."""
    resource = payload.get('resource')
    if not resource:
        return None, None
    if not isinstance(resource, str) or resource not in _RESOURCES:
        return None, (
            f'resource must be one of {sorted(_RESOURCES)}', 400)
    return resource, None


def _parse_session_create(payload: dict):
    """Validate the POST /sessions body; returns ``(fields, error)``.

    Strict schema: unknown keys are rejected, not ignored — a
    misspelled flag must never silently produce a wider link. The
    returned ``fields`` dict is ready to be splatted into the use case.
    """
    unknown_keys = set(payload) - _SESSION_CREATE_KEYS
    if unknown_keys:
        return None, (f'Unknown fields: {sorted(unknown_keys)}', 400)

    from vnc_remote_secure.security.ephemeral_sessions import ROLES

    role = payload.get('role', 'viewer')
    if not isinstance(role, str) or role not in ROLES:
        return None, (f'Unknown role: {role}', 400)
    permissions, error = _parse_permissions_field(payload)
    if error:
        return None, error
    ttl, error = _bounded_int(payload, 'ttl_seconds', 1800, 60,
                              7 * 86400)
    if error:
        return None, error
    max_uses, error = _bounded_int(payload, 'max_uses', 0, 0, 1000)
    if error:
        return None, error
    flag_err = _bool_flags(
        payload, ('single_use', 'view_only', 'no_terminal'))
    if flag_err:
        return None, flag_err
    allowed_ip, error = _parse_allowed_ip(payload)
    if error:
        return None, error
    resource, error = _parse_resource_field(payload)
    if error:
        return None, error
    return {
        'role': role, 'permissions': permissions, 'ttl': ttl,
        'single_use': payload.get('single_use', False),
        'view_only': payload.get('view_only', False),
        'no_terminal': payload.get('no_terminal', False),
        'allowed_ip': allowed_ip, 'resource': resource,
        'max_uses': max_uses,
    }, None


def _post_session_create(handler, query):
    """POST /api/v1/sessions — share-link creation for the wizard.
    Auth+CSRF+capability already ran in _dispatch; the operator is
    stashed on ``handler._api_operator``."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    fields, error = _parse_session_create(payload)
    if error:
        _err(handler, *error)
        return

    # Delegation + creation are domain rules — the use case owns them.
    from vnc_remote_secure.engine.application.sessions import create_share_link
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        session, signed = create_share_link(
            operator.get('username', 'admin'),
            set(operator.get('permissions') or []), **fields)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
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
    from vnc_remote_secure.engine.application.sessions import revoke_share_link
    revoked = revoke_share_link(
        operator.get('username', 'unknown'), token_id)
    # Uniform 200 whether the token existed or not — the caller is
    # already authorized; distinguishing 404 would only help enumerate
    # live session ids.
    _ok(handler, {'revoked': bool(revoked)})


def _post_session_revoke_all(handler, query):
    """POST /api/v1/sessions/revoke-all — emergency kill-switch."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.sessions import revoke_all_share_links
    count = revoke_all_share_links(operator.get('username', 'unknown'))
    _ok(handler, {'revoked': count})


def _post_step_up(handler, query):
    """POST /api/v1/step-up — re-authenticate the operator's password
    for a recent-auth grant (step-up) without minting a new session.

    The grant is recorded in shared state; routes flagged
    ``step_up=True`` in ``_ROUTES`` check it via ``needs_step_up``.
    """
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    password = payload.get('password')
    if not isinstance(password, str) or not password:
        _err(handler, 'password required', 400)
        return
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
    audit_event('step_up_granted', user=username)
    _ok(handler, {'stepped_up': True, 'expires_in': 300})


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
        ERR_STEP_UP,
    )
    return {ERR_NOT_FOUND: 404, ERR_PERMISSION: 403,
            ERR_STEP_UP: 403,
            ERR_CONFLICT: 409, ERR_LAST_ADMIN: 409}.get(err.code, 400)


def _get_operator_detail(handler, query):
    username = handler._api_params['username']
    rec = _operator_record(username)
    if rec is None:
        _err(handler, 'Operator not found', 404)
        return
    from vnc_remote_secure.engine.application.operators import viable_admin_count
    from vnc_remote_secure.security.operator_users import get_permissions
    from vnc_remote_secure.security.webauthn import list_credentials
    data = operator_to_api({'username': username, **rec})
    data['permissions'] = sorted(get_permissions(username))
    data['passkey_count'] = len(list_credentials(username))
    # Deletion gating for the UI: the backend still enforces at apply
    # time — this is display metadata, not the authority.
    blocking = []
    if rec.get('role') == 'admin' \
            and viable_admin_count(excluding=username) == 0:
        blocking.append('last_viable_administrator')
    data['deletion_allowed'] = not blocking
    data['blocking_reasons'] = blocking
    _ok(handler, {'operator': data})


def _get_operator_passkeys(handler, query):
    """Public passkey view: opaque ref (sha256 prefix of the
    credential id), name, timestamps — never the credential id or
    public key."""
    username = handler._api_params['username']
    operator = getattr(handler, '_api_operator', None) or {}
    if _operator_record(username) is None:
        _err(handler, 'Operator not found', 404)
        return
    from vnc_remote_secure.engine.application.passkeys import _gate_manage, list_passkeys
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _gate_manage(operator.get('username', '?'),
                     set(operator.get('permissions') or []), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'passkeys': list_passkeys(username)})


def _post_passkey_register_begin(handler, query):
    """POST …/passkeys/register/begin — WebAuthn options (self, step-up)."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.passkeys import begin_registration
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        options = begin_registration(
            operator.get('username', '?'),
            handler._api_params['username'])
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'options': options})


def _post_passkey_register_complete(handler, query):
    """POST …/passkeys/register/complete — verify + persist."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=_MAX_BODY)
    if error:
        _err(handler, *error)
        return
    if not isinstance(payload.get('credential'), dict):
        _err(handler, 'credential object required', 400)
        return
    from vnc_remote_secure.engine.application.passkeys import complete_registration
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        complete_registration(
            operator.get('username', '?'),
            handler._api_params['username'],
            payload['credential'], str(payload.get('name', '')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'registered': True}, status=201)


def _patch_passkey(handler, query):
    """PATCH …/passkeys/{ref} — rename (owner or admin_users)."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    name = payload.get('name')
    if not isinstance(name, str):
        _err(handler, 'name must be a string', 400)
        return
    from vnc_remote_secure.engine.application.passkeys import rename_passkey
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        rename_passkey(
            operator.get('username', '?'),
            set(operator.get('permissions') or []),
            handler._api_params['username'],
            handler._api_params['credential_ref'], name)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'renamed': True})


def _delete_passkey(handler, query):
    """DELETE …/passkeys/{ref} — revoke (last-auth-method guarded)."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.passkeys import delete_passkey
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_passkey(
            operator.get('username', '?'),
            set(operator.get('permissions') or []),
            handler._api_params['username'],
            handler._api_params['credential_ref'])
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'deleted': True})


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


def _parse_operator_patch(payload: dict):
    """Body → use-case kwargs; ``(kw, error)``."""
    kw: dict = {}
    if 'role' in payload:
        if not isinstance(payload['role'], str):
            return None, ('role must be a string', 400)
        kw['role'] = payload['role']
    if 'disabled' in payload:
        if type(payload['disabled']) is not bool:  # noqa: E721
            return None, ('disabled must be a boolean', 400)
        kw['disabled'] = payload['disabled']
    if 'password' in payload:
        password = payload['password']
        if not isinstance(password, str) or not password:
            return None, ('password must be a non-empty string', 400)
        from vnc_remote_secure.core.validation import ValidationError, validate_password
        try:
            validate_password(password)
        except ValidationError as exc:
            return None, (str(exc), 400)
        kw['password'] = password
    return kw, None


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
    kw, error = _parse_operator_patch(payload)
    if error:
        _err(handler, *error)
        return
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

# ``step_up`` — a mutation additionally requires a *recent*
# authentication (POST /api/v1/step-up grants 5 minutes): mass
# revocation and operator lifecycle changes are gated on it.
_Route = namedtuple(
    '_Route', 'fn perm scope audit resp step_up', defaults=[False])

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
    ('POST', 'maintenance'): _Route(
        _post_maintenance, 'admin:*', 'maintenance',
        'maintenance_toggle', 'MaintenanceSetResponse', True),
    ('POST', 'sessions'): _Route(
        _post_session_create, 'admin_sessions', 'sessions.create',
        'portal_session_create', 'SessionCreatedResponse'),
    ('POST', 'sessions/revoke'): _Route(
        _post_session_revoke, 'admin_sessions', 'sessions.revoke',
        'portal_session_revoke', 'SessionRevokeResponse'),
    ('POST', 'sessions/revoke-all'): _Route(
        _post_session_revoke_all, 'admin_sessions', 'sessions.revoke-all',
        'portal_session_revoke_all', 'SessionRevokeResponse', True),
    ('POST', 'logout'): _Route(
        _post_logout, 'operator', 'default', 'portal_logout',
        'LogoutResponse'),
    ('POST', 'step-up'): _Route(
        _post_step_up, 'operator', 'stepup', 'step_up_granted',
        'StepUpResponse'),
    # Operator management — {username} is a path parameter resolved
    # by _dispatch into handler._api_params.
    ('GET', 'operators/{username}'): _Route(
        _get_operator_detail, 'admin_users', 'default', None,
        'OperatorResponse'),
    ('GET', 'operators/{username}/passkeys'): _Route(
        _get_operator_passkeys, 'operator', 'default', None,
        'PasskeyPageResponse'),
    ('POST', 'operators/{username}/passkeys/register/begin'): _Route(
        _post_passkey_register_begin, 'operator', 'passkeys.register',
        'passkey_register_begin', 'PasskeyOptionsResponse', True),
    ('POST', 'operators/{username}/passkeys/register/complete'): _Route(
        _post_passkey_register_complete, 'operator',
        'passkeys.register', 'passkey_registered',
        'PasskeyRegisteredResponse', True),
    ('PATCH', 'operators/{username}/passkeys/{credential_ref}'): _Route(
        _patch_passkey, 'operator', 'passkeys.manage',
        'passkey_renamed', 'PasskeyRenamedResponse'),
    ('DELETE', 'operators/{username}/passkeys/{credential_ref}'): _Route(
        _delete_passkey, 'operator', 'passkeys.manage',
        'passkey_revoked', 'DeleteResponse', True),
    ('POST', 'operators'): _Route(
        _post_operator_create, 'admin_users', 'operators.create',
        'operator_created', 'OperatorResponse', True),
    ('PATCH', 'operators/{username}'): _Route(
        _patch_operator, 'admin_users', 'operators.update',
        'operator_updated', 'OperatorResponse'),
    ('DELETE', 'operators/{username}'): _Route(
        _delete_operator, 'admin_users', 'operators.delete',
        'operator_deleted', 'DeleteResponse', True),
    ('POST', 'operators/{username}/sessions/revoke-all'): _Route(
        _post_operator_revoke_sessions, 'admin_users',
        'operators.sessions_revoke', 'operator_sessions_revoked',
        'SessionRevokeResponse', True),
    # OS-level runtime accounts (migrated from the Flask users UI).
    ('GET', 'system-users'): _Route(
        _get_system_users, 'admin_users', 'default', None,
        'SystemUserPageResponse'),
    ('POST', 'system-users'): _Route(
        _post_system_user_create, 'admin_users', 'system_users.manage',
        'user_create', 'SystemUserCreatedResponse', True),
    ('DELETE', 'system-users/{username}'): _Route(
        _delete_system_user, 'admin_users', 'system_users.manage',
        'user_delete', 'DeleteResponse', True),
}

# Operator capabilities the registry may reference — anything else is
# a configuration bug a contract test catches.
_KNOWN_PERMS = {
    'operator', 'admin_sessions', 'admin_audit', 'admin_config',
    'admin_users', 'admin_secrets',
    # System-wide gate — only the umbrella holder may touch it.
    'admin:*',
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


def _match_route(method: str, rel: str):
    """Resolve ``(method, path)`` to ``(spec, params)`` — literal
    routes first, then compiled ``{param}`` templates."""
    spec = _ROUTES.get((method, rel))
    if spec is not None:
        return spec, {}
    for rmethod, regex, rspec in _template_routes():
        if rmethod == method:
            m = regex.match(rel)
            if m:
                return rspec, m.groupdict()
    return None, {}


def _deny_step_up(handler, operator: dict, method: str,
                  rel: str) -> None:
    """403 + machine-readable code — the SPA opens the step-up
    dialog instead of treating it as a permission failure."""
    from vnc_remote_secure.security.audit import audit_event
    audit_event(
        'step_up_required',
        user=operator.get('username', '?'),
        detail=f'{method} {rel}')
    handler.send_json({
        'error': True,
        'message': 'Step-up authentication required',
        'code': 'STEP_UP_REQUIRED',
        'request_id': _request_id(),
    }, 403)


def _dispatch(handler, method: str, path: str, query: dict) -> bool:
    """Central dispatch: rate limit -> auth/capability -> handler.

    Returns True when the route was handled (response written), False
    when ``path`` matches no route.
    """
    rel = path[len(_API_PREFIX):]
    spec, params = _match_route(method, rel)
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
        # Destructive/mass operations require a recent
        # authentication, not just a valid session (POST step-up
        # grants 5 min).
        from vnc_remote_secure.security.step_up_auth import needs_step_up
        if spec.step_up and needs_step_up(
                operator.get('username', '')):
            _deny_step_up(handler, operator, method, rel)
            return True
    elif spec.perm is not None:
        cap = None if spec.perm == 'operator' else spec.perm
        operator = _operator(handler, cap)
        if operator is None:
            return True
        handler._api_operator = operator
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
