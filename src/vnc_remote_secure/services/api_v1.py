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
    # Operations parity — destructive/host-level actions get the
    # tightest budgets.
    'lifecycle': (6, 60),
    'backups.write': (10, 60),
    'secrets.rotate': (10, 60),
    'config.write': (10, 60),
    'upgrade': (6, 60),
    # Credential oracles — throttled as hard as the login limiter.
    'login': (10, 60),
    'passkeys.auth': (10, 60),
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

    Mirrors ``read_models.portal``: the forwarded host lands inside
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
    from vnc_remote_secure.core.portal import build_service_list
    services = build_service_list(_protocol(), _external_base(handler))
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
        from vnc_remote_secure.engine.infrastructure import stores
        store = stores.session_store()
        stores.session_refresh(store)
        sess = store.get(internal) if internal else None
    except Exception:  # noqa: BLE001 - fail closed
        sess = None
    if sess is None or getattr(sess, 'revoked', False):
        _ok(handler, {'ephemeral': True, 'active': False})
        return
    try:
        from vnc_remote_secure.engine.infrastructure import stores as _st
        maintenance = _st.maintenance_active()
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
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, read_models.health())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /health')
        _err(handler, 'Health status generation failed', 500)


def _get_posture(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, read_models.posture())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /security/posture')
        _err(handler, 'Posture calculation failed', 500)


def _get_doctor(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, read_models.doctor())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /doctor')
        _err(handler, 'Doctor run failed', 500)


def _get_audit(handler, query):
    try:
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
        from vnc_remote_secure.engine.application import read_models
        page = read_models.audit_page(
            limit, event=_flt('event'), before_seq=before_seq,
            user=_flt('user'), result=_flt('result'))
        _ok(handler, {
            'entries': [audit_event_to_api(e)
                        for e in page['entries']],
            'next_cursor': page['next_cursor'],
            'has_more': page['has_more'],
        })
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit')
        _err(handler, 'Audit read failed', 500)


def _get_audit_verify(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, read_models.audit_integrity())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /audit/verify')
        _err(handler, 'Audit verification failed', 500)


def _get_config(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, {'vars': [
            config_entry_to_api(e) for e in read_models.config_vars()]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /config')
        _err(handler, 'Config inspection failed', 500)


def _get_backups(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models
        items = []
        for path in read_models.backup_paths():
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
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, {'operators': [
            operator_to_api(u) for u in read_models.operators_index()]})
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

    from vnc_remote_secure.core.share_url import share_base_url
    base = share_base_url()
    _ok(handler, {
        # Fragment-carried link: the token never reaches the server in
        # the URL, so it cannot leak via history, Referer, or logs.
        'url': f'{base}/share#t={signed}',
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
    from vnc_remote_secure.engine.application import read_models
    data = read_models.operator_detail(username)
    if data is None:
        _err(handler, 'Operator not found', 404)
        return
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
    from vnc_remote_secure.engine.application.passkeys import gate_manage, list_passkeys
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        gate_manage(operator.get('username', '?'),
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


# ---------------------------------------------------------------------------
# System (OS) accounts
# ---------------------------------------------------------------------------
#   GET    /system-users
#   POST   /system-users            {username, password}
#   DELETE /system-users/{username}
_SYSTEM_USER_CREATE_KEYS = {'username', 'password'}


def _public_gate(handler) -> bool:
    """Origin + Fetch-Metadata checks for unauthenticated endpoints.

    Public routes can't run ``_operator_gate`` (no session exists
    yet) but a cross-site POST must still be rejected — rate limiting
    was already applied by ``_dispatch``.
    """
    from vnc_remote_secure.security.auth_gateway import (
        check_origin,
        get_allowed_origins,
    )
    origin = handler.headers.get('Origin', '')
    if origin and not check_origin(origin, get_allowed_origins()):
        _err(handler, 'Invalid origin', 403)
        return False
    if handler.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
        _err(handler, 'Cross-site request rejected', 403)
        return False
    return True


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
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    username = payload.get('username')
    password = payload.get('password')
    if not isinstance(username, str) or not isinstance(password, str) \
            or not username or not password:
        _err(handler, 'username and password are required', 400)
        return
    if len(username) > 128 or len(password) > 512:
        _err(handler, 'credentials too long', 400)
        return
    import base64
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
        totp = payload.get('totp')
        if not isinstance(totp, str) or not totp.strip():
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
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    username = payload.get('username')
    if not isinstance(username, str) or not username.strip():
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
    payload, error = _read_json_body(handler, limit=_MAX_BODY)
    if error:
        _err(handler, *error)
        return
    username = payload.get('username')
    credential = payload.get('credential')
    if not isinstance(username, str) or not isinstance(credential, dict):
        _err(handler, 'username and credential are required', 400)
        return
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


# ---------------------------------------------------------------------------
# Portal + share-link surface (the React portal page consumes these)
# ---------------------------------------------------------------------------

def _get_portal(handler, query):
    """GET /portal — read-model for the React portal page.

    ``perm='session'`` admits any authenticated portal identity:
    ``_api_operator`` carries the operator record, or ``None`` when
    the caller is an activated share-link session (a view recipient
    must not see the session inventory or the gamepad kill-switch).
    """
    import ssl as _ssl

    from vnc_remote_secure.engine.application import read_models
    trusted = env_flag('TRUSTED_PROXY', 'false')
    try:
        data = read_models.portal(
            is_operator=handler._api_operator is not None,
            host=handler.headers.get('Host', ''),
            forwarded_host=(handler.headers.get('X-Forwarded-Host', '')
                            if trusted else ''),
            forwarded_proto=(handler.headers.get('X-Forwarded-Proto', '')
                             if trusted else ''),
            is_tls=(getattr(handler, 'is_tls', None) is True
                    or isinstance(getattr(handler, 'connection', None),
                                  _ssl.SSLSocket)),
            trusted_proxy=trusted)
    except Exception as e:  # noqa: BLE001 - never take the portal down
        log_exception(e, 'api /portal')
        _err(handler, 'Portal data unavailable', 500)
        return
    if data.get('sessions'):
        data['sessions'] = [session_to_api(s)
                            for s in data['sessions']]
    _ok(handler, data)


def _post_session_preview(handler, query):
    """POST /session/preview — non-consuming grant summary.

    Public: the token IS the credential, so the preview reveals only
    what the link grants (role, expiry, coarse flags) — never creator
    or infrastructure detail. Rate-limited by ``session.preview``.
    """
    if not _public_gate(handler):
        return
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    token = payload.get('token')
    if not isinstance(token, str) or not token.strip():
        _err(handler, 'token required', 400)
        return
    from vnc_remote_secure.engine.application import read_models
    preview = read_models.session_grant_preview(token.strip())
    if preview is None:
        _err(handler,
             'Session link is invalid, expired, or already used', 403)
        return
    from vnc_remote_secure.security.audit import audit_event
    audit_event('session_preview',
                detail=f"role={preview.get('role', '?')}")
    _ok(handler, preview)


def _post_session_activate(handler, query):
    """POST /session/activate — exchange a share-link token.

    Public: the link itself is the credential; the token arrives in
    the request BODY so it never lands in a URL the server logs or a
    Referer could carry onward. On success the ``vnc_ephemeral``
    cookie is queued onto the JSON response.
    """
    if not _public_gate(handler):
        return
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    token = payload.get('token')
    if not isinstance(token, str) or not token.strip():
        _err(handler, 'token required', 400)
        return
    from vnc_remote_secure.engine.application import read_models
    from vnc_remote_secure.security.http_auth import client_ip_from
    internal = read_models.activate_share_link(
        token.strip(),
        client_ip=client_ip_from(handler.headers, handler.peer_ip()))
    if not internal:
        _err(handler,
             'Session link is invalid, expired, or already used', 403)
        return
    # Same cookie semantics as the old landing exchange — Secure only
    # over a real TLS hop (direct SSLSocket or the trusted-proxy
    # X-Forwarded-Proto); a direct client claiming https must not get
    # a Secure cookie the browser would never send back over HTTP.
    import ssl as _ssl
    trusted = env_flag('TRUSTED_PROXY', 'false')
    is_tls = ((trusted and
               handler.headers.get('X-Forwarded-Proto', '') == 'https')
              or getattr(handler, 'is_tls', None) is True
              or isinstance(getattr(handler, 'connection', None),
                            _ssl.SSLSocket))
    secure = ' Secure;' if is_tls else ''
    from vnc_remote_secure.core.config import resolve_samesite
    handler._queue_cookie(
        f'vnc_ephemeral={internal};{secure} HttpOnly; Path=/; '
        f'SameSite={resolve_samesite()}')
    _ok(handler, {'activated': True})


def _gamepad_control(handler, stop: bool):
    """Local kill-switch — flips the shared ``gamepad:stopped`` flag
    the gamepad service checks per-connection and per-message, so the
    operator at the machine can cut remote input injection even while
    a session holds it."""
    from vnc_remote_secure.engine.infrastructure import stores
    try:
        stores.gamepad_set_stopped(stop)
    except Exception as e:  # noqa: BLE001
        _err(handler, str(e), 500)
        return
    from vnc_remote_secure.security.audit import audit_event
    audit_event(
        'portal_gamepad_' + ('stop' if stop else 'resume'),
        user=(handler._api_operator or {}).get('username', 'unknown'))
    _ok(handler, {'gamepad_stopped': stop})


def _post_gamepad_stop(handler, query):
    _gamepad_control(handler, True)


def _post_gamepad_resume(handler, query):
    _gamepad_control(handler, False)


def _get_jobs(handler, query):
    """GET /api/v1/jobs — recent destructive-operation records."""
    try:
        limit = int((query.get('limit') or ['100'])[0])
    except ValueError:
        limit = 100
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, {'jobs': read_models.jobs(limit)})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /jobs')
        _err(handler, 'Job listing failed', 500)


def _get_operators_deleted(handler, query):
    """GET /api/v1/operators/deleted — tombstone restore candidates."""
    try:
        from vnc_remote_secure.engine.application import read_models
        _ok(handler, {'deleted': read_models.deleted_operators()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /operators/deleted')
        _err(handler, 'Deleted-operator listing failed', 500)


def _post_operator_restore(handler, query):
    """POST /api/v1/operators/{u}/restore — undo a deletion from its
    tombstone. The account returns disabled with a random password —
    an admin must set a password and re-enable it."""
    operator = handler._api_operator
    username = handler._api_params['username']
    from vnc_remote_secure.engine.application.operators import restore_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        rec = restore_operator(
            operator.get('username', '?'), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'operator': operator_to_api(
        {'username': username, **rec})})


def _get_system_users(handler, query):
    from vnc_remote_secure.engine.application.system_users import list_system_users
    _ok(handler, {'users': list_system_users()})


def _post_system_user_create(handler, query):
    """POST /api/v1/system-users — create a runtime OS account
    (admin_users + step-up)."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    unknown = set(payload) - _SYSTEM_USER_CREATE_KEYS
    if unknown:
        _err(handler, f'Unknown fields: {sorted(unknown)}', 400)
        return
    username = payload.get('username')
    password = payload.get('password')
    if not isinstance(username, str) or not username.strip():
        _err(handler, 'username required', 400)
        return
    if not isinstance(password, str) or not password:
        _err(handler, 'password required', 400)
        return
    from vnc_remote_secure.engine.application.system_users import create_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        create_system_user(operator.get('username', '?'),
                           username, password)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'username': username.strip()}, status=201)


def _delete_system_user(handler, query):
    """DELETE /api/v1/system-users/{username} — admin_users + step-up;
    the current process account and reserved names are protected."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.system_users import delete_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_system_user(operator.get('username', '?'),
                           handler._api_params['username'])
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'deleted': True})


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
# Operations parity endpoints — the same verbs the CLI exposes
# ---------------------------------------------------------------------------

def _get_version(handler, query):
    """GET /api/v1/version — installed package version."""
    try:
        from vnc_remote_secure.engine.application import ops
        _ok(handler, ops.version())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /version')
        _err(handler, 'Version read failed', 500)


def _get_lifecycle(handler, query):
    """GET /api/v1/lifecycle — PID/running map + port health
    (``vnc-remote status`` parity)."""
    try:
        from vnc_remote_secure.engine.application import ops
        _ok(handler, ops.lifecycle_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /lifecycle')
        _err(handler, 'Service status read failed', 500)


def _post_lifecycle(handler, query):
    """POST /api/v1/lifecycle — {action: start|stop|restart}.

    Spawns the detached deferred runner: the portal answers the
    request, then the child runs the action — so ``stop``/``restart``
    can kill the portal service itself without losing the response.
    """
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=1024)
    if error:
        _err(handler, *error)
        return
    if set(payload) - {'action'}:
        _err(handler, 'Allowed fields: action', 400)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        result = ops.lifecycle_action(
            operator.get('username', '?'), payload.get('action'))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, result, status=202)


def _post_backup_create(handler, query):
    """POST /api/v1/backups — create a backup archive."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.create_backup(
            operator.get('username', '?')), status=201)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_backup_verify(handler, query):
    """POST /api/v1/backups/verify — {file} CRC/decrypt check."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    if set(payload) - {'file'}:
        _err(handler, 'Allowed fields: file', 400)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.verify_backup(
            operator.get('username', '?'), payload.get('file')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_backup_restore(handler, query):
    """POST /api/v1/backups/restore — {file} overwrites live config."""
    operator = handler._api_operator
    payload, error = _read_json_body(handler, limit=4096)
    if error:
        _err(handler, *error)
        return
    if set(payload) - {'file'}:
        _err(handler, 'Allowed fields: file', 400)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.restore_backup(
            operator.get('username', '?'), payload.get('file')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _get_secrets(handler, query):
    """GET /api/v1/secrets — per-secret status, never values."""
    try:
        from vnc_remote_secure.engine.application import ops
        _ok(handler, ops.secrets_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /secrets')
        _err(handler, 'Secret status read failed', 500)


def _get_secret_redact(handler, query):
    """GET /api/v1/secrets/{name} — fingerprinted redaction."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.secret_redact(handler._api_params['name']))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_secret_rotate(handler, query):
    """POST /api/v1/secrets/{name}/rotate — hard cutover rotation."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.rotate_secret(
            operator.get('username', '?'),
            handler._api_params['name']))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_secrets_rotate_signing(handler, query):
    """POST /api/v1/secrets/rotate-signing — coexistence window."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.rotate_signing_key(operator.get('username', '?')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_secrets_check(handler, query):
    """POST /api/v1/secrets/check — {fix?} TLS + permission findings.
    An empty body means check-only."""
    operator = handler._api_operator
    try:
        length = int(handler.headers.get('Content-Length', 0) or 0)
    except (TypeError, ValueError):
        length = 0
    payload = {}
    if length:
        payload, error = _read_json_body(handler, limit=1024)
        if error:
            _err(handler, *error)
            return
    fix = bool(payload.get('fix'))
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.secrets_check(
            operator.get('username', '?'), fix=fix))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_recovery_codes(handler, query):
    """POST /api/v1/secrets/recovery-codes — the plaintext codes are
    returned ONCE in the response; only hashes persist."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.recovery_codes(operator.get('username', '?')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _get_config_effective(handler, query):
    """GET /api/v1/config/effective?profile= — full provenance table."""
    profile = (query.get('profile') or [None])[0]
    try:
        from vnc_remote_secure.engine.infrastructure import stores
        entries = stores.config_effective_profile(profile or None)
        _ok(handler, {'profile': profile, 'vars': [
            config_entry_to_api(e) for e in entries]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /config/effective')
        _err(handler, 'Config inspection failed', 500)


def _get_config_explain(handler, query):
    """GET /api/v1/config/explain/{name} — one variable's provenance."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        result = ops.config_explain(handler._api_params['name'])
        _ok(handler, {'entry': config_entry_to_api(result['entry'])})
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _get_config_validate(handler, query):
    """GET /api/v1/config/validate?profile= — contradiction findings."""
    profile = (query.get('profile') or [None])[0]
    try:
        from vnc_remote_secure.engine.application import ops
        _ok(handler, ops.config_validate(profile or None))
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /config/validate')
        _err(handler, 'Config validation failed', 500)


def _get_config_diff(handler, query):
    """GET /api/v1/config/diff?a=..&b=.. — profile diff."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.config_diff(
            (query.get('a') or [''])[0],
            (query.get('b') or [''])[0]))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_config_migrate(handler, query):
    """POST /api/v1/config/migrate — {dry_run?} legacy .env renames.
    An empty body defaults to a real (non-dry-run) apply."""
    operator = handler._api_operator
    try:
        length = int(handler.headers.get('Content-Length', 0) or 0)
    except (TypeError, ValueError):
        length = 0
    payload = {}
    if length:
        payload, error = _read_json_body(handler, limit=1024)
        if error:
            _err(handler, *error)
            return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.config_migrate(
            operator.get('username', '?'),
            dry_run=bool(payload.get('dry_run'))))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _get_upgrade(handler, query):
    """GET /api/v1/upgrade — installed vs available version."""
    try:
        from vnc_remote_secure.engine.application import ops
        _ok(handler, ops.upgrade_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /upgrade')
        _err(handler, 'Upgrade check failed', 500)


def _post_upgrade(handler, query):
    """POST /api/v1/upgrade — {source?} self-upgrade w/ rollback."""
    operator = handler._api_operator
    try:
        length = int(handler.headers.get('Content-Length', 0) or 0)
    except (TypeError, ValueError):
        length = 0
    payload = {}
    if length:
        payload, error = _read_json_body(handler, limit=4096)
        if error:
            _err(handler, *error)
            return
    if set(payload) - {'source'}:
        _err(handler, 'Allowed fields: source', 400)
        return
    source = payload.get('source')
    if source is not None and not isinstance(source, str):
        _err(handler, 'source must be a string', 400)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.upgrade_run(
            operator.get('username', '?'), source=source))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_upgrade_rollback(handler, query):
    """POST /api/v1/upgrade/rollback — restore pre-upgrade snapshot."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        _ok(handler, ops.upgrade_rollback(operator.get('username', '?')))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


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
    ('GET', 'portal'): _Route(
        _get_portal, 'session', 'default', None, 'PortalResponse'),
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
    # Public auth surface — the SPA login page consumes these before
    # any session exists. 'public' skips _operator_gate; handlers run
    # _public_gate (Origin + Sec-Fetch) instead.
    ('GET', 'auth/methods'): _Route(
        _get_auth_methods, 'public', 'default', None,
        'AuthMethodsResponse'),
    ('POST', 'auth/login'): _Route(
        _post_auth_login, 'public', 'login', 'operator_login',
        'LoginResponse'),
    ('POST', 'auth/passkey/begin'): _Route(
        _post_auth_passkey_begin, 'public', 'passkeys.auth',
        'passkey_auth_begin', 'PasskeyAuthOptionsResponse'),
    ('POST', 'auth/passkey/complete'): _Route(
        _post_auth_passkey_complete, 'public', 'passkeys.auth',
        'operator_login', 'LoginResponse'),
    # Share-link exchange — public: the token IS the credential and
    # travels in the request body, never in a URL.
    ('POST', 'session/preview'): _Route(
        _post_session_preview, 'public', 'session.preview',
        'session_preview', 'SessionPreviewResponse'),
    ('POST', 'session/activate'): _Route(
        _post_session_activate, 'public', 'session.activate',
        'ephemeral_session_activate', 'SessionActivateResponse'),
    # Local gamepad kill-switch (operator-only — the flag cuts remote
    # input injection even while a share session holds it).
    ('POST', 'gamepad/stop'): _Route(
        _post_gamepad_stop, 'admin_sessions', 'default',
        'portal_gamepad_stop', 'GamepadStateResponse'),
    ('POST', 'gamepad/resume'): _Route(
        _post_gamepad_resume, 'admin_sessions', 'default',
        'portal_gamepad_resume', 'GamepadStateResponse'),
    ('POST', 'maintenance'): _Route(
        _post_maintenance, 'admin:*', 'maintenance',
        'maintenance_changed', 'MaintenanceSetResponse', True),
    ('POST', 'sessions'): _Route(
        _post_session_create, 'admin_sessions', 'sessions.create',
        'ephemeral_session_create', 'SessionCreatedResponse'),
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
    # Destructive-op ledger + operator restore (tombstone recovery).
    ('GET', 'jobs'): _Route(
        _get_jobs, 'admin_audit', 'default', None,
        'JobPageResponse'),
    ('GET', 'operators/deleted'): _Route(
        _get_operators_deleted, 'admin_users', 'default', None,
        'DeletedOperatorsResponse'),
    ('POST', 'operators/{username}/restore'): _Route(
        _post_operator_restore, 'admin_users', 'operators.create',
        'operator_restored', 'OperatorResponse', True),
    # OS-level runtime accounts surfaced to the admin SPA.
    ('GET', 'system-users'): _Route(
        _get_system_users, 'admin_users', 'default', None,
        'SystemUserPageResponse'),
    ('POST', 'system-users'): _Route(
        _post_system_user_create, 'admin_users', 'system_users.manage',
        'user_create', 'SystemUserCreatedResponse', True),
    ('DELETE', 'system-users/{username}'): _Route(
        _delete_system_user, 'admin_users', 'system_users.manage',
        'user_delete', 'DeleteResponse', True),
    # --- Operations parity with the CLI ----------------------------------
    # Version/status.
    ('GET', 'version'): _Route(
        _get_version, 'session', 'default', None, 'VersionResponse'),
    ('GET', 'lifecycle'): _Route(
        _get_lifecycle, 'operator', 'default', None,
        'LifecycleStatusResponse'),
    ('POST', 'lifecycle'): _Route(
        _post_lifecycle, 'admin:*', 'lifecycle', 'lifecycle_action',
        'LifecycleActionResponse', True),
    # Backups — create/verify/restore over ``core.backup``; names are
    # resolved server-side (basename allowlist) so the wire value never
    # reaches the filesystem.
    ('POST', 'backups'): _Route(
        _post_backup_create, 'admin:*', 'backups.write',
        'backup_create', 'BackupCreatedResponse', True),
    ('POST', 'backups/verify'): _Route(
        _post_backup_verify, 'admin:*', 'default',
        'backup_verify', 'BackupVerifyResponse'),
    ('POST', 'backups/restore'): _Route(
        _post_backup_restore, 'admin:*', 'backups.write',
        'backup_restore', 'BackupRestoreResponse', True),
    # Secrets — status/redact are admin reads; rotations are step-up.
    ('GET', 'secrets'): _Route(
        _get_secrets, 'admin:*', 'default', None, 'SecretsResponse'),
    ('GET', 'secrets/{name}'): _Route(
        _get_secret_redact, 'admin:*', 'default', None,
        'SecretRedactResponse'),
    ('POST', 'secrets/{name}/rotate'): _Route(
        _post_secret_rotate, 'admin:*', 'secrets.rotate',
        'secret_rotate', 'SecretRotateResponse', True),
    ('POST', 'secrets/rotate-signing'): _Route(
        _post_secrets_rotate_signing, 'admin:*', 'secrets.rotate',
        'signing_key_rotate', 'SigningRotateResponse', True),
    ('POST', 'secrets/check'): _Route(
        _post_secrets_check, 'admin:*', 'default',
        'secrets_check', 'SecretsCheckResponse'),
    ('POST', 'secrets/recovery-codes'): _Route(
        _post_recovery_codes, 'admin:*', 'secrets.rotate',
        'recovery_codes_generate', 'RecoveryCodesResponse', True),
    # Config inspector — explain/validate/diff are reads; migrate
    # mutates .env so it gets step-up.
    ('GET', 'config/effective'): _Route(
        _get_config_effective, 'admin_config', 'default', None,
        'ConfigPageResponse'),
    ('GET', 'config/explain/{name}'): _Route(
        _get_config_explain, 'admin_config', 'default', None,
        'ConfigExplainResponse'),
    ('GET', 'config/validate'): _Route(
        _get_config_validate, 'admin_config', 'default', None,
        'ConfigValidateResponse'),
    ('GET', 'config/diff'): _Route(
        _get_config_diff, 'admin_config', 'default', None,
        'ConfigDiffResponse'),
    ('POST', 'config/migrate'): _Route(
        _post_config_migrate, 'admin_config', 'config.write',
        'config_migrate', 'ConfigMigrateResponse', True),
    # Self-upgrade — long-running pip work under a job-ledger entry.
    ('GET', 'upgrade'): _Route(
        _get_upgrade, 'operator', 'default', None, 'UpgradeResponse'),
    ('POST', 'upgrade'): _Route(
        _post_upgrade, 'admin:*', 'upgrade', 'upgrade_run',
        'UpgradeRunResponse', True),
    ('POST', 'upgrade/rollback'): _Route(
        _post_upgrade_rollback, 'admin:*', 'upgrade',
        'upgrade_rollback', 'UpgradeRollbackResponse', True),
}

# Operator capabilities the registry may reference — anything else is
# a configuration bug a contract test catches.
_KNOWN_PERMS = {
    'operator', 'admin_sessions', 'admin_audit', 'admin_config',
    'admin_users',
    # Unauthenticated surface — login ceremonies only.
    'public',
    # Any authenticated portal identity — operator or share session.
    'session',
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


def is_public_route(method: str, path: str) -> bool:
    """True when ``method path`` resolves to a ``perm='public'``
    route — the caller (landing) must let these past the portal
    auth gate, since login ceremonies predate any session."""
    rel = path[len(_API_PREFIX):] if path.startswith(_API_PREFIX) \
        else path
    spec, _ = _match_route(method, rel)
    return spec is not None and spec.perm == 'public'


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
    handler.send_json_error(
        'Step-up authentication required', 403, code='STEP_UP_REQUIRED')


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
    if spec.perm == 'public':
        # Unauthenticated surface (login ceremonies): no operator
        # gate — handlers run _public_gate for Origin/Sec-Fetch
        # checks; CSRF is meaningless before a session exists.
        handler._api_params = params
        spec.fn(handler, query)
        return True
    if spec.perm == 'session':
        # Any authenticated portal identity — an activated share-link
        # cookie or an operator session. GETs already ran
        # _portal_identity in do_GET; the explicit re-check keeps
        # direct dispatch paths (mutations, tests) from trusting the
        # caller to have run it.
        if handler._valid_ephemeral_cookie():
            handler._api_ephemeral = True
            handler._api_operator = None
        else:
            operator = (handler._operator_gate(None)
                        if method != 'GET'
                        else _operator(handler, None))
            if operator is None:
                return True
            handler._api_ephemeral = False
            handler._api_operator = operator
        handler._api_params = params
        spec.fn(handler, query)
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
