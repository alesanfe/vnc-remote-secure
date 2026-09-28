"""Shared handler plumbing for ``backend/handlers`` — the envelope
writers, body readers, identity helpers and wire serializers every
handler module uses. Transport only: all policy lives in
``engine``/``security``.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import uuid

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.security.http_auth import cookie_value

logger = logging.getLogger(__name__)

_MAX_BODY = 16384


def _request_id() -> str:
    return uuid.uuid4().hex[:16]


def _ok(handler, data, status: int = 200) -> None:
    handler.send_json(
        {'data': data, 'error': None, 'request_id': _request_id()},
        status)


def _err(handler, message: str, status: int) -> None:
    handler.send_json_error(message, status)


def _uc_err(handler, exc) -> None:
    """Send a UseCaseError — STEP_UP_REQUIRED carries its code so the
    SPA opens the step-up dialog instead of a generic 403."""
    from vnc_remote_secure.engine.domain.decision import ERR_STEP_UP
    if exc.code == ERR_STEP_UP:
        handler.send_json_error(
            'Step-up authentication required', 403,
            code='STEP_UP_REQUIRED')
        return
    _err(handler, exc.detail or exc.code, _uc_error_status(exc))


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


def _auth_ctx(handler) -> dict:
    """Transport context for bound step-up grants — binds the grant
    consumption to the operator session that minted it."""
    operator = getattr(handler, '_api_operator', None) or {}
    sid = cookie_value(handler.headers.get('Cookie', ''), 'vnc_op')
    return {'transport': 'api',
            'username': operator.get('username', '?'),
            'sid': sid}


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


def _read_typed_body(handler, model, limit: int = _MAX_BODY):
    """Read + validate the body against a pydantic schema.

    Returns ``(model_instance, None)`` or ``(None, error_tuple)``.
    Field-level detail goes to the response only in the generic
    message — enough to correct a request, not to enumerate fields.
    """
    payload, error = _read_json_body(handler, limit=limit)
    if error:
        return None, error
    try:
        return model.model_validate(payload), None
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError
        try:
            from pydantic import ValidationError
            if isinstance(exc, ValidationError):
                errors = exc.errors()
                extra = [str(e.get('loc', ('?',))[0])
                         for e in errors
                         if e.get('type') == 'extra_forbidden']
                if extra:
                    return None, (
                        f'Unknown fields: {sorted(extra)}', 400)
                first = errors[0]
                loc = '.'.join(str(p) for p in first.get('loc', ()))
                msg = first.get('msg', 'invalid')
                detail = f'{loc}: {msg}' if loc else msg
                return None, (detail, 400)
        except Exception:  # noqa: BLE001
            pass
        return None, ('Invalid request body', 400)


def session_to_api(s: dict) -> dict:
    """Ephemeral-session dict -> public shape. Never emits the raw
    session token or any server-side secret."""
    keys = ('token_id', 'role', 'permissions', 'expires_at',
            'single_use', 'view_only', 'no_terminal', 'allowed_ip',
            'created_by', 'created_at', 'used', 'revoked', 'resource',
            'max_uses', 'use_count', 'last_used_at', 'last_used_ip',
            'last_connected_at', 'last_disconnected_at',
            'connection_count')
    return {k: s.get(k) for k in keys if k in s}


def operator_to_api(u: dict) -> dict:
    keys = ('username', 'role', 'disabled', 'created_at', 'permissions')
    return {k: u.get(k) for k in keys if k in u}


def backup_to_api(path: str, st) -> dict:
    return {
        'name': os.path.basename(path),
        'size': st.st_size,
        'modified': st.st_mtime,
        'encrypted': path.endswith(('.enc.tar.zst', '.enc.tar.gz')),
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


def _ephemeral_session(handler):
    """Resolve the request's ``vnc_ephemeral`` cookie to its store
    session object, or None. Used by 'session'-perm routes that must
    distinguish a guest's own grant from an operator's."""
    if not getattr(handler, '_api_ephemeral', False):
        return None
    internal = cookie_value(
        handler.headers.get('Cookie', ''), 'vnc_ephemeral')
    if not internal:
        return None
    try:
        from vnc_remote_secure.engine.infrastructure import stores
        store = stores.session_store()
        stores.session_refresh(store)
        return store.get(internal)
    except Exception:  # noqa: BLE001
        return None


def _actor_name(handler) -> str:
    """Audit/alert actor label: operator username or guest fingerprint."""
    operator = getattr(handler, '_api_operator', None)
    if operator is not None:
        return operator.get('username', '?')
    session = _ephemeral_session(handler)
    if session is not None:
        return f'guest:{session.to_dict().get("token_id", "?")}'
    return 'anonymous'


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
