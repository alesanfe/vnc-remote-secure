"""Portal-facing handlers: identity, status, services, portal data, share-link preview/activate."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _err,
    _external_base,
    _ok,
    _protocol,
    _public_gate,
    _read_typed_body,
    session_to_api,
)
from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import cookie_value

logger = logging.getLogger(__name__)


def _get_me(handler, query):
    operator = getattr(handler, "_portal_operator", None)
    _ok(
        handler,
        {
            "authenticated": True,
            "operator": (
                {
                    "username": operator.get("username"),
                    "role": operator.get("role"),
                    "permissions": sorted(operator.get("permissions") or []),
                }
                if operator
                else None
            ),
            "ephemeral": operator is None,
            # Session-bound CSRF token (HMAC of the vnc_csrf nonce) — the
            # SPA presents it as X-CSRF-Token on every mutation.
            "csrf_token": (handler._csrf_token() if operator else None),
        },
    )


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
        svc.pop("color", None)
    _ok(handler, {"services": services})


def _get_portal(handler, query):
    """GET /portal — read-model for the React portal page.

    ``perm='session'`` admits any authenticated portal identity:
    ``_api_operator`` carries the operator record, or ``None`` when
    the caller is an activated share-link session (a view recipient
    must not see the session inventory or the gamepad kill-switch).
    """
    import ssl as _ssl

    from vnc_remote_secure.engine.application import read_models

    trusted = env_flag("TRUSTED_PROXY", "false")
    try:
        data = read_models.portal(
            is_operator=handler._api_operator is not None,
            host=handler.headers.get("Host", ""),
            forwarded_host=(handler.headers.get("X-Forwarded-Host", "") if trusted else ""),
            forwarded_proto=(handler.headers.get("X-Forwarded-Proto", "") if trusted else ""),
            is_tls=(
                getattr(handler, "is_tls", None) is True
                or isinstance(getattr(handler, "connection", None), _ssl.SSLSocket)
            ),
            trusted_proxy=trusted,
        )
    except Exception as e:  # noqa: BLE001 - never take the portal down
        log_exception(e, "api /portal")
        _err(handler, "Portal data unavailable", 500)
        return
    if data.get("sessions"):
        data["sessions"] = [session_to_api(s) for s in data["sessions"]]
    _ok(handler, data)


def _get_session_context(handler, query):
    """GET /api/v1/session-context — the share-link session's own
    minimal context (what an ephemeral client may know about itself).

    Separates ephemeral reads from the operator /status contract:
    this payload can never grow admin telemetry by accident.
    """
    operator = getattr(handler, "_portal_operator", None)
    if operator is not None:
        _ok(handler, {"ephemeral": False})
        return
    internal = cookie_value(handler.headers.get("Cookie", ""), "vnc_ephemeral")
    try:
        from vnc_remote_secure.engine.infrastructure import stores

        store = stores.session_store()
        stores.session_refresh(store)
        sess = store.get(internal) if internal else None
    except Exception:  # noqa: BLE001 - fail closed
        sess = None
    if sess is None or getattr(sess, "revoked", False):
        _ok(handler, {"ephemeral": True, "active": False})
        return
    try:
        from vnc_remote_secure.engine.infrastructure import stores as _st

        maintenance = _st.maintenance_active()
    except Exception:  # noqa: BLE001
        maintenance = False
    _ok(
        handler,
        {
            "ephemeral": True,
            "active": True,
            "role": getattr(sess, "role", ""),
            "permissions": sorted(getattr(sess, "permissions", []) or []),
            "expires_at": getattr(sess, "expires_at", None),
            "view_only": bool(getattr(sess, "view_only", False)),
            "single_use": bool(getattr(sess, "single_use", False)),
            "no_terminal": bool(getattr(sess, "no_terminal", False)),
            "resource": getattr(sess, "resource", None),
            # Public fingerprint — the chat channel and detail links use
            # it; the internal token never leaves the cookie.
            "token_id": sess.to_dict().get("token_id"),
            "maintenance": maintenance,
        },
    )


def _post_session_preview(handler, query):
    """POST /session/preview — non-consuming grant summary.

    Public: the token IS the credential, so the preview reveals only
    what the link grants (role, expiry, coarse flags) — never creator
    or infrastructure detail. Rate-limited by ``session.preview``.
    """
    if not _public_gate(handler):
        return
    from vnc_remote_secure.backend.schemas import TokenBody

    body, error = _read_typed_body(handler, TokenBody, limit=4096)
    if error:
        _err(handler, *error)
        return
    token = body.token.strip()
    if not token:
        _err(handler, "token required", 400)
        return
    from vnc_remote_secure.engine.application import read_models

    preview = read_models.session_grant_preview(token)
    if preview is None:
        _err(handler, "Session link is invalid, expired, or already used", 403)
        return
    from vnc_remote_secure.security.audit import audit_event

    audit_event("session_preview", detail=f"role={preview.get('role', '?')}")
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
    from vnc_remote_secure.backend.schemas import TokenBody

    body, error = _read_typed_body(handler, TokenBody, limit=4096)
    if error:
        _err(handler, *error)
        return
    token = body.token.strip()
    if not token:
        _err(handler, "token required", 400)
        return
    from vnc_remote_secure.engine.application import read_models
    from vnc_remote_secure.security.http_auth import client_ip_from

    internal = read_models.activate_share_link(
        token, client_ip=client_ip_from(handler.headers, handler.peer_ip())
    )
    if not internal:
        _err(handler, "Session link is invalid, expired, or already used", 403)
        return
    # Same cookie semantics as the old landing exchange — Secure only
    # over a real TLS hop (direct SSLSocket or the trusted-proxy
    # X-Forwarded-Proto); a direct client claiming https must not get
    # a Secure cookie the browser would never send back over HTTP.
    import ssl as _ssl

    trusted = env_flag("TRUSTED_PROXY", "false")
    is_tls = (
        (trusted and handler.headers.get("X-Forwarded-Proto", "") == "https")
        or getattr(handler, "is_tls", None) is True
        or isinstance(getattr(handler, "connection", None), _ssl.SSLSocket)
    )
    secure = " Secure;" if is_tls else ""
    from vnc_remote_secure.core.config import resolve_samesite

    handler._queue_cookie(
        f"vnc_ephemeral={internal};{secure} HttpOnly; Path=/; " f"SameSite={resolve_samesite()}"
    )
    # An activation means an external party just consumed a grant —
    # worth paging the configured alert channels about.
    try:
        from vnc_remote_secure.monitoring.alerts import notify

        notify(
            "Share link activated",
            f"ip={client_ip_from(handler.headers, handler.peer_ip())}",
            "warning",
        )
    except Exception:  # noqa: BLE001 - alerting must not break auth
        pass
    _ok(handler, {"activated": True})
