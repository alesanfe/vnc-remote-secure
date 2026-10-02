"""Share-link session handlers: inventory, detail, create, revoke."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _err,
    _ok,
    _read_typed_body,
    _uc_error_status,
    session_to_api,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _get_sessions(handler, query):
    try:
        from vnc_remote_secure.engine.application.sessions import (
            LIST_FILTERS,
            list_share_links,
        )
        from vnc_remote_secure.engine.domain.decision import UseCaseError

        status = (query.get("status") or ["active"])[0]
        try:
            sessions = list_share_links(status=status)
        except UseCaseError:
            _err(handler, f"status must be one of {sorted(LIST_FILTERS)}", 400)
            return
        _ok(handler, _sessions_page(sessions, query))
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /sessions")
        _err(handler, "Failed to list sessions", 500)


def _sessions_page(sessions, query: dict) -> dict:
    """Cursor pagination over the public token_id — stable under
    concurrent creates/revokes, opaque, and never leaks ordering
    by creation time or token value."""
    try:
        limit = int((query.get("limit") or ["200"])[0])
    except ValueError:
        limit = 200
    limit = max(1, min(limit, 500))
    cursor = (query.get("cursor") or [None])[0]
    items = sorted((session_to_api(s) for s in sessions), key=lambda s: s.get("token_id") or "")
    if cursor:
        items = [s for s in items if (s.get("token_id") or "") > cursor]
    has_more = len(items) > limit
    items = items[:limit]
    return {
        "sessions": items,
        "next_cursor": (items[-1]["token_id"] if has_more and items else None),
        "has_more": has_more,
    }


def _get_session_detail(handler, query):
    """GET /api/v1/sessions/{token_id} — one share-link record by its
    public fingerprint. Unknown and reaped ids both answer 404; the
    detail page refreshes against this rather than paging the whole
    inventory."""
    try:
        from vnc_remote_secure.engine.application.sessions import (
            get_share_link,
        )

        session = get_share_link(handler._api_params["token_id"])
        if session is None:
            _err(handler, "Session not found", 404)
            return
        from vnc_remote_secure.engine.application.sessions import (
            share_link_connections,
        )

        _ok(
            handler,
            {
                "session": session_to_api(session),
                # Live sockets carrying this grant right now — resource,
                # peer IP and connect time per connection.
                "connections": share_link_connections(handler._api_params["token_id"]),
            },
        )
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /sessions/{token_id}")
        _err(handler, "Failed to read session", 500)


def _post_session_create(handler, query):
    """POST /api/v1/sessions — share-link creation for the wizard.
    Auth+CSRF+capability already ran in _dispatch; the operator is
    stashed on ``handler._api_operator``."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import SessionCreateRequest

    body, error = _read_typed_body(handler, SessionCreateRequest)
    if error:
        _err(handler, *error)
        return
    fields = {
        "role": body.role,
        "permissions": (set(body.permissions) if body.permissions is not None else None),
        "ttl": body.ttl_seconds,
        "single_use": body.single_use,
        "view_only": body.view_only,
        "no_terminal": body.no_terminal,
        "allowed_ip": body.allowed_ip,
        "resource": body.resource,
        "max_uses": body.max_uses,
        "label": body.label,
    }

    # Delegation + creation are domain rules — the use case owns them.
    from vnc_remote_secure.engine.application.sessions import create_share_link
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        session, signed = create_share_link(
            operator.get("username", "admin"), set(operator.get("permissions") or []), **fields
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return

    from vnc_remote_secure.core.share_url import share_base_url

    base = share_base_url()
    url = f"{base}/share#t={signed}"
    emailed = False
    if body.email_to:
        # Link delivery is best-effort: a mail failure must not lose a
        # freshly minted grant — the operator still sees the URL to
        # copy. Audit records the attempt, not the token.
        try:
            from vnc_remote_secure.monitoring.alerts import (
                send_email_alert,
            )

            emailed = send_email_alert(
                "Enlace de acceso remoto",
                "Se te ha compartido un acceso remoto.\n\n"
                f"Abre este enlace para conectar:\n{url}\n\n"
                f"Caduca (epoch): {int(session.expires_at)}\n",
                to_addr=body.email_to,
            )
            from vnc_remote_secure.engine.infrastructure import (
                stores as _st,
            )

            _st.audit(
                "share_link_email",
                operator.get("username", "admin"),
                f"to={body.email_to} sent={emailed}",
            )
        except Exception:  # noqa: BLE001 - alerting must not break create
            emailed = False
    _ok(
        handler,
        {
            # Fragment-carried link: the token never reaches the server in
            # the URL, so it cannot leak via history, Referer, or logs.
            "url": url,
            "emailed": emailed,
            "token_id": session.to_dict()["token_id"],
            "expires_at": session.expires_at,
            "role": session.role,
            "permissions": sorted(session.permissions),
            "single_use": session.single_use,
            "view_only": session.view_only,
            "no_terminal": session.no_terminal,
            "max_uses": session.max_uses,
            "resource": session.resource,
            "allowed_ip": session.allowed_ip,
            "label": session.label,
        },
        status=201,
    )


def _post_session_revoke(handler, query):
    """POST /api/v1/sessions/revoke — revoke one share-link session."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import SessionRevokeRequest

    body, error = _read_typed_body(handler, SessionRevokeRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    token_id = body.token_id.strip()
    if not token_id:
        _err(handler, "token_id required", 400)
        return
    from vnc_remote_secure.engine.application.sessions import revoke_share_link

    revoked = revoke_share_link(operator.get("username", "unknown"), token_id)
    if revoked:
        # A revoked grant kills any live guest sessions — page the
        # configured channels so the operator sees who cut it and when.
        try:
            from vnc_remote_secure.monitoring.alerts import notify

            notify(
                "Share link revoked",
                f"token_id={token_id} " f'by={operator.get("username", "unknown")}',
                "warning",
            )
        except Exception:  # noqa: BLE001 - alerting must not break revoke
            pass
    # Uniform 200 whether the token existed or not — the caller is
    # already authorized; distinguishing 404 would only help enumerate
    # live session ids.
    _ok(handler, {"revoked": bool(revoked)})


def _patch_session_label(handler, query):
    """PATCH /api/v1/sessions/{token_id} — edit the inventory tag.

    Unknown/reaped ids answer 404 (same disclosure rule as the detail
    GET); the label itself is domain-validated by the use case."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import SessionUpdateRequest

    body, error = _read_typed_body(handler, SessionUpdateRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    # {'label': null} clears the tag; omitting the key entirely is a
    # malformed PATCH, not a silent clear.
    if "label" not in body.model_fields_set:
        _err(handler, "label required", 400)
        return
    from vnc_remote_secure.engine.application.sessions import (
        update_share_link_label,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        ok = update_share_link_label(
            operator.get("username", "unknown"), handler._api_params["token_id"], body.label
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    if not ok:
        _err(handler, "Session not found", 404)
        return
    _ok(handler, {"token_id": handler._api_params["token_id"], "label": body.label})


def _post_session_revoke_all(handler, query):
    """POST /api/v1/sessions/revoke-all — emergency kill-switch."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.sessions import revoke_all_share_links

    count = revoke_all_share_links(operator.get("username", "unknown"))
    if count:
        try:
            from vnc_remote_secure.monitoring.alerts import notify

            notify(
                "All share links revoked",
                f"count={count} " f'by={operator.get("username", "unknown")}',
                "critical",
            )
        except Exception:  # noqa: BLE001 - alerting must not break revoke
            pass
    _ok(handler, {"revoked": count})
