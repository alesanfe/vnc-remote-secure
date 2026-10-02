"""Session-scoped chat handlers."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _actor_name,
    _ephemeral_session,
    _err,
    _ok,
    _read_json_body,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _chat_session_id(handler, query, body: dict | None = None):
    """The chat channel id for this request: an operator names the
    session explicitly; a guest always gets their own grant's
    fingerprint (never a caller-chosen id — guests can't read other
    sessions' channels)."""
    if getattr(handler, "_api_operator", None) is not None:
        src = body if body is not None else query
        raw = src.get("session")
        return (raw[0] if isinstance(raw, list) else raw) or None
    session = _ephemeral_session(handler)
    if session is None:
        return None
    return session.to_dict().get("token_id")


def _get_chat(handler, query):
    """GET /chat?session=<id> — channel history (polled by the UI)."""
    from vnc_remote_secure.engine.application import chat

    token_id = _chat_session_id(handler, query)
    if not token_id:
        _err(handler, "session required", 400)
        return
    try:
        _ok(handler, {"session": token_id, "messages": chat.list_messages(token_id)})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /chat")
        _err(handler, "Chat read failed", 500)


def _post_chat(handler, query):
    """POST /chat — {session?, text}. Guests omit ``session`` (the
    channel is derived from their cookie)."""
    body, error = _read_json_body(handler, limit=8192)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import chat

    token_id = _chat_session_id(handler, query, body)
    if not token_id:
        _err(handler, "session required", 400)
        return
    try:
        msg = chat.post_message(token_id, _actor_name(handler), str(body.get("text") or ""))
        _ok(handler, {"message": msg}, status=201)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /chat post")
        _err(handler, "Chat post failed", 500)
