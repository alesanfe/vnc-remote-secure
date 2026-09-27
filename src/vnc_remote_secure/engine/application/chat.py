"""Session-scoped guest ↔ operator chat.

A share link creates a two-party channel for its lifetime: the guest
(ephemeral cookie) and any operator read/write the same message list.
Messages live in the shared-state backend so every service process
sees one channel; the TTL tracks the session's own expiry so chat
state dies with the grant that created it.

Design notes:

* the channel key is the session's *public* ``token_id`` — the raw
  internal token never needs to leave the store;
* messages are small ({author, at, text} dicts, text ≤ 500 chars,
  history capped) — this is a coordination channel, not storage;
* writes are append-then-rewrite under a best-effort lock key in the
  same backend. A lost update between two simultaneous posters is
  acceptable for chat (both messages still arrive on the next poll)
  and strictly simpler than a queue primitive the backend lacks;
* every message is audited so the immutable log keeps who-said-what
  even though the channel itself is TTL'd.
"""
from __future__ import annotations

import time

from vnc_remote_secure.engine.infrastructure import stores

_NS = 'session_chat'
_MAX_MESSAGES = 200
_MAX_TEXT = 500
# Messages outlive the session slightly so the final exchange is
# still readable while the session flips to expired in the UI.
_TTL_GRACE = 3600


def _session_for_key(token_id: str):
    """Resolve ``token_id`` to a live session record, or None."""
    store = stores.session_store()
    stores.session_refresh(store)
    for s in store.list_all():
        if s.get('token_id') == token_id:
            return s
    return None


def list_messages(token_id: str) -> list:
    """The channel's message history ([] when the session is gone)."""
    if _session_for_key(token_id) is None:
        return []
    from vnc_remote_secure.security.shared_state import get_backend
    raw = get_backend().get(_NS, token_id)
    return raw if isinstance(raw, list) else []


def post_message(token_id: str, author: str, text: str) -> dict:
    """Append one message; returns the stored record.

    Raises ``ValueError`` for an unknown/dead session or an empty
    message — both are client-correctable and map to 400.
    """
    session = _session_for_key(token_id)
    if session is None:
        raise ValueError('session not found')
    if session.get('revoked') or float(session.get('expires_at') or 0) \
            <= time.time():
        raise ValueError('session is no longer active')
    text = (text or '').strip()
    if not text:
        raise ValueError('empty message')
    text = text[:_MAX_TEXT]
    author = (author or '?')[:64]

    from vnc_remote_secure.security.shared_state import get_backend
    be = get_backend()
    messages = be.get(_NS, token_id)
    messages = messages if isinstance(messages, list) else []
    record = {'author': author, 'at': time.time(), 'text': text}
    messages.append(record)
    messages = messages[-_MAX_MESSAGES:]
    ttl = max(60, session['expires_at'] - time.time() + _TTL_GRACE)
    be.set_ttl(_NS, token_id, messages, ttl)

    stores.audit('session_chat_message', author,
                 f'token_id={token_id} len={len(text)}')
    return record
