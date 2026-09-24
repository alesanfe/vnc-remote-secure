"""Central session-revocation coordinator.

Before this module, revocation was scattered: the WebSocket registry
marked and closed, auth_policy dropped contexts, logout orchestrated
by hand, and nothing recorded WHICH granularity fired. Two
granularities now exist — a v3 session revokes by its random sid
(precise, one session dies), a legacy v1/v2 identity revokes the
shared ``username:created`` pair (every same-second session dies) —
so every path must be explicit about scope.

This service owns: resolve target -> mark revocation -> drop
auth-context + index entries -> close WebSocket connections ->
audit with a typed revocation_scope. The registry remains the
connection closer; it is a surface, not the coordinator.

All operations are idempotent: re-revoking is a no-op that still
returns a coherent RevocationResult.
"""
import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_NS_REVOKED = 'websocket_revoked_sessions'


@dataclass(frozen=True)
class RevocationResult:
    """Structured outcome of a revocation — the logical mark is
    fail-closed and reported separately from cleanup, so a partial
    failure is visible without pretending the revoke failed."""
    target_kind: str          # 'sid' | 'legacy_pair'
    logically_revoked: bool   # shared marker landed — the ONLY
                            # thing that makes a revoke effective
    sessions_marked: int
    contexts_dropped: int
    connections_closed: int
    already_revoked: int = 0  # idempotency: second call reports this
    errors: tuple = ()


def _mark(key: str, marked_at: float | None = None) -> bool:
    """Write a revocation marker in shared state with a TTL that
    outlives the session it kills. Returns True when this call
    created the mark, False when it was already revoked."""
    from vnc_remote_secure.security.shared_state import get_backend
    try:
        max_lifetime = int(os.environ.get(
            'SESSION_MAX_LIFETIME', '86400'))
    except (TypeError, ValueError):
        max_lifetime = 86400
    existing = get_backend().get(_NS_REVOKED, key)
    if isinstance(existing, (int, float)) \
            and not isinstance(existing, bool):
        marked_at = existing  # preserve original mark timestamp
        get_backend().set_ttl(_NS_REVOKED, key, marked_at,
                              max(86400, max_lifetime))
        return False  # was already revoked
    if marked_at is None:
        marked_at = time.time()
    get_backend().set_ttl(_NS_REVOKED, key, marked_at,
                          max(86400, max_lifetime))
    return True


def _audit(event: str, **fields) -> None:
    try:
        from vnc_remote_secure.security.audit import audit_event
        audit_event(event, **fields)
    except Exception:  # noqa: BLE001 - audit must not break revoke
        pass


def _session_ref(sid: str) -> str:
    """Short pseudonymized session reference for audit — never the
    raw sid or cookie."""
    import hashlib
    return hashlib.sha256(sid.encode()).hexdigest()[:12]


def revoke_sid(sid: str, reason: str = 'revoked',
               actor: str | None = None) -> RevocationResult:
    """Revoke exactly one v3 session by its random sid."""
    from vnc_remote_secure.security.websocket_registry import revoke_session_connections
    errors = []
    # Mark FIRST — the logical revocation is fail-closed; everything
    # after (ctx, idx, conns) is cleanup that may fail partially.
    already = 0
    try:
        if not _mark(f'sid:{sid}'):
            already = 1  # idempotent: second revoke reports it
        marked_ok = True
    except Exception as exc:  # noqa: BLE001
        marked_ok = False
        errors.append(f'mark: {exc}')
    dropped = 0
    try:
        import hashlib as _h

        from vnc_remote_secure.security.shared_state import get_backend
        sid_hash = _h.sha256(sid.encode()).hexdigest()
        be = get_backend()
        be.delete('web_auth_context', sid_hash)
        dropped = 1
        # The idx entry needs the stable pair, which a bare sid
        # doesn't carry — sweep the orphan idx entries pointing at
        # this sid hash.
        for k in be.list_keys('web_auth_context'):
            if k.startswith('idx:') and k.endswith(':' + sid_hash):
                be.delete('web_auth_context', k)
    except Exception as exc:  # noqa: BLE001
        errors.append(f'ctx: {exc}')
    closed = 0
    try:
        # v3 conns register under the sid — precise close.
        closed = revoke_session_connections(sid)
    except Exception as exc:  # noqa: BLE001
        errors.append(f'ws: {exc}')
    _audit('session_revoked', revocation_scope='individual',
           session_ref=_session_ref(sid), reason=reason, actor=actor)
    return RevocationResult('sid', marked_ok, 1 - already, dropped,
                            closed, already_revoked=already,
                            errors=tuple(errors))


def revoke_stable_pair(stable_id: str, reason: str = 'revoked',
                       actor: str | None = None) -> RevocationResult:
    """Revoke a legacy ``username:created`` group — every session
    sharing the pair dies (the only granularity v1/v2 support).

    The pair marker covers legacy cookies; each indexed sid is also
    individually marked, ctx-dropped and conn-closed so v3 sessions
    sharing the pair are cleaned up precisely."""
    from vnc_remote_secure.security.websocket_registry import revoke_session_connections
    errors = []
    # Group mark first — a session created mid-sweep shares the pair
    # and dies on check_authenticated even if the sweep missed it.
    marked_ok = True
    try:
        _mark(stable_id)
    except Exception as exc:  # noqa: BLE001
        marked_ok = False
        errors.append(f'mark: {exc}')
    dropped = 0
    closed = 0
    marked = 1
    try:
        from vnc_remote_secure.security.auth_policy import _session_key
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        prefix = f'idx:{_session_key(stable_id)}:'
        for idx_key in be.list_keys('web_auth_context',
                                    prefix=prefix):
            sid = be.get('web_auth_context', idx_key)
            be.delete('web_auth_context', idx_key)
            be.delete('web_auth_context',
                      idx_key[len(prefix):])  # ctx key = sha256(sid)
            dropped += 1
            # Validate the stored sid before acting on it — a
            # corrupt value must not mark or close anything.
            import re as _re
            if isinstance(sid, str) and _re.fullmatch(
                    r'[A-Za-z0-9_-]{16,64}', sid):
                try:
                    _mark(f'sid:{sid}')
                    marked += 1
                    closed += revoke_session_connections(sid)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f'sid mark/close failed: '
                                  f'{type(exc).__name__}')
    except Exception as exc:  # noqa: BLE001
        errors.append(f'ctx: {exc}')
    try:
        # Legacy conns registered under the stable pair itself.
        closed += revoke_session_connections(stable_id)
    except Exception as exc:  # noqa: BLE001
        errors.append(f'ws: {exc}')
    _audit('session_revoked', revocation_scope='legacy_group',
           session_ref=_session_ref(stable_id), reason=reason,
           actor=actor, sessions_marked=marked)
    return RevocationResult('legacy_pair', marked_ok, marked,
                            dropped, closed, errors=tuple(errors))


def revoke_cookie(cookie_value: str, reason: str = 'revoked',
                  actor: str | None = None) -> RevocationResult:
    """Revoke whatever a verified cookie represents: v3 -> precise
    sid revocation; v1/v2 -> the legacy stable-pair group."""
    from vnc_remote_secure.security.sessions import verify_session_cookie
    parsed = verify_session_cookie(cookie_value)
    if parsed is None:
        _audit('session_revoke_failed', reason='invalid_cookie')
        return RevocationResult('sid', False, 0, 0, 0,
                                errors=('invalid_cookie',))
    if parsed.get('sid'):
        return revoke_sid(parsed['sid'], reason=reason, actor=actor)
    return revoke_stable_pair(
        f"{parsed['username']}:{parsed['created']}",
        reason=reason, actor=actor)
