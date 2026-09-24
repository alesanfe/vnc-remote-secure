"""WebSocket connection registry for immediate revocation.

Tracks active WebSocket connections by session ID so that when a
session is revoked, all its active connections can be closed
immediately — not just prevented from reconnecting.

Close callbacks are inherently process-local (Python callables), so
the registry cannot directly close connections in another process.
However, revocation is propagated via the shared-state backend: when
a session is revoked, its token is added to a shared ``revoked``
namespace. Other processes check this namespace before allowing new
WebSocket upgrades, ensuring revocation takes effect cluster-wide
even if the in-memory close callbacks cannot reach another process.

Usage:
    from vnc_remote_secure.security.websocket_registry import (
        register_connection,
        unregister_connection,
        revoke_session_connections,
    )

    # When a WebSocket connection is established:
    conn_id = register_connection(session_id, websocket.close)
    if conn_id is None:
        # Session revoked between validation and registration —
        # close the socket, do not keep serving it.
        websocket.close()

    # When the connection closes normally:
    unregister_connection(conn_id)

    # When the session is revoked:
    closed = revoke_session_connections(session_id)
    # closed = number of connections that were forcibly closed
"""
import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable

from vnc_remote_secure.core.constants import DEFAULT_SESSION_MAX_LIFETIME
from vnc_remote_secure.security.shared_state import get_backend

logger = logging.getLogger(__name__)


def _redact(session_id: str) -> str:
    """Return a short hash of a session ID for safe logging."""
    if not session_id:
        return '<empty>'
    return hashlib.sha256(session_id.encode()).hexdigest()[:12]


# Shared-state namespace for cross-process revocation propagation.
_NS_REVOKED = 'websocket_revoked_sessions'
_expiry_warned_at = 0.0
_revoke_check_warned_at = 0.0

# Type for a close callback. The callback should close the WebSocket
# connection. This abstraction allows the registry to work with
# different WebSocket implementations (Tornado, Flask-SocketIO, etc.).
CloseCallback = Callable[[], bool]


class _ConnectionEntry:
    """Internal: tracks a single WebSocket connection."""

    __slots__ = ('conn_id', 'session_id', 'close_callback', 'resource',
                 'created_at', 'loop', 'client_ip')

    def __init__(self, conn_id: str, session_id: str,
                 close_callback: CloseCallback,
                 resource: str | None = None,
                 created_at: float | None = None,
                 loop=None, client_ip: str = ''):
        self.conn_id = conn_id
        self.session_id = session_id
        self.close_callback = close_callback
        self.resource = resource
        self.client_ip = client_ip
        # The registering thread's asyncio loop (None for sync/threaded
        # handlers). Needed when close_callback() returns a coroutine —
        # scheduling it requires the loop it was created on.
        self.loop = loop
        self.created_at = created_at or time.time()


class WebSocketRegistry:
    """Thread-safe registry of active WebSocket connections.

    Maps session_id -> set of connection entries, allowing immediate
    closure of all connections when a session is revoked.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._connections: dict[str, _ConnectionEntry] = {}  # conn_id -> entry
        self._by_session: dict[str, set[str]] = {}  # session_id -> {conn_ids}
        self._next_id = 0

    def register(self, session_id: str, close_callback: CloseCallback,
                 resource: str | None = None,
                 client_ip: str = '') -> str | None:
        """Register a new WebSocket connection.

        Args:
            session_id: The session this connection belongs to.
            close_callback: Callable that closes the WebSocket.
            resource: Optional resource name (e.g. 'desktop', 'terminal').
            client_ip: Peer IP for the per-IP connection cap.

        Returns:
            A unique connection ID for later unregister, or ``None`` if
            the session was revoked between validation and registration
            (TOCTOU guard).
        """
        with self._lock:
            # TOCTOU guard: reject if the session was revoked between the
            # auth-gateway validation and this registration call.
            if is_revoked_shared(session_id):
                logger.debug(
                    'Refused WebSocket registration for revoked session %s',
                    _redact(session_id),
                )
                return None
            # Connection cap: an authenticated client that opens
            # thousands of sockets exhausts fds/threads — a bound is a
            # resource limit, not an auth decision.
            if len(self._connections) >= _max_connections():
                logger.warning(
                    'Refused WebSocket registration: connection cap '
                    '(%d) reached', _max_connections())
                return None
            # Per-IP cap: one source address must not own a large
            # fraction of the global budget on its own.
            if client_ip:
                per_ip = sum(
                    1 for e in self._connections.values()
                    if e.client_ip == client_ip)
                if per_ip >= _max_connections_per_ip():
                    logger.warning(
                        'Refused WebSocket registration: per-IP cap '
                        '(%d) reached', _max_connections_per_ip())
                    return None
            self._next_id += 1
            conn_id = f'ws_{self._next_id}'
            loop = None
            try:
                import asyncio
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None  # threaded handler (novnc) — sync callback
            entry = _ConnectionEntry(
                conn_id, session_id, close_callback, resource,
                loop=loop, client_ip=client_ip)
            self._connections[conn_id] = entry
            if session_id not in self._by_session:
                self._by_session[session_id] = set()
            self._by_session[session_id].add(conn_id)
            self._emit_active_gauges()
            logger.debug(
                'Registered WebSocket connection %s for session %s (resource=%s)',
                conn_id, _redact(session_id), resource,
            )
            return conn_id

    def _emit_active_gauges(self):
        """Emit per-resource active-connection gauges (best-effort).

        Labels are resource-scoped (desktop/terminal/audio/gamepad) —
        each resource is served by exactly one service process, so
        cross-process gauge writes never overwrite each other.
        """
        try:
            from vnc_remote_secure.monitoring.prometheus import set_gauge
            counts: dict = {}
            for e in self._connections.values():
                key = e.resource or 'unknown'
                counts[key] = counts.get(key, 0) + 1
            for res, n in counts.items():
                set_gauge('vnc_remote_ws_connections_active',
                          float(n), labels=f'resource={res}')
        except Exception:  # noqa: BLE001
            pass

    def unregister(self, conn_id: str):
        """Unregister a connection (called when it closes normally)."""
        with self._lock:
            entry = self._connections.pop(conn_id, None)
            if entry is None:
                return
            session_set = self._by_session.get(entry.session_id)
            if session_set is not None:
                session_set.discard(conn_id)
                if not session_set:
                    del self._by_session[entry.session_id]
            self._emit_active_gauges()
            logger.debug(
                'Unregistered WebSocket connection %s for session %s',
                conn_id, entry.session_id,
            )

    def revoke_session(self, session_id: str) -> int:
        """Force-close all WebSocket connections for a session.

        Also marks the session as revoked in the shared-state backend
        so that other processes reject new WebSocket upgrades for this
        session even if they do not have the connection in their
        local registry.

        Args:
            session_id: The session to revoke connections for.

        Returns:
            Number of connections that were closed.
        """
        # Propagate revocation to other processes via shared state.
        # The marker must outlive the session it kills: with an
        # operator-set SESSION_MAX_LIFETIME above the 24h floor, a
        # shorter marker would let the revoked token re-authenticate
        # after the marker expired.
        try:
            max_lifetime = int(os.environ.get(
                'SESSION_MAX_LIFETIME',
                str(DEFAULT_SESSION_MAX_LIFETIME)))
        except (ValueError, TypeError):
            max_lifetime = DEFAULT_SESSION_MAX_LIFETIME
        # The marker stores the revocation timestamp so the sweep can
        # measure mark->close latency. Re-marking (e.g. the sweeper's
        # own close path) preserves the original timestamp — only a
        # legacy True value or a missing marker gets a fresh one.
        existing = get_backend().get(_NS_REVOKED, session_id)
        if isinstance(existing, (int, float)) \
                and not isinstance(existing, bool):
            marked_at = existing
        else:
            marked_at = time.time()
        # Granularity depends on what the caller handed us. A v3
        # cookie resolves to a random sid — revoke ONLY that sid so a
        # same-second sibling session (identical username:created)
        # survives. A stable pair or legacy cookie gets the group
        # semantics its own revocation model already implies.
        from vnc_remote_secure.security.auth_policy import (
            drop_auth_context_for,
            session_id_for_cookie,
        )
        sid = session_id_for_cookie(session_id)
        if sid:
            get_backend().set_ttl(_NS_REVOKED, f'sid:{sid}',
                                  marked_at, max(86400, max_lifetime))
            drop_auth_context_for(session_id)  # sid branch: one ctx
        else:
            get_backend().set_ttl(
                _NS_REVOKED, session_id, marked_at,
                max(86400, max_lifetime))
            # Stable pair / legacy cookie: every session sharing it
            # dies, so every indexed ctx goes too.
            drop_auth_context_for(session_id)
        # Snapshot and detach under the lock, then invoke the close
        # callbacks AFTER releasing it — a callback that touches the
        # registry (e.g. calls unregister from the socket's close
        # handler) would deadlock on the non-reentrant lock.
        with self._lock:
            conn_ids = list(self._by_session.get(session_id, set()))
            entries = [self._connections.pop(cid, None) for cid in conn_ids]
            self._by_session.pop(session_id, None)
        closed = 0
        for conn_id, entry in zip(conn_ids, entries):
            if entry is None:
                continue
            if self._fire_close(conn_id, entry):
                closed += 1
        logger.info(
            'Revoked %d WebSocket connection(s) for session %s',
            closed, _redact(session_id),
        )
        return closed

    @staticmethod
    def _fire_close(conn_id: str, entry: '_ConnectionEntry') -> bool:
        """Invoke one close callback; returns True if the close ran.

        Handles callbacks that return a coroutine (websockets<=13's
        ``websocket.close()``): scheduling them on the registering
        loop is the only way they actually execute — calling and
        dropping a coroutine leaves the socket open while looking
        closed.
        """
        import asyncio
        import inspect
        try:
            result = entry.close_callback()
        except Exception as e:
            logger.warning(
                'Error closing WebSocket connection %s: %s',
                conn_id, e,
            )
            return False
        if not inspect.iscoroutine(result):
            return True
        loop = entry.loop
        if loop is not None and loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(result, loop)
                return True
            except RuntimeError as e:
                logger.warning(
                    'Could not schedule close for %s: %s', conn_id, e)
        else:
            logger.warning(
                'Close callback for %s is a coroutine but no running '
                'loop was captured — connection may stay open', conn_id)
        # Silence the "coroutine never awaited" warning on the
        # abandoned coroutine object.
        result.close()
        return False

    def get_active_count(self, session_id: str) -> int:
        """Return the number of active connections for a session."""
        with self._lock:
            return len(self._by_session.get(session_id, set()))

    def get_active_sessions(self) -> list[str]:
        """Return a list of session IDs with active connections."""
        with self._lock:
            return list(self._by_session.keys())

    def get_connection_info(self, session_id: str) -> list[dict]:
        """Return connection info for a session (for diagnostics)."""
        with self._lock:
            conn_ids = self._by_session.get(session_id, set())
            result = []
            for conn_id in conn_ids:
                entry = self._connections.get(conn_id)
                if entry:
                    result.append({
                        'conn_id': entry.conn_id,
                        'session_id': entry.session_id,
                        'resource': entry.resource,
                        'created_at': entry.created_at,
                    })
            return result


# Global singleton (process-wide).
_registry: WebSocketRegistry | None = None


def get_registry() -> WebSocketRegistry:
    """Return the process-wide WebSocket registry."""
    global _registry
    if _registry is None:
        _registry = WebSocketRegistry()
    return _registry


def reset_registry():
    """Reset the global registry (for testing only)."""
    global _registry
    _registry = WebSocketRegistry()


def register_connection(session_id: str, close_callback: CloseCallback,
                        resource: str | None = None,
                        client_ip: str = '') -> str | None:
    """Register a new WebSocket connection (convenience function)."""
    return get_registry().register(
        session_id, close_callback, resource, client_ip=client_ip)


def unregister_connection(conn_id: str):
    """Unregister a connection (convenience function)."""
    get_registry().unregister(conn_id)


def revoke_session_connections(session_id: str) -> int:
    """Force-close all WebSocket connections for a session."""
    return get_registry().revoke_session(session_id)


def is_revoked_shared(session_id: str) -> bool:
    """Check whether a session has been revoked in another process.

    This consults the shared-state backend so that revocations issued
    by a different process (e.g. the CLI) are visible to long-running
    service processes. Close callbacks remain process-local, but this
    check prevents new WebSocket upgrades for revoked sessions.

    Backend outage policy matches ``ephemeral_sessions
    ._is_revoked_shared``: ``SHARED_STATE_STRICT=true`` denies the
    session; otherwise the check degrades to not-revoked with a
    throttled warning + metric (availability choice — a lost-to-race
    revocation may lag while the backend is down).
    """
    try:
        return bool(get_backend().get(_NS_REVOKED, session_id))
    except Exception:  # noqa: BLE001 - see docstring for the policy
        global _revoke_check_warned_at
        now = time.time()
        if now - _revoke_check_warned_at > 60:
            _revoke_check_warned_at = now
            logger.warning(
                "Shared revocation check failed — treating sessions "
                "as %s", 'revoked' if _strict() else 'not revoked')
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_shared_state_errors_total',
                    'op=revocation_check')
        return _strict()


def _strict() -> bool:
    from vnc_remote_secure.security.shared_state import shared_state_strict
    return shared_state_strict()


def clear_revoked_shared(session_id: str):
    """Remove a session from the shared revocation set (for testing)."""
    get_backend().delete(_NS_REVOKED, session_id)


# --- Cross-process live-connection revocation -------------------------
#
# ``revoke_session_connections`` only fires close callbacks in ITS OWN
# process — a share link revoked via the CLI marks the shared
# ``revoked`` namespace, but a desktop/audio session already open in a
# service process would stream forever without a poller. The watchers
# below poll the shared namespace and run the local revoke path when
# the mark appears.

_watcher_tasks: set = set()


def _session_expired(session_id: str) -> bool:
    """Return True when the ephemeral session exists but is expired.

    Revocation is not the only way a session dies: a session that
    crosses ``expires_at`` mid-connection must have its live sockets
    closed too — otherwise a link valid for 30 min stays connected
    forever once opened. Best-effort: unknown token types (operator
    sessions) are not looked up here and never match.
    """
    try:

        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        sess = get_session_store().get(session_id)
        return sess is not None and time.time() > sess.expires_at
    except Exception:  # noqa: BLE001 - expiry check must not kill watcher
        # Degraded-enforcement window: while the store is unreadable an
        # expired session's live sockets stay open. Log once per
        # minute so the window is visible, not silent. Under
        # SHARED_STATE_STRICT the session is treated as dead instead.
        global _expiry_warned_at
        now = time.time()
        if now - _expiry_warned_at > 60:
            _expiry_warned_at = now
            logger.warning(
                "Session expiry check unavailable — live WebSockets "
                "for expired sessions are not being swept")
        return _strict()


def _max_connections() -> int:
    """Return the per-process WebSocket connection cap."""
    try:
        return max(1, int(os.environ.get('WS_MAX_CONNECTIONS', '256')))
    except (TypeError, ValueError):
        return 256


def _max_connections_per_ip() -> int:
    """Return the per-source-IP WebSocket connection cap."""
    try:
        return max(1, int(
            os.environ.get('WS_MAX_CONNECTIONS_PER_IP', '32')))
    except (TypeError, ValueError):
        return 32


def _operator_session_dead(session_id: str) -> str | None:
    """Return a close reason for a dead operator session cookie.

    A ``vnc_session`` cookie registered at upgrade time can die
    mid-stream two ways that MUST close its live sockets:

    - absolute ``expires`` crossed (``SESSION_MAX_LIFETIME``) →
      ``'expired'``
    - ``created`` predates the operator-session epoch (credential
      rotation bumps it via ``bump_operator_epoch``) → ``'revoked'``

    The HTTP sliding idle timeout is deliberately NOT enforced here:
    ``last_seen`` only advances on HTTP requests, so enforcing it
    would kill an actively-used desktop that simply hasn't polled an
    HTTP endpoint. The absolute cap still bounds total stream life.
    """
    if not session_id.startswith('session:'):
        return None
    try:
        from vnc_remote_secure.security.token_signing import TOKEN_TYPE_SESSION, verify_token
        payload = verify_token(TOKEN_TYPE_SESSION, session_id)
        if payload is None:
            # A cookie that verified at upgrade and no longer does
            # (key fully retired past the coexistence window, or a
            # corrupted value) is dead — close it.
            return 'expired'
        parts = payload.split(':')
        if len(parts) == 4:
            _u, created_s, _last_seen_s, expires_s = parts
        elif len(parts) == 3:
            _u, created_s, expires_s = parts
        else:
            return 'expired'
        if time.time() > int(expires_s):
            return 'expired'
        from vnc_remote_secure.security.sessions import operator_session_epoch
        if int(created_s) < operator_session_epoch():
            return 'revoked'
        return None
    except Exception:  # noqa: BLE001 - watcher must not die
        # Under strict policy a failed liveness check denies — an
        # unverifiable privileged session is worse than a dropped one.
        return 'revoked' if _strict() else None


def _sweep_revoked_session(session_id: str) -> bool:
    """Close the session's connections on revocation OR expiry."""
    reason = None
    marked_at = None
    if is_revoked_shared(session_id):
        reason = 'revoked'
        try:
            raw = get_backend().get(_NS_REVOKED, session_id)
            if isinstance(raw, (int, float)) \
                    and not isinstance(raw, bool):
                marked_at = float(raw)
        except Exception:  # noqa: BLE001
            pass
    elif _session_expired(session_id):
        reason = 'expired'
    else:
        reason = _operator_session_dead(session_id)
    if reason is None:
        return False
    closed = get_registry().revoke_session(session_id)
    try:
        from vnc_remote_secure.monitoring.prometheus import inc_counter, set_gauge
        inc_counter('vnc_remote_ws_connections_closed_total',
                    f'reason={reason}',
                    value=closed if isinstance(closed, int) else 1)
        if marked_at is not None:
            # mark->close propagation latency, clamped for clock skew.
            set_gauge('vnc_remote_revocation_latency_seconds',
                      max(0.0, time.time() - marked_at),
                      labels='channel=websocket')
    except Exception:  # noqa: BLE001 - metrics must not break cleanup
        pass
    return True


async def watch_shared_revocation_async(session_id: str,
                                        interval: float = 5.0) -> None:
    """Poll the shared revocation set; closes local connections on hit.

    Exits when the session has no local connections left (normal
    disconnect), so no per-connection cleanup is needed beyond keeping
    a task reference until completion.
    """
    import asyncio
    while True:
        await asyncio.sleep(interval)
        if _sweep_revoked_session(session_id):
            return
        if get_registry().get_active_count(session_id) == 0:
            return


def start_revocation_watcher(session_id: str,
                             interval: float = 5.0):
    """Spawn the async watcher on the current loop.

    Call right after a successful ``register_connection`` from an
    asyncio handler (audio/gamepad/terminal). The task is kept in a
    module set so it is not garbage-collected mid-run; it removes
    itself when the watcher exits.
    """
    import asyncio
    task = asyncio.ensure_future(
        watch_shared_revocation_async(session_id, interval))
    _watcher_tasks.add(task)
    task.add_done_callback(_watcher_tasks.discard)
    return task


def start_revocation_watcher_thread(session_id: str,
                                    interval: float = 5.0
                                    ) -> threading.Thread:
    """Spawn the watcher on a daemon thread (for non-asyncio handlers).

    Used by the noVNC relay, whose connections live in
    ``http.server`` worker threads rather than an event loop.
    """
    def _run():
        while True:
            if _sweep_revoked_session(session_id):
                return
            if get_registry().get_active_count(session_id) == 0:
                return
            time.sleep(interval)

    t = threading.Thread(
        target=_run, daemon=True,
        name=f'ws-revoke-{_redact(session_id)}')
    t.start()
    return t
