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
        return "<empty>"
    return hashlib.sha256(session_id.encode()).hexdigest()[:12]


# Shared-state namespace for cross-process revocation propagation.
_NS_REVOKED = "websocket_revoked_sessions"
_expiry_warned_at = 0.0
_revoke_check_warned_at = 0.0

# Type for a close callback. The callback should close the WebSocket
# connection. This abstraction allows the registry to work with
# different WebSocket implementations (websockets, Starlette, etc.).
CloseCallback = Callable[[], bool]


class _ConnectionEntry:
    """Internal: tracks a single WebSocket connection."""

    __slots__ = (
        "conn_id",
        "session_id",
        "close_callback",
        "resource",
        "created_at",
        "loop",
        "client_ip",
    )

    def __init__(
        self,
        conn_id: str,
        session_id: str,
        close_callback: CloseCallback,
        resource: str | None = None,
        created_at: float | None = None,
        loop=None,
        client_ip: str = "",
    ):
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
        self._by_ip: dict[str, set[str]] = {}  # client_ip -> {conn_ids}
        # Incremental per-resource counts — _emit_active_gauges used to
        # scan every connection on each register/unregister (O(N) under
        # the global lock); these counters make it O(#resources).
        self._resource_counts: dict[str, int] = {}
        self._next_id = 0

    def register(
        self,
        session_id: str,
        close_callback: CloseCallback,
        resource: str | None = None,
        client_ip: str = "",
    ) -> str | None:
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
            # auth-gateway validation and this registration call. Check
            # both the raw key (legacy pair / ephemeral token) and the
            # sid-namespaced mark written by revoke_sid.
            if is_revoked_shared(session_id) or is_revoked_shared(f"sid:{session_id}"):
                logger.debug(
                    "Refused WebSocket registration for revoked session %s",
                    _redact(session_id),
                )
                return None
            # Connection cap: an authenticated client that opens
            # thousands of sockets exhausts fds/threads — a bound is a
            # resource limit, not an auth decision.
            if len(self._connections) >= _max_connections():
                logger.warning(
                    "Refused WebSocket registration: connection cap " "(%d) reached",
                    _max_connections(),
                )
                return None
            # Per-IP cap: O(1) via the index — one source address must
            # not own a large fraction of the global budget.
            if client_ip:
                per_ip = len(self._by_ip.get(client_ip, ()))
                if per_ip >= _max_connections_per_ip():
                    logger.warning(
                        "Refused WebSocket registration: per-IP cap " "(%d) reached",
                        _max_connections_per_ip(),
                    )
                    return None
            self._next_id += 1
            conn_id = f"ws_{self._next_id}"
            loop = None
            try:
                import asyncio

                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None  # threaded handler (novnc) — sync callback
            entry = _ConnectionEntry(
                conn_id, session_id, close_callback, resource, loop=loop, client_ip=client_ip
            )
            self._connections[conn_id] = entry
            if session_id not in self._by_session:
                self._by_session[session_id] = set()
            self._by_session[session_id].add(conn_id)
            if client_ip:
                self._by_ip.setdefault(client_ip, set()).add(conn_id)
            res_key = resource or "unknown"
            self._resource_counts[res_key] = self._resource_counts.get(res_key, 0) + 1
            # Post-register double-check: closes the
            # check->register->revoke race. A revoke landing BETWEEN
            # the first check and registration would leave a live
            # conn the sweep already missed — remove it and fire its
            # close callback after releasing the lock.
            close_now = None
            if is_revoked_shared(session_id) or is_revoked_shared(f"sid:{session_id}"):
                entry = self._detach_locked(conn_id)
                close_now = entry
            self._emit_active_gauges()
            logger.debug(
                "Registered WebSocket connection %s for session %s (resource=%s)",
                conn_id,
                _redact(session_id),
                resource,
            )
        if close_now is not None:
            self._fire_close(conn_id, close_now)
            return None
        # Forensics: the grant went live. session_id is the internal
        # ephemeral token for share links; operator cookie sessions
        # ('session:...') simply do not match a store record.
        _note_session_connect(session_id)
        return conn_id

    def _detach_locked(self, conn_id: str):
        """Remove ``conn_id`` from every index. Caller holds ``_lock``.

        Returns the detached entry (or None). Keeping all index
        maintenance in ONE place is what makes register/unregister/
        revoke_session unable to drift out of sync.
        """
        entry = self._connections.pop(conn_id, None)
        if entry is None:
            return None
        session_set = self._by_session.get(entry.session_id)
        if session_set is not None:
            session_set.discard(conn_id)
            if not session_set:
                del self._by_session[entry.session_id]
        if entry.client_ip:
            ip_set = self._by_ip.get(entry.client_ip)
            if ip_set is not None:
                ip_set.discard(conn_id)
                if not ip_set:
                    del self._by_ip[entry.client_ip]
        res_key = entry.resource or "unknown"
        # Keep the key at 0 — the gauge must be able to report the
        # resource going quiet, not freeze at its last nonzero value.
        self._resource_counts[res_key] = max(0, self._resource_counts.get(res_key, 0) - 1)
        return entry

    def _emit_active_gauges(self):
        """Emit per-resource active-connection gauges (best-effort).

        Reads the incremental counters — O(#resources), never a scan
        of ``_connections``. ``set_gauge`` dirty-checks, so unchanged
        values cost a dict compare, not a metrics write.
        """
        try:
            from vnc_remote_secure.monitoring.prometheus import set_gauge

            for res, n in self._resource_counts.items():
                set_gauge("vnc_remote_ws_connections_active", float(n), labels=f"resource={res}")
        except Exception:  # noqa: BLE001
            pass

    def unregister(self, conn_id: str):
        """Unregister a connection (called when it closes normally)."""
        drained = False
        with self._lock:
            entry = self._detach_locked(conn_id)
            if entry is None:
                return
            drained = entry.session_id not in self._by_session
            self._emit_active_gauges()
            logger.debug(
                "Unregistered WebSocket connection %s for session %s",
                conn_id,
                entry.session_id,
            )
        if drained:
            _note_session_disconnect(entry.session_id)

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
            max_lifetime = int(
                os.environ.get("SESSION_MAX_LIFETIME", str(DEFAULT_SESSION_MAX_LIFETIME))
            )
        except (ValueError, TypeError):
            max_lifetime = DEFAULT_SESSION_MAX_LIFETIME
        # The marker stores the revocation timestamp so the sweep can
        # measure mark->close latency. Re-marking (e.g. the sweeper's
        # own close path) preserves the original timestamp — only a
        # legacy True value or a missing marker gets a fresh one.
        existing = get_backend().get(_NS_REVOKED, session_id)
        if isinstance(existing, (int, float)) and not isinstance(existing, bool):
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
            get_backend().set_ttl(_NS_REVOKED, f"sid:{sid}", marked_at, max(86400, max_lifetime))
            drop_auth_context_for(session_id)  # sid branch: one ctx
        else:
            get_backend().set_ttl(_NS_REVOKED, session_id, marked_at, max(86400, max_lifetime))
            # Stable pair / legacy cookie: every session sharing it
            # dies, so every indexed ctx goes too.
            drop_auth_context_for(session_id)
        # A revocation must be visible on the very next check — drop
        # every cached "not revoked" answer (the cache is small and
        # revocations are rare).
        _revoked_neg_cache.clear()
        # Snapshot and detach under the lock, then invoke the close
        # callbacks AFTER releasing it — a callback that touches the
        # registry (e.g. calls unregister from the socket's close
        # handler) would deadlock on the non-reentrant lock.
        # _detach_locked keeps _by_ip/_resource_counts consistent.
        with self._lock:
            conn_ids = list(self._by_session.get(session_id, set()))
            entries = [self._detach_locked(cid) for cid in conn_ids]
            if conn_ids:
                self._emit_active_gauges()
        closed = 0
        for conn_id, entry in zip(conn_ids, entries):
            if entry is None:
                continue
            if self._fire_close(conn_id, entry):
                closed += 1
        if conn_ids:
            _note_session_disconnect(session_id)
        logger.info(
            "Revoked %d WebSocket connection(s) for session %s",
            closed,
            _redact(session_id),
        )
        return closed

    @staticmethod
    def _fire_close(conn_id: str, entry: "_ConnectionEntry") -> bool:
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
                "Error closing WebSocket connection %s: %s",
                conn_id,
                e,
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
                logger.warning("Could not schedule close for %s: %s", conn_id, e)
        else:
            logger.warning(
                "Close callback for %s is a coroutine but no running "
                "loop was captured — connection may stay open",
                conn_id,
            )
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
                    result.append(
                        {
                            "conn_id": entry.conn_id,
                            "session_id": entry.session_id,
                            "resource": entry.resource,
                            "created_at": entry.created_at,
                            "client_ip": entry.client_ip,
                        }
                    )
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


def _note_session_connect(session_id: str):
    """Forensic stamp: an ephemeral grant opened a live socket.

    Best-effort — a forensics write must never break the connection
    path, and non-ephemeral session ids (operator cookies) silently
    match nothing in the session store.
    """
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store

        get_session_store().note_connection(session_id, connected=True)
    except Exception:  # noqa: BLE001
        pass


def _note_session_disconnect(session_id: str):
    """Forensic stamp: the last live socket for a session closed."""
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store

        get_session_store().note_connection(session_id, connected=False)
    except Exception:  # noqa: BLE001
        pass


def register_connection(
    session_id: str, close_callback: CloseCallback, resource: str | None = None, client_ip: str = ""
) -> str | None:
    """Register a new WebSocket connection (convenience function)."""
    conn_id = get_registry().register(session_id, close_callback, resource, client_ip=client_ip)
    if conn_id is not None:
        # Wake the global sweeper so a fresh session is covered
        # immediately rather than after an idle-backoff sleep.
        _sweeper_wakeup.set()
        _ensure_sweeper()
    return conn_id


def unregister_connection(conn_id: str):
    """Unregister a connection (convenience function)."""
    get_registry().unregister(conn_id)


def revoke_session_connections(session_id: str) -> int:
    """Force-close all WebSocket connections for a session."""
    return get_registry().revoke_session(session_id)


# Negative-result cache for is_revoked_shared: a "not revoked" answer
# is reused for a short TTL so registration's double-check does not
# pay two SELECTs per upgrade. Positive results are NEVER cached —
# a revocation must be visible on the next check. The residual window
# is bounded by the TTL (default 1s), during which the sweeper still
# closes any connection admitted in the gap.
_revoked_neg_cache: dict = {}


def _revocation_cache_ttl() -> float:
    try:
        return max(0.0, float(os.environ.get("WS_REVOKED_CACHE_TTL", "1.0")))
    except (TypeError, ValueError):
        return 1.0


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
    ttl = _revocation_cache_ttl()
    if ttl > 0:
        exp = _revoked_neg_cache.get(session_id)
        if exp is not None and time.monotonic() < exp:
            return False
    try:
        revoked = bool(get_backend().get(_NS_REVOKED, session_id))
    except Exception:  # noqa: BLE001 - see docstring for the policy
        global _revoke_check_warned_at
        now = time.time()
        if now - _revoke_check_warned_at > 60:
            _revoke_check_warned_at = now
            logger.warning(
                "Shared revocation check failed — treating sessions " "as %s",
                "revoked" if _strict() else "not revoked",
            )
        from vnc_remote_secure.monitoring.prometheus import inc_counter

        inc_counter("vnc_remote_shared_state_errors_total", "op=revocation_check")
        return _strict()
    if not revoked and ttl > 0:
        # Bound the cache: a flood of distinct session ids must not
        # grow it without limit — a full clear is cheap and rare.
        if len(_revoked_neg_cache) > 4096:
            _revoked_neg_cache.clear()
        _revoked_neg_cache[session_id] = time.monotonic() + ttl
    return revoked


def _strict() -> bool:
    from vnc_remote_secure.security.shared_state import shared_state_strict

    return shared_state_strict()


def clear_revoked_shared(session_id: str):
    """Remove a session from the shared revocation set (for testing)."""
    get_backend().delete(_NS_REVOKED, session_id)
    _revoked_neg_cache.clear()


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
                "for expired sessions are not being swept"
            )
        return _strict()


def _max_connections() -> int:
    """Return the per-process WebSocket connection cap."""
    try:
        return max(1, int(os.environ.get("WS_MAX_CONNECTIONS", "256")))
    except (TypeError, ValueError):
        return 256


def _max_connections_per_ip() -> int:
    """Return the per-source-IP WebSocket connection cap."""
    try:
        return max(1, int(os.environ.get("WS_MAX_CONNECTIONS_PER_IP", "32")))
    except (TypeError, ValueError):
        return 32


def _operator_session_dead(session_id: str, epoch=None) -> str | None:
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

    ``epoch`` lets the sweeper pass a per-cycle value instead of one
    shared-state read per session.
    """
    if not session_id.startswith("session:"):
        return None
    try:
        from vnc_remote_secure.security.token_signing import TOKEN_TYPE_SESSION, verify_token

        payload = verify_token(TOKEN_TYPE_SESSION, session_id)
        if payload is None:
            # A cookie that verified at upgrade and no longer does
            # (key fully retired past the coexistence window, or a
            # corrupted value) is dead — close it.
            return "expired"
        parts = payload.split(":")
        # Field layouts match verify_session_cookie(): v3 carries a
        # per-login sid (5 fields), v2 dropped it (4), legacy v1 has no
        # last_seen (3). Only created/expires matter for liveness.
        if len(parts) == 5:
            _u, created_s, _last_seen_s, expires_s, _sid = parts
        elif len(parts) == 4:
            _u, created_s, _last_seen_s, expires_s = parts
        elif len(parts) == 3:
            _u, created_s, expires_s = parts
        else:
            return "expired"
        if time.time() > int(expires_s):
            return "expired"
        if epoch is None:
            from vnc_remote_secure.security.sessions import operator_session_epoch

            epoch = operator_session_epoch()
        if int(created_s) < epoch:
            return "revoked"
        return None
    except Exception:  # noqa: BLE001 - watcher must not die
        # Under strict policy a failed liveness check denies — an
        # unverifiable privileged session is worse than a dropped one.
        return "revoked" if _strict() else None


def _sweep_revoked_session(session_id: str, revoked_keys: set | None = None, epoch=None) -> bool:
    """Close the session's connections on revocation OR expiry.

    ``revoked_keys`` (a snapshot of the shared revocation namespace
    from ONE ``list_keys`` per sweep cycle) replaces the per-session
    ``is_revoked_shared`` SELECT; ``epoch`` does the same for the
    operator-session epoch read. Both default to the per-session
    checks so direct callers/tests keep working.
    """
    reason = None
    marked_at = None
    # Revocation markers exist under two key forms — the raw session id
    # and the ``sid:``-prefixed variant (see ``register``'s checks).
    if revoked_keys is not None:
        revoked = session_id in revoked_keys or f"sid:{session_id}" in revoked_keys
    else:
        revoked = is_revoked_shared(session_id) or is_revoked_shared(f"sid:{session_id}")
    if revoked:
        reason = "revoked"
        for key in (session_id, f"sid:{session_id}"):
            try:
                raw = get_backend().get(_NS_REVOKED, key)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                marked_at = float(raw)
                break
    elif _session_expired(session_id):
        reason = "expired"
    else:
        reason = _operator_session_dead(session_id, epoch=epoch)
    if reason is None:
        return False
    closed = get_registry().revoke_session(session_id)
    try:
        from vnc_remote_secure.monitoring.prometheus import inc_counter, set_gauge

        inc_counter(
            "vnc_remote_ws_connections_closed_total",
            f"reason={reason}",
            value=closed if isinstance(closed, int) else 1,
        )
        if marked_at is not None:
            # mark->close propagation latency, clamped for clock skew.
            set_gauge(
                "vnc_remote_revocation_latency_seconds",
                max(0.0, time.time() - marked_at),
                labels="channel=websocket",
            )
    except Exception:  # noqa: BLE001 - metrics must not break cleanup
        pass
    return True


async def watch_shared_revocation_async(session_id: str, interval: float = 5.0) -> None:
    """Poll the shared revocation set; closes local connections on hit.

    Exits when the session has no local connections left (normal
    disconnect), so no per-connection cleanup is needed beyond keeping
    a task reference until completion.

    NOTE: services now use the single global sweeper
    (:func:`_ensure_sweeper`); this per-session variant remains for
    tests and any caller that needs a dedicated watcher.
    """
    import asyncio

    while True:
        await asyncio.sleep(interval)
        if _sweep_revoked_session(session_id):
            return
        if get_registry().get_active_count(session_id) == 0:
            return


# --- Global revocation sweeper -----------------------------------------
#
# One daemon thread per process replaces the previous per-session
# watcher (thread OR asyncio task) — with N live sessions the old
# design ran N pollers, each paying 2-3 shared-state SELECTs per tick.
# The sweeper does ONE list_keys for the whole revoked namespace and
# ONE epoch read per cycle, then evaluates each registered session
# locally. New registrations wake it immediately via the event, so
# revocation latency is unchanged (~one interval) while idle cost
# drops to a sleeping thread.

_sweeper_thread = None
_sweeper_lock = threading.Lock()
_sweeper_wakeup = threading.Event()


def _sweep_cycle() -> int:
    """One pass over every locally-registered session.

    Returns the number of sessions whose connections were closed.
    Shared-state reads are batched: ONE ``list_keys`` for the revoked
    namespace + ONE operator-epoch read per cycle (vs 2-3 SELECTs per
    session before). A backend failure falls back to per-session
    checks — correctness over speed.
    """
    sessions = get_registry().get_active_sessions()
    if not sessions:
        return 0
    revoked_keys = None
    try:
        revoked_keys = set(get_backend().list_keys(_NS_REVOKED))
    except Exception:  # noqa: BLE001 - per-session fallback below
        revoked_keys = None
    epoch = None
    epoch_failed = False
    try:
        from vnc_remote_secure.security.sessions import operator_session_epoch

        epoch = operator_session_epoch()
    except Exception:  # noqa: BLE001
        epoch_failed = True
    closed = 0
    for sid in sessions:
        try:
            if _sweep_revoked_session(
                sid, revoked_keys=revoked_keys, epoch=None if epoch_failed else epoch
            ):
                closed += 1
        except Exception:  # noqa: BLE001 - one bad session must not stop the cycle
            logger.debug("Sweep failed for session %s", _redact(sid), exc_info=True)
    return closed


def _sweeper_loop():
    import random

    empty_cycles = 0
    while True:
        try:
            _sweep_cycle()
        except Exception:  # noqa: BLE001 - the sweeper must never die
            logger.debug("Revocation sweep cycle failed", exc_info=True)
        active = bool(get_registry().get_active_sessions())
        if active:
            empty_cycles = 0
            delay = 5.0 * random.uniform(0.8, 1.2)
        else:
            empty_cycles += 1
            # Idle backoff: cheap sleep when nothing is connected, but
            # a new registration wakes the loop immediately anyway.
            delay = 15.0 if empty_cycles > 2 else 5.0
        _sweeper_wakeup.wait(delay)
        _sweeper_wakeup.clear()


def _ensure_sweeper():
    """Start the single per-process revocation sweeper (lazy, daemon).

    Disabled under ``VRS_TEST_MODE`` — the suite drives sweeps
    explicitly and a background thread would make tests nondeterministic.
    """
    if os.environ.get("VRS_TEST_MODE") == "1":
        return None
    global _sweeper_thread
    if _sweeper_thread is not None and _sweeper_thread.is_alive():
        return _sweeper_thread
    with _sweeper_lock:
        if _sweeper_thread is not None and _sweeper_thread.is_alive():
            return _sweeper_thread
        t = threading.Thread(target=_sweeper_loop, name="ws-revocation-sweeper", daemon=True)
        t.start()
        _sweeper_thread = t
        _sweeper_wakeup.set()
        return t


def start_revocation_watcher(session_id: str, interval: float = 5.0):
    """Ensure the global revocation sweeper is running.

    Kept for call-site compatibility — the per-session ``interval``
    argument is superseded by the sweeper's adaptive cadence (the
    session id is discovered via the registry, not tracked here).
    """
    return _ensure_sweeper()


def start_revocation_watcher_thread(session_id: str, interval: float = 5.0) -> threading.Thread:
    """Ensure the global revocation sweeper is running (threaded callers)."""
    return _ensure_sweeper()
