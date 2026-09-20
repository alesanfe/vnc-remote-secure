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
from typing import Callable, Dict, List, Optional, Set

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

# Type for a close callback. The callback should close the WebSocket
# connection. This abstraction allows the registry to work with
# different WebSocket implementations (Tornado, Flask-SocketIO, etc.).
CloseCallback = Callable[[], bool]


class _ConnectionEntry:
    """Internal: tracks a single WebSocket connection."""

    __slots__ = ('conn_id', 'session_id', 'close_callback', 'resource', 'created_at')

    def __init__(self, conn_id: str, session_id: str,
                 close_callback: CloseCallback,
                 resource: Optional[str] = None,
                 created_at: Optional[float] = None):
        self.conn_id = conn_id
        self.session_id = session_id
        self.close_callback = close_callback
        self.resource = resource
        import time
        self.created_at = created_at or time.time()


class WebSocketRegistry:
    """Thread-safe registry of active WebSocket connections.

    Maps session_id -> set of connection entries, allowing immediate
    closure of all connections when a session is revoked.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._connections: Dict[str, _ConnectionEntry] = {}  # conn_id -> entry
        self._by_session: Dict[str, Set[str]] = {}  # session_id -> {conn_ids}
        self._next_id = 0

    def register(self, session_id: str, close_callback: CloseCallback,
                 resource: Optional[str] = None) -> str:
        """Register a new WebSocket connection.

        Args:
            session_id: The session this connection belongs to.
            close_callback: Callable that closes the WebSocket.
            resource: Optional resource name (e.g. 'desktop', 'terminal').

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
            self._next_id += 1
            conn_id = f'ws_{self._next_id}'
            entry = _ConnectionEntry(conn_id, session_id, close_callback, resource)
            self._connections[conn_id] = entry
            if session_id not in self._by_session:
                self._by_session[session_id] = set()
            self._by_session[session_id].add(conn_id)
            logger.debug(
                'Registered WebSocket connection %s for session %s (resource=%s)',
                conn_id, _redact(session_id), resource,
            )
            return conn_id

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
        get_backend().set_ttl(
            _NS_REVOKED, session_id, True, max(86400, max_lifetime))
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
            try:
                entry.close_callback()
                closed += 1
            except Exception as e:
                logger.warning(
                    'Error closing WebSocket connection %s: %s',
                    conn_id, e,
                )
                closed += 1  # Count as closed even on error
        logger.info(
            'Revoked %d WebSocket connection(s) for session %s',
            closed, _redact(session_id),
        )
        return closed

    def get_active_count(self, session_id: str) -> int:
        """Return the number of active connections for a session."""
        with self._lock:
            return len(self._by_session.get(session_id, set()))

    def get_active_sessions(self) -> List[str]:
        """Return a list of session IDs with active connections."""
        with self._lock:
            return list(self._by_session.keys())

    def get_connection_info(self, session_id: str) -> List[Dict]:
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
_registry: Optional[WebSocketRegistry] = None


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
                         resource: Optional[str] = None) -> str:
    """Register a new WebSocket connection (convenience function)."""
    return get_registry().register(session_id, close_callback, resource)


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
    """
    return bool(get_backend().get(_NS_REVOKED, session_id))


def clear_revoked_shared(session_id: str):
    """Remove a session from the shared revocation set (for testing)."""
    get_backend().delete(_NS_REVOKED, session_id)
