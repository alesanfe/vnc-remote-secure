"""Shared state abstraction for multi-process deployments.

Stateful components (rate limiter, session store, WebSocket registry,
audit chain) share state through a pluggable backend. The canonical
deployment runs every service as a separate process, so the platform
default (``SHARED_STATE_BACKEND=sqlite`` in
``config/defaults/common.env``) is the SQLite backend — an in-memory
backend would give each process its own empty copy of rate-limit
budgets, revocation markers, and auth times.

- ``SQLiteBackend``: durable, file-based shared state. Works across
  processes on a single host. No external server required.
- ``MemoryBackend``: in-process dict. No external dependencies.
  Intended for single-process/test scenarios only.

The backend is selected via the ``SHARED_STATE_BACKEND`` env var
(``memory`` or ``sqlite``). The SQLite path defaults to
``<run_dir>/shared_state.db`` and can be overridden via
``SHARED_STATE_DB_PATH``.

This module is intentionally dependency-free (uses only the standard
library) so it works on every platform without additional packages.
"""
import json
import logging
import os
import sqlite3
import threading
import time

logger = logging.getLogger(__name__)

BACKEND_MEMORY = 'memory'
BACKEND_SQLITE = 'sqlite'


# ---------------------------------------------------------------------------
# Backend abstraction
# ---------------------------------------------------------------------------

class StateBackend:
    """Abstract backend for shared state with TTL support."""

    def get(self, namespace: str, key: str):
        """Return the value for ``namespace:key`` or ``None``."""
        raise NotImplementedError

    def set(self, namespace: str, key: str, value):
        """Set ``namespace:key`` to ``value`` (no TTL)."""
        raise NotImplementedError

    def delete(self, namespace: str, key: str):
        """Delete ``namespace:key``."""
        raise NotImplementedError

    def set_ttl(self, namespace: str, key: str, value, ttl_seconds: float):
        """Set ``namespace:key`` to ``value`` with a TTL."""
        raise NotImplementedError

    def set_if_absent(self, namespace: str, key: str, value,
                      ttl_seconds: float | None = None) -> bool:
        """Atomically set ``namespace:key`` only when it is absent.

        Returns ``True`` when the value was written, ``False`` when a
        live (non-expired) entry already exists. Used for single-use
        claims (recovery codes, TOTP counters) where a check-then-set
        pair would be racy across processes.
        """
        raise NotImplementedError

    def list_keys(self, namespace: str, prefix: str = '') -> list:
        """Return all keys in ``namespace`` matching ``prefix``."""
        raise NotImplementedError

    def increment(self, namespace: str, key: str, amount: int = 1,
                  ttl_seconds: float | None = None) -> int:
        """Atomically increment ``namespace:key`` by ``amount``.

        When ``ttl_seconds`` is provided the entry's expiry is set
        (or refreshed) in the same atomic operation, so bounded-use
        counters do not leak stale rows.
        """
        raise NotImplementedError

    def close(self):
        """Release any resources held by the backend."""


class MemoryBackend(StateBackend):
    """In-memory backend (single-process/test scenarios)."""

    def __init__(self):
        self._store: dict = {}  # (namespace, key) -> (value, expires_at or None)
        self._lock = threading.Lock()

    def get(self, namespace: str, key: str):
        nk = (namespace, key)
        with self._lock:
            entry = self._store.get(nk)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at is not None and time.time() > expires_at:
                del self._store[nk]
                return None
            return value

    def set(self, namespace: str, key: str, value):
        nk = (namespace, key)
        with self._lock:
            self._store[nk] = (value, None)

    def delete(self, namespace: str, key: str):
        nk = (namespace, key)
        with self._lock:
            self._store.pop(nk, None)

    def set_ttl(self, namespace: str, key: str, value, ttl_seconds: float):
        nk = (namespace, key)
        with self._lock:
            self._store[nk] = (value, time.time() + ttl_seconds)

    def set_if_absent(self, namespace: str, key: str, value,
                      ttl_seconds: float | None = None) -> bool:
        nk = (namespace, key)
        with self._lock:
            entry = self._store.get(nk)
            if entry is not None:
                _, expires_at = entry
                if expires_at is None or time.time() <= expires_at:
                    return False
            exp = time.time() + ttl_seconds if ttl_seconds else None
            self._store[nk] = (value, exp)
            return True

    def list_keys(self, namespace: str, prefix: str = '') -> list:
        with self._lock:
            now = time.time()
            result = []
            for (ns, key), (_, expires_at) in self._store.items():
                if ns != namespace:
                    continue
                if expires_at is not None and now > expires_at:
                    continue
                if prefix and not key.startswith(prefix):
                    continue
                result.append(key)
            return result

    def increment(self, namespace: str, key: str, amount: int = 1,
                  ttl_seconds: float | None = None) -> int:
        nk = (namespace, key)
        with self._lock:
            entry = self._store.get(nk)
            current = 0
            if entry is not None:
                value, expires_at = entry
                if expires_at is None or time.time() <= expires_at:
                    current = value if isinstance(value, int) else 0
            new_val = current + amount
            if ttl_seconds is not None:
                expires = time.time() + ttl_seconds
            elif entry is not None:
                # Preserve an existing TTL when the caller did not
                # ask for one — a bare increment must not silently
                # make a bounded counter immortal.
                expires = entry[1]
            else:
                expires = None
            self._store[nk] = (new_val, expires)
            return new_val

    def close(self):
        with self._lock:
            self._store.clear()


class SQLiteBackend(StateBackend):
    """SQLite-backed shared state (multi-process, single host).

    Uses a single database file with a ``state`` table. All operations
    are serialised by SQLite's own locking. TTL is implemented via an
    ``expires_at`` column; expired entries are lazily removed on read.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        # dirname() is '' for a bare filename (SHARED_STATE_DB_PATH=
        # "state.db") — makedirs('') raises FileNotFoundError.
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None,
            timeout=10,
        )
        # WAL + busy_timeout: several service processes share this DB
        # (counters, revoked-session namespace). The default DELETE
        # journal makes readers block writers and vice versa, surfacing
        # as "database is locked" under concurrent access.
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA busy_timeout=10000')
        # Restrict file permissions to owner-only. os.chmod is a
        # no-op on Windows ACLs — use the platform-aware helper. The
        # WAL/SHM sidecar files hold the same data as the db and are
        # created with inherited ACLs — they must be restricted too.
        try:
            from vnc_remote_secure.security.certificates import _restrict_key_permissions
            for sidecar in (db_path, db_path + '-wal', db_path + '-shm'):
                if os.path.exists(sidecar):
                    _restrict_key_permissions(sidecar, writable=True)
        except Exception:  # noqa: BLE001
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        self._conn.execute(
            'CREATE TABLE IF NOT EXISTS state ('
            '  namespace TEXT NOT NULL,'
            '  key TEXT NOT NULL,'
            '  value TEXT NOT NULL,'
            '  expires_at REAL,'
            '  PRIMARY KEY (namespace, key)'
            ')'
        )
        self._conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_state_ns ON state(namespace)'
        )

    def _serialise(self, value):
        return json.dumps(value)

    def _deserialise(self, raw):
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    def get(self, namespace: str, key: str):
        with self._lock:
            row = self._conn.execute(
                'SELECT value, expires_at FROM state WHERE namespace=? AND key=?',
                (namespace, key),
            ).fetchone()
        if row is None:
            return None
        raw, expires_at = row
        if expires_at is not None and time.time() > expires_at:
            self.delete(namespace, key)
            return None
        return self._deserialise(raw)

    def set(self, namespace: str, key: str, value):
        with self._lock:
            self._conn.execute(
                'INSERT OR REPLACE INTO state (namespace, key, value, expires_at) '
                'VALUES (?, ?, ?, NULL)',
                (namespace, key, self._serialise(value)),
            )

    def delete(self, namespace: str, key: str):
        with self._lock:
            self._conn.execute(
                'DELETE FROM state WHERE namespace=? AND key=?',
                (namespace, key),
            )

    def set_ttl(self, namespace: str, key: str, value, ttl_seconds: float):
        with self._lock:
            self._conn.execute(
                'INSERT OR REPLACE INTO state (namespace, key, value, expires_at) '
                'VALUES (?, ?, ?, ?)',
                (namespace, key, self._serialise(value),
                 time.time() + ttl_seconds),
            )

    def set_if_absent(self, namespace: str, key: str, value,
                      ttl_seconds: float | None = None) -> bool:
        """Atomic test-and-set for single-use claims.

        ``INSERT OR IGNORE`` returns 0 rows on conflict; an expired
        existing row counts as absent and is replaced.
        """
        expires = time.time() + ttl_seconds if ttl_seconds else None
        now = time.time()
        with self._lock:
            # Single atomic statement: INSERT when absent, UPDATE only
            # when the conflicting row is already expired. The previous
            # SELECT-then-REPLACE path let two processes both reclaim an
            # expired key (TOCTOU on single-use claims).
            cur = self._conn.execute(
                'INSERT INTO state (namespace, key, value, expires_at) '
                'VALUES (?, ?, ?, ?) '
                'ON CONFLICT(namespace, key) DO UPDATE SET '
                'value=excluded.value, expires_at=excluded.expires_at '
                'WHERE state.expires_at IS NOT NULL AND state.expires_at <= ?',
                (namespace, key, self._serialise(value), expires, now),
            )
            return cur.rowcount == 1

    def list_keys(self, namespace: str, prefix: str = '') -> list:
        now = time.time()
        with self._lock:
            if prefix:
                # LIKE with an ESCAPE clause: a prefix containing
                # '%'/'_' (e.g. a spoofed X-Forwarded-For client IP)
                # must be literal, not a wildcard that matches other
                # keys' records. substr() is not an option — SQLite
                # string functions stop at the first U+0000 and our
                # key separators are '\x00'.
                escaped = prefix.replace('\\', '\\\\') \
                    .replace('%', '\\%').replace('_', '\\_')
                rows = self._conn.execute(
                    "SELECT key, expires_at FROM state "
                    "WHERE namespace=? AND key LIKE ? ESCAPE '\\'",
                    (namespace, escaped + '%'),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    'SELECT key, expires_at FROM state WHERE namespace=?',
                    (namespace,),
                ).fetchall()
        result = []
        for key, expires_at in rows:
            if expires_at is not None and now > expires_at:
                continue
            result.append(key)
        return result

    def increment(self, namespace: str, key: str, amount: int = 1,
                  ttl_seconds: float | None = None) -> int:
        """Atomically increment a counter.

        Uses ``INSERT ... ON CONFLICT DO UPDATE`` so the read-modify-write
        is a single SQL statement, preventing lost updates across
        processes (the per-process ``_lock`` still serialises threads
        within this process). When ``ttl_seconds`` is given the entry's
        expiry is refreshed atomically in the same statement; otherwise
        an existing TTL is preserved.
        """
        expires = (time.time() + ttl_seconds
                   if ttl_seconds is not None else None)
        with self._lock:
            # SQLite UPSERT with atomic increment. The ``excluded`` table
            # refers to the row that would have been inserted. expires_at
            # is updated only when a TTL is requested (excluded non-NULL);
            # otherwise the current value is kept.
            self._conn.execute(
                'INSERT INTO state (namespace, key, value, expires_at) '
                'VALUES (?, ?, ?, ?) '
                'ON CONFLICT(namespace, key) DO UPDATE SET '
                'value = CAST('
                '  (CASE WHEN state.expires_at IS NULL OR ? <= state.expires_at '
                '   THEN CAST(state.value AS INTEGER) ELSE 0 END) '
                '  + ? AS TEXT), '
                'expires_at = COALESCE(excluded.expires_at, state.expires_at)',
                (namespace, key, self._serialise(amount), expires,
                 time.time(), amount),
            )
            # Read back the resulting value so callers get the new total.
            # Note: a bare increment on an expired key keeps the stale
            # expiry (matching MemoryBackend — it must not silently make
            # a bounded counter immortal), so the row may still read as
            # expired via get(). The returned total is the stored value
            # either way, same as the memory backend.
            row = self._conn.execute(
                'SELECT value FROM state WHERE namespace=? AND key=?',
                (namespace, key),
            ).fetchone()
            if row is None:
                return amount
            val = self._deserialise(row[0])
            return val if isinstance(val, int) else 0

    def close(self):
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

_backend: StateBackend | None = None


def _default_sqlite_path() -> str:
    from vnc_remote_secure.core.paths import get_run_dir
    return os.path.join(get_run_dir(), 'shared_state.db')


def get_backend() -> StateBackend:
    """Return the configured shared-state backend.

    The backend is selected via ``SHARED_STATE_BACKEND``:
    - ``memory``: in-process dict (test/dev only).
    - ``sqlite``: SQLite file at ``SHARED_STATE_DB_PATH`` (defaults to
      ``<run_dir>/shared_state.db``).
    """
    global _backend
    if _backend is not None:
        return _backend
    choice = os.environ.get(
        'SHARED_STATE_BACKEND', BACKEND_SQLITE).lower()
    if choice == BACKEND_SQLITE:
        db_path = os.environ.get('SHARED_STATE_DB_PATH', _default_sqlite_path())
        try:
            _backend = SQLiteBackend(db_path)
            logger.info("Shared state backend: sqlite (%s)", db_path)
        except Exception as exc:  # noqa: BLE001 - degrade, don't break auth
            # A broken run-dir/DB must not take down every auth check in
            # the process (500 on login, health, terminal). Degrade to
            # the in-memory backend and scream loudly — single-use and
            # revocation guarantees become single-process until fixed.
            logger.error(
                "Shared state sqlite backend failed (%s); falling back "
                "to in-memory state — cross-process single-use and "
                "revocation guarantees are degraded until this is fixed",
                exc)
            _backend = MemoryBackend()
    else:
        _backend = MemoryBackend()
        logger.debug("Shared state backend: memory")
    return _backend


def reset_backend():
    """Reset the global backend (for testing)."""
    global _backend
    if _backend is not None:
        _backend.close()
    _backend = None
