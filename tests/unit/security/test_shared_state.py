"""Tests for the shared-state abstraction layer.

Verifies that both the MemoryBackend and SQLiteBackend correctly
implement the StateBackend interface, and that the RateLimiter and
WebSocketRegistry use the backend for cross-process state.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security import shared_state
from vnc_remote_secure.security.shared_state import (
    MemoryBackend,
    SQLiteBackend,
    get_backend,
    reset_backend,
)

# ---------------------------------------------------------------------------
# MemoryBackend
# ---------------------------------------------------------------------------


class TestMemoryBackend:
    def test_set_get(self):
        b = MemoryBackend()
        b.set('ns', 'key', {'a': 1})
        assert b.get('ns', 'key') == {'a': 1}

    def test_get_missing(self):
        b = MemoryBackend()
        assert b.get('ns', 'key') is None

    def test_delete(self):
        b = MemoryBackend()
        b.set('ns', 'key', 'val')
        b.delete('ns', 'key')
        assert b.get('ns', 'key') is None

    def test_set_ttl_expires(self):
        b = MemoryBackend()
        b.set_ttl('ns', 'key', 'val', 0.01)
        import time
        time.sleep(0.02)
        assert b.get('ns', 'key') is None

    def test_list_keys(self):
        b = MemoryBackend()
        b.set('ns', 'k1', 1)
        b.set('ns', 'k2', 2)
        b.set('other', 'k3', 3)
        assert sorted(b.list_keys('ns')) == ['k1', 'k2']

    def test_list_keys_with_prefix(self):
        b = MemoryBackend()
        b.set('ns', 'user_alice', 1)
        b.set('ns', 'user_bob', 2)
        b.set('ns', 'ip_1.2.3.4', 3)
        assert sorted(b.list_keys('ns', 'user_')) == ['user_alice', 'user_bob']

    def test_increment(self):
        b = MemoryBackend()
        assert b.increment('ns', 'counter') == 1
        assert b.increment('ns', 'counter') == 2
        assert b.increment('ns', 'counter', 5) == 7


# ---------------------------------------------------------------------------
# SQLiteBackend
# ---------------------------------------------------------------------------

class TestSQLiteBackend:
    def test_set_get(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        b.set('ns', 'key', {'a': 1})
        assert b.get('ns', 'key') == {'a': 1}
        b.close()

    def test_get_missing(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        assert b.get('ns', 'key') is None
        b.close()

    def test_delete(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        b.set('ns', 'key', 'val')
        b.delete('ns', 'key')
        assert b.get('ns', 'key') is None
        b.close()

    def test_set_ttl_expires(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        b.set_ttl('ns', 'key', 'val', 0.01)
        import time
        time.sleep(0.02)
        assert b.get('ns', 'key') is None
        b.close()

    def test_list_keys(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        b.set('ns', 'k1', 1)
        b.set('ns', 'k2', 2)
        b.set('other', 'k3', 3)
        assert sorted(b.list_keys('ns')) == ['k1', 'k2']
        b.close()

    def test_increment(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / 'test.db'))
        assert b.increment('ns', 'counter') == 1
        assert b.increment('ns', 'counter') == 2
        assert b.increment('ns', 'counter', 5) == 7
        b.close()

    def test_persistence_across_connections(self, tmp_path):
        """Data written by one connection is visible to a new one."""
        db_path = str(tmp_path / 'test.db')
        b1 = SQLiteBackend(db_path)
        b1.set('ns', 'key', 'value')
        b1.close()
        b2 = SQLiteBackend(db_path)
        assert b2.get('ns', 'key') == 'value'
        b2.close()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

class TestBackendSelection:
    def test_default_is_sqlite(self, monkeypatch):
        # The platform default is SQLite: services run as separate
        # processes, so memory-backed state would silently break
        # cross-process rate limits, revocation and step-up auth.
        reset_backend()
        monkeypatch.delenv('SHARED_STATE_BACKEND', raising=False)
        b = get_backend()
        assert isinstance(b, SQLiteBackend)
        b.close()
        reset_backend()

    def test_sqlite_selection(self, monkeypatch, tmp_path):
        reset_backend()
        monkeypatch.setenv('SHARED_STATE_BACKEND', 'sqlite')
        monkeypatch.setenv('SHARED_STATE_DB_PATH', str(tmp_path / 'state.db'))
        b = get_backend()
        assert isinstance(b, SQLiteBackend)
        b.close()
        reset_backend()


# ---------------------------------------------------------------------------
# RateLimiter with shared backend
# ---------------------------------------------------------------------------

class TestRateLimiterShared:
    def test_rate_limiter_uses_backend(self, monkeypatch):
        """RateLimiter records failures via the shared backend."""
        from vnc_remote_secure.security.rate_limit import RateLimiter
        reset_backend()
        b = MemoryBackend()
        monkeypatch.setattr(shared_state, '_backend', b)

        rl = RateLimiter(max_attempts=3, lockout_seconds=60, window_seconds=60)
        rl.record_failure('1.2.3.4')
        rl.record_failure('1.2.3.4')
        assert rl.remaining_attempts('1.2.3.4') == 1
        reset_backend()

    def test_rate_limiter_lockout(self, monkeypatch):
        """RateLimiter locks out after threshold."""
        from vnc_remote_secure.security.rate_limit import RateLimiter
        reset_backend()
        b = MemoryBackend()
        monkeypatch.setattr(shared_state, '_backend', b)

        rl = RateLimiter(max_attempts=2, lockout_seconds=60, window_seconds=60)
        rl.record_failure('user')
        rl.record_failure('user')
        assert rl.is_locked('user')
        reset_backend()

    def test_rate_limiter_cross_backend(self, monkeypatch, tmp_path):
        """Two RateLimiters sharing a SQLite backend see the same state."""
        from vnc_remote_secure.security.rate_limit import RateLimiter
        reset_backend()
        db_path = str(tmp_path / 'shared.db')
        b = SQLiteBackend(db_path)
        monkeypatch.setattr(shared_state, '_backend', b)

        rl1 = RateLimiter(max_attempts=2, lockout_seconds=60, window_seconds=60)
        rl1.record_failure('1.2.3.4')
        rl1.record_failure('1.2.3.4')

        # Simulate a second process by creating a new backend connection.
        b2 = SQLiteBackend(db_path)
        monkeypatch.setattr(shared_state, '_backend', b2)
        rl2 = RateLimiter(max_attempts=2, lockout_seconds=60, window_seconds=60)
        assert rl2.is_locked('1.2.3.4')
        b.close()
        b2.close()
        reset_backend()


# ---------------------------------------------------------------------------
# WebSocketRegistry cross-process revocation
# ---------------------------------------------------------------------------

class TestWebSocketRevocationShared:
    def test_revoke_marks_shared(self, monkeypatch):
        """Revoking a session marks it in the shared backend."""
        from vnc_remote_secure.security.websocket_registry import (
            is_revoked_shared,
            revoke_session_connections,
        )
        reset_backend()
        b = MemoryBackend()
        monkeypatch.setattr(shared_state, '_backend', b)

        revoke_session_connections('session_123')
        assert is_revoked_shared('session_123')
        reset_backend()

    def test_not_revoked_by_default(self, monkeypatch):
        from vnc_remote_secure.security.websocket_registry import is_revoked_shared
        reset_backend()
        b = MemoryBackend()
        monkeypatch.setattr(shared_state, '_backend', b)

        assert not is_revoked_shared('session_456')
        reset_backend()

    def test_cross_process_revocation(self, monkeypatch, tmp_path):
        """Revocation in one backend is visible to another."""
        from vnc_remote_secure.security.websocket_registry import (
            is_revoked_shared,
            revoke_session_connections,
        )
        reset_backend()
        db_path = str(tmp_path / 'ws.db')
        b = SQLiteBackend(db_path)
        monkeypatch.setattr(shared_state, '_backend', b)

        revoke_session_connections('session_x')

        # Simulate a second process.
        b2 = SQLiteBackend(db_path)
        monkeypatch.setattr(shared_state, '_backend', b2)
        assert is_revoked_shared('session_x')
        b.close()
        b2.close()
        reset_backend()
