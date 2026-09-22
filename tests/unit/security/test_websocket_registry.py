"""Tests for WebSocket connection registry and immediate revocation."""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.websocket_registry import (
    WebSocketRegistry,
    clear_revoked_shared,
    get_registry,
    register_connection,
    revoke_session_connections,
)


@pytest.fixture(autouse=True)
def _clear_revoked_state():
    """Clear shared revocation state before each test so tests are isolated."""
    for sid in ('ses_1', 'ses_2', 'ses_a', 'ses_b'):
        clear_revoked_shared(sid)
    yield
    for sid in ('ses_1', 'ses_2', 'ses_a', 'ses_b'):
        clear_revoked_shared(sid)


class TestWebSocketRegistry:
    """Tests for the WebSocket connection registry."""

    def test_register_and_unregister(self):
        """A connection can be registered and unregistered."""
        reg = WebSocketRegistry()
        closed = []
        conn_id = reg.register('ses_1', lambda: closed.append(True) or True)
        assert reg.get_active_count('ses_1') == 1
        reg.unregister(conn_id)
        assert reg.get_active_count('ses_1') == 0

    def test_revoke_session_closes_connections(self):
        """Revoking a session closes all its connections."""
        reg = WebSocketRegistry()
        closed = []
        reg.register('ses_1', lambda: closed.append('c1') or True, resource='desktop')
        reg.register('ses_1', lambda: closed.append('c2') or True, resource='terminal')
        reg.register('ses_2', lambda: closed.append('c3') or True, resource='desktop')

        count = reg.revoke_session('ses_1')
        assert count == 2
        assert len(closed) == 2
        assert reg.get_active_count('ses_1') == 0
        assert reg.get_active_count('ses_2') == 1  # Other session unaffected

    def test_revoke_nonexistent_session(self):
        """Revoking a session with no connections returns 0."""
        reg = WebSocketRegistry()
        assert reg.revoke_session('nonexistent') == 0

    def test_revoke_calls_close_callback(self):
        """The close callback is actually called on revocation."""
        reg = WebSocketRegistry()
        was_closed = {'value': False}

        def close_cb():
            was_closed['value'] = True
            return True

        reg.register('ses_1', close_cb)
        reg.revoke_session('ses_1')
        assert was_closed['value'] is True

    def test_revoke_callback_exception_does_not_crash(self):
        """If the close callback raises, revocation continues."""
        reg = WebSocketRegistry()

        def bad_cb():
            raise RuntimeError('close failed')

        reg.register('ses_1', bad_cb)
        reg.register('ses_1', lambda: True)
        count = reg.revoke_session('ses_1')
        # Only the callback that actually ran counts — a failed close
        # is reported honestly, not silently counted as closed.
        assert count == 1

    def test_multiple_sessions_tracked_independently(self):
        """Multiple sessions are tracked independently."""
        reg = WebSocketRegistry()
        reg.register('ses_a', lambda: True, 'desktop')
        reg.register('ses_a', lambda: True, 'terminal')
        reg.register('ses_b', lambda: True, 'desktop')

        assert reg.get_active_count('ses_a') == 2
        assert reg.get_active_count('ses_b') == 1
        assert sorted(reg.get_active_sessions()) == ['ses_a', 'ses_b']

    def test_connection_info_for_diagnostics(self):
        """Connection info can be retrieved for diagnostics."""
        reg = WebSocketRegistry()
        reg.register('ses_1', lambda: True, 'desktop')
        info = reg.get_connection_info('ses_1')
        assert len(info) == 1
        assert info[0]['session_id'] == 'ses_1'
        assert info[0]['resource'] == 'desktop'

    def test_register_rejects_revoked_session(self):
        """register() returns None when the session is already revoked."""
        # Use the shared backend directly.
        from vnc_remote_secure.security.shared_state import get_backend

        # Mark 'ses_1' as revoked in the shared backend before registering.
        from vnc_remote_secure.security.websocket_registry import (
            is_revoked_shared,
        )
        backend = get_backend()
        backend.set('websocket_revoked_sessions', 'ses_1', True)
        assert is_revoked_shared('ses_1') is True
        reg = WebSocketRegistry()
        result = reg.register('ses_1', lambda: True)
        assert result is None
        # Clean up.
        backend.delete('websocket_revoked_sessions', 'ses_1')

    def test_thread_safety(self):
        """The registry is thread-safe under concurrent access."""
        reg = WebSocketRegistry()
        results = []

        def worker():
            for _i in range(20):
                conn_id = reg.register('ses_1', lambda: True)
                results.append(conn_id)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert reg.get_active_count('ses_1') == 100
        count = reg.revoke_session('ses_1')
        assert count == 100


class TestSingleUseTokenConcurrency:
    """Race condition test: two clients consuming a single-use token."""

    def test_single_use_token_only_one_consumes(self):
        """Two threads try to consume a single-use token simultaneously.
        Only one should succeed."""
        from vnc_remote_secure.security.ephemeral_sessions import (
            SessionStore,
            consume_ephemeral_session,
        )

        # Use a fresh store to avoid interference from other tests.
        store = SessionStore()
        session, signed = store.create(
            role='viewer',
            single_use=True,
            expires_in=300,
        )

        # Monkey-patch the global store to use our fresh instance.
        import vnc_remote_secure.security.ephemeral_sessions as mod
        original_store = mod._store
        mod._store = store
        try:
            results = []
            lock = threading.Lock()

            def consumer():
                result = consume_ephemeral_session(signed)
                with lock:
                    results.append(bool(result))

            # Launch two consumers simultaneously.
            threads = [threading.Thread(target=consumer) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Exactly one should have succeeded.
            successes = sum(results)
            assert successes == 1, (
                f'Expected exactly 1 success, got {successes} — '
                f'single-use token is not atomic'
            )
        finally:
            mod._store = original_store


class TestImmediateRevocationFlow:
    """End-to-end test of the revocation flow."""

    def test_revoke_closes_active_connection(self):
        """When a session is revoked, the active connection is closed."""
        connection_state = {'closed': False}

        def close_cb():
            connection_state['closed'] = True
            return True

        # Simulate: connection established.
        register_connection('ses_123', close_cb, 'desktop')
        reg = get_registry()
        assert reg.get_active_count('ses_123') == 1

        # Simulate: admin revokes the session.
        closed = revoke_session_connections('ses_123')
        assert closed == 1
        assert connection_state['closed'] is True

        # Simulate: client tries to reconnect — no active connections.
        assert reg.get_active_count('ses_123') == 0


class TestCloseCallbackFailures:
    """A close callback that raises must not abort the revocation of
    the session's OTHER connections or corrupt the registry."""

    def test_raising_callback_others_still_closed(self):
        from vnc_remote_secure.security.websocket_registry import (
            WebSocketRegistry)
        reg = WebSocketRegistry()
        closed = []
        reg.register('s1', lambda: closed.append('a'), resource='vnc')
        reg.register('s1',
                     lambda: (_ for _ in ()).throw(RuntimeError('boom')),
                     resource='vnc')
        reg.register('s1', lambda: closed.append('c'), resource='vnc')
        n = reg.revoke_session('s1')
        # Both healthy callbacks fired; the raising one reported False.
        assert n == 2
        assert sorted(closed) == ['a', 'c']
        # Registry fully drained for the session.
        assert reg.get_active_count('s1') == 0

    def test_revoke_marks_session_revoked_shared(self):
        """revoke_session must write the shared-state marker so other
        processes reject the session too (real backend)."""
        from vnc_remote_secure.security import websocket_registry as wsr
        reg = wsr.WebSocketRegistry()
        sid = 's9-shared-marker'
        reg.register(sid, lambda: True, resource='vnc')
        try:
            reg.revoke_session(sid)
            assert wsr.is_revoked_shared(sid) is True
        finally:
            wsr.clear_revoked_shared(sid)

    def test_unregister_unknown_conn_id_noop(self):
        from vnc_remote_secure.security.websocket_registry import (
            WebSocketRegistry)
        reg = WebSocketRegistry()
        reg.unregister('ghost')  # must not raise
