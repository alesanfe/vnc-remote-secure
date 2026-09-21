"""Regression tests for the audit-hardening round.

Covers: PID-kill fail-closed (F3), health peer check (F9), shared
ephemeral revocation (F4), atomic rate limiting (F7), coroutine
close callbacks (F2), and share-token log redaction (F1).
"""
import asyncio
import sys


class TestKillPidFailClosed:
    def test_refuses_unknown_identity(self, monkeypatch):
        """When the cmdline cannot be read (None), _kill_pid must NOT
        kill — a recycled PID could belong to a foreign process."""
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, '_pid_alive', lambda pid: True)
        monkeypatch.setattr(sm, '_pid_is_ours', lambda pid, service=None: None)
        killed = []
        monkeypatch.setattr(
            sm.subprocess, 'run',
            lambda *a, **k: killed.append(a) or None)
        monkeypatch.setattr(sm.os, 'kill',
                            lambda pid, sig: killed.append(sig))
        assert sm._kill_pid(4242, service='vnc') is False
        assert killed == []

    def test_force_kills_unknown_identity(self, monkeypatch):
        from vnc_remote_secure.core import service_manager as sm
        # Alive on the pre-check, dead after the kill attempt.
        alive = iter([True, False])
        monkeypatch.setattr(sm, '_pid_alive', lambda pid: next(alive, False))
        monkeypatch.setattr(sm, '_pid_is_ours', lambda pid, service=None: None)
        cleared = []
        monkeypatch.setattr(sm, '_clear_pid_by_value',
                            lambda pid: cleared.append(pid))
        monkeypatch.setattr(sm.time, 'sleep', lambda s: None)
        if sys.platform == 'win32':
            calls = []
            monkeypatch.setattr(
                sm.subprocess, 'run',
                lambda *a, **k: calls.append(a))
            assert sm._kill_pid(4242, service='vnc', force=True) is True
            assert calls, 'taskkill was not invoked'
        else:
            sigs = []
            monkeypatch.setattr(
                sm.os, 'kill', lambda pid, sig: sigs.append(sig))
            assert sm._kill_pid(4242, service='vnc', force=True) is True
            assert sigs, 'no signal was sent'


class TestHealthAuthPeerCheck:
    def test_non_loopback_peer_denied_without_token(self, monkeypatch):
        from vnc_remote_secure.security.http_auth import check_health_auth
        monkeypatch.delenv('HEALTH_AUTH_TOKEN', raising=False)
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.delenv('USER_UI_HOST', raising=False)
        monkeypatch.delenv('HEALTH_WEB_HOST', raising=False)
        assert check_health_auth('', peer_ip='203.0.113.9') is False

    def test_loopback_peer_allowed_without_token(self, monkeypatch):
        from vnc_remote_secure.security.http_auth import check_health_auth
        monkeypatch.delenv('HEALTH_AUTH_TOKEN', raising=False)
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.delenv('USER_UI_HOST', raising=False)
        monkeypatch.delenv('HEALTH_WEB_HOST', raising=False)
        assert check_health_auth('', peer_ip='127.0.0.1') is True
        assert check_health_auth('', peer_ip='::1') is True

    def test_token_still_enforced_when_set(self, monkeypatch):
        from vnc_remote_secure.security.http_auth import check_health_auth
        monkeypatch.setenv('HEALTH_AUTH_TOKEN', 's3cret')
        assert check_health_auth(
            'Bearer s3cret', peer_ip='203.0.113.9') is True
        assert check_health_auth(
            'Bearer wrong', peer_ip='127.0.0.1') is False


class TestEphemeralSharedRevocation:
    def test_shared_marker_survives_lost_update(self, monkeypatch,
                                                tmp_path):
        """revoke() marks shared state; get() honours the marker even
        when the JSON flag was overwritten by a racing _save."""
        from vnc_remote_secure.security import ephemeral_sessions as es
        store = es.SessionStore.__new__(es.SessionStore)
        store._sessions = {}
        store._lock = __import__('threading').Lock()
        store._last_mtime = 0.0
        store._cleanup_interval = 300
        monkeypatch.setattr(store, '_persist_path',
                            lambda: str(tmp_path / 'eph.json'))
        session, signed = store.create(expires_in=3600)
        internal = session.token
        assert store.revoke(internal) is True
        assert es._is_revoked_shared(internal)
        # Simulate the lost update: a racing _save resurrects the flag.
        session.revoked = False
        store._sessions[internal] = session
        got = store.get(internal)
        assert got.revoked is True


class TestAtomicRateLimit:
    def test_budget_is_hard(self, monkeypatch):
        from vnc_remote_secure.security.rate_limit import check_rate_limit
        monkeypatch.setenv('SHARED_STATE_BACKEND', 'memory')
        ip = '198.51.100.7'
        results = [check_rate_limit(ip, max_requests=3, window_seconds=60)
                   for _ in range(5)]
        assert results == [True, True, True, False, False]


class TestCoroutineCloseCallback:
    def test_coroutine_close_scheduled_on_loop(self):
        """websockets<=13 close() is a coroutine — revoke must schedule
        it, not drop it."""
        from vnc_remote_secure.security import websocket_registry as wr
        wr.reset_registry()
        closed = []

        async def scenario():
            ws_close_called = []

            class FakeWS:
                async def close(self):
                    ws_close_called.append(True)
                    closed.append(True)

            ws = FakeWS()
            conn_id = wr.register_connection('sess1', ws.close)
            assert conn_id is not None
            wr.revoke_session_connections('sess1')
            # The coroutine was scheduled on this loop — let it run.
            await asyncio.sleep(0.05)
            assert ws_close_called == [True]

        asyncio.run(scenario())

    def test_sync_close_still_works(self):
        from vnc_remote_secure.security import websocket_registry as wr
        wr.reset_registry()
        closed = []
        conn_id = wr.register_connection('sess2', lambda: closed.append(1))
        assert conn_id is not None
        assert wr.revoke_session_connections('sess2') == 1
        assert closed == [1]


class TestLandingLogRedaction:
    def test_session_token_redacted(self):
        import logging

        from vnc_remote_secure.services.landing import LandingHandler
        records = []

        class _Cap(logging.Handler):
            def emit(self, r):
                records.append(r.getMessage())

        logger = logging.getLogger('vnc_remote_secure.services.landing')
        old_level = logger.level
        logger.setLevel(logging.INFO)
        cap = _Cap()
        logger.addHandler(cap)
        try:
            handler = LandingHandler.__new__(LandingHandler)
            handler.client_address = ('127.0.0.1', 1234)
            handler.log_message(
                '"GET /?session=SECRET_TOKEN_123 HTTP/1.1" 302 -')
        finally:
            logger.removeHandler(cap)
            logger.setLevel(old_level)
        assert records
        assert 'SECRET_TOKEN_123' not in records[0]
        assert 'session=<redacted>' in records[0]
