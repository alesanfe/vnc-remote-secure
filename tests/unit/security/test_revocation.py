"""Tests for the central revocation coordinator."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.revocation import (
    revoke_cookie,
    revoke_sid,
)
from vnc_remote_secure.security.sessions import create_session_cookie
from vnc_remote_secure.security.websocket_registry import (
    register_connection,
)


class TestSidRevocation:

    def test_revoke_sid_closes_only_its_connections(self):
        """Two sessions, same user — conns under sid-A close, sid-B's
        stay open."""
        a = create_session_cookie('alice')['value']
        b = create_session_cookie('alice')['value']
        from vnc_remote_secure.security.sessions import verify_session_cookie
        sid_a = verify_session_cookie(a)['sid']
        sid_b = verify_session_cookie(b)['sid']

        closed = []
        register_connection(sid_a, lambda: closed.append('A'),
                            'terminal')
        register_connection(sid_b, lambda: closed.append('B'),
                            'terminal')

        res = revoke_sid(sid_a)
        assert res.logically_revoked is True
        assert res.target_kind == 'sid'
        assert closed == ['A']
        assert 'B' not in closed

    def test_revoke_sid_idempotent(self):
        sid = 'abc123def456ghij'
        first = revoke_sid(sid)
        second = revoke_sid(sid)
        assert first.logically_revoked is True
        assert first.already_revoked == 0
        assert second.logically_revoked is True
        assert second.already_revoked == 1
        assert second.errors == ()

    def test_revoke_cookie_invalid_fails_closed(self):
        res = revoke_cookie('garbage')
        assert res.logically_revoked is False
        assert any(e.code == 'INVALID_COOKIE' for e in res.errors)
        assert res.retry_recommended is False

    def test_second_revoke_is_clean_idempotent(self):
        """already_revoked reports the prior mark; cleanup still runs
        (idempotent deletes/closes are harmless retries)."""
        sid = 'retry' + 'x' * 17
        closed = []
        register_connection(sid, lambda: closed.append(1),
                            'terminal')
        first = revoke_sid(sid)
        assert first.logically_revoked
        assert closed == [1]
        second = revoke_sid(sid)
        assert second.already_revoked == 1
        assert second.errors == ()

    def test_revoked_sid_cannot_register_new_conn(self):
        """Post-revoke registration is refused — the close-race is
        closed at the registry, not just at auth time."""
        sid = 'guardsid' + 'y' * 14
        revoke_sid(sid)
        conn = register_connection(sid, lambda: None, 'terminal')
        assert conn is None

    def test_revoke_landing_mid_registration_closes_conn(self):
        """Race: revoke lands BETWEEN the pre-register check and the
        post-register double-check. The conn must be unregistered and
        closed, not left live after the sweep missed it."""
        import threading
        import time as _t
        import unittest.mock as _mock

        from vnc_remote_secure.security import websocket_registry as wsr
        sid = 'racesid' + 'z' * 15
        closed = []
        entered = threading.Event()
        proceed = threading.Event()
        orig = wsr.is_revoked_shared

        def _staggered(key, _calls=[0]):
            # Calls 1-2 are the pre-register checks — pass them.
            # Call 3 is the post-register double-check: block until
            # the revocation mark has landed, then answer honestly.
            _calls[0] += 1
            if _calls[0] <= 2:
                return False
            if _calls[0] == 3:
                entered.set()
                proceed.wait(timeout=5)
            return orig(key)

        result = []
        with _mock.patch.object(wsr, 'is_revoked_shared', _staggered):
            t = threading.Thread(target=lambda: result.append(
                register_connection(
                    sid, lambda: closed.append(1), 'terminal')))
            t.start()
            assert entered.wait(timeout=5)
            # Revocation lands while register() is paused between
            # registration and the double-check.
            from vnc_remote_secure.security.shared_state import get_backend
            get_backend().set_ttl('websocket_revoked_sessions',
                                  f'sid:{sid}', _t.time(), 86400)
            proceed.set()
            t.join(timeout=5)
        assert result == [None]   # refused — not left registered
        assert closed == [1]      # and its close callback fired


class TestStablePairRevocation:

    def test_group_revoke_cleans_every_indexed_sid(self):
        """Two same-second logins share username:created — pair
        revoke marks both sids and drops both ctxs."""
        from vnc_remote_secure.security.auth_policy import auth_context_for, record_auth_context
        from vnc_remote_secure.security.revocation import revoke_stable_pair
        from vnc_remote_secure.security.websocket_registry import is_revoked_shared

        stable = 'alice:1727.0'
        sid_a, sid_b = 'sidA' + 'x' * 14, 'sidB' + 'y' * 14
        record_auth_context(sid_a, {'username': 'alice'},
                            stable_id=stable)
        record_auth_context(sid_b, {'username': 'alice'},
                            stable_id=stable)

        res = revoke_stable_pair(stable)
        assert res.logically_revoked is True
        assert res.target_kind == 'legacy_pair'
        assert res.contexts_dropped == 2
        assert auth_context_for(sid_a) == {}
        assert auth_context_for(sid_b) == {}
        assert is_revoked_shared(f'sid:{sid_a}')
        assert is_revoked_shared(f'sid:{sid_b}')

    def test_group_revoke_tolerates_corrupt_sid(self):
        """A corrupt idx value (not a valid sid) is dropped but not
        marked — no crash, no partial failure cascade."""
        from vnc_remote_secure.security.revocation import revoke_stable_pair
        from vnc_remote_secure.security.shared_state import get_backend
        stable = 'alice:corrupt'
        be = get_backend()
        # Plant a corrupt idx entry directly.
        from vnc_remote_secure.security.auth_policy import _session_key
        be.set_ttl('web_auth_context',
                   f'idx:{_session_key(stable)}:{"x" * 64}',
                   'not-a-sid!!!', 60)
        res = revoke_stable_pair(stable)
        assert res.logically_revoked is True
        # Corrupt entry is reported structurally, non-retryable.
        assert any(e.code == 'INDEX_INVALID_SID' and not e.retryable
                   for e in res.errors)
        assert res.retry_recommended is False
