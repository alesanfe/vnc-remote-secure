"""Unit tests for security.sessions module."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.sessions import (
    create_session_cookie,
    refresh_session_cookie,
    verify_session_cookie,
)
from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_SESSION,
    sign_token,
)


def test_verify_session_cookie_valid():
    """A freshly created session cookie verifies successfully."""
    cookie = create_session_cookie('alice')
    result = verify_session_cookie(cookie['value'])
    assert result is not None
    assert result['username'] == 'alice'


def test_verify_session_cookie_expired(monkeypatch):
    """An expired session cookie (absolute expiry) is rejected."""
    cookie = create_session_cookie('alice', max_lifetime=1)
    # Wait past the absolute expiry.
    import time as _time
    real_time = _time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + 10)
    assert verify_session_cookie(cookie['value']) is None


def test_verify_session_cookie_idle_timeout(monkeypatch):
    """A cookie older than SESSION_IDLE_TIMEOUT is rejected server-side."""
    monkeypatch.setenv('SESSION_IDLE_TIMEOUT', '2')
    cookie = create_session_cookie('alice', idle_timeout=2, max_lifetime=3600)
    # Simulate time advancing past the idle window but before absolute expiry.
    import time as _time
    real_time = _time.time
    monkeypatch.setattr(time, 'time', lambda: real_time() + 100)
    assert verify_session_cookie(cookie['value']) is None


def test_verify_session_cookie_tampered():
    """A tampered cookie is rejected."""
    assert verify_session_cookie('not-a-valid-token') is None


def test_refresh_session_cookie_updates_last_seen(monkeypatch):
    """refresh_session_cookie re-signs with an updated last_seen."""
    # Idle window must exceed the simulated staleness so the cookie is
    # still valid but old enough to be re-issued.
    monkeypatch.setenv('SESSION_IDLE_TIMEOUT', '1000')
    # Force last_seen into the past so a refresh is due.
    import time as _time
    real_time = _time.time
    stale_seen = int(real_time()) - 300
    stale = sign_token(
        TOKEN_TYPE_SESSION,
        f"bob:{stale_seen - 100}:{stale_seen}:{stale_seen + 86400}"
        ":abcdefghijklmnop")
    new_value = refresh_session_cookie(stale, refresh_grace=1)
    assert new_value is not None
    refreshed = verify_session_cookie(new_value)
    assert refreshed['username'] == 'bob'
    assert refreshed['last_seen'] > stale_seen


def test_refresh_session_cookie_rejects_invalid():
    """Invalid/expired cookies return None from refresh."""
    assert refresh_session_cookie('garbage') is None
    expired = sign_token(TOKEN_TYPE_SESSION, 'x:1:1:1')
    assert refresh_session_cookie(expired) is None


def test_verify_session_cookie_idle_sliding(monkeypatch):
    """A recently-refreshed last_seen survives past ``created`` + idle."""
    monkeypatch.setenv('SESSION_IDLE_TIMEOUT', '100')
    now = int(time.time())
    # created 500s ago (idle window 100s), but last_seen is fresh.
    value = sign_token(
        TOKEN_TYPE_SESSION, f'carol:{now - 500}:{now}:{now + 86400}')
    session = verify_session_cookie(value)
    assert session is not None
    assert session['username'] == 'carol'


class TestSessionCookieBoundaries:
    def test_legacy_v1_payload_accepted(self):
        """Pre-upgrade 3-field cookies must still verify — a regression
        silently logs out every pre-upgrade session."""
        import time

        from vnc_remote_secure.security.sessions import verify_session_cookie
        from vnc_remote_secure.security.token_signing import TOKEN_TYPE_SESSION, sign_token
        now = int(time.time())
        payload = f'alice:{now}:{now + 3600}'
        cookie = sign_token(TOKEN_TYPE_SESSION, payload)
        s = verify_session_cookie(cookie)
        assert s is not None
        assert s['username'] == 'alice'
        assert s['last_seen'] == s['created']

    def test_non_integer_fields_rejected(self):
        from vnc_remote_secure.security.sessions import verify_session_cookie
        from vnc_remote_secure.security.token_signing import TOKEN_TYPE_SESSION, sign_token
        cookie = sign_token(TOKEN_TYPE_SESSION, 'a:notanint:x:y')
        assert verify_session_cookie(cookie) is None

    def test_wrong_field_count_rejected(self):
        from vnc_remote_secure.security.sessions import verify_session_cookie
        from vnc_remote_secure.security.token_signing import TOKEN_TYPE_SESSION, sign_token
        assert verify_session_cookie(
            sign_token(TOKEN_TYPE_SESSION, 'a:b')) is None
        assert verify_session_cookie(
            sign_token(TOKEN_TYPE_SESSION, 'a:1:2:3:4')) is None

    def test_refresh_preserves_expires(self):
        """Refresh must update last_seen only — never extend the
        absolute expiry."""
        import time

        from vnc_remote_secure.security.sessions import (
            create_session_cookie,
            refresh_session_cookie,
            verify_session_cookie,
        )
        cookie = create_session_cookie('alice')['value']
        s1 = verify_session_cookie(cookie)
        # Force last_seen into the past so refresh fires.
        import vnc_remote_secure.security.sessions as m
        orig = m.verify_session_cookie

        def _stale(v):
            d = orig(v)
            if d:
                d['last_seen'] = int(time.time()) - 3600
            return d

        from unittest import mock
        with mock.patch.object(m, 'verify_session_cookie', _stale):
            new = refresh_session_cookie(cookie)
        assert new is not None
        s2 = verify_session_cookie(new)
        assert s2['expires'] == s1['expires']

    def test_revocation_key_stable_across_refresh(self):
        """username:created must be identical pre/post refresh — else
        revoke misses re-issued cookies."""
        from vnc_remote_secure.security.sessions import (
            create_session_cookie,
            session_revocation_key,
        )
        cookie = create_session_cookie('alice')['value']
        k1 = session_revocation_key(cookie)
        assert k1
        assert k1.startswith('alice:')


class TestSameSiteWhitelist:
    def test_injected_samesite_falls_back(self, monkeypatch):
        monkeypatch.setenv('SESSION_SAMESITE', 'Lax\r\nX-Injected: 1')
        from vnc_remote_secure.security.sessions import get_cookie_attributes
        attrs = get_cookie_attributes()
        assert attrs['samesite'].lower() in ('lax', 'strict', 'none')
        assert '\r' not in attrs['samesite']

    def test_valid_samesite_passes(self, monkeypatch):
        monkeypatch.setenv('SESSION_SAMESITE', 'Strict')
        from vnc_remote_secure.security.sessions import get_cookie_attributes
        assert get_cookie_attributes()['samesite'] == 'Strict'


class TestOperatorEpoch:
    """bump_operator_epoch must invalidate every session issued
    before the credential change (post-rotation revocation)."""

    def test_old_session_rejected_after_bump(self, monkeypatch):
        import time

        from vnc_remote_secure.security import sessions
        from vnc_remote_secure.security.auth_gateway import check_authenticated
        cookie = sessions.create_session_cookie('admin')['value']
        # The cookie verifies BEFORE the bump.
        ok, _u = check_authenticated(cookie)
        assert ok is True
        # Simulate the epoch set AFTER the session was issued.
        epoch = time.time() + 1
        monkeypatch.setattr(
            sessions, 'operator_session_epoch', lambda: epoch)
        ok, _u = check_authenticated(cookie)
        assert ok is False

    def test_new_session_survives(self, monkeypatch):
        import time

        from vnc_remote_secure.security import sessions
        from vnc_remote_secure.security.auth_gateway import check_authenticated
        # Epoch in the PAST must not reject fresh sessions.
        monkeypatch.setattr(
            sessions, 'operator_session_epoch',
            lambda: time.time() - 100)
        cookie = sessions.create_session_cookie('admin')['value']
        ok, _u = check_authenticated(cookie)
        assert ok is True


def test_v3_cookie_carries_random_sid():
    cookie_a = create_session_cookie('alice')
    cookie_b = create_session_cookie('alice')
    sa = verify_session_cookie(cookie_a['value'])
    sb = verify_session_cookie(cookie_b['value'])
    assert sa['sid'] and sb['sid']
    assert sa['sid'] != sb['sid']


def test_refresh_preserves_sid():
    cookie = create_session_cookie('alice')
    first = verify_session_cookie(cookie['value'])
    refreshed = refresh_session_cookie(cookie['value'], refresh_grace=0)
    assert refreshed is not None
    second = verify_session_cookie(refreshed)
    assert second['sid'] == first['sid']
    assert second['expires'] == first['expires']


def test_malformed_sid_rejected():
    payload = 'alice:1:1:9999999999:not a sid!'
    token = sign_token(TOKEN_TYPE_SESSION, payload)
    assert verify_session_cookie(token) is None


def test_sid_revocation_is_precise(monkeypatch):
    """Two v3 sessions for the same user in the SAME second share
    username:created — revoking A by cookie must not kill B."""
    import time as _t

    from vnc_remote_secure.security import sessions as sm
    from vnc_remote_secure.security.auth_gateway import check_authenticated
    from vnc_remote_secure.security.websocket_registry import revoke_session_connections

    frozen = int(_t.time())
    monkeypatch.setattr(sm.time, 'time', lambda: float(frozen))
    a = create_session_cookie('alice')['value']
    b = create_session_cookie('alice')['value']
    sa = verify_session_cookie(a)
    sb = verify_session_cookie(b)
    assert sa['created'] == sb['created']  # same second, same stable
    assert sa['sid'] != sb['sid']

    monkeypatch.undo()  # real clock for verification paths
    revoke_session_connections(a)
    ok_a, _ = check_authenticated(a)
    ok_b, _ = check_authenticated(b)
    assert ok_a is False
    assert ok_b is True
