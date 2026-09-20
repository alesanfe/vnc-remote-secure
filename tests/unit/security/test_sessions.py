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
        f"bob:{stale_seen - 100}:{stale_seen}:{stale_seen + 86400}")
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
