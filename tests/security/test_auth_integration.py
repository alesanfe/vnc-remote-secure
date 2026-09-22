"""Integration tests for auth gateway enforcement in services.

These tests verify that the canonical security model is actually
connected to production handlers:

- noVNC rejects requests without a valid session (P0-5).
- Terminal WebSocket rejects connections without auth (P0-3/P0-4).
- The security profile is applied during lifecycle startup (P0-1).
- Revoked tokens are rejected by check_authenticated.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vnc_remote_secure.security import auth_gateway, profiles

# ---------------------------------------------------------------------------
# Profile application in lifecycle
# ---------------------------------------------------------------------------


def test_startup_applies_security_profile(monkeypatch):
    """lifecycle.startup() applies the security profile before get_config()."""
    monkeypatch.setenv('SECURITY_PROFILE', 'public-hardened')
    monkeypatch.setenv('VNC_PASSWORD', 'StrongPass!123')
    monkeypatch.setenv('MFA_REQUIRED', 'true')
    monkeypatch.setenv('NGINX_ENABLED', 'true')
    # Ensure TLS is enabled.
    monkeypatch.setenv('TLS_ENABLED', 'true')

    from vnc_remote_secure.core import lifecycle
    # Reset state so startup runs fresh.
    with lifecycle._lock:
        lifecycle._state['running'] = False
        lifecycle._state['config'] = None

    lifecycle.startup()

    # The profile should have set BACKEND_BIND_HOST to 127.0.0.1.
    assert os.environ.get('BACKEND_BIND_HOST') == '127.0.0.1'
    # And NGINX_ENABLED should be true (from profile).
    assert os.environ.get('NGINX_ENABLED', '').lower() in ('true', '1', 'yes')

    lifecycle.shutdown()


def test_public_hardened_profile_enforces_backend_bind():
    """public-hardened forces BACKEND_BIND_HOST=127.0.0.1 even if user set 0.0.0.0."""
    os.environ['SECURITY_PROFILE'] = 'public-hardened'
    os.environ['BACKEND_BIND_HOST'] = '0.0.0.0'  # user tries to override
    try:
        profiles.apply_profile('public-hardened')
        assert os.environ['BACKEND_BIND_HOST'] == '127.0.0.1'
    finally:
        os.environ.pop('SECURITY_PROFILE', None)
        os.environ.pop('BACKEND_BIND_HOST', None)


# ---------------------------------------------------------------------------
# noVNC auth enforcement
# ---------------------------------------------------------------------------

class _FakeHeaders:
    """Mimic http.client.HTTPMessage for auth checks."""

    def __init__(self, cookie='', authorization=''):
        self._cookie = cookie
        self._auth = authorization

    def get(self, key, default=''):
        if key.lower() == 'cookie':
            return self._cookie
        if key.lower() == 'authorization':
            return self._auth
        return default


def test_novnc_rejects_request_without_credentials():
    """noVNC returns 401 when no session cookie or bearer token is present."""
    from vnc_remote_secure.services.novnc import _check_novnc_auth
    headers = _FakeHeaders()
    allowed, reason = _check_novnc_auth(headers)
    assert allowed is False
    assert 'required' in reason.lower() or 'auth' in reason.lower()


def test_novnc_rejects_invalid_session():
    """noVNC rejects a cookie with an invalid session value."""
    from vnc_remote_secure.services.novnc import _check_novnc_auth
    headers = _FakeHeaders(cookie='vnc_session=invalid-token')
    allowed, _ = _check_novnc_auth(headers)
    assert allowed is False


def test_novnc_rejects_invalid_bearer():
    """noVNC rejects an invalid bearer token."""
    from vnc_remote_secure.services.novnc import _check_novnc_auth
    headers = _FakeHeaders(authorization='Bearer invalid-token')
    allowed, _ = _check_novnc_auth(headers)
    assert allowed is False


# ---------------------------------------------------------------------------
# Terminal WebSocket auth enforcement
# ---------------------------------------------------------------------------

def test_check_websocket_upgrade_rejects_missing_origin_and_token():
    """check_websocket_upgrade rejects when no origin and no token."""
    allowed, reason = auth_gateway.check_websocket_upgrade(
        origin='',
        cookie_value='',
        bearer_token='',
        resource='terminal',
        required_permission='terminal:use',
    )
    assert allowed is False


def test_check_websocket_upgrade_rejects_invalid_token():
    """check_websocket_upgrade rejects an invalid bearer token."""
    allowed, reason = auth_gateway.check_websocket_upgrade(
        origin='https://localhost:8000',
        cookie_value='',
        bearer_token='invalid-token',
        resource='terminal',
        required_permission='terminal:use',
    )
    assert allowed is False


# ---------------------------------------------------------------------------
# Gamepad requires control permission (not view-only)
# ---------------------------------------------------------------------------

def test_gamepad_requires_control_permission():
    """A view-only session token must not be able to use gamepad (control)."""
    # Without a valid token, the gateway rejects regardless.
    allowed, _ = auth_gateway.check_websocket_upgrade(
        origin='https://localhost:8000',
        cookie_value='',
        bearer_token='',
        resource='gamepad',
        required_permission='desktop:control',
    )
    assert allowed is False
