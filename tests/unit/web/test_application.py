"""Unit tests for web.application module."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.web.application import SimpleWebApp, create_app


def test_create_app_returns_flask_when_available():
    """create_app returns a Flask app when Flask is installed."""
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed; fallback app is tested separately")
    app = create_app({})
    assert isinstance(app, Flask)


def test_create_app_registers_blueprints():
    """Flask app should register the expected blueprints."""
    pytest.importorskip('flask')
    app = create_app({})
    rules = {r.endpoint for r in app.url_map.iter_rules()}
    # health_bp, landing_bp, users_bp register endpoints containing these names.
    assert any('health' in r for r in rules)
    assert any('landing' in r for r in rules)
    assert any('user' in r for r in rules)


def test_create_app_has_secret_key():
    """Flask app must have a non-empty secret_key."""
    pytest.importorskip('flask')
    app = create_app({})
    assert app.secret_key
    assert len(app.secret_key) > 0


def test_create_app_stores_config():
    """Flask app should expose the provided config under VNC_CONFIG."""
    pytest.importorskip('flask')
    cfg = {'vnc_port': 9999, 'custom': True}
    app = create_app(cfg)
    assert app.config.get('VNC_CONFIG') is cfg


def test_fallback_app_serves_health():
    """SimpleWebApp should serve JSON at /health."""
    app = SimpleWebApp({})
    captured = {}

    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)
    body = b''.join(app({'PATH_INFO': '/health', 'REQUEST_METHOD': 'GET'}, start_response))
    assert captured['status'].startswith('200')
    assert 'application/json' in captured['headers'].get('Content-Type', '')
    import json
    data = json.loads(body)
    assert 'status' in data


def test_fallback_app_serves_text_for_other_paths(monkeypatch):
    """SimpleWebApp should serve a text page for non-health paths
    (with landing auth satisfied via a configured LANDING_PASSWORD)."""
    import base64
    monkeypatch.setenv('LANDING_PASSWORD', 'test-pass-1234')
    app = SimpleWebApp({})
    captured = {}

    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)
    cred = base64.b64encode(b'admin:test-pass-1234').decode()
    body = b''.join(app({
        'PATH_INFO': '/', 'REQUEST_METHOD': 'GET',
        'HTTP_AUTHORIZATION': f'Basic {cred}',
    }, start_response))
    assert captured['status'].startswith('200')
    assert 'text/plain' in captured['headers'].get('Content-Type', '')
    assert b'Flask' in body


def test_fallback_app_landing_denies_empty_password(monkeypatch):
    """With no LANDING_PASSWORD configured the landing is fail-closed
    (401), not open — a directly-launched service must not serve the
    portal unauthenticated."""
    monkeypatch.delenv('LANDING_PASSWORD', raising=False)
    app = SimpleWebApp({})
    captured = {}

    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)
    b''.join(app({'PATH_INFO': '/', 'REQUEST_METHOD': 'GET'}, start_response))
    assert captured['status'].startswith('401')


def test_flask_landing_exchanges_session_token(monkeypatch):
    """GET /?session=<signed> must activate the ephemeral session, set
    the vnc_ephemeral cookie and redirect — same semantics as the
    http.server landing service."""
    pytest.importorskip('flask')
    from vnc_remote_secure.security import ephemeral_sessions as ephem
    monkeypatch.setattr(
        ephem, 'activate_ephemeral_session', lambda signed, client_ip=None: 'internal-tok')
    app = create_app({})
    client = app.test_client()
    resp = client.get('/?session=ephemeral:x:1:0.sig')
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/')
    cookie = resp.headers.get('Set-Cookie', '')
    assert 'vnc_ephemeral=internal-tok' in cookie
    assert 'HttpOnly' in cookie
    assert resp.headers.get('Cache-Control') == 'no-store'


def test_flask_landing_rejects_invalid_session_token(monkeypatch):
    """An invalid/expired ?session= link returns 403, not the portal."""
    pytest.importorskip('flask')
    from vnc_remote_secure.security import ephemeral_sessions as ephem
    monkeypatch.setattr(
        ephem, 'activate_ephemeral_session', lambda signed, client_ip=None: None)
    app = create_app({})
    client = app.test_client()
    resp = client.get('/?session=ephemeral:bad:1:0.sig')
    assert resp.status_code == 403


def test_flask_session_cookie_does_not_collide_with_token_cookie():
    """Flask's session cookie must not be named 'vnc_session' — that
    name is reserved for the raw HMAC session token the non-Flask
    services (noVNC, terminal, audio, gamepad) verify via
    verify_session_cookie. A shared name made WS cookie-auth
    unresolvable."""
    pytest.importorskip('flask')
    app = create_app({})
    assert app.config['SESSION_COOKIE_NAME'] != 'vnc_session'


def test_flask_session_cookie_name_rejects_collision(monkeypatch):
    """An operator forcing SESSION_COOKIE_NAME=vnc_session must fall
    back to the safe default rather than collide with the token cookie."""
    pytest.importorskip('flask')
    monkeypatch.setenv('SESSION_COOKIE_NAME', 'vnc_session')
    app = create_app({})
    assert app.config['SESSION_COOKIE_NAME'] == 'vnc_flask_session'


def test_logout_expires_both_session_cookies():
    """POST /logout must expire vnc_session AND vnc_ephemeral.

    A share-link session cookie surviving logout means "logout" is a
    no-op for ephemeral users — the browser keeps a working credential.
    """
    pytest.importorskip('flask')
    app = create_app({})
    client = app.test_client()
    with client.session_transaction() as s:
        s['csrf_token'] = 'tok123'
    resp = client.post('/logout', headers={'X-CSRF-Token': 'tok123'})
    assert resp.status_code == 302
    cookies = resp.headers.getlist('Set-Cookie')
    expired = [c for c in cookies if 'Max-Age=0' in c]
    assert any('vnc_session=' in c for c in expired)
    assert any('vnc_ephemeral=' in c for c in expired)


class TestHardenedProfileGuards:
    """Fallback app + ephemeral secret must be refused in hardened
    profiles — otherwise a missing dep silently downgrades security."""

    @pytest.mark.parametrize(
        'profile', ['public-hardened', 'private-overlay', 'trusted-lan'])
    def test_hardened_profile_requires_flask_secret(
            self, monkeypatch, profile):
        pytest.importorskip('flask')
        monkeypatch.setenv('SECURITY_PROFILE', profile)
        monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.authentication._get_secret',
            lambda: b'', raising=False)
        with pytest.raises(RuntimeError, match='FLASK_SECRET_KEY'):
            create_app({})

    def test_development_profile_allows_persisted_secret(
            self, monkeypatch, tmp_path):
        pytest.importorskip('flask')
        monkeypatch.setenv('SECURITY_PROFILE', 'development')
        monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)
        app = create_app({})
        assert app.secret_key  # persisted auth secret reused


class TestCookieNameValidation:
    def test_malicious_cookie_name_sanitized(self, monkeypatch):
        pytest.importorskip('flask')
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        monkeypatch.setenv('SESSION_COOKIE_NAME',
                           'x; Secure\r\nSet-Cookie: evil=1')
        app = create_app({})
        name = app.config['SESSION_COOKIE_NAME']
        assert ';' not in name
        assert '\r' not in name
        assert '\n' not in name

    def test_valid_cookie_name_preserved(self, monkeypatch):
        pytest.importorskip('flask')
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        monkeypatch.setenv('SESSION_COOKIE_NAME', 'my_sess-1')
        app = create_app({})
        assert app.config['SESSION_COOKIE_NAME'] == 'my_sess-1'


class TestSecurityHeadersAndLimits:
    def test_security_headers_present(self, monkeypatch):
        pytest.importorskip('flask')
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        app = create_app({})
        c = app.test_client()
        resp = c.get('/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
        assert 'Content-Security-Policy' in resp.headers

    def test_oversized_body_rejected_413(self, monkeypatch):
        pytest.importorskip('flask')
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        app = create_app({})
        app.config['MAX_CONTENT_LENGTH'] = 16
        c = app.test_client()
        resp = c.post('/login', data={'x': 'y' * 100})
        assert resp.status_code == 413
