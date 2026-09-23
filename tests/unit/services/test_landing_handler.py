"""Live-server tests for the landing HTTP handler.

Spins LandingHandler on a real ThreadingHTTPServer over loopback so
the full request path is exercised: the auth gate, the ephemeral
session exchange, HEAD/GET routing, and status.json — not just the
helpers behind them.
"""
import base64
import http.client
import os
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import landing  # noqa: E402


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Real threaded HTTP server running LandingHandler, patched to
    require Basic auth with a known password."""
    monkeypatch.setenv('LANDING_PASSWORD', 'T3st-Landing!Pass')
    monkeypatch.setattr(
        landing, 'generate_landing_page',
        lambda forwarded_host=None, forwarded_proto=None:
        '<html><body>portal</body></html>')
    monkeypatch.setattr(landing, 'check_port', lambda *a, **k: True)
    monkeypatch.setattr(landing, 'get_lan_ips', lambda: ['10.0.0.9'])
    monkeypatch.setattr(
        landing, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    cfg = {
        'novnc_port': 6080, 'ttyd_port': 7681, 'health_port': 8080,
        'landing_port': 8000, 'vnc_port': 5900, 'vnc_http_port': 5800,
        'novnc_host': '127.0.0.1', 'ttyd_host': '127.0.0.1',
        'health_host': '127.0.0.1',
    }
    monkeypatch.setattr(landing, '_config', lambda: cfg)
    # Serve from a scratch dir so SimpleHTTPRequestHandler never leaks
    # the project tree for unhandled paths.
    cwd = os.getcwd()
    os.chdir(tmp_path)
    srv = socketserver.ThreadingTCPServer(
        ('127.0.0.1', 0), landing.LandingHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()
    os.chdir(cwd)


def _req(port, path, method='GET', headers=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


def _auth_headers():
    cred = base64.b64encode(b'admin:T3st-Landing!Pass').decode()
    return {'Authorization': f'Basic {cred}'}


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------

def test_get_unauthenticated_returns_401(server):
    status, headers, body = _req(server, '/')
    assert status == 401
    assert 'WWW-Authenticate' in headers


def test_head_unauthenticated_returns_401(server):
    """HEAD goes through the same auth gate — no metadata leak."""
    status, headers, body = _req(server, '/', method='HEAD')
    assert status == 401


def test_get_authenticated_serves_portal(server):
    status, headers, body = _req(server, '/', headers=_auth_headers())
    assert status == 200
    assert b'portal' in body


def test_get_wrong_password_401(server):
    cred = base64.b64encode(b'admin:wrong').decode()
    status, _, _ = _req(
        server, '/', headers={'Authorization': f'Basic {cred}'})
    assert status == 401


def test_status_json_authenticated(server):
    status, headers, body = _req(
        server, '/status.json', headers=_auth_headers())
    assert status == 200
    import json
    data = json.loads(body)
    assert 'services' in data
    assert 'landing_page' in data['services']


def test_unknown_path_404_when_authed(server):
    status, _, _ = _req(server, '/nonexistent', headers=_auth_headers())
    assert status == 404


def test_head_known_path_200_when_authed(server):
    status, _, body = _req(
        server, '/', method='HEAD', headers=_auth_headers())
    assert status == 200
    assert body == b''


def test_head_unknown_path_404_when_authed(server):
    status, _, _ = _req(
        server, '/nope.txt', method='HEAD', headers=_auth_headers())
    assert status == 404


# ---------------------------------------------------------------------------
# Ephemeral session exchange (?session=)
# ---------------------------------------------------------------------------

def test_session_exchange_invalid_token_403(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.activate_ephemeral_session',
        lambda signed, client_ip=None: None)
    status, _, _ = _req(server, '/?session=bogus')
    assert status == 403


def test_session_exchange_sets_cookie_and_redirects(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.activate_ephemeral_session',
        lambda signed, client_ip=None: 'internal-tok')
    status, headers, _ = _req(server, '/?session=valid.signed')
    assert status == 302
    assert headers.get('Location', '').endswith('/')
    cookie = headers.get('Set-Cookie', '')
    assert 'vnc_ephemeral=internal-tok' in cookie
    assert 'HttpOnly' in cookie


def test_ephemeral_cookie_grants_portal(server, monkeypatch):
    """A valid vnc_ephemeral cookie bypasses Basic auth on the portal."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda internal, perm, client_ip=None, resource=None: True)
    status, _, body = _req(
        server, '/', headers={'Cookie': 'vnc_ephemeral=tok'})
    assert status == 200
    assert b'portal' in body


def test_invalid_ephemeral_falls_back_to_basic_401(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda *a, **k: False)
    status, headers, _ = _req(
        server, '/', headers={'Cookie': 'vnc_ephemeral=bad'})
    assert status == 401
    assert 'WWW-Authenticate' in headers


# ---------------------------------------------------------------------------
# Share-link prefetch interstitial + log redaction
# ---------------------------------------------------------------------------

def test_prefetch_does_not_consume_token(server, monkeypatch):
    """Link scanners/prefetchers must get the interstitial WITHOUT
    consuming the single-use session."""
    calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'activate_ephemeral_session',
        lambda *a, **kw: calls.append(1) or _FakeSession(),
        raising=False)
    status, headers, body = _req(
        server, '/?session=SIGNEDTOK',
        headers={**_auth_headers(), 'Sec-Purpose': 'prefetch'})
    assert status == 200
    assert calls == []  # token NOT consumed
    # Interstitial keeps the session link for the real navigation.
    assert b'session=SIGNEDTOK' in body


def test_real_navigation_consumes_token(server, monkeypatch):
    """A real navigation (no prefetch hints) consumes the session and
    sets the vnc_ephemeral cookie + redirect."""
    calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'activate_ephemeral_session',
        lambda *a, **kw: calls.append(1) or _FakeSession(),
        raising=False)
    status, headers, body = _req(
        server, '/?session=SIGNEDTOK', headers=_auth_headers())
    assert calls == [1]
    assert status in (302, 303)
    assert 'vnc_ephemeral' in headers.get('Set-Cookie', '')


class _FakeSession:
    token = 'internal-tok'
    permissions = {'view'}
    role = 'viewer'
    single_use = True


def test_log_message_redacts_session_token(server, caplog):
    """The signed session token must never reach the access log."""
    import logging
    caplog.set_level(logging.INFO)
    # Any authenticated request with ?session= logs the path.
    _req(server, '/?session=SECRETTOKEN123', headers=_auth_headers())
    joined = ' '.join(r.getMessage() for r in caplog.records)
    assert 'SECRETTOKEN123' not in joined


class TestHostHeaderXss:
    """Host / X-Forwarded-Host must never reach the rendered page
    verbatim — reflected XSS on authenticated endpoints."""

    def test_safe_ws_host_passes_valid(self):
        from vnc_remote_secure.services.landing import _safe_ws_host
        assert _safe_ws_host('vnc.example.com') == 'vnc.example.com'
        assert _safe_ws_host('127.0.0.1:8000') == '127.0.0.1:8000'
        assert _safe_ws_host('[::1]') == '[::1]'

    def test_safe_ws_host_rejects_xss(self):
        from vnc_remote_secure.services.landing import _safe_ws_host
        for evil in ('"><script>alert(1)</script>',
                     "x'onload='alert(1)", 'a\nb', 'a;b', 'a b', ''):
            assert _safe_ws_host(evil) == '127.0.0.1', evil

    def test_landing_page_ignores_malicious_forwarded_host(
            self, monkeypatch, fake_metrics):
        """A crafted X-Forwarded-Host must not appear in the HTML."""
        from vnc_remote_secure.services import landing
        monkeypatch.setattr(landing, 'check_port', lambda *a, **k: False)
        monkeypatch.setattr(landing, 'get_system_metrics',
                            lambda: fake_metrics)
        page = landing.generate_landing_page(
            forwarded_host='"><script>alert(1)</script>',
            forwarded_proto='https')
        assert '<script>alert(1)' not in page
        assert '"><script' not in page

    def test_forwarded_host_valid_used_in_links(self, monkeypatch, fake_metrics):
        from vnc_remote_secure.services import landing
        monkeypatch.setattr(landing, 'check_port', lambda *a, **k: False)
        monkeypatch.setattr(landing, 'get_system_metrics',
                            lambda: fake_metrics)
        page = landing.generate_landing_page(
            forwarded_host='vnc.example.com', forwarded_proto='https')
        assert 'https://vnc.example.com/vnc/vnc.html' in page


class TestExchangeSecureCookie:
    """The vnc_ephemeral cookie must be Secure over TLS — both via
    X-Forwarded-Proto (trusted proxy) and direct TLS sockets."""

    def _handler(self, stub_handler):
        from vnc_remote_secure.services.landing import LandingHandler
        return stub_handler(LandingHandler, path='/?session=tok')

    def test_secure_flag_when_forwarded_https(self, monkeypatch, stub_handler):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        h = self._handler(stub_handler)
        h.headers = {'X-Forwarded-Proto': 'https'}
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'activate_ephemeral_session',
            lambda t, client_ip=None: 'inner', raising=False)
        h._handle_session_exchange()
        cookie = [c for c in h.send_header.call_args_list
                  if c[0][0] == 'Set-Cookie'][0][0][1]
        assert 'Secure' in cookie

    def test_no_secure_flag_plain_http(self, monkeypatch, stub_handler):
        """Plain HTTP must NOT mark the cookie Secure — the browser
        would never return it."""
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        h = self._handler(stub_handler)
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'activate_ephemeral_session',
            lambda t, client_ip=None: 'inner', raising=False)
        h._handle_session_exchange()
        cookie = [c for c in h.send_header.call_args_list
                  if c[0][0] == 'Set-Cookie'][0][0][1]
        assert 'Secure' not in cookie

    def test_forwarded_proto_ignored_without_trust(self, monkeypatch, stub_handler):
        """X-Forwarded-Proto=https on an UNTRUSTED direct connection
        must not set Secure — header spoofing would strip the cookie."""
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        h = self._handler(stub_handler)
        h.headers = {'X-Forwarded-Proto': 'https'}
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'activate_ephemeral_session',
            lambda t, client_ip=None: 'inner', raising=False)
        h._handle_session_exchange()
        cookie = [c for c in h.send_header.call_args_list
                  if c[0][0] == 'Set-Cookie'][0][0][1]
        assert 'Secure' not in cookie
