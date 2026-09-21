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

import vnc_remote_secure.services.landing as landing  # noqa: E402


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
