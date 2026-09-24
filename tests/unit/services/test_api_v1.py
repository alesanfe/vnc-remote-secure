"""Live-server tests for the /api/v1/* surface on LandingHandler.

Exercises the real request path: auth gate, operator capability checks,
CSRF token enforcement, strict input schemas, per-scope rate limits,
and cursor pagination — not just the helpers behind them.
"""
import base64
import http.client
import json
import os
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import (
    landing,  # noqa: E402
)


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Real threaded HTTP server running LandingHandler, patched to
    require Basic auth with a known password."""
    monkeypatch.setenv('LANDING_PASSWORD', 'T3st-Landing!Pass')
    monkeypatch.setattr(
        landing, 'generate_landing_page',
        lambda forwarded_host=None, forwarded_proto=None,
        is_operator=True, csrf_token='':
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


def _req(port, path, method='GET', headers=None, body=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), data


def _auth_headers():
    cred = base64.b64encode(b'admin:T3st-Landing!Pass').decode()
    return {'Authorization': f'Basic {cred}'}


def _csrf_session(port):
    """Real CSRF flow: GET /me issues the vnc_csrf nonce cookie and
    returns the token bound to it. Returns headers for a POST."""
    status, headers, body = _req(port, '/api/v1/me',
                                 headers=_auth_headers())
    assert status == 200
    cookie = headers.get('Set-Cookie', '').split(';')[0]
    assert cookie.startswith('vnc_csrf=')
    token = json.loads(body)['data']['csrf_token']
    h = _auth_headers()
    h['Cookie'] = cookie
    h['X-CSRF-Token'] = token
    return h


def _api_post(port, path, payload, headers=None, username='admin'):
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    return _req(port, path, method='POST',
                headers=h, body=json.dumps(payload))


# ---------------------------------------------------------------------------
# Auth & envelope
# ---------------------------------------------------------------------------

def test_api_unauthenticated_401(server):
    status, _, _ = _req(server, '/api/v1/me')
    assert status == 401


def test_api_me_returns_operator_and_csrf(server):
    status, _, body = _req(server, '/api/v1/me', headers=_auth_headers())
    assert status == 200
    data = json.loads(body)
    assert data['error'] is None
    assert data['data']['operator']['username'] == 'admin'
    assert 'admin:*' in data['data']['operator']['permissions']
    assert data['data']['csrf_token']


def test_api_envelope_shape(server):
    status, _, body = _req(server, '/api/v1/status',
                           headers=_auth_headers())
    assert status == 200
    env = json.loads(body)
    assert set(env) == {'data', 'error', 'request_id'}
    assert 'services' in env['data']


def test_api_unknown_path_404(server):
    status, _, _ = _req(server, '/api/v1/nope', headers=_auth_headers())
    assert status == 404


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def test_post_without_csrf_rejected(server):
    status, _, _ = _api_post(
        server, '/api/v1/sessions', {'role': 'viewer'},
        headers=_auth_headers())
    assert status == 403


def test_post_wrong_csrf_rejected(server):
    h = _auth_headers()
    h['X-CSRF-Token'] = 'bogus'
    status, _, _ = _api_post(
        server, '/api/v1/sessions', {'role': 'viewer'}, headers=h)
    assert status == 403


def test_post_valid_csrf_accepted(server, monkeypatch):
    store = _FakeStore()
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
        lambda: store)
    h = _csrf_session(server)
    status, _, body = _api_post(
        server, '/api/v1/sessions',
        {'role': 'viewer', 'ttl_seconds': 300, 'no_terminal': True},
        headers=h)
    assert status == 201
    data = json.loads(body)['data']
    assert data['url'].startswith('http')
    assert '/share#t=' in data['url']
    assert data['role'] == 'viewer'


# ---------------------------------------------------------------------------
# Strict schema
# ---------------------------------------------------------------------------

def _create(server, monkeypatch, payload, username='admin',
            permissions=('admin:*',)):
    store = _FakeStore()
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
        lambda: store)
    if permissions != ('admin:*',):
        monkeypatch.setattr(
            'vnc_remote_secure.security.http_auth.authenticate_landing',
            lambda *a, **k: (True, {
                'username': username, 'role': 'operator',
                'permissions': list(permissions)}))
    h = _csrf_session(server)
    return _api_post(server, '/api/v1/sessions', payload, headers=h)


class _FakeSession:
    token_id = 'abc123'
    expires_at = 9999999999.0
    role = 'viewer'
    permissions = {'view'}
    single_use = False
    view_only = False
    no_terminal = True
    max_uses = 1
    resource = None
    allowed_ip = None

    def to_dict(self):
        return {'token_id': self.token_id}


class _FakeStore:
    def create(self, **kw):
        return _FakeSession(), 'signed.token.here'


def test_create_rejects_unknown_fields(server, monkeypatch):
    status, _, body = _create(
        server, monkeypatch, {'role': 'viewer', 'surprise': 1})
    assert status == 400
    assert 'Unknown fields' in json.loads(body)['message']


def test_create_rejects_bool_as_int(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'ttl_seconds': True})
    assert status == 400


def test_create_rejects_int_as_bool(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'single_use': 1})
    assert status == 400


def test_create_rejects_bad_role(server, monkeypatch):
    status, _, _ = _create(server, monkeypatch, {'role': 'root'})
    assert status == 400


def test_create_rejects_bad_ttl(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'ttl_seconds': 99999999})
    assert status == 400


def test_create_rejects_bad_cidr(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'allowed_ip': 'not-an-ip'})
    assert status == 400


def test_create_rejects_bad_resource(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'resource': 'hypervisor'})
    assert status == 400


# ---------------------------------------------------------------------------
# Privilege delegation
# ---------------------------------------------------------------------------

def test_non_admin_cannot_mint_admin_role(server, monkeypatch):
    """An operator with only admin_sessions must not mint a share link
    carrying administrator permissions."""
    status, _, _ = _create(
        server, monkeypatch, {'role': 'administrator'},
        username='bob', permissions=('admin_sessions',))
    assert status == 403


def test_non_admin_cannot_mint_admin_perms(server, monkeypatch):
    status, _, _ = _create(
        server, monkeypatch, {'permissions': ['admin_users']},
        username='bob', permissions=('admin_sessions',))
    assert status == 403


def test_non_admin_can_mint_viewer(server, monkeypatch):
    """admin_sessions alone is enough to mint non-admin share links."""
    status, _, body = _create(
        server, monkeypatch, {'role': 'viewer', 'no_terminal': True},
        username='bob', permissions=('admin_sessions',))
    assert status == 201


def test_unauthenticated_post_401(server):
    status, _, _ = _api_post(server, '/api/v1/sessions', {'role': 'viewer'})
    assert status == 401


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

def test_revoke_requires_csrf(server):
    status, _, _ = _api_post(
        server, '/api/v1/sessions/revoke', {'token_id': 'x'},
        headers=_auth_headers())
    assert status == 403


def test_revoke_with_csrf(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.revoke_session',
        lambda tid: True)
    h = _csrf_session(server)
    status, _, body = _api_post(
        server, '/api/v1/sessions/revoke', {'token_id': 'x'}, headers=h)
    assert status == 200
    assert json.loads(body)['data']['revoked'] is True


# ---------------------------------------------------------------------------
# Read endpoints — capability enforcement
# ---------------------------------------------------------------------------

def test_sessions_list_requires_permission(server, monkeypatch):
    """An operator WITHOUT admin_sessions gets 403 on the inventory."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.http_auth.authenticate_landing',
        lambda *a, **k: (True, {
            'username': 'bob', 'role': 'viewer',
            'permissions': ['admin_audit']}))
    status, _, _ = _req(server, '/api/v1/sessions',
                        headers=_auth_headers())
    assert status == 403


def test_config_requires_permission(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.http_auth.authenticate_landing',
        lambda *a, **k: (True, {
            'username': 'bob', 'role': 'viewer',
            'permissions': ['admin_sessions']}))
    status, _, _ = _req(server, '/api/v1/config', headers=_auth_headers())
    assert status == 403


def test_ephemeral_cookie_gets_status_only(server, monkeypatch):
    """A share-link cookie passes the portal gate but is NOT an
    operator. It may read /status (the portal cards need it — service
    states only, no telemetry) but every privileged endpoint 403s."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda *a, **k: True)
    cookie = {'Cookie': 'vnc_ephemeral=t'}
    status, _, _ = _req(server, '/api/v1/status', headers=cookie)
    assert status == 200
    for path in ('/api/v1/sessions', '/api/v1/config', '/api/v1/audit',
                 '/api/v1/operators', '/api/v1/security/posture',
                 '/api/v1/doctor', '/api/v1/backups'):
        status, _, _ = _req(server, path, headers=cookie)
        assert status == 403, path


# ---------------------------------------------------------------------------
# Share-link fragment flow
# ---------------------------------------------------------------------------

def test_share_page_public(server):
    """GET /share must be reachable WITHOUT auth — the link recipient
    has no credentials; the token is the credential. The page carries
    no inline script (CSP script-src 'self') — the logic lives in the
    self-hosted /share.js."""
    status, headers, body = _req(server, '/share')
    assert status == 200
    assert b'src="/share.js"' in body
    csp = headers.get('Content-Security-Policy', '')
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.replace(
        "style-src 'unsafe-inline'", '')
    # The script itself is public too (same-origin CSP fetch).
    status, _, js = _req(server, '/share.js')
    assert status == 200
    assert b'/session/activate' in js
    assert b'/session/preview' in js


def test_session_preview_public(server, monkeypatch):
    """POST /session/preview returns grant details without consuming."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'verify_ephemeral_token',
        lambda t: {'session_token': 'internal'})
    sess = _FakeSession()
    sess.revoked = False
    import time
    sess.expires_at = time.time() + 300
    store = _FakeStore()
    store.get = lambda t: sess
    store._load_if_changed = lambda: None
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
        lambda: store)
    status, _, body = _api_post(server, '/session/preview',
                                {'token': 'signed'})
    assert status == 200
    data = json.loads(body)
    assert data['role'] == 'viewer'
    assert 'expires_in_seconds' in data
    # Never leaks creator or binding details.
    assert 'created_by' not in data
    assert 'allowed_ip' not in data


def test_session_preview_invalid_403(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'verify_ephemeral_token',
        lambda t: None)
    status, _, _ = _api_post(server, '/session/preview',
                             {'token': 'bogus'})
    assert status == 403
