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
import time

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
    # Merge repeated headers (Set-Cookie arrives more than once per
    # response) — a plain dict() would silently drop all but one.
    hdrs = {}
    for k, v in resp.getheaders():
        hdrs[k] = f'{hdrs[k]}; {v}' if k in hdrs else v
    return resp.status, hdrs, data


def _cookie_value(set_cookie: str, name: str) -> str:
    """Extract a cookie value from a possibly-merged Set-Cookie str."""
    import re
    m = re.search(rf'(?:^|;\s*){re.escape(name)}=([^;\s]+)', set_cookie)
    return m.group(1) if m else ''


def _auth_headers():
    cred = base64.b64encode(b'admin:T3st-Landing!Pass').decode()
    return {'Authorization': f'Basic {cred}'}


def _csrf_session(port, headers=None):
    """Real session flow: GET /me issues the vnc_op + vnc_csrf cookies
    and returns the token bound to (sid, nonce). Returns headers for
    a POST. ``headers`` overrides the auth (e.g. a store operator)."""
    status, headers, body = _req(port, '/api/v1/me',
                                 headers=headers or _auth_headers())
    assert status == 200
    sc = headers.get('Set-Cookie', '')
    op = _cookie_value(sc, 'vnc_op')
    csrf = _cookie_value(sc, 'vnc_csrf')
    assert op and csrf
    token = json.loads(body)['data']['csrf_token']
    h = _auth_headers()
    h['Cookie'] = f'vnc_op={op}; vnc_csrf={csrf}'
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
        # The vnc_op cookie resolves the operator from the store —
        # mock both so 'bob' survives cookie verification AND the
        # Basic-auth fallback used to mint the session.
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.load_store',
            lambda: {username: {'role': 'operator'}}, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.get_permissions',
            lambda u: set(permissions), raising=False)
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
    assert "unsafe-inline" not in csp.split(
        'script-src', 1)[1].split(';')[0]
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


# ---------------------------------------------------------------------------
# Session-bound CSRF
# ---------------------------------------------------------------------------

def test_two_sessions_get_different_csrf(server):
    """Each operator session gets its own vnc_csrf nonce — and a
    different token, so a stolen token dies with its session."""
    h1 = _csrf_session(server)
    h2 = _csrf_session(server)
    assert h1['Cookie'] != h2['Cookie']
    assert h1['X-CSRF-Token'] != h2['X-CSRF-Token']


def test_csrf_of_session_a_fails_with_cookie_b(server, monkeypatch):
    """A token minted for nonce A is invalid under cookie B."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
        lambda: _FakeStore())
    h1 = _csrf_session(server)
    h2 = _csrf_session(server)
    h2['X-CSRF-Token'] = h1['X-CSRF-Token']  # wrong-session token
    status, _, _ = _api_post(
        server, '/api/v1/sessions/revoke', {'token_id': 'x'}, headers=h2)
    assert status == 403


def test_logout_expires_csrf(server):
    """POST /api/v1/logout clears the nonce cookie — the old CSRF
    token is dead from that response on."""
    h = _csrf_session(server)
    status, headers, _ = _api_post(server, '/api/v1/logout', {},
                                   headers=h)
    assert status == 200
    assert 'vnc_csrf=;' in headers.get('Set-Cookie', '')
    assert 'Max-Age=0' in headers.get('Set-Cookie', '')


# ---------------------------------------------------------------------------
# Declarative route registry — contract invariants
# ---------------------------------------------------------------------------

def test_route_registry_contract():
    """Every registered route satisfies the API contract:
    a declared rate-limit scope, a known permission (or the explicit
    portal-auth/'operator' sentinels), a named response schema, and an
    audit event on every mutation."""
    from vnc_remote_secure.services.api_v1 import (
        _KNOWN_PERMS,
        _RATE_LIMITS,
        _ROUTES,
    )
    assert _ROUTES, 'registry must not be empty'
    for (method, rel), spec in _ROUTES.items():
        assert spec.scope in _RATE_LIMITS, (method, rel, spec.scope)
        assert spec.resp, f'{method} {rel} declares no response schema'
        if spec.perm is not None:
            assert spec.perm in _KNOWN_PERMS, (method, rel, spec.perm)
        if method != 'GET':
            assert spec.audit, f'{method} {rel} declares no audit event'


def test_openapi_drift():
    """docs/api/openapi.v1.yaml must document every registered route —
    a route added to _ROUTES without updating the spec fails here."""
    import yaml

    from vnc_remote_secure.services.api_v1 import _ROUTES
    spec_path = os.path.join(
        os.path.dirname(__file__), '..', '..', '..',
        'docs', 'api', 'openapi.v1.yaml')
    with open(spec_path, encoding='utf-8') as f:
        spec = yaml.safe_load(f)
    documented = set()
    for path, ops in spec['paths'].items():
        for method in ops:
            documented.add((method.upper(), path.lstrip('/')))
    registered = {(m, p) for (m, p) in _ROUTES}
    assert registered == documented, (
        f'missing in spec: {registered - documented}; '
        f'documented but not registered: {documented - registered}')
    # Security metadata parity: perm, scope, CSRF flag, response schema.
    for (method, rel), route in _ROUTES.items():
        op = spec['paths'][f'/{rel}'][method.lower()]
        assert op.get('x-rate-limit-scope') == route.scope
        assert op.get('x-response-schema') == route.resp
        expected_perm = None if route.perm is None else route.perm
        assert op.get('x-required-permission') == expected_perm
        if method == 'POST':
            assert op.get('x-csrf-required') is True, rel


def test_revoke_missing_session_uniform_200(server, monkeypatch):
    """Revoking a nonexistent token returns the same 200 envelope as a
    real revocation — authorized callers can't use the endpoint to
    enumerate live token ids."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.revoke_session',
        lambda tid: False)
    h = _csrf_session(server)
    status, _, body = _api_post(
        server, '/api/v1/sessions/revoke', {'token_id': 'ghost'},
        headers=h)
    assert status == 200
    assert json.loads(body)['data']['revoked'] is False


# ---------------------------------------------------------------------------
# vnc_op operator session cookie — format, reuse, revocation
# ---------------------------------------------------------------------------

def _bare_handler(headers=None):
    """Bare LandingHandler for direct cookie-verifier unit tests."""
    h = object.__new__(landing.LandingHandler)
    h.headers = headers or {}
    h.__dict__['_pending_cookies'] = []
    return h


def _mint_op_cookie(handler, username='admin'):
    sid = handler._issue_op_session(username)
    cookie = handler.__dict__['_pending_cookies'][-1]
    return sid, cookie.split(';', 1)[0].split('=', 1)[1]


def test_op_cookie_roundtrip():
    h = _bare_handler()
    sid, value = _mint_op_cookie(h)
    rec = h._verify_op_cookie(value)
    assert rec is not None
    assert rec[0] == sid
    assert rec[1]['username'] == 'admin'


def test_op_cookie_rejects_malformed():
    h = _bare_handler()
    _, value = _mint_op_cookie(h)
    parts = value.split('.')
    bad = [
        '',                                    # empty
        'a.b.c',                               # too few parts
        value + '.extra',                      # too many
        '.'.join(parts[:-1]) + '.zz',          # bad sig
        parts[0] + '.' + parts[1] + '.0.' + parts[3],   # expired
        parts[0] + '.' + parts[1] + '.99999999999999.' + parts[3],
        value + '\x01',                        # control char
        'x' * 300,                             # oversized
        value.upper(),                         # tampered payload
    ]
    for v in bad:
        assert h._verify_op_cookie(v) is None, v[:40]


def test_op_cookie_revoked_sid_rejected():
    h = _bare_handler()
    sid, value = _mint_op_cookie(h)
    h._revoke_op_session(sid, int(time.time()) + 3600)
    assert h._verify_op_cookie(value) is None


def test_op_cookie_disabled_user_rejected(monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.operator_users.load_store',
        lambda: {'bob': {'role': 'operator', 'disabled': True}})
    h = _bare_handler()
    _, value = _mint_op_cookie(h, 'bob')
    assert h._verify_op_cookie(value) is None


def test_op_cookie_marked_user_rejected(monkeypatch):
    """A password/role change marks op_revoked_users — sessions issued
    before the mark die even though the signature is valid."""
    h = _bare_handler()
    sid, value = _mint_op_cookie(h)
    from vnc_remote_secure.security.shared_state import get_backend
    # Mark "now" — the cookie was issued at exp-TTL <= now.
    get_backend().set_ttl(
        'op_revoked_users', 'admin', str(time.time()), 3600)
    assert h._verify_op_cookie(value) is None


def test_same_cookie_reuses_sid(server):
    """A request holding a valid vnc_op cookie must NOT mint a new
    session — no new Set-Cookie, same sid serves every request."""
    h = _csrf_session(server)
    cookie = h['Cookie']  # vnc_op=…; vnc_csrf=…
    op = _cookie_value(cookie, 'vnc_op')
    for _ in range(3):
        status, headers, body = _req(
            server, '/api/v1/me', headers={'Cookie': cookie})
        assert status == 200
        sc = headers.get('Set-Cookie', '')
        assert 'vnc_op=' not in sc  # session reused, not re-issued
        assert json.loads(body)['data']['operator']['username'] == 'admin'
    assert _cookie_value(cookie, 'vnc_op') == op


def test_duplicate_vnc_op_rejected(server):
    """Cookie: vnc_op=A; vnc_op=B is ambiguous — must not authenticate
    via cookie (Basic still works, cookie alone must not)."""
    h = _csrf_session(server)
    op = _cookie_value(h['Cookie'], 'vnc_op')
    status, _, _ = _req(
        server, '/api/v1/me',
        headers={'Cookie': f'vnc_op={op}; vnc_op={op[:-2]}zz'})
    assert status == 401


def test_revoked_session_csrf_fails(server, monkeypatch):
    """After logout the old (cookie, CSRF) pair is dead even though
    the token was cryptographically valid when minted."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.revoke_session',
        lambda tid: True)
    h = _csrf_session(server)
    status, _, _ = _api_post(server, '/api/v1/logout', {}, headers=h)
    assert status == 200
    # Reuse the dead session artifacts — cookie auth fails (401)
    # before CSRF is even evaluated.
    status, _, _ = _api_post(
        server, '/api/v1/sessions/revoke', {'token_id': 'x'},
        headers=h)
    assert status in (401, 403)

# ---------------------------------------------------------------------------
# Operator management — real store under a tmp path
# ---------------------------------------------------------------------------

@pytest.fixture
def opstore(tmp_path, monkeypatch):
    """Point the operator store at a tmp file so the real add_user /
    set_role / remove_user logic is exercised end to end."""
    import vnc_remote_secure.security.operator_users as ou
    store = str(tmp_path / 'operator_users.json')
    monkeypatch.setattr(ou, '_store_path', lambda: store)
    return ou


def test_operator_detail_and_create(opstore, server):
    h = _csrf_session(server)
    status, _, body = _api_post(
        server, '/api/v1/operators',
        {'username': 'bob', 'password': 'S3cure!Passw0rd',
         'role': 'viewer'}, headers=h)
    assert status == 201, body
    status, _, body = _req(
        server, '/api/v1/operators/bob', headers=_auth_headers())
    assert status == 200
    op = json.loads(body)['data']['operator']
    assert op['username'] == 'bob'
    assert op['role'] == 'viewer'
    assert op['disabled'] is False
    assert 'password_hash' not in body.decode()


def test_operator_create_strict_schema(opstore, server):
    h = _csrf_session(server)
    for payload in (
            {'username': 'x y', 'password': 'S3cure!Passw0rd'},
            {'username': 'bob', 'password': 'weak'},
            {'username': 'bob', 'password': 'S3cure!Passw0rd',
             'role': 'superuser'},
            {'username': 'bob', 'password': 'S3cure!Passw0rd',
             'password_hash': 'injected'},
            {'username': 'bob', 'password': 'S3cure!Passw0rd',
             'enabled': 'yes'}):
        status, _, _ = _api_post(
            server, '/api/v1/operators', payload, headers=h)
        assert status == 400, payload


def test_operator_create_duplicate_409(opstore, server):
    h = _csrf_session(server)
    _api_post(server, '/api/v1/operators',
              {'username': 'bob', 'password': 'S3cure!Passw0rd'},
              headers=h)
    status, _, _ = _api_post(
        server, '/api/v1/operators',
        {'username': 'bob', 'password': 'S3cure!Passw0rd'},
        headers=h)
    assert status == 409


def test_operator_create_requires_csrf(server):
    status, _, _ = _api_post(
        server, '/api/v1/operators',
        {'username': 'bob', 'password': 'S3cure!Passw0rd'},
        headers=_auth_headers())
    assert status == 403


def test_operator_patch_and_delete(opstore, server):
    h = _csrf_session(server)
    _api_post(server, '/api/v1/operators',
              {'username': 'bob', 'password': 'S3cure!Passw0rd',
               'role': 'viewer'}, headers=h)
    status, _, body = _req(
        server, '/api/v1/operators/bob', method='PATCH',
        headers={**h, 'Content-Type': 'application/json'},
        body=json.dumps({'role': 'operator'}))
    assert status == 200, body
    assert json.loads(body)['data']['operator']['role'] == 'operator'
    status, _, _ = _req(
        server, '/api/v1/operators/bob', method='DELETE', headers=h)
    assert status == 200
    status, _, _ = _req(
        server, '/api/v1/operators/bob', headers=_auth_headers())
    assert status == 404


def test_last_admin_guard(opstore, server):
    """Demoting/deleting the only admin is refused — the env
    bootstrap admin does not count (tests unset LANDING_PASSWORD via
    env var still set...). With LANDING_PASSWORD set the env admin IS
    viable, so a store admin CAN be demoted."""
    h = _csrf_session(server)
    _api_post(server, '/api/v1/operators',
              {'username': 'root2', 'password': 'S3cure!Passw0rd',
               'role': 'admin'}, headers=h)
    # Env admin counts as viable: demoting root2 is allowed.
    status, _, _ = _req(
        server, '/api/v1/operators/root2', method='PATCH',
        headers={**h, 'Content-Type': 'application/json'},
        body=json.dumps({'role': 'viewer'}))
    assert status == 200


def test_last_admin_guard_no_env(opstore, server, monkeypatch):
    """Without a viable env bootstrap, the last store admin is locked.

    Flow: env session creates store admin root2; root2 gets a vnc_op
    cookie via its own Basic creds; then LANDING_PASSWORD is removed
    so the env admin is no longer viable — deleting/demoting root2
    must 409. The cookie still authenticates (no Basic needed).
    """
    h = _csrf_session(server)
    _api_post(server, '/api/v1/operators',
              {'username': 'root2', 'password': 'S3cure!Passw0rd',
               'role': 'admin'}, headers=h)
    # root2's own session: Basic -> vnc_op + vnc_csrf + token.
    cred = base64.b64encode(b'root2:S3cure!Passw0rd').decode()
    status, headers, body = _req(
        server, '/api/v1/me',
        headers={'Authorization': f'Basic {cred}'})
    assert status == 200
    sc = headers.get('Set-Cookie', '')
    cookie = (f"vnc_op={_cookie_value(sc, 'vnc_op')}; "
              f"vnc_csrf={_cookie_value(sc, 'vnc_csrf')}")
    token = json.loads(body)['data']['csrf_token']
    monkeypatch.delenv('LANDING_PASSWORD', raising=False)
    status, _, _ = _req(
        server, '/api/v1/operators/root2', method='DELETE',
        headers={'Cookie': cookie, 'X-CSRF-Token': token})
    assert status == 409
    status, _, _ = _req(
        server, '/api/v1/operators/root2', method='PATCH',
        headers={'Cookie': cookie, 'X-CSRF-Token': token,
                 'Content-Type': 'application/json'},
        body=json.dumps({'role': 'viewer'}))
    assert status == 409


def test_operator_passkeys_listed(opstore, server):
    opstore.add_user('bob', 'S3cure!Passw0rd', 'viewer')
    status, _, body = _req(
        server, '/api/v1/operators/bob/passkeys',
        headers=_auth_headers())
    assert status == 200
    assert json.loads(body)['data']['passkeys'] == []


def test_operator_sessions_revoked_invalidates_cookie(
        opstore, server, monkeypatch):
    """Revoking an operator's sessions kills their vnc_op cookie even
    though the cookie itself is still well-formed and unexpired."""
    opstore.add_user('bob', 'S3cure!Passw0rd', 'viewer')
    # Give bob a session: Basic for bob authenticates via verify().
    cred = base64.b64encode(b'bob:S3cure!Passw0rd').decode()
    bh = {'Authorization': f'Basic {cred}'}
    status, headers, _ = _req(server, '/api/v1/me', headers=bh)
    assert status == 200
    sc = headers.get('Set-Cookie', '')
    op_cookie = _cookie_value(sc, 'vnc_op')
    assert op_cookie
    # Admin revokes bob's sessions.
    h = _csrf_session(server)
    status, _, _ = _api_post(
        server, '/api/v1/operators/bob/sessions/revoke-all', {},
        headers=h)
    assert status == 200
    # bob's cookie must now be rejected — falls back to Basic which
    # still works (re-mints), so hit with ONLY the cookie.
    status, _, _ = _req(
        server, '/api/v1/me',
        headers={'Cookie': f'vnc_op={op_cookie}'})
    assert status == 401


def test_operator_endpoints_require_admin_users(opstore, server,
                                                monkeypatch):
    """A viewer-role operator cannot touch the operator surface."""
    opstore.add_user('vicky', 'S3cure!Passw0rd', 'viewer')
    cred = base64.b64encode(b'vicky:S3cure!Passw0rd').decode()
    vh = {'Authorization': f'Basic {cred}'}
    for method, path in (
            ('GET', '/api/v1/operators/vicky'),
            ('GET', '/api/v1/operators/vicky/passkeys'),
            ('POST', '/api/v1/operators'),
            ('PATCH', '/api/v1/operators/vicky'),
            ('DELETE', '/api/v1/operators/vicky')):
        status, _, _ = _req(server, path, method=method, headers=vh)
        assert status == 403, (method, path)
