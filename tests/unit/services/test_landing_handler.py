"""Live-server tests for the landing portal surface.

Spins the FastAPI app on a real uvicorn instance over loopback so
the full request path is exercised: the auth gate, the ephemeral
session exchange, HEAD/GET routing, and status.json — not just the
helpers behind them.
"""
import base64
import http.client
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import landing  # noqa: E402


@pytest.fixture
def server(monkeypatch, tmp_path, asgi_server):
    """Real uvicorn server running the FastAPI portal app, patched to
    require Basic auth with a known password.

    The status payload now flows through the engine read model
    (``stores`` → ``core.portal``), so the probes are patched at the
    ``core.portal`` seam — the same seam _patch_portal_stores uses.
    """
    monkeypatch.setenv('LANDING_PASSWORD', 'T3st-Landing!Pass')
    from vnc_remote_secure.core import portal as cp
    monkeypatch.setattr(cp, 'check_port', lambda *a, **k: True)
    monkeypatch.setattr(cp, 'get_lan_ips', lambda: ['10.0.0.9'])
    monkeypatch.setattr(
        cp, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    cfg = {
        'novnc_port': 6080, 'ttyd_port': 7681, 'health_port': 8080,
        'landing_port': 8000, 'vnc_port': 5900, 'vnc_http_port': 5800,
        'novnc_host': '127.0.0.1', 'ttyd_host': '127.0.0.1',
        'health_host': '127.0.0.1', 'audio_stream_enabled': False,
        'gamepad_enabled': False,
    }
    monkeypatch.setattr(cp, 'portal_config', lambda: cfg)
    monkeypatch.setattr(landing, '_config', lambda: cfg)
    # Serve from a scratch dir so nothing leaks the project tree.
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        from vnc_remote_secure.backend.app import create_app
        yield asgi_server(create_app())
    finally:
        os.chdir(cwd)


class _Hdrs(dict):
    """Case-insensitive response-header mapping (ASGI servers
    lowercase names on the wire — http.client returns them as sent)."""
    def __getitem__(self, k):
        return super().__getitem__(k.lower())

    def get(self, k, default=None):
        return super().get(k.lower(), default)

    def __contains__(self, k):
        return super().__contains__(k.lower())


def _req(port, path, method='GET', headers=None, body=None):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    hdrs = _Hdrs()
    for k, v in resp.getheaders():
        kl = k.lower()
        hdrs[kl] = f'{hdrs[kl]}; {v}' if kl in hdrs else v
    return resp.status, hdrs, data


def _auth_headers():
    cred = base64.b64encode(b'admin:T3st-Landing!Pass').decode()
    return {'Authorization': f'Basic {cred}'}


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------

def test_get_unauthenticated_returns_401(server):
    # The SPA shell is public; data endpoints keep the auth gate.
    status, headers, body = _req(server, '/status.json')
    assert status == 401
    assert 'WWW-Authenticate' in headers


def test_root_serves_spa_publicly(server):
    """GET / serves the React SPA — a public static shell; every API
    call it makes is independently authenticated."""
    status, _, body = _req(server, '/')
    assert status == 200
    assert b'id="root"' in body


def test_head_unauthenticated_returns_401(server):
    """HEAD goes through the same auth gate — no metadata leak."""
    status, headers, body = _req(server, '/status.json', method='HEAD')
    assert status == 401


def test_get_authenticated_serves_portal(server):
    status, headers, body = _req(server, '/', headers=_auth_headers())
    assert status == 200
    assert b'id="root"' in body


def test_get_wrong_password_401(server):
    cred = base64.b64encode(b'admin:wrong').decode()
    status, _, _ = _req(
        server, '/status.json',
        headers={'Authorization': f'Basic {cred}'})
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
# Ephemeral session exchange (?session= interstitial -> POST activate)
# ---------------------------------------------------------------------------

def _post_activate(port, token, headers=None):
    import json as _j
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    return _req(port, '/api/v1/session/activate', method='POST',
                headers=h, body=_j.dumps({'token': token}))


def _mock_valid_share(monkeypatch):
    """Make the interstitial preview see a live session for
    'SIGNEDTOK' — verify + store lookups both succeed."""
    import time as _t

    class _Sess:
        revoked = False
        expires_at = _t.time() + 300
        role = 'viewer'
        view_only = True
        single_use = True
        no_terminal = False
        max_uses = 0
        allowed_ip = None
        resource = None

    class _Store:
        def _load_if_changed(self): pass
        def get(self, token): return _Sess()

    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'verify_ephemeral_token',
        lambda t: {'session_token': 'internal'} if t else None,
        raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'get_session_store',
        lambda: _Store(), raising=False)


def test_session_exchange_get_serves_spa(server, monkeypatch):
    """GET never activates: the link lands on the React SPA, which
    wipes the token client-side and POSTs it to /api/v1/session/
    preview — the server response never echoes the token."""
    calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'activate_ephemeral_session',
        lambda *a, **kw: calls.append(1) or 'internal-tok',
        raising=False)
    _mock_valid_share(monkeypatch)
    status, _, body = _req(server, '/?session=SIGNEDTOK')
    assert status == 200
    assert calls == []  # GET does not consume
    assert b'id="root"' in body
    assert b'SIGNEDTOK' not in body  # token never leaves the client


def test_session_activate_invalid_token_403(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.activate_ephemeral_session',
        lambda signed, client_ip=None: None)
    status, _, _ = _post_activate(server, 'bogus')
    assert status == 403


def test_session_activate_sets_cookie(server, monkeypatch):
    """Activation returns JSON + the vnc_ephemeral Set-Cookie (the SPA
    navigates to '/' itself — no server redirect)."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.activate_ephemeral_session',
        lambda signed, client_ip=None: 'internal-tok')
    status, headers, _ = _post_activate(server, 'valid.signed')
    assert status == 200
    cookie = headers.get('Set-Cookie', '')
    assert 'vnc_ephemeral=internal-tok' in cookie
    assert 'HttpOnly' in cookie


def test_ephemeral_cookie_grants_portal(server, monkeypatch):
    """A valid vnc_ephemeral cookie passes the portal gate on data
    endpoints (the SPA itself is public static)."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda internal, perm, client_ip=None, resource=None: True)
    status, _, _ = _req(
        server, '/status.json', headers={'Cookie': 'vnc_ephemeral=tok'})
    assert status == 200


def test_invalid_ephemeral_falls_back_to_basic_401(server, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda *a, **k: False)
    status, headers, _ = _req(
        server, '/status.json', headers={'Cookie': 'vnc_ephemeral=bad'})
    assert status == 401
    assert 'WWW-Authenticate' in headers


# ---------------------------------------------------------------------------
# Share-link prefetch interstitial + log redaction
# ---------------------------------------------------------------------------

def test_prefetch_does_not_consume_token(server, monkeypatch):
    """Link scanners/prefetchers get the SPA shell only — nothing on
    the server consumes the single-use session (the React page's
    preview POST is itself non-consuming)."""
    calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'activate_ephemeral_session',
        lambda *a, **kw: calls.append(1) or _FakeSession(),
        raising=False)
    _mock_valid_share(monkeypatch)
    status, headers, body = _req(
        server, '/?session=SIGNEDTOK',
        headers={**_auth_headers(), 'Sec-Purpose': 'prefetch'})
    assert status == 200
    assert calls == []  # token NOT consumed
    assert b'SIGNEDTOK' not in body


def test_real_navigation_consumes_token(server, monkeypatch):
    """GET serves the SPA; only the explicit POST to
    /api/v1/session/activate consumes the session and sets the
    vnc_ephemeral cookie."""
    calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.'
        'activate_ephemeral_session',
        lambda *a, **kw: calls.append(1) or _FakeSession(),
        raising=False)
    _mock_valid_share(monkeypatch)
    status, headers, body = _req(
        server, '/?session=SIGNEDTOK', headers=_auth_headers())
    assert status == 200
    assert calls == []  # GET never consumes
    status, headers, _ = _post_activate(server, 'SIGNEDTOK')
    assert calls == [1]
    assert status == 200
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
    """Host / X-Forwarded-Host must never reach a rendered page
    verbatim — reflected XSS on authenticated endpoints."""

    def _patch_portal_stores(self, monkeypatch, fake_metrics,
                             nginx=False):
        """Patch the engine read-model inputs at the boundary the code
        actually reads: core.portal (transport-free helpers)."""
        from vnc_remote_secure.core import portal as cp
        monkeypatch.setattr(cp, 'check_port', lambda *a, **k: False)
        monkeypatch.setattr(cp, 'get_system_metrics',
                            lambda: fake_metrics)
        monkeypatch.setattr(cp, 'get_lan_ips', list)
        monkeypatch.setattr(cp, 'tls_available', lambda cfg: False)
        cfg = dict(cp.portal_config())
        cfg['nginx_enabled'] = nginx
        monkeypatch.setattr(cp, 'portal_config', lambda: cfg)
        monkeypatch.setattr(
            'vnc_remote_secure.engine.infrastructure.stores.'
            'session_store', lambda: _EmptyStore(), raising=False)

    def test_portal_ignores_malicious_forwarded_host(
            self, monkeypatch, fake_metrics):
        """A crafted X-Forwarded-Host must not reach the portal
        read-model — the SPA renders these URLs into hrefs."""
        from vnc_remote_secure.engine.application import read_models
        self._patch_portal_stores(monkeypatch, fake_metrics)
        data = read_models.portal(
            is_operator=False, host='',
            forwarded_host='"><script>alert(1)</script>',
            forwarded_proto='https', is_tls=True, trusted_proxy=True)
        rendered = repr(data)
        assert '<script>alert(1)' not in rendered
        assert '"><script' not in rendered
        assert data['external_base'] is None

    def test_forwarded_host_valid_used_in_links(
            self, monkeypatch, fake_metrics):
        from vnc_remote_secure.engine.application import read_models
        self._patch_portal_stores(monkeypatch, fake_metrics, nginx=True)
        data = read_models.portal(
            is_operator=False, host='',
            forwarded_host='vnc.example.com', forwarded_proto='https',
            is_tls=True, trusted_proxy=True)
        urls = [s['url'] for s in data['services'] if s.get('url')]
        assert 'https://vnc.example.com/vnc/vnc.html' in urls


class _EmptyStore:
    def list_active(self):
        return []


class TestExchangeSecureCookie:
    """The vnc_ephemeral cookie must be Secure over TLS — both via
    X-Forwarded-Proto (trusted proxy) and direct TLS sockets. Exercised
    end-to-end through POST /api/v1/session/activate."""

    def _activate(self, server, monkeypatch, headers=None):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'activate_ephemeral_session',
            lambda signed, client_ip=None: 'internal-tok')
        status, hdrs, _ = _post_activate(server, 'tok', headers=headers)
        assert status == 200
        return hdrs.get('Set-Cookie', '')

    def test_secure_flag_when_forwarded_https(self, server, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        cookie = self._activate(
            server, monkeypatch,
            headers={'X-Forwarded-Proto': 'https'})
        assert 'Secure' in cookie

    def test_no_secure_flag_plain_http(self, server, monkeypatch):
        """Plain HTTP must NOT mark the cookie Secure — the browser
        would never return it."""
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        cookie = self._activate(server, monkeypatch)
        assert 'Secure' not in cookie

    def test_forwarded_proto_ignored_without_trust(self, server, monkeypatch):
        """X-Forwarded-Proto=https on an UNTRUSTED direct connection
        must not set Secure — header spoofing would strip the cookie."""
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        cookie = self._activate(
            server, monkeypatch,
            headers={'X-Forwarded-Proto': 'https'})
        assert 'Secure' not in cookie


# ---------------------------------------------------------------------------
# status.json disclosure boundary + CSRF hardening + framing
# ---------------------------------------------------------------------------

def test_status_json_operator_gets_metrics(server):
    """Operators see lan_ips + system telemetry."""
    status, _, body = _req(server, '/status.json',
                           headers=_auth_headers())
    assert status == 200
    import json
    data = json.loads(body)
    assert 'lan_ips' in data
    assert 'system' in data


def test_status_json_ephemeral_hides_metrics(server, monkeypatch):
    """An ephemeral view-only session gets service states only
    internal topology and resource usage are operator-grade."""
    monkeypatch.setattr(
        'vnc_remote_secure.security.ephemeral_sessions.check_session_permission',
        lambda internal, perm, client_ip=None, resource=None: True)
    status, _, body = _req(
        server, '/status.json', headers={'Cookie': 'vnc_ephemeral=tok'})
    assert status == 200
    import json
    data = json.loads(body)
    assert 'services' in data
    assert 'lan_ips' not in data
    assert 'system' not in data


def test_post_cross_site_fetch_metadata_rejected(server):
    """Sec-Fetch-Site: cross-site is set by the browser on every
    cross-site POST and cannot be forged  reject before auth even."""
    headers = dict(_auth_headers())
    headers['Sec-Fetch-Site'] = 'cross-site'
    status, _, _ = _req(
        server, '/api/v1/sessions/revoke', method='POST',
        headers=headers)
    assert status == 403


def _portal_csrf(port):
    """Real CSRF flow: an authenticated GET /api/v1/me issues the
    vnc_op session + vnc_csrf nonce cookies; the token is HMAC-bound
    to (sid, nonce). Returns (cookie_header, token)."""
    import http.client
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/api/v1/me', headers=_auth_headers())
    resp = conn.getresponse()
    resp.read()
    cookies = [v for k, v in resp.getheaders()
               if k.lower() == 'set-cookie']
    conn.close()
    assert resp.status == 200
    joined = '; '.join(cookies)
    import re
    op = re.search(r'vnc_op=([^;\s]+)', joined)
    nonce = re.search(r'vnc_csrf=([^;\s]+)', joined)
    assert op and nonce
    sid = op.group(1).split('.')[0]
    from vnc_remote_secure.services.api_v1 import _csrf_token
    cookie = f'vnc_op={op.group(1)}; vnc_csrf={nonce.group(1)}'
    return cookie, _csrf_token(sid, nonce.group(1))


def test_post_same_site_fetch_metadata_passes_gate(server):
    """same-origin Sec-Fetch-Site + a valid session CSRF token reach
    the handler (which then applies its own validation, 400/404 on a
    bad token_id)."""
    import http.client
    import json as _j
    cookie, token = _portal_csrf(server)
    conn = http.client.HTTPConnection('127.0.0.1', server, timeout=5)
    conn.request('POST', '/api/v1/sessions/revoke',
                 body=_j.dumps({'token_id': 'nonexistent'}),
                 headers={**_auth_headers(),
                          'Cookie': cookie,
                          'X-CSRF-Token': token,
                          'Sec-Fetch-Site': 'same-origin',
                          'Content-Type': 'application/json'})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    # Not the CSRF 403 — the request reached handler-level validation.
    assert resp.status in (200, 400, 404)


def test_post_no_fetch_metadata_still_allowed(server):
    """Non-browser clients (curl, scripts) send no Sec-Fetch-Site —
    they keep working as long as they hold the CSRF token."""
    import http.client
    import json as _j
    cookie, token = _portal_csrf(server)
    conn = http.client.HTTPConnection('127.0.0.1', server, timeout=5)
    conn.request('POST', '/api/v1/sessions/revoke',
                 body=_j.dumps({'token_id': 'x'}),
                 headers={**_auth_headers(),
                          'Cookie': cookie,
                          'X-CSRF-Token': token,
                          'Content-Type': 'application/json'})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.status in (200, 400, 404)


def test_post_without_csrf_nonce_denied(server):
    """A mutation without the session CSRF token is denied even with
    valid Basic credentials — cookies+auth alone don't authorize."""
    import http.client
    import json as _j
    conn = http.client.HTTPConnection('127.0.0.1', server, timeout=5)
    conn.request('POST', '/api/v1/sessions/revoke',
                 body=_j.dumps({'token_id': 'x'}),
                 headers={**_auth_headers(),
                          'Content-Type': 'application/json'})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.status == 403


def test_get_transfer_encoding_rejected(server):
    """TE on a GET makes body framing ambiguous  http.server has no
    chunked parser; reject rather than risk pipeline confusion."""
    status, _, _ = _req(
        server, '/', headers={**_auth_headers(),
                              'Transfer-Encoding': 'chunked'})
    assert status == 400


def test_head_transfer_encoding_rejected(server):
    status, _, _ = _req(
        server, '/', method='HEAD',
        headers={**_auth_headers(), 'Transfer-Encoding': 'chunked'})
    assert status == 400


def test_post_transfer_encoding_rejected(server):
    status, _, _ = _req(
        server, '/api/v1/sessions/revoke', method='POST',
        headers={**_auth_headers(), 'Transfer-Encoding': 'chunked'})
    assert status == 400
