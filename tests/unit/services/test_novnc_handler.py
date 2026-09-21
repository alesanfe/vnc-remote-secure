"""Live-server tests for the noVNC static-file HTTP handler.

Runs _AuthedSimpleHTTPRequestHandler on a real ThreadingTCPServer in a
temp directory so the auth gate, static serving and 404s are exercised
end-to-end — complementing the relay unit tests (relay_rfb_stream)
and the ephemeral e2e.
"""
import http.client
import os
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.services.novnc as novnc  # noqa: E402


@pytest.fixture
def novnc_server(monkeypatch, tmp_path):
    """Real threaded server serving a scratch static dir.

    Auth is stubbed at the module boundary — the credential-resolution
    tree is covered by auth_gateway tests; here we test the handler's
    enforcement contract (401 + WWW-Authenticate vs. serve).
    """
    (tmp_path / 'vnc.html').write_text('<html>novnc</html>')
    (tmp_path / 'app').mkdir()
    (tmp_path / 'app' / 'ui.js').write_text('// js')

    def fake_check(headers, client_ip=None):
        if headers.get('Cookie', '').startswith('vnc_session=good'):
            return True, ''
        return False, 'missing credentials'

    monkeypatch.setattr(novnc, '_check_novnc_auth', fake_check)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    srv = socketserver.ThreadingTCPServer(
        ('127.0.0.1', 0), novnc._AuthedSimpleHTTPRequestHandler)
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


def test_get_unauthenticated_401(novnc_server):
    status, headers, body = _req(novnc_server, '/vnc.html')
    assert status == 401
    assert 'WWW-Authenticate' in headers
    assert b'unauthorized' in body


def test_head_unauthenticated_401(novnc_server):
    """HEAD goes through the same gate — no metadata leak."""
    status, _, _ = _req(novnc_server, '/vnc.html', method='HEAD')
    assert status == 401


def test_get_authenticated_serves_file(novnc_server):
    status, _, body = _req(
        novnc_server, '/vnc.html',
        headers={'Cookie': 'vnc_session=good'})
    assert status == 200
    assert b'novnc' in body


def test_head_authenticated_200(novnc_server):
    status, _, body = _req(
        novnc_server, '/vnc.html', method='HEAD',
        headers={'Cookie': 'vnc_session=good'})
    assert status == 200
    assert body == b''


def test_nested_path_served_when_authed(novnc_server):
    status, _, body = _req(
        novnc_server, '/app/ui.js',
        headers={'Cookie': 'vnc_session=good'})
    assert status == 200
    assert b'// js' in body


def test_unknown_path_404_when_authed(novnc_server):
    status, _, _ = _req(
        novnc_server, '/missing.txt',
        headers={'Cookie': 'vnc_session=good'})
    assert status == 404


def test_security_headers_present(novnc_server):
    """end_headers must attach the shared security headers."""
    _, headers, _ = _req(
        novnc_server, '/vnc.html',
        headers={'Cookie': 'vnc_session=good'})
    # At minimum the standard hardening headers are set.
    assert any(k.lower().startswith('x-') or k == 'Content-Security-Policy'
               for k in headers)


def test_query_string_does_not_bypass_auth(novnc_server):
    """/?x=1 must hit the same auth gate as / — the WS-upgrade check
    strips the query, and so does static serving."""
    status, _, _ = _req(novnc_server, '/vnc.html?cache=bust')
    assert status == 401
