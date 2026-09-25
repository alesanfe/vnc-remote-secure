"""Browser E2E for the landing portal (Playwright).

Covers what unit tests cannot: the SPA actually boots in a real
browser, the share-link fragment flow end-to-end, and the terminal
service redirect. Requires the playwright package and a downloaded
chromium; skipped only when the toolchain is absent.
"""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

playwright_sync = pytest.importorskip(
    'playwright.sync_api', reason='playwright toolchain not installed')


@pytest.fixture
def portal_server(monkeypatch, tmp_path):
    """Run the FastAPI portal app (uvicorn) on an ephemeral port."""
    monkeypatch.setenv('LANDING_PASSWORD', 'E2e-Portal-Pw-123')
    monkeypatch.delenv('SSL_CERT', raising=False)
    monkeypatch.delenv('SSL_KEY', raising=False)
    monkeypatch.delenv('AUDIT_MIRROR_FILE', raising=False)
    # The revoke endpoints Origin-check the fetch — 127.0.0.1 must be
    # a LAN-allowed host or the POST gets a legitimate 403.
    monkeypatch.setenv('ALLOWED_LAN_IPS', '127.0.0.1')
    # The shared auth limiter persists lockouts in the REAL
    # shared_state.db (get_data_dir is not patched) — lockouts left
    # by earlier tests would 401 every portal auth here. Swap the
    # backend for a fresh in-memory one.
    monkeypatch.setenv('SHARED_STATE_BACKEND', 'memory')
    import vnc_remote_secure.security.shared_state as _ss
    monkeypatch.setattr(_ss, '_backend', None, raising=False)
    import vnc_remote_secure.security.rate_limit as _rl
    monkeypatch.setattr(_rl, '_auth_limiter', None, raising=False)
    # Isolate the ephemeral session store.
    run_dir = tmp_path / 'run'
    run_dir.mkdir(exist_ok=True)
    from vnc_remote_secure.core import paths
    monkeypatch.setattr(paths, 'get_run_dir', lambda: str(run_dir))
    import vnc_remote_secure.security.ephemeral_sessions as eph
    monkeypatch.setattr(eph, '_store', eph.SessionStore())

    import uvicorn

    from vnc_remote_secure.backend.app import create_app
    config = uvicorn.Config(
        create_app(), host='127.0.0.1', port=0,
        log_level='error', access_log=False, proxy_headers=False)
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    import time
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, 'uvicorn did not start'
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f'http://127.0.0.1:{port}'
    server.should_exit = True
    t.join(timeout=5)


@pytest.fixture
def browser_ctx():
    with playwright_sync.sync_playwright() as p:
        browser = p.chromium.launch()
        yield browser
        browser.close()


def test_portal_serves_spa_shell(portal_server, browser_ctx):
    """The SPA shell is public — it carries no data."""
    page = browser_ctx.new_context().new_page()
    resp = page.goto(portal_server, wait_until='domcontentloaded')
    assert resp.status == 200
    assert page.locator('#root').count() == 1
    page.close()


def test_status_json_requires_auth(portal_server, browser_ctx):
    """Data endpoints stay behind the auth gate — no credentials,
    401 with WWW-Authenticate."""
    page = browser_ctx.new_context().new_page()
    resp = page.goto(f'{portal_server}/status.json',
                     wait_until='domcontentloaded')
    assert resp.status == 401
    page.close()


def test_share_link_fragment_flow(portal_server, browser_ctx):
    """/share#t=<signed> renders the React preview; accepting POSTs
    /api/v1/session/activate and lands on the portal with the
    vnc_ephemeral cookie — no Basic credentials needed."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    _session, signed = get_session_store().create(
        role='viewer', expires_in=600)

    ctx = browser_ctx.new_context()
    page = ctx.new_page()
    page.goto(f'{portal_server}/share#t={signed}',
              wait_until='domcontentloaded')
    # Fragment wiped from the address bar; wait for the preview fetch
    # to resolve (React starts on 'Comprobando enlace…' first).
    page.wait_for_selector('.data', timeout=10000)
    assert 't=' not in page.url
    assert 'forma remota' in page.locator('#info').inner_text()
    with page.expect_response('**/api/v1/session/activate') as r:
        page.get_by_role('button', name='Aceptar y abrir sesión').click()
    assert r.value.status == 200
    cookies = {c['name']: c for c in ctx.cookies()}
    assert 'vnc_ephemeral' in cookies
    assert cookies['vnc_ephemeral']['httpOnly']
    page.close()
    ctx.close()


def test_share_link_invalid_token_shows_error(portal_server,
                                              browser_ctx):
    ctx = browser_ctx.new_context()
    page = ctx.new_page()
    page.goto(f'{portal_server}/share#t=forged.token.value',
              wait_until='domcontentloaded')
    # Wait for the preview POST to resolve into the error box.
    page.wait_for_selector('.error-box', timeout=10000)
    assert 'caducado o ya ha sido utilizado' in \
        page.locator('#info').inner_text()
    page.close()
    ctx.close()


@pytest.fixture
def terminal_server(monkeypatch):
    """Run the real FastAPI terminal app on an ephemeral port."""
    monkeypatch.setenv("TTYD_USERNAME", "admin")
    monkeypatch.setenv("TTYD_PASSWD", "E2e-Term-Pw-123")
    monkeypatch.setenv("SHARED_STATE_BACKEND", "memory")
    import vnc_remote_secure.security.shared_state as _ss
    monkeypatch.setattr(_ss, "_backend", None, raising=False)
    import vnc_remote_secure.security.rate_limit as _rl
    monkeypatch.setattr(_rl, "_auth_limiter", None, raising=False)

    import uvicorn

    from vnc_remote_secure.services.terminal import make_app
    config = uvicorn.Config(
        make_app(), host='127.0.0.1', port=0,
        log_level='error', access_log=False, proxy_headers=False)
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    import time
    deadline = time.time() + 10
    while not server.started:
        assert time.time() < deadline, 'uvicorn did not start'
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=5)


def test_terminal_root_redirects_to_portal(terminal_server,
                                           browser_ctx):
    """GET / on the terminal service redirects to the React page on
    the portal — the service itself only owns /ws."""
    # The redirect target is the portal's /terminal page — nothing
    # answers there in this fixture, so assert the redirect itself
    # without following it (a browser goto would hit a dead origin).
    ctx = browser_ctx.new_context()
    resp = ctx.request.get(terminal_server, max_redirects=0)
    assert resp.status in (301, 302, 307, 308)
    assert '/terminal' in resp.headers.get('location', '')
    ctx.close()
