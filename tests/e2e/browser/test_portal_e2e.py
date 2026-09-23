"""Browser E2E for the landing portal (Playwright).

Covers what unit tests cannot: the sessions panel's JS wiring —
clicking "Revocar" must actually POST /sessions/revoke and the row
must fade; "Cerrar todas" must revoke every session. Requires the
playwright package and a downloaded chromium; skipped only when the
toolchain is absent.
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
    """Run the landing handler on an ephemeral port (plain HTTP)."""
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

    from vnc_remote_secure.services.bounded_server import BoundedThreadingTCPServer
    from vnc_remote_secure.services.landing import LandingHandler
    server = BoundedThreadingTCPServer(('127.0.0.1', 0), LandingHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f'http://127.0.0.1:{port}'
    server.shutdown()
    server.server_close()


@pytest.fixture
def browser_ctx():
    with playwright_sync.sync_playwright() as p:
        browser = p.chromium.launch()
        yield browser
        browser.close()


def _new_page(browser_ctx):
    return browser_ctx.new_context(
        http_credentials={'username': 'admin',
                          'password': 'E2e-Portal-Pw-123'}).new_page()


def test_portal_renders_sessions_panel(portal_server, browser_ctx):
    """The sessions panel appears once a session exists — an empty
    store renders no panel at all (by design)."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    get_session_store().create(role='viewer', expires_in=600)
    page = _new_page(browser_ctx)
    page.goto(portal_server, wait_until='domcontentloaded')
    assert 'Sesiones activas' in page.content()
    assert 'revoke-btn' in page.content()
    page.close()


def test_revoke_button_posts_and_fades(portal_server, browser_ctx):
    """Create a session, click Revocar, verify the POST revoked it."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    store = get_session_store()
    session, _signed = store.create(role='viewer', expires_in=600)
    token_id = session.to_dict()['token_id']

    page = _new_page(browser_ctx)
    page.goto(portal_server, wait_until='domcontentloaded')
    btn = page.locator(f'button.revoke-btn[data-token="{token_id}"]')
    assert btn.count() == 1
    page.on('dialog', lambda d: d.accept())
    with page.expect_response('**/sessions/revoke') as resp_info:
        btn.click()
    assert resp_info.value.status == 200
    page.wait_for_timeout(300)  # let the fade apply
    assert store.get(session.token).revoked
    # The row faded — JS wiring actually ran.
    row = btn.locator('xpath=ancestor::tr')
    assert '0.3' in (row.get_attribute('style') or '')
    page.close()


def test_revoke_all_revokes_everything(portal_server, browser_ctx):
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    store = get_session_store()
    s1, _ = store.create(role='viewer', expires_in=600)
    s2, _ = store.create(role='support', expires_in=600)

    page = _new_page(browser_ctx)
    page.goto(portal_server, wait_until='domcontentloaded')
    page.on('dialog', lambda d: d.accept())
    with page.expect_response('**/sessions/revoke-all') as resp_info:
        page.locator('#revoke-all-btn').click()
    assert resp_info.value.status == 200
    page.wait_for_timeout(300)
    assert store.get(s1.token).revoked
    assert store.get(s2.token).revoked
    page.close()


@pytest.fixture
def terminal_server(monkeypatch):
    """Run the real tornado terminal app on an ephemeral port."""
    monkeypatch.setenv("TTYD_USERNAME", "admin")
    monkeypatch.setenv("TTYD_PASSWD", "E2e-Term-Pw-123")
    monkeypatch.setenv("SHARED_STATE_BACKEND", "memory")
    import vnc_remote_secure.security.shared_state as _ss
    monkeypatch.setattr(_ss, "_backend", None, raising=False)
    import vnc_remote_secure.security.rate_limit as _rl
    monkeypatch.setattr(_rl, "_auth_limiter", None, raising=False)

    import tornado.httpserver
    import tornado.ioloop
    import tornado.netutil

    from vnc_remote_secure.services.terminal import make_app
    app = make_app()
    server = tornado.httpserver.HTTPServer(app)
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    port = sockets[0].getsockname()[1]
    ready = threading.Event()
    holder = {}

    def _serve():
        # The IOLoop must be current IN THE SERVING THREAD — sockets
        # registered on the main thread's default loop never fire.
        loop = tornado.ioloop.IOLoop()
        loop.make_current()
        server.add_sockets(sockets)
        holder['loop'] = loop
        ready.set()
        loop.start()
        loop.close(all_fds=True)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    ready.wait(timeout=10)
    yield f"http://127.0.0.1:{port}"
    loop = holder.get('loop')
    if loop is not None:
        loop.add_callback(loop.stop)
        t.join(timeout=5)
    # No server.stop(): loop.close(all_fds=True) already closed the
    # sockets — calling it afterwards trips its fileno assertion.


def test_portal_denies_without_auth(portal_server, browser_ctx):
    """No credentials -> 401, never a silently public portal."""
    page = browser_ctx.new_context().new_page()
    resp = page.goto(portal_server, wait_until="domcontentloaded")
    assert resp.status == 401
    page.close()


def test_share_link_activates_and_grants_portal(
        portal_server, browser_ctx):
    """GET /?session=<signed> issues the vnc_ephemeral cookie and
    lands on the portal WITHOUT Basic credentials — the link itself
    is the credential."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    _session, signed = get_session_store().create(
        role="viewer", expires_in=600)

    ctx = browser_ctx.new_context()  # no http_credentials
    page = ctx.new_page()
    page.goto(f"{portal_server}/?session={signed}",
              wait_until="domcontentloaded")
    # Landed on the portal (302 -> /), cookie issued.
    cookies = {c["name"]: c for c in ctx.cookies()}
    assert "vnc_ephemeral" in cookies
    assert cookies["vnc_ephemeral"]["httpOnly"]
    assert "VNC" in page.content() or "Portal" in page.content()
    page.close()
    ctx.close()


def test_share_link_reuse_still_works_multi_use(
        portal_server, browser_ctx):
    """A non-single-use link can activate again (fresh context) —
    single-use semantics are the explicit opt-in, not the default."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    _session, signed = get_session_store().create(
        role="viewer", expires_in=600)
    for _ in range(2):
        ctx = browser_ctx.new_context()
        page = ctx.new_page()
        resp = page.goto(f"{portal_server}/?session={signed}",
                         wait_until="domcontentloaded")
        assert resp.status == 200
        page.close()
        ctx.close()


def test_terminal_page_requires_auth(terminal_server, browser_ctx):
    page = browser_ctx.new_context().new_page()
    resp = page.goto(terminal_server, wait_until="domcontentloaded")
    assert resp.status == 401
    page.close()


def test_terminal_page_loads_with_auth(terminal_server, browser_ctx):
    ctx = browser_ctx.new_context(http_credentials={
        "username": "admin", "password": "E2e-Term-Pw-123"})
    page = ctx.new_page()
    resp = page.goto(terminal_server, wait_until="domcontentloaded")
    assert resp.status == 200
    assert "terminal" in page.content().lower()
    page.close()
    ctx.close()
