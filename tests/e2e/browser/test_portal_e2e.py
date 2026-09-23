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

    from vnc_remote_secure.services.bounded_server import (
        BoundedThreadingTCPServer)
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
    from vnc_remote_secure.security.ephemeral_sessions import (
        get_session_store)
    get_session_store().create(role='viewer', expires_in=600)
    page = _new_page(browser_ctx)
    page.goto(portal_server, wait_until='domcontentloaded')
    assert 'Sesiones activas' in page.content()
    assert 'revoke-btn' in page.content()
    page.close()


def test_revoke_button_posts_and_fades(portal_server, browser_ctx):
    """Create a session, click Revocar, verify the POST revoked it."""
    from vnc_remote_secure.security.ephemeral_sessions import (
        get_session_store)
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
    from vnc_remote_secure.security.ephemeral_sessions import (
        get_session_store)
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
