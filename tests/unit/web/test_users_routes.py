"""Unit tests for web.routes.users — the user-management blueprint.

Exercises the routes through Flask's test client with auth stubbed at
the module boundary (check_authenticated, attempt_login, step-up) so
the tests cover the blueprint's own logic: session gating, CSRF,
input validation, reserved-name protection and error mapping.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

pytest.importorskip('flask')

import vnc_remote_secure.web.routes.users as users_mod  # noqa: E402
from vnc_remote_secure.web.application import create_app  # noqa: E402


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(
        users_mod, 'check_authenticated',
        lambda token, bearer='': (True, 'admin'))
    monkeypatch.setattr(
        'vnc_remote_secure.security.step_up_auth.require_step_up',
        lambda user, action: None)
    a = create_app({})
    a.config['TESTING'] = True
    return a


@pytest.fixture
def authed_client(app):
    """Test client with an authenticated Flask session + CSRF token."""
    c = app.test_client()
    with c.session_transaction() as s:
        s['token'] = 'tok'
        s['csrf_token'] = 'csrf123'
    return c


# ---------------------------------------------------------------------------
# _require_session gating
# ---------------------------------------------------------------------------

def test_users_requires_auth_redirects(app, monkeypatch):
    monkeypatch.setattr(
        users_mod, 'check_authenticated',
        lambda token, bearer='': (False, None))
    c = app.test_client()
    resp = c.get('/users')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


def test_api_users_requires_auth_returns_401(app, monkeypatch):
    monkeypatch.setattr(
        users_mod, 'check_authenticated',
        lambda token, bearer='': (False, None))
    c = app.test_client()
    resp = c.get('/api/users')
    assert resp.status_code == 401
    assert resp.is_json


def test_bearer_auth_accepted(app, monkeypatch):
    """Authorization: Bearer is an alternative to the session token."""
    seen = {}

    def fake_check(token, bearer=''):
        seen['bearer'] = bearer
        return True, 'admin'

    monkeypatch.setattr(users_mod, 'check_authenticated', fake_check)
    c = app.test_client()
    resp = c.get('/api/users',
                 headers={'Authorization': 'Bearer abc123'})
    assert resp.status_code == 200
    assert seen['bearer'] == 'abc123'


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

def test_login_get_renders(authed_client):
    resp = authed_client.get('/login')
    assert resp.status_code == 200


def test_login_post_rejects_bad_csrf(authed_client):
    resp = authed_client.post('/login', data={
        'username': 'admin', 'password': 'x', 'csrf_token': 'wrong'})
    assert resp.status_code == 400


def test_login_post_success_sets_vnc_session(app, authed_client, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.attempt_login',
        lambda u, p, totp_code='', client_ip='': (True, 'ok', {}))
    resp = authed_client.post('/login', data={
        'username': 'admin', 'password': 'pw',
        'csrf_token': 'csrf123'})
    assert resp.status_code == 302
    cookies = resp.headers.getlist('Set-Cookie')
    assert any('vnc_session=' in c for c in cookies)


def test_login_post_failure_returns_401(app, authed_client, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.attempt_login',
        lambda u, p, totp_code='', client_ip='': (False, 'bad creds', None))
    resp = authed_client.post('/login', data={
        'username': 'admin', 'password': 'wrong',
        'csrf_token': 'csrf123'})
    assert resp.status_code == 401


def test_logout_rejects_missing_csrf(authed_client):
    resp = authed_client.post('/logout')
    assert resp.status_code == 403


def test_logout_with_csrf_redirects_and_expires(authed_client):
    resp = authed_client.post('/logout',
                              headers={'X-CSRF-Token': 'csrf123'})
    assert resp.status_code == 302
    cookies = resp.headers.getlist('Set-Cookie')
    assert any('vnc_session=' in c and 'Max-Age=0' in c for c in cookies)
    assert any('vnc_ephemeral=' in c and 'Max-Age=0' in c for c in cookies)


# ---------------------------------------------------------------------------
# User CRUD — HTML routes
# ---------------------------------------------------------------------------

def test_users_page_renders_for_authed(authed_client):
    resp = authed_client.get('/users')
    assert resp.status_code == 200


def test_create_user_requires_csrf(authed_client):
    resp = authed_client.post('/create_user', data={
        'username': 'bob', 'password': 'Str0ng!Pass'})
    assert resp.status_code == 403


def test_create_user_rejects_reserved_name(authed_client):
    resp = authed_client.post('/create_user',
                              headers={'X-CSRF-Token': 'csrf123'},
                              data={'username': 'root',
                                    'password': 'Str0ng!Pass'})
    assert resp.status_code == 400


def test_create_user_rejects_weak_password(authed_client):
    resp = authed_client.post('/create_user',
                              headers={'X-CSRF-Token': 'csrf123'},
                              data={'username': 'bob', 'password': 'x'})
    assert resp.status_code == 400


def test_delete_user_rejects_reserved(authed_client):
    resp = authed_client.post('/delete_user/root',
                              headers={'X-CSRF-Token': 'csrf123'})
    assert resp.status_code == 400


def test_delete_user_rejects_current_user(authed_client):
    import getpass
    resp = authed_client.post(
        f'/delete_user/{getpass.getuser()}',
        headers={'X-CSRF-Token': 'csrf123'})
    assert resp.status_code == 400


def test_step_up_blocks_create_user(app, authed_client, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.step_up_auth.require_step_up',
        lambda user, action: 're-auth required')
    resp = authed_client.post('/create_user',
                              headers={'X-CSRF-Token': 'csrf123'},
                              data={'username': 'bob',
                                    'password': 'Str0ng!Pass'})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

def test_api_users_get_returns_json(authed_client):
    resp = authed_client.get('/api/users')
    assert resp.status_code == 200
    assert 'users' in resp.get_json()


def test_api_users_post_rejects_non_object(authed_client):
    resp = authed_client.post('/api/users',
                              headers={'X-CSRF-Token': 'csrf123'},
                              json=['not', 'an', 'object'])
    assert resp.status_code == 400


def test_api_users_post_rejects_reserved(authed_client):
    resp = authed_client.post('/api/users',
                              headers={'X-CSRF-Token': 'csrf123'},
                              json={'username': 'root',
                                    'password': 'Str0ng!Pass'})
    assert resp.status_code == 400


def test_api_users_delete_rejects_reserved(authed_client):
    resp = authed_client.delete('/api/users',
                                headers={'X-CSRF-Token': 'csrf123'},
                                json={'username': 'root'})
    assert resp.status_code == 400


def test_api_users_delete_rejects_non_object(authed_client):
    resp = authed_client.delete('/api/users',
                                headers={'X-CSRF-Token': 'csrf123'},
                                json=['root'])
    assert resp.status_code == 400
