"""Tests for the multi-operator store and permission enforcement."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest  # noqa: E402

from vnc_remote_secure.security import operator_users as ops  # noqa: E402


@pytest.fixture
def store(monkeypatch, tmp_path):
    """Point the operator store at a temp file."""
    path = tmp_path / 'operator_users.json'
    monkeypatch.setattr(ops, '_store_path', lambda: str(path))
    return path


def _basic(user, pw):
    return 'Basic ' + base64.b64encode(
        f'{user}:{pw}'.encode()).decode()


class TestStore:
    def test_add_verify_list(self, store):
        ops.add_user('alice', 'Correct Horse 1!', 'operator')
        rec = ops.verify('alice', 'Correct Horse 1!')
        assert rec and rec['role'] == 'operator'
        assert 'admin_sessions' in rec['permissions']
        listed = ops.list_users()
        assert listed[0]['username'] == 'alice'
        assert 'password_hash' not in listed[0]

    def test_wrong_password_denied(self, store):
        ops.add_user('bob', 'RightPass 1!', 'viewer')
        assert ops.verify('bob', 'WrongPass') is None

    def test_unknown_user_denied(self, store):
        # Unknown usernames still run one pbkdf2 (no timing leak).
        assert ops.verify('ghost', 'x') is None

    def test_duplicate_rejected(self, store):
        ops.add_user('dup', 'Pass 1!', 'viewer')
        with pytest.raises(ValueError, match='already exists'):
            ops.add_user('dup', 'Other 1!', 'admin')

    def test_bad_role_rejected(self, store):
        with pytest.raises(ValueError, match='Unknown role'):
            ops.add_user('x', 'Pass 1!', 'superadmin')

    @pytest.mark.parametrize('bad', ['', 'a' * 65, 'bad name', 'a;b',
                                     'x' * 64 + '\n'])
    def test_bad_username_rejected(self, store, bad):
        with pytest.raises(ValueError):
            ops.add_user(bad, 'Pass 1!', 'viewer')

    def test_remove(self, store):
        ops.add_user('tmp', 'Pass 1!', 'viewer')
        assert ops.remove_user('tmp') is True
        assert ops.remove_user('tmp') is False
        assert ops.verify('tmp', 'Pass 1!') is None

    def test_set_role(self, store):
        ops.add_user('eve', 'Pass 1!', 'viewer')
        assert ops.set_role('eve', 'operator') is True
        assert 'admin_sessions' in ops.verify(
            'eve', 'Pass 1!')['permissions']
        assert ops.set_role('eve', 'bogus') is False

    def test_disabled_cannot_auth(self, store):
        ops.add_user('off', 'Pass 1!', 'admin')
        ops.set_disabled('off', True)
        assert ops.verify('off', 'Pass 1!') is None
        assert ops.has_permission('off', 'admin_users') is False

    def test_store_persists_and_permissions(self, store):
        ops.add_user('persist', 'Pass 1!', 'operator')
        data = json.loads(store.read_text())
        assert 'persist' in data
        assert data['persist']['password_hash'].startswith('pbkdf2:')
        assert not store.read_text().count('Pass 1!')  # no plaintext


class TestPermissions:
    def test_admin_umbrella_expands(self, store):
        ops.add_user('root', 'Pass 1!', 'admin')
        for perm in ('admin_users', 'admin_config', 'admin_secrets',
                     'admin_audit', 'admin_sessions'):
            assert ops.has_permission('root', perm)

    def test_operator_scope(self, store):
        ops.add_user('op', 'Pass 1!', 'operator')
        assert ops.has_permission('op', 'admin_sessions')
        assert ops.has_permission('op', 'admin_audit')
        assert not ops.has_permission('op', 'admin_users')
        assert not ops.has_permission('op', 'admin_config')

    def test_viewer_read_only(self, store):
        ops.add_user('look', 'Pass 1!', 'viewer')
        assert not ops.has_permission('look', 'admin_sessions')
        assert not ops.has_permission('look', 'admin_audit')

    def test_env_bootstrap_is_admin(self, store):
        """A user absent from the store resolves to env-admin perms
        (bootstrap path — single-credential deployments keep working)."""
        assert ops.has_permission('admin', 'admin_users')
        assert ops.has_permission('admin', 'admin_sessions')


class TestAuthenticateLanding:
    def test_store_user_authenticates(self, store, monkeypatch):
        ops.add_user('svc', 'S3cret Pass!', 'operator')
        from vnc_remote_secure.security import http_auth
        ok, rec = http_auth.authenticate_landing(
            _basic('svc', 'S3cret Pass!'))
        assert ok and rec['role'] == 'operator'

    def test_store_user_wrong_password(self, store, monkeypatch):
        ops.add_user('svc', 'S3cret Pass!', 'operator')
        from vnc_remote_secure.security import http_auth
        ok, rec = http_auth.authenticate_landing(
            _basic('svc', 'bad'))
        assert not ok and rec is None

    def test_stored_user_no_env_fallback(self, store, monkeypatch):
        """A stored username must NOT fall back to the env password —
        that would silently widen their credentials to admin."""
        ops.add_user('admin', 'StorePass 1!', 'viewer')
        monkeypatch.setenv('LANDING_PASSWORD', 'EnvPass 1!')
        from vnc_remote_secure.security import http_auth
        ok, _rec = http_auth.authenticate_landing(
            _basic('admin', 'EnvPass 1!'))
        assert not ok  # env password does NOT apply to stored users

    def test_env_admin_bootstrap(self, store, monkeypatch):
        monkeypatch.setenv('LANDING_PASSWORD', 'EnvPass 1!')
        from vnc_remote_secure.security import http_auth
        ok, rec = http_auth.authenticate_landing(
            _basic('admin', 'EnvPass 1!'))
        assert ok and rec['role'] == 'admin'
        assert 'admin:*' in rec['permissions']

    def test_no_credentials(self, store):
        from vnc_remote_secure.security import http_auth
        ok, rec = http_auth.authenticate_landing('')
        assert not ok and rec is None
