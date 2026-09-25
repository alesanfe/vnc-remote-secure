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
        for perm in ('admin_users', 'admin_config',
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


class TestRehashOnLogin:
    """A hash minted under a weaker iteration policy is transparently
    upgraded on the next successful login."""

    def _weak_hash(self, password):
        import hashlib
        salt = 'aa' * 16
        dk = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), 1000)
        return f'pbkdf2:sha256:1000${salt}${dk.hex()}'

    def test_stale_iterations_upgraded(self, store):
        data = {'alice': {
            'password_hash': self._weak_hash('Correct Horse 1!'),
            'role': 'operator', 'disabled': False,
            'created_at': 1}}
        store.write_text(json.dumps(data))
        rec = ops.verify('alice', 'Correct Horse 1!')
        assert rec is not None
        reloaded = json.loads(store.read_text())
        new_hash = reloaded['alice']['password_hash']
        assert new_hash.startswith(
            f'pbkdf2:sha256:{ops._PBKDF2_ITERATIONS}$')
        # And the rehashed password still verifies.
        assert ops.verify('alice', 'Correct Horse 1!') is not None

    def test_current_iterations_not_rewritten(self, store):
        ops.add_user('bob', 'RightPass 1!', 'viewer')
        before = json.loads(store.read_text())['bob']['password_hash']
        assert ops.verify('bob', 'RightPass 1!') is not None
        after = json.loads(store.read_text())['bob']['password_hash']
        assert after == before

    def test_failed_login_does_not_rehash(self, store):
        data = {'carol': {
            'password_hash': self._weak_hash('RightPass 1!'),
            'role': 'viewer', 'disabled': False, 'created_at': 1}}
        store.write_text(json.dumps(data))
        assert ops.verify('carol', 'wrong') is None
        reloaded = json.loads(store.read_text())
        assert reloaded['carol']['password_hash'].startswith(
            'pbkdf2:sha256:1000$')

    def test_stored_iterations_parser(self):
        assert ops._stored_iterations(
            'pbkdf2:sha256:600000$salt$hash') == 600000
        assert ops._stored_iterations('pbkdf2:sha256:1000$a$b') == 1000
        assert ops._stored_iterations('garbage') == 0
        assert ops._stored_iterations('') == 0
        assert ops._stored_iterations('scrypt:1$x$y') == 0
