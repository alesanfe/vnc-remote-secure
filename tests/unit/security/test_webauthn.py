"""Tests for the WebAuthn/passkey module (security.webauthn)."""
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.security.webauthn as wn  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.delenv('WEBAUTHN_ENABLED', raising=False)
    monkeypatch.setattr(
        wn, 'get_data_dir', lambda: str(tmp_path / 'data'))
    import vnc_remote_secure.security.shared_state as ss
    ss._backend = None
    monkeypatch.setenv('SHARED_STATE_DB',
                       str(tmp_path / 'shared_state.db'))
    yield
    ss._backend = None


class TestAvailability:
    def test_disabled_by_default(self):
        assert wn.webauthn_available() is False

    def test_enabled_with_lib(self, monkeypatch):
        pytest.importorskip('webauthn')
        monkeypatch.setenv('WEBAUTHN_ENABLED', 'true')
        assert wn.webauthn_available() is True


class TestCredentialStore:
    def _store(self, username='alice', cid='Y3JlZDE'):
        wn._save_store({
            cid: {'username': username, 'public_key': 'AAAA',
                  'sign_count': 5, 'name': 'key',
                  'created_at': '2026-01-01T00:00:00Z'}})

    def test_list_only_shows_owner(self):
        self._store()
        wn._save_store(dict(
            wn._load_store(),
            cred2={'username': 'bob', 'public_key': 'BBBB',
                   'sign_count': 0}))
        creds = wn.list_credentials('alice')
        assert len(creds) == 1
        assert creds[0]['credential_id'] == 'Y3JlZDE'
        assert 'public_key' not in creds[0]

    def test_delete_enforces_ownership(self):
        self._store()
        assert wn.delete_credential('Y3JlZDE', 'bob') is False
        assert wn.delete_credential('Y3JlZDE', 'alice') is True
        assert wn.list_credentials('alice') == []

    def test_store_file_perms(self):
        self._store()
        import stat
        mode = stat.S_IMODE(os.stat(wn._store_path()).st_mode)
        if os.name == 'posix':
            assert mode & 0o777 == 0o600


class TestChallenges:
    def test_put_pop_single_use(self):
        wn._put_challenge('assert', 'alice', b'challenge-123')
        assert wn._pop_challenge('assert', 'alice') == b'challenge-123'
        # Second pop must fail — challenges are single-use.
        assert wn._pop_challenge('assert', 'alice') is None

    def test_purposes_isolated(self):
        wn._put_challenge('register', 'alice', b'reg')
        assert wn._pop_challenge('assert', 'alice') is None
        assert wn._pop_challenge('register', 'alice') == b'reg'


class TestCeremonies:
    @pytest.fixture(autouse=True)
    def _enabled(self, monkeypatch):
        pytest.importorskip('webauthn')
        monkeypatch.setenv('WEBAUTHN_ENABLED', 'true')

    def test_begin_registration_returns_options(self):
        opts = wn.begin_registration('alice', 'Alice', 'example.test',
                                     'VRS')
        assert opts['rp']['id'] == 'example.test'
        assert opts['challenge']
        # Challenge was stored for completion.
        assert wn._pop_challenge('register', 'alice') is not None

    def test_complete_registration_stores_credential(self, monkeypatch):
        wn._put_challenge('register', 'alice', b'expected-challenge')
        fake = SimpleNamespace(
            credential_id=b'cred-id-1',
            credential_public_key=b'pub-key-bytes',
            sign_count=1)
        monkeypatch.setattr(
            'webauthn.verify_registration_response',
            lambda **kw: fake)
        ok, _ = wn.complete_registration(
            'alice', {'id': 'x'}, 'example.test', 'https://example.test',
            name='yubikey')
        assert ok is True
        creds = wn.list_credentials('alice')
        assert len(creds) == 1
        assert creds[0]['name'] == 'yubikey'

    def test_complete_without_begin_fails(self):
        ok, _ = wn.complete_registration(
            'alice', {'id': 'x'}, 'rp', 'https://o')
        assert ok is False

    def test_assert_begin_none_without_credentials(self):
        assert wn.begin_authentication('alice', 'rp') is None

    def test_assert_complete_roundtrip(self, monkeypatch):
        # Seed a credential directly.
        cred_id = wn._b64e(b'cred-id-9')
        wn._save_store({cred_id: {
            'username': 'alice', 'public_key': wn._b64e(b'pub'),
            'sign_count': 3, 'name': 'k'}})
        opts = wn.begin_authentication('alice', 'example.test')
        assert opts['allowCredentials'][0]['id'] == cred_id
        fake = SimpleNamespace(new_sign_count=4)
        monkeypatch.setattr(
            'webauthn.verify_authentication_response',
            lambda **kw: fake)
        res = wn.complete_authentication(
            'alice', {'id': cred_id}, 'example.test',
            'https://example.test')
        assert res.ok is True
        # Sign count advanced on disk.
        assert wn._load_store()[cred_id]['sign_count'] == 4

    def test_assert_rejects_foreign_credential(self, monkeypatch):
        cred_id = wn._b64e(b'cred-id-9')
        wn._save_store({cred_id: {
            'username': 'bob', 'public_key': wn._b64e(b'pub'),
            'sign_count': 0}})
        wn._put_challenge('assert', 'alice', b'ch')
        res = wn.complete_authentication(
            'alice', {'id': cred_id}, 'rp', 'https://o')
        assert res.ok is False


class TestRpConfigPolicy:
    @pytest.fixture(autouse=True)
    def _enabled(self, monkeypatch):
        pytest.importorskip('webauthn')
        monkeypatch.setenv('WEBAUTHN_ENABLED', 'true')

    def test_direct_deployment_allows_inferred(self, monkeypatch):
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        assert wn.rp_config_error() is None

    def test_proxied_requires_explicit(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.delenv('WEBAUTHN_ORIGIN', raising=False)
        monkeypatch.delenv('WEBAUTHN_RP_ID', raising=False)
        assert 'WEBAUTHN_ORIGIN' in wn.rp_config_error()
        monkeypatch.setenv('WEBAUTHN_ORIGIN', 'https://vnc.example.com')
        monkeypatch.setenv('WEBAUTHN_RP_ID', 'vnc.example.com')
        assert wn.rp_config_error() is None

    def test_hardened_profile_requires_explicit(self, monkeypatch):
        monkeypatch.setenv('SECURITY_PROFILE', 'public-hardened')
        assert wn.rp_config_error() is not None


class TestStoreFormat:
    def test_legacy_bare_map_loads(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wn, 'get_data_dir',
                            lambda: str(tmp_path))
        import json as _j
        (tmp_path / 'webauthn_credentials.json').write_text(
            _j.dumps({'cid1': {'username': 'a'}}))
        assert wn.list_credentials('a')[0]['credential_id'] == 'cid1'


class TestStoreLock:
    def test_concurrent_writes_no_lost_update(self):
        import threading

        def add(i):
            with wn._store_lock():
                store = wn._load_store()
                store[f'k{i}'] = {'username': 'u'}
                wn._save_store(store)
        ts = [threading.Thread(target=add, args=(i,))
              for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert len(wn._load_store()) == 8

    def test_lock_holds_across_processes(self, tmp_path):
        """The guarantee is cross-PROCESS — threads sharing the GIL
        would serialise anyway. Spawn real interpreters racing on the
        same store file."""
        import subprocess
        import sys as _s
        src = os.path.join(os.path.dirname(__file__), '..', '..', '..',
                           'src')
        data_dir = str(tmp_path / 'mpdata')
        child = (
            "import os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import vnc_remote_secure.security.webauthn as wn\n"
            "wn.get_data_dir = lambda: sys.argv[2]\n"
            "for i in range(5):\n"
            "    with wn._store_lock():\n"
            "        s = wn._load_store()\n"
            "        s['c%d-%d' % (os.getpid(), i)] = {}\n"
            "        wn._save_store(s)\n"
        )
        procs = [subprocess.Popen(
            [_s.executable, '-c', child, os.path.abspath(src), data_dir])
            for _ in range(4)]
        for p in procs:
            assert p.wait(timeout=60) == 0
        import vnc_remote_secure.security.webauthn as wn2
        wn2.get_data_dir = lambda: data_dir
        assert len(wn2._load_store()) == 20  # 4 procs x 5 writes

    def test_symlink_store_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wn, 'get_data_dir',
                            lambda: str(tmp_path))
        import json as _j
        target = tmp_path / 'real.json'
        target.write_text(_j.dumps({'evil': {'username': 'root'}}))
        link = tmp_path / 'webauthn_credentials.json'
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip('symlink requires privilege on Windows')
        assert wn._load_store() == {}
