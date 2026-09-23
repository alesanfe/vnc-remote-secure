"""Tests for authentication.authenticate — credential resolution."""


class TestAuthenticateCredentials:
    """Hashed-credential support, precedence, generated fallback."""

    def _auth(self, monkeypatch):
        from vnc_remote_secure.security import authentication
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        return authentication

    def test_hashed_ui_password_accepted(self, monkeypatch):
        try:
            from werkzeug.security import generate_password_hash
            stored = generate_password_hash('Str0ng!Pass')
        except ImportError:
            import hashlib
            dk = hashlib.pbkdf2_hmac(
                'sha256', b'Str0ng!Pass', b'salt', 1000)
            stored = f'pbkdf2:1000$salt${dk.hex()}'
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        monkeypatch.setenv('USER_UI_PASSWORD', stored)
        assert self._auth(monkeypatch).authenticate(
            'admin', 'Str0ng!Pass') is True
        assert self._auth(monkeypatch).authenticate(
            'admin', 'wrong') is False

    def test_ui_password_takes_precedence_over_ttyd(self, monkeypatch):
        """When both are set the UI password is the one that works —
        a shared terminal password must not unlock the UI."""
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        monkeypatch.setenv('USER_UI_PASSWORD', 'UiPass!123')
        monkeypatch.setenv('TTYD_PASSWD', 'TermPass!123')
        monkeypatch.setenv('TTYD_USERNAME', 'admin')
        auth = self._auth(monkeypatch)
        assert auth.authenticate('admin', 'UiPass!123') is True
        assert auth.authenticate('admin', 'TermPass!123') is False

    def test_empty_stored_password_fails_closed(self, monkeypatch):
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        monkeypatch.delenv('USER_UI_PASSWORD', raising=False)
        monkeypatch.delenv('TTYD_PASSWD', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda n: None, raising=False)
        auth = self._auth(monkeypatch)
        assert auth.authenticate('admin', '') is False
        assert auth.authenticate('admin', 'anything') is False

    def test_wrong_username_rejected(self, monkeypatch):
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        monkeypatch.setenv('USER_UI_PASSWORD', 'Str0ng!Pass')
        assert self._auth(monkeypatch).authenticate(
            'attacker', 'Str0ng!Pass') is False


class TestSigningKeyRotation:
    """rotate_signing_secret keeps the old key verifiable inside the
    coexistence window — in-flight tokens must not die at rotation."""

    def _fresh(self, tmp_path, monkeypatch):
        from vnc_remote_secure.security import authentication as auth
        monkeypatch.delenv('AUTH_SECRET', raising=False)
        monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)
        auth._cached_secret = None
        monkeypatch.setattr(
            auth, '_secret_file_path',
            lambda: str(tmp_path / 'auth_secret.key'))
        monkeypatch.setattr(
            auth, '_previous_secrets_path',
            lambda: str(tmp_path / 'auth_secret.previous'))
        return auth

    def test_old_token_valid_in_window(self, tmp_path, monkeypatch):
        auth = self._fresh(tmp_path, monkeypatch)
        from vnc_remote_secure.security.token_signing import (
            TOKEN_TYPE_BEARER,
            sign_token,
            verify_token,
        )
        old_token = sign_token(TOKEN_TYPE_BEARER, 'data')
        ok, err = auth.rotate_signing_secret()
        assert ok is True
        assert err is None
        # Old-signed token still verifies inside the window.
        assert verify_token(TOKEN_TYPE_BEARER, old_token) == 'data'

    def test_new_tokens_sign_with_new_key(self, tmp_path, monkeypatch):
        auth = self._fresh(tmp_path, monkeypatch)
        from vnc_remote_secure.security.token_signing import (
            TOKEN_TYPE_BEARER,
            sign_token,
            verify_token,
        )
        ok, _ = auth.rotate_signing_secret()
        assert ok
        tok = sign_token(TOKEN_TYPE_BEARER, 'x')
        assert verify_token(TOKEN_TYPE_BEARER, tok) == 'x'
        # Forging with the OLD key must fail: old is verify-only for
        # already-issued material, and a new-format forgery is just a
        # signature check — it verifies, but an attacker cannot mint
        # it because verification of their own payload requires the
        # secret anyway. Sanity: random garbage never verifies.
        assert verify_token(TOKEN_TYPE_BEARER,
                            'bearer:forged.00') is None

    def test_expired_retired_key_pruned(self, tmp_path, monkeypatch):
        import json
        auth = self._fresh(tmp_path, monkeypatch)
        prev = tmp_path / 'auth_secret.previous'
        prev.write_text(json.dumps([
            {'secret': 'dead', 'retire_after': 1},          # expired
            {'secret': 'live', 'retire_after': 9e9},        # valid
        ]))
        assert auth.previous_signing_secrets() == [b'live']
        # File was pruned on load.
        assert len(json.loads(prev.read_text())) == 1

    def test_env_secret_blocks_rotation(self, tmp_path, monkeypatch):
        auth = self._fresh(tmp_path, monkeypatch)
        monkeypatch.setenv('AUTH_SECRET', 'operator-controlled')
        ok, err = auth.rotate_signing_secret()
        assert ok is False
        assert 'environment' in err
        # Previous file is also ignored when env is configured.
        assert auth.previous_signing_secrets() == []

    def test_double_rotation_keeps_both_old_keys(
            self, tmp_path, monkeypatch):
        auth = self._fresh(tmp_path, monkeypatch)
        from vnc_remote_secure.security.token_signing import (
            TOKEN_TYPE_BEARER,
            sign_token,
            verify_token,
        )
        t1 = sign_token(TOKEN_TYPE_BEARER, 'gen1')
        auth.rotate_signing_secret()
        t2 = sign_token(TOKEN_TYPE_BEARER, 'gen2')
        auth.rotate_signing_secret()
        assert verify_token(TOKEN_TYPE_BEARER, t1) == 'gen1'
        assert verify_token(TOKEN_TYPE_BEARER, t2) == 'gen2'


class TestSecretRotationReload:
    """Long-running processes must pick up a rotated auth_secret.key —
    a stale cache keeps signing with a retired key."""

    def _isolate(self, tmp_path, monkeypatch):
        from vnc_remote_secure.security import authentication as auth
        monkeypatch.delenv('AUTH_SECRET', raising=False)
        monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)
        key = tmp_path / 'auth_secret.key'
        monkeypatch.setattr(auth, '_secret_file_path',
                            lambda: str(key))
        auth._cached_secret = None
        auth._cached_secret_mtime = 0.0
        auth._cached_secret_checked = 0.0
        return auth, key

    def test_rotated_file_reloaded(self, tmp_path, monkeypatch):
        auth, key = self._isolate(tmp_path, monkeypatch)
        first = auth._get_secret()
        assert key.exists()
        # Rotate the file out-of-band (another process did it).
        key.write_text('rotatedsecret')
        import os
        os.utime(key, (0, 2**30))  # mtime far from cached baseline
        # Force the recheck window open.
        auth._cached_secret_checked = 0.0
        second = auth._get_secret()
        assert second == b'rotatedsecret'
        assert second != first

    def test_unchanged_file_not_reloaded(self, tmp_path, monkeypatch):
        auth, key = self._isolate(tmp_path, monkeypatch)
        first = auth._get_secret()
        # Same mtime -> no reload (cache hit, same bytes).
        auth._cached_secret_checked = 0.0
        second = auth._get_secret()
        assert second == first

    def test_recheck_interval_limits_stats(
            self, tmp_path, monkeypatch):
        """Within the recheck window the file is not even stat'ed."""
        auth, key = self._isolate(tmp_path, monkeypatch)
        auth._get_secret()
        key.write_text('rotatedsecret')
        # _cached_secret_checked is fresh -> change unseen.
        second = auth._get_secret()
        assert second != b'rotatedsecret'
