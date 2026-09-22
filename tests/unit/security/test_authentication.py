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
