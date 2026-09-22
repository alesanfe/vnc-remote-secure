"""Unit tests for auth gateway module."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.auth_gateway import (
    attempt_login,
    check_origin,
    check_websocket_upgrade,
    get_allowed_origins,
)


class TestOriginValidation:
    def test_rejects_empty_origin(self):
        assert not check_origin('', ['https://localhost'])

    def test_rejects_null_origin(self):
        assert not check_origin('null', ['https://localhost'])

    def test_accepts_allowed_origin(self):
        assert check_origin('https://localhost', ['https://localhost'])

    def test_rejects_unlisted_origin(self):
        assert not check_origin('https://evil.com', ['https://localhost'])

    def test_allowed_origins_include_localhost(self):
        origins = get_allowed_origins()
        assert 'http://localhost:8000' in origins
        assert 'http://127.0.0.1:8000' in origins

    def test_allowed_origins_include_duck_domain(self, monkeypatch):
        monkeypatch.setenv('DUCK_DOMAIN', 'myhost.duckdns.org')
        origins = get_allowed_origins()
        assert 'https://myhost.duckdns.org' in origins


class TestWebSocketUpgrade:
    def test_rejects_invalid_origin(self):
        allowed, reason = check_websocket_upgrade('https://evil.com')
        assert not allowed
        assert 'origin' in reason.lower()

    def test_rejects_no_auth(self):
        origins = get_allowed_origins()
        allowed, reason = check_websocket_upgrade(origins[0])
        assert not allowed
        assert 'auth' in reason.lower()


class TestLogin:
    def test_rejects_wrong_credentials(self, monkeypatch):
        monkeypatch.setenv('TTYD_USERNAME', 'admin')
        monkeypatch.setenv('TTYD_PASSWD', 'StrongP@ss1')
        ok, msg, session = attempt_login('admin', 'wrong', client_ip='1.2.3.4')
        assert not ok
        assert 'invalid' in msg.lower() or 'attempts' in msg.lower()

    def test_accepts_correct_credentials(self, monkeypatch):
        monkeypatch.setenv('TTYD_USERNAME', 'admin')
        monkeypatch.setenv('TTYD_PASSWD', 'StrongP@ss1')
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        monkeypatch.delenv('MFA_REQUIRED', raising=False)
        ok, msg, session = attempt_login('admin', 'StrongP@ss1', client_ip='1.2.3.4')
        assert ok
        assert session is not None
        assert 'value' in session
        assert 'csrf_token' in session

    def test_requires_mfa_when_configured(self, monkeypatch):
        from vnc_remote_secure.security.mfa import generate_totp_secret
        monkeypatch.setenv('TTYD_USERNAME', 'admin')
        monkeypatch.setenv('TTYD_PASSWD', 'StrongP@ss1')
        monkeypatch.setenv('TOTP_SECRET', generate_totp_secret())
        ok, msg, session = attempt_login('admin', 'StrongP@ss1', client_ip='1.2.3.4')
        assert not ok
        assert 'mfa' in msg.lower()

    def test_web_session_token_validates_as_session_cookie(self):
        """create_web_session() must store a session-type token.

        Regression: it used to store a TOKEN_TYPE_BEARER value which
        verify_session_cookie() (TOKEN_TYPE_SESSION) rejected — the web
        login succeeded but every subsequent request bounced to /login.
        """
        from vnc_remote_secure.security.authentication import create_web_session
        from vnc_remote_secure.security.sessions import verify_session_cookie

        flask_session = {}
        token = create_web_session(flask_session, 'alice')
        assert flask_session['token'] == token

        verified = verify_session_cookie(token)
        assert verified is not None
        assert verified['username'] == 'alice'


from vnc_remote_secure.security.auth_gateway import authorize_request


class TestAuthorizeRequest:
    """authorize_request: the single credential enforcement tree."""

    def _no_limiter(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.rate_limit.get_auth_limiter",
            lambda: None, raising=False)
        monkeypatch.setattr(
            "vnc_remote_secure.security.auth_gateway.get_auth_limiter",
            lambda: None)

    def test_rejects_when_no_credentials(self, monkeypatch):
        self._no_limiter(monkeypatch)
        allowed, reason, ident = authorize_request()
        assert allowed is False
        assert 'required' in reason.lower()
        assert ident is None

    def test_operator_cookie_allowed(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.auth_gateway.check_authenticated",
            lambda c, b: (True, 'admin'))
        allowed, reason, ident = authorize_request(cookie_value='sess')
        assert allowed is True
        assert ident == 'sess'

    def test_operator_failure_rejected(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.auth_gateway.check_authenticated",
            lambda c, b: (False, None))
        allowed, reason, ident = authorize_request(cookie_value='bad')
        assert allowed is False
        assert ident is None

    def test_ephemeral_cookie_with_permission(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.ephemeral_sessions.check_session_permission",
            lambda tok, perm, **kw: tok == 'eph' and perm == 'view',
            raising=False)
        allowed, reason, ident = authorize_request(
            ephemeral_cookie='eph', required_permission='view')
        assert allowed is True
        assert ident == 'eph'

    def test_stale_ephemeral_alone_rejected(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.ephemeral_sessions.check_session_permission",
            lambda *a, **k: False, raising=False)
        allowed, reason, ident = authorize_request(ephemeral_cookie='stale')
        assert allowed is False

    def test_stale_ephemeral_does_not_block_valid_cookie(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.ephemeral_sessions.check_session_permission",
            lambda *a, **k: False, raising=False)
        monkeypatch.setattr(
            "vnc_remote_secure.security.auth_gateway.check_authenticated",
            lambda c, b: (True, 'admin'))
        allowed, reason, ident = authorize_request(
            ephemeral_cookie='stale', cookie_value='sess')
        assert allowed is True
        assert ident == 'sess'

    def test_ephemeral_bearer_permission(self, monkeypatch):
        self._no_limiter(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.ephemeral_sessions.check_permission",
            lambda tok, perm, **kw: True, raising=False)
        monkeypatch.setattr(
            "vnc_remote_secure.security.auth_gateway.check_authenticated",
            lambda c, b: (False, None))
        allowed, reason, ident = authorize_request(
            bearer_token='tok', required_permission='desktop:view')
        assert allowed is True
        assert ident == 'tok'
