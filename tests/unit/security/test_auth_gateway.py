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

    def test_lan_ip_arbitrary_port_rejected(self, monkeypatch):
        """ALLOWED_LAN_IPS must not admit origins from ports we do
        not serve — a rogue page on :9999 of an allowed host used to
        pass validation."""
        monkeypatch.setenv('ALLOWED_LAN_IPS', '10.0.0.5')
        monkeypatch.setenv('LANDING_PORT', '8443')
        assert not check_origin(
            'http://10.0.0.5:9999', [])

    def test_lan_ip_service_port_accepted(self, monkeypatch):
        monkeypatch.setenv('ALLOWED_LAN_IPS', '10.0.0.5')
        monkeypatch.setenv('LANDING_PORT', '8443')
        assert check_origin('http://10.0.0.5:8443', [])

    def test_lan_ip_default_port_accepted(self, monkeypatch):
        """No explicit port = scheme-default — the nginx entry."""
        monkeypatch.setenv('ALLOWED_LAN_IPS', '10.0.0.5')
        assert check_origin('https://10.0.0.5', [])

    def test_lan_ip_non_http_scheme_rejected(self, monkeypatch):
        monkeypatch.setenv('ALLOWED_LAN_IPS', '10.0.0.5')
        assert not check_origin('ftp://10.0.0.5', [])
        assert not check_origin('ws://10.0.0.5:8443', [])

    def test_lan_ip_not_configured_rejected(self, monkeypatch):
        monkeypatch.delenv('ALLOWED_LAN_IPS', raising=False)
        assert not check_origin('https://10.0.0.5', [])

    def test_loopback_lan_ip_any_port(self, monkeypatch):
        """Loopback keeps any-port acceptance — a hostile local
        process can read .env directly, so the port check buys
        nothing; dev servers on random ports keep working."""
        monkeypatch.setenv('ALLOWED_LAN_IPS', '127.0.0.1')
        assert check_origin('http://127.0.0.1:54321', [])
        # ...but the port check still applies to NON-loopback.
        monkeypatch.setenv('ALLOWED_LAN_IPS', '10.0.0.5')
        assert not check_origin('http://10.0.0.5:54321', [])

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


class TestWebSocketRateLimitAccounting:
    """Rejected WS upgrades must count against the auth limiter.

    Without ws:<ip> accounting, the WebSocket endpoint is a
    lockout-free credential oracle — unlimited guesses.
    """

    def test_rejected_upgrade_records_ws_failure(self, monkeypatch):
        from vnc_remote_secure.security import auth_gateway
        from vnc_remote_secure.security.rate_limit import RateLimiter
        limiter = RateLimiter()
        monkeypatch.setattr(
            auth_gateway, 'get_auth_limiter', lambda: limiter)
        monkeypatch.setattr(
            'vnc_remote_secure.security.rate_limit.get_auth_limiter',
            lambda: limiter, raising=False)
        allowed, reason = check_websocket_upgrade(
            origin='https://evil.example',
            client_ip='10.9.9.9')
        assert allowed is False
        # The failure must be recorded under the ws: namespace so
        # is_client_locked() sees it.
        assert limiter._attempt_count('ws:10.9.9.9') == 1

    def test_repeated_rejections_lock_ip(self, monkeypatch):
        from vnc_remote_secure.security import auth_gateway
        from vnc_remote_secure.security.rate_limit import RateLimiter
        limiter = RateLimiter()
        monkeypatch.setattr(
            auth_gateway, 'get_auth_limiter', lambda: limiter)
        monkeypatch.setattr(
            'vnc_remote_secure.security.rate_limit.get_auth_limiter',
            lambda: limiter, raising=False)
        # Explicit max_attempts — RateLimiter reads AUTH_MAX_ATTEMPTS
        # from os.environ at construction time; relying on the default
        # makes the lock threshold order-dependent under the full suite.
        limiter = RateLimiter()
        limiter.max_attempts = 3
        for _ in range(3):
            check_websocket_upgrade(
                origin='https://evil.example',
                client_ip='10.9.9.10')
        # Even a *valid* credential is now rejected up front.
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_authenticated',
            lambda c, b: (True, 'admin'), raising=False)
        allowed, reason = check_websocket_upgrade(
            origin='https://evil.example',
            cookie_value='valid-sess',
            client_ip='10.9.9.10')
        assert allowed is False
        assert 'rate' in reason.lower()


def _clear_rate_limit_state():
    """Wipe shared-state lockouts+attempts — they persist across tests."""
    from vnc_remote_secure.security.shared_state import get_backend
    be = get_backend()
    for ns in ('rate_limit_lockouts', 'rate_limit_attempts'):
        try:
            for k in list(be.list_keys(ns)):
                be.delete(ns, k)
        except Exception:
            pass


class TestAttemptLoginLockout:
    """attempt_login rate-limit behavior — the brute-force gate."""

    def _setup(self, monkeypatch, password='Str0ng!Pass', max_att=3):
        from vnc_remote_secure.security import auth_gateway as gw
        from vnc_remote_secure.security.rate_limit import RateLimiter
        _clear_rate_limit_state()
        limiter = RateLimiter()
        limiter.max_attempts = max_att
        monkeypatch.setattr(gw, 'get_auth_limiter', lambda: limiter)
        monkeypatch.setenv('USER_UI_PASSWORD', password)
        # Pin the expected username — import-time env mutation in other
        # modules (or a real .env) must not decide which user logs in.
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        monkeypatch.delenv('TTYD_USERNAME', raising=False)
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.mfa_required_for_login',
            lambda: False, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.step_up_auth.record_auth_time',
            lambda u: None, raising=False)
        return gw, limiter

    def test_lockout_after_max_attempts(self, monkeypatch):
        gw, _ = self._setup(monkeypatch)
        for _ in range(3):
            gw.attempt_login('admin', 'wrong')
        ok, msg, _ = gw.attempt_login('admin', 'wrong')
        assert ok is False
        assert 'locked' in msg.lower()

    def test_correct_password_rejected_while_locked(self, monkeypatch):
        """Lockout is enforced BEFORE credential check — the right
        password must not get in during lockout."""
        gw, _ = self._setup(monkeypatch)
        for _ in range(3):
            gw.attempt_login('admin', 'wrong')
        ok, msg, _ = gw.attempt_login('admin', 'Str0ng!Pass')
        assert ok is False
        assert 'locked' in msg.lower()

    def test_username_lockout_independent_of_ip(self, monkeypatch):
        """Attacker rotating IPs still hits the user:<name> lock."""
        gw, _ = self._setup(monkeypatch)
        for i in range(3):
            gw.attempt_login('admin', 'wrong', client_ip=f'10.0.0.{i}')
        ok, msg, _ = gw.attempt_login(
            'admin', 'Str0ng!Pass', client_ip='10.9.9.9')
        assert ok is False
        assert 'locked' in msg.lower()

    def test_ip_lockout_independent_of_username(self, monkeypatch):
        """Same attacker IP cannot pivot to a different account."""
        gw, _ = self._setup(monkeypatch)
        for i in range(3):
            gw.attempt_login(f'user{i}', 'wrong', client_ip='10.1.1.1')
        ok, msg, _ = gw.attempt_login(
            'admin', 'Str0ng!Pass', client_ip='10.1.1.1')
        assert ok is False
        assert 'locked' in msg.lower()

    def test_success_clears_failures(self, monkeypatch):
        gw, _ = self._setup(monkeypatch)
        gw.attempt_login('admin', 'wrong', client_ip='10.2.2.2')
        ok, msg, sess = gw.attempt_login(
            'admin', 'Str0ng!Pass', client_ip='10.2.2.2')
        assert ok is True
        assert sess
        assert 'admin' in sess.get('value', '')


class TestRecoveryCodeLogin:
    """Recovery-code MFA path — the MFA-bypass surface."""

    def _setup_mfa(self, monkeypatch):
        _clear_rate_limit_state()
        import secrets as _s
        user = 'adm-' + _s.token_hex(4)
        ip = '10.99.' + str(_s.randbelow(250) + 1) + '.1'
        from vnc_remote_secure.security import auth_gateway as gw
        from vnc_remote_secure.security.mfa import hash_recovery_code
        from vnc_remote_secure.security.rate_limit import RateLimiter
        limiter = RateLimiter()
        limiter.max_attempts = 20
        monkeypatch.setattr(gw, 'get_auth_limiter', lambda: limiter)
        monkeypatch.setenv('USER_UI_PASSWORD', 'Str0ng!Pass')
        monkeypatch.setenv('USER_UI_USERNAME', user)
        monkeypatch.delenv('TTYD_USERNAME', raising=False)
        monkeypatch.setenv('TOTP_SECRET', 'BASE32SECRET')
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.mfa_required_for_login',
            lambda: True, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.step_up_auth.record_auth_time',
            lambda u: None, raising=False)
        import secrets as _s
        # Unique per test — claims persist in the shared backend, so a
        # fixed code would poison later tests in the same run.
        code = 'RC-' + _s.token_hex(6).upper()
        monkeypatch.setenv(
            'RECOVERY_CODES_HASHES', hash_recovery_code(code))
        # TOTP verify must fail so the recovery path is exercised.
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.verify_totp',
            lambda *a: False, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.mfa.verify_totp',
            lambda *a: False, raising=False)
        return gw, code, user, ip

    def test_valid_recovery_code_logs_in(self, monkeypatch):
        gw, code, user, ip = self._setup_mfa(monkeypatch)
        ok, msg, sess = gw.attempt_login(
            user, 'Str0ng!Pass', totp_code=code, client_ip=ip)
        assert ok is True
        assert sess

    def test_recovery_code_single_use(self, monkeypatch):
        """Same code twice -> second is rejected (claimed in shared
        state even if .env cannot be rewritten)."""
        gw, code, user, ip = self._setup_mfa(monkeypatch)
        ok1, _, _ = gw.attempt_login(
            user, 'Str0ng!Pass', totp_code=code, client_ip=ip)
        assert ok1 is True
        ok2, msg2, _ = gw.attempt_login(
            user, 'Str0ng!Pass', totp_code=code, client_ip=ip)
        assert ok2 is False
        assert 'invalid' in msg2.lower()

    def test_invalid_code_records_failure_both_keys(self, monkeypatch):
        gw, _, user, ip = self._setup_mfa(monkeypatch)
        ok, msg, _ = gw.attempt_login(user, 'Str0ng!Pass',
                                      totp_code='WRONGCODE', client_ip=ip)
        assert ok is False
        assert 'invalid' in msg.lower()


class TestAuthorizeRequestEphemeral:
    """authorize_request ephemeral-cookie and bearer-permission paths."""

    def test_ephemeral_cookie_with_permission(self, monkeypatch):
        from vnc_remote_secure.security import auth_gateway as gw
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_session_permission',
            lambda t, perm, **kw: perm == 'desktop:control')
        ok, reason, ident = gw.authorize_request(
            ephemeral_cookie='inner-tok',
            required_permission='desktop:control')
        assert ok is True
        assert ident == 'inner-tok'

    def test_ephemeral_cookie_wrong_permission_denied(self, monkeypatch):
        """viewer cookie cannot gain control — required_permission is
        enforced on activated sessions too."""
        from vnc_remote_secure.security import auth_gateway as gw
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_session_permission',
            lambda t, perm, **kw: False)
        ok, reason, ident = gw.authorize_request(
            ephemeral_cookie='inner-tok',
            required_permission='desktop:control')
        assert ok is False
        assert ident is None

    def test_stale_ephemeral_falls_through_to_session(self, monkeypatch):
        """A bad ephemeral cookie must not mask a valid operator
        session cookie presented alongside it."""
        from vnc_remote_secure.security import auth_gateway as gw
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_session_permission',
            lambda *a, **kw: False)
        monkeypatch.setattr(
            gw, 'check_authenticated', lambda c, b: (True, 'admin'))
        ok, reason, ident = gw.authorize_request(
            cookie_value='sess-cookie',
            ephemeral_cookie='stale-tok')
        assert ok is True
        assert ident == 'sess-cookie'

    def test_bearer_operator_required_permission(self, monkeypatch):
        """Ephemeral bearer passes only via check_permission — an
        operator-session bearer bypass would skip permissions."""
        from vnc_remote_secure.security import auth_gateway as gw
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_permission',
            lambda t, perm, **kw: True)
        ok, reason, ident = gw.authorize_request(
            bearer_token='eph-bearer',
            required_permission='desktop:view')
        assert ok is True
        assert ident == 'eph-bearer'


class TestBearerPermissionDenied:
    """An ephemeral bearer token must be REJECTED when it lacks the
    required permission — 'any valid token' is not authorization."""

    def test_bearer_insufficient_permission_denied(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_permission',
            lambda *a, **k: False)
        from vnc_remote_secure.security.auth_gateway import authorize_request
        allowed, reason, _ident = authorize_request(
            bearer_token='viewer-tok', required_permission='control')
        assert allowed is False

    def test_bearer_granted_permission_allowed(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_permission',
            lambda *a, **k: True)
        from vnc_remote_secure.security.auth_gateway import authorize_request
        allowed, _reason, ident = authorize_request(
            bearer_token='op-tok', required_permission='control')
        assert allowed is True
        assert ident == 'op-tok'

    def test_bearer_permission_receives_resource_and_ip(
            self, monkeypatch):
        """check_permission must get the real resource+client_ip —
        dropping them silently un-binds resource/IP-bound tokens."""
        seen = {}
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.'
            'check_permission',
            lambda tok, perm, resource=None, client_ip=None:
            seen.update(resource=resource, client_ip=client_ip) or True)
        from vnc_remote_secure.security.auth_gateway import authorize_request
        authorize_request(
            bearer_token='t', required_permission='view',
            resource='desktop', client_ip='10.0.0.1')
        assert seen == {'resource': 'desktop', 'client_ip': '10.0.0.1'}
