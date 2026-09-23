"""Unit tests for security.http_auth — Basic-auth surfaces + client_ip_from."""
import base64

from vnc_remote_secure.security import http_auth


def _basic(user, pwd):
    return 'Basic ' + base64.b64encode(f'{user}:{pwd}'.encode()).decode()


class TestLandingAuth:
    """Landing portal auth — fail-closed when no password exists."""

    def test_no_password_denies(self, monkeypatch):
        """Empty LANDING_PASSWORD AND no generated credential => deny."""
        monkeypatch.delenv('LANDING_PASSWORD', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda name: '', raising=False)
        assert http_auth.check_landing_auth(
            _basic('admin', 'anything')) is False

    def test_correct_credentials_accept(self, monkeypatch):
        monkeypatch.setenv('LANDING_PASSWORD', 'S3cure!Pass')
        assert http_auth.check_landing_auth(
            _basic('admin', 'S3cure!Pass')) is True

    def test_wrong_password_denies(self, monkeypatch):
        monkeypatch.setenv('LANDING_PASSWORD', 'S3cure!Pass')
        assert http_auth.check_landing_auth(
            _basic('admin', 'wrong')) is False

    def test_wrong_username_denies(self, monkeypatch):
        monkeypatch.setenv('LANDING_PASSWORD', 'S3cure!Pass')
        assert http_auth.check_landing_auth(
            _basic('root', 'S3cure!Pass')) is False

    def test_generated_credential_fallback(self, monkeypatch):
        """A persisted generated credential is honored when env unset."""
        monkeypatch.delenv('LANDING_PASSWORD', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda name: 'GenP@ss99', raising=False)
        assert http_auth.check_landing_auth(
            _basic('admin', 'GenP@ss99')) is True

    def test_locked_ip_denied_even_with_correct_creds(self, monkeypatch):
        monkeypatch.setenv('LANDING_PASSWORD', 'S3cure!Pass')
        from vnc_remote_secure.security.rate_limit import RateLimiter
        limiter = RateLimiter()
        limiter.max_attempts = 2
        monkeypatch.setattr(
            http_auth, 'get_auth_limiter', lambda: limiter, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.rate_limit.get_auth_limiter',
            lambda: limiter, raising=False)
        for _ in range(3):
            http_auth.check_landing_auth(
                _basic('admin', 'wrong'), client_ip='10.8.8.8')
        assert http_auth.check_landing_auth(
            _basic('admin', 'S3cure!Pass'), client_ip='10.8.8.8') is False


class TestClientIpFrom:
    """XFF handling — spoof-proof unless behind a trusted proxy."""

    def test_no_trust_returns_peer(self, monkeypatch):
        monkeypatch.delenv('TRUSTED_PROXY', raising=False)
        headers = {'X-Forwarded-For': '1.2.3.4'}
        assert http_auth.client_ip_from(headers, '10.0.0.9') == '10.0.0.9'

    def test_trusted_proxy_takes_last_xff(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        headers = {'X-Forwarded-For': 'spoofed, real-client'}
        # peer is loopback (nginx same host) — last XFF is proxy-set.
        assert http_auth.client_ip_from(
            headers, '127.0.0.1') == 'real-client'

    def test_non_proxy_peer_ignores_xff(self, monkeypatch):
        """Direct client hitting the port cannot spoof via XFF."""
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        headers = {'X-Forwarded-For': '1.2.3.4'}
        assert http_auth.client_ip_from(
            headers, '203.0.113.5') == '203.0.113.5'

    def test_trusted_proxy_ips_extra(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.setenv('TRUSTED_PROXY_IPS', '10.0.0.2')
        headers = {'X-Forwarded-For': 'client-ip'}
        assert http_auth.client_ip_from(headers, '10.0.0.2') == 'client-ip'
        # A non-listed peer still gets its own address.
        assert http_auth.client_ip_from(headers, '10.0.0.3') == '10.0.0.3'

    def test_empty_xff_returns_peer(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        assert http_auth.client_ip_from({}, '127.0.0.1') == '127.0.0.1'


class TestHealthAuth:
    """check_health_auth — open access ONLY for loopback-only binds."""

    def _loopback_env(self, monkeypatch):
        monkeypatch.delenv('HEALTH_AUTH_TOKEN', raising=False)
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.delenv('USER_UI_HOST', raising=False)
        monkeypatch.delenv('HEALTH_WEB_HOST', raising=False)

    def test_no_token_loopback_bind_and_peer_allows(self, monkeypatch):
        self._loopback_env(monkeypatch)
        assert http_auth.check_health_auth(
            '', peer_ip='127.0.0.1') is True

    def test_no_token_loopback_bind_external_peer_denied(self, monkeypatch):
        """A public reverse proxy in front of the loopback port must
        NOT turn open health into open-for-the-network."""
        self._loopback_env(monkeypatch)
        assert http_auth.check_health_auth(
            '', peer_ip='203.0.113.7') is False

    def test_no_token_public_bind_denied(self, monkeypatch):
        self._loopback_env(monkeypatch)
        monkeypatch.setenv('HEALTH_WEB_HOST', '0.0.0.0')
        # Even a loopback peer must auth when the bind is public.
        assert http_auth.check_health_auth(
            '', peer_ip='127.0.0.1') is False

    def test_no_token_no_peer_denied_on_public_bind(self, monkeypatch):
        self._loopback_env(monkeypatch)
        monkeypatch.setenv('USER_UI_HOST', '0.0.0.0')
        assert http_auth.check_health_auth('', peer_ip=None) is False

    def test_token_wrong_bearer_denied(self, monkeypatch):
        self._loopback_env(monkeypatch)
        monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'tok123')
        assert http_auth.check_health_auth(
            'Bearer wrong', client_ip='127.0.0.1') is False

    def test_token_correct_bearer_accepted(self, monkeypatch):
        self._loopback_env(monkeypatch)
        monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'tok123')
        assert http_auth.check_health_auth(
            'Bearer tok123', client_ip='127.0.0.1') is True


class TestTerminalAuth:
    """check_terminal_auth — fail-closed Basic + ephemeral Bearer."""

    def test_no_password_denies(self, monkeypatch):
        monkeypatch.delenv('TTYD_PASSWD', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda name: '', raising=False)
        assert http_auth.check_terminal_auth(
            _basic('admin', 'x')) is False

    def test_correct_basic_accepted(self, monkeypatch):
        monkeypatch.setenv('TTYD_USERNAME', 'termop')
        monkeypatch.setenv('TTYD_PASSWD', 'T3rm!nal')
        assert http_auth.check_terminal_auth(
            _basic('termop', 'T3rm!nal')) is True

    def test_bearer_delegates_to_permission(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.check_permission',
            lambda tok, perm, **kw: tok == 'good' and perm == 'terminal:use',
            raising=False)
        assert http_auth.check_terminal_auth('Bearer good') is True
        assert http_auth.check_terminal_auth('Bearer bad') is False

    def test_xff_trailing_comma_returns_last_nonempty(self, monkeypatch):
        """'1.2.3.4,' must not produce an empty client key — empty keys
        collapse into a shared rate-limit bucket."""
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        headers = {'X-Forwarded-For': '1.2.3.4,'}
        assert http_auth.client_ip_from(headers, '127.0.0.1') == '1.2.3.4'

    def test_xff_all_empty_returns_peer(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        headers = {'X-Forwarded-For': ', ,'}
        assert http_auth.client_ip_from(headers, '127.0.0.1') == '127.0.0.1'


class TestMalformedAuthHeaders:
    """check_basic_auth / check_bearer_token must fail closed without
    raising on malformed input."""

    def test_basic_invalid_base64(self):
        assert http_auth.check_basic_auth('Basic !!!', 'u', 'p') is False

    def test_basic_lowercase_scheme_rejected(self):
        """Scheme matching is strict ('Basic ') — pinned contract; a
        client sending 'basic' gets denied, not silently accepted."""
        import base64
        hdr = 'basic ' + base64.b64encode(b'u:p').decode()
        assert http_auth.check_basic_auth(hdr, 'u', 'p') is False

    def test_basic_decoded_without_colon(self):
        import base64
        hdr = 'Basic ' + base64.b64encode(b'nocolon').decode()
        assert http_auth.check_basic_auth(hdr, 'u', 'p') is False

    def test_bearer_non_ascii_fails_closed(self):
        assert http_auth.check_bearer_token(
            'Bearer \xc3\xbf\xc3\xbf', 'tok') is False

    def test_bearer_wrong_scheme(self):
        assert http_auth.check_bearer_token('Basic dGg=', 'tok') is False


class TestConstantTimeCompare:
    """Credential compares must go through hmac.compare_digest — an
    early-exit == leaks a per-byte timing oracle. The property is
    only observable via the call, so spy on it."""

    def test_basic_uses_compare_digest(self, monkeypatch):
        import base64
        import hmac
        calls = []
        real = hmac.compare_digest
        monkeypatch.setattr(
            'vnc_remote_secure.security.http_auth.hmac.compare_digest',
            lambda a, b: calls.append((a, b)) or real(a, b))
        from vnc_remote_secure.security.http_auth import check_basic_auth
        hdr = 'Basic ' + base64.b64encode(b'u:p').decode()
        check_basic_auth(hdr, 'u', 'p')
        assert calls, 'Basic auth bypassed compare_digest'

    def test_bearer_uses_compare_digest(self, monkeypatch):
        import hmac
        calls = []
        real = hmac.compare_digest
        monkeypatch.setattr(
            'vnc_remote_secure.security.http_auth.hmac.compare_digest',
            lambda a, b: calls.append((a, b)) or real(a, b))
        from vnc_remote_secure.security.http_auth import check_bearer_token
        check_bearer_token('Bearer x', 'x')
        assert calls, 'Bearer auth bypassed compare_digest'


class TestTrustedProxyCidr:
    """TRUSTED_PROXY_IPS accepts CIDR ranges — a proxy pool must not
    require listing every address."""

    def test_cidr_peer_trusted(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.setenv('TRUSTED_PROXY_IPS', '10.0.0.0/24')
        from vnc_remote_secure.security.http_auth import client_ip_from
        ip = client_ip_from(
            {'X-Forwarded-For': '203.0.113.9'}, '10.0.0.55')
        assert ip == '203.0.113.9'

    def test_outside_cidr_not_trusted(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.setenv('TRUSTED_PROXY_IPS', '10.0.0.0/24')
        from vnc_remote_secure.security.http_auth import client_ip_from
        # Peer outside the range: XFF must be ignored (spoof-proof).
        ip = client_ip_from(
            {'X-Forwarded-For': '203.0.113.9'}, '10.0.1.55')
        assert ip == '10.0.1.55'

    def test_malformed_entry_not_trusted(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.setenv('TRUSTED_PROXY_IPS', 'not-an-ip/99')
        from vnc_remote_secure.security.http_auth import client_ip_from
        ip = client_ip_from(
            {'X-Forwarded-For': '203.0.113.9'}, '10.0.0.55')
        assert ip == '10.0.0.55'

    def test_exact_ip_still_works(self, monkeypatch):
        monkeypatch.setenv('TRUSTED_PROXY', 'true')
        monkeypatch.setenv('TRUSTED_PROXY_IPS', '10.0.0.55')
        from vnc_remote_secure.security.http_auth import client_ip_from
        ip = client_ip_from(
            {'X-Forwarded-For': '203.0.113.9'}, '10.0.0.55')
        assert ip == '203.0.113.9'


class TestRequestHeadersSafe:
    """Request-smuggling rejection: http.server only understands
    Content-Length — TE or duplicated CL make framing ambiguous."""

    def test_plain_headers_ok(self):
        assert http_auth.request_headers_safe({}) is True
        assert http_auth.request_headers_safe(
            {'Content-Length': '12'}) is True

    def test_transfer_encoding_rejected(self):
        assert http_auth.request_headers_safe(
            {'Transfer-Encoding': 'chunked'}) is False

    def test_email_message_duplicate_cl_rejected(self):
        """With a real http.server header object (email.message) a
        duplicated Content-Length is visible via get_all."""
        import email.message
        m = email.message.Message()
        m.add_header('Content-Length', '5')
        m.add_header('Content-Length', '10')
        assert http_auth.request_headers_safe(m) is False

    def test_email_message_single_cl_ok(self):
        import email.message
        m = email.message.Message()
        m.add_header('Content-Length', '5')
        assert http_auth.request_headers_safe(m) is True

    def test_email_message_te_and_cl_rejected(self):
        """TE+CL together is the classic desync — reject."""
        import email.message
        m = email.message.Message()
        m.add_header('Content-Length', '5')
        m.add_header('Transfer-Encoding', 'chunked')
        assert http_auth.request_headers_safe(m) is False

    def test_empty_duplicate_cl_ignored(self):
        """A second EMPTY Content-Length header is not ambiguous."""
        import email.message
        m = email.message.Message()
        m.add_header('Content-Length', '5')
        m.add_header('Content-Length', '   ')
        assert http_auth.request_headers_safe(m) is True
