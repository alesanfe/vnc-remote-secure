"""Tests for the alert dispatch module (monitoring/alerts.py)."""
import pytest

from vnc_remote_secure.monitoring import alerts
from vnc_remote_secure.security import http_client


@pytest.fixture(autouse=True)
def _clean_alert_env(monkeypatch):
    """Ensure no alert-related env leaks between tests."""
    for var in ('ALERTS_ENABLED', 'DISCORD_ENABLED', 'DISCORD_WEBHOOK_URL',
                'ALERT_WEBHOOK_URL', 'ALERT_EMAIL_TO', 'ALERT_SMTP_SERVER',
                'ALERT_EMAIL_FROM', 'ALERT_SMTP_USER', 'ALERT_SMTP_PASS',
                'ALERT_WEBHOOK_ALLOW_HTTP',
                'ALERT_WEBHOOK_ALLOW_PRIVATE'):
        monkeypatch.delenv(var, raising=False)


class TestNotifyGate:
    def test_disabled_by_default(self):
        assert alerts.notify('t', 'm') == 0

    def test_disabled_explicit(self, monkeypatch):
        monkeypatch.setenv('ALERTS_ENABLED', 'false')
        assert alerts.notify('t', 'm') == 0

    def test_enabled_no_channels_returns_zero(self, monkeypatch):
        monkeypatch.setenv('ALERTS_ENABLED', 'true')
        assert alerts.notify('t', 'm') == 0


class TestChannelGating:
    def test_discord_no_url(self):
        assert alerts.send_discord_alert('t', 'm') is False

    def test_webhook_no_url(self):
        assert alerts.send_webhook_alert('t', 'm') is False

    def test_email_no_config(self):
        assert alerts.send_email_alert('t', 'm') is False

    def test_email_partial_config(self, monkeypatch):
        monkeypatch.setenv('ALERT_EMAIL_TO', 'a@b.c')
        # Missing ALERT_SMTP_SERVER -> no attempt
        assert alerts.send_email_alert('t', 'm') is False

    def test_webhook_unreachable(self, monkeypatch):
        monkeypatch.setenv('ALERT_WEBHOOK_URL', 'http://127.0.0.1:1/x')
        assert alerts.send_webhook_alert('t', 'm') is False

    def test_discord_unreachable(self, monkeypatch):
        monkeypatch.setenv('DISCORD_WEBHOOK_URL', 'http://127.0.0.1:1/x')
        assert alerts.send_discord_alert('t', 'm') is False


class TestNotifyDispatch:
    def test_force_bypasses_gate(self, monkeypatch):
        monkeypatch.setenv('DISCORD_WEBHOOK_URL', 'http://127.0.0.1:1/x')
        # force=True sends even with ALERTS_ENABLED unset; the single
        # configured channel is unreachable -> returns 0 without raising.
        assert alerts.notify('t', 'm', force=True) == 0

    def test_discord_requires_discord_enabled(self, monkeypatch):
        # DISCORD_WEBHOOK_URL alone does not enable the Discord channel.
        monkeypatch.setenv('ALERTS_ENABLED', 'true')
        monkeypatch.setenv('DISCORD_WEBHOOK_URL', 'http://127.0.0.1:1/x')
        # Discord channel skipped (DISCORD_ENABLED unset) -> 0 channels.
        assert alerts.notify('t', 'm') == 0


class TestWatchdog:
    def test_tick_disabled(self):
        from vnc_remote_secure.core import service_manager
        assert service_manager.watchdog_tick(
            {'healthcheck_enabled': False}) == {}


class TestWebhookSchemeGuard:
    """_post_json must refuse non-HTTP schemes — a tampered .env must
    not turn the alerter into a file:// / gopher:// reader."""

    def _post(self, url, monkeypatch):
        hits = []
        from vnc_remote_secure.monitoring import alerts
        monkeypatch.setattr(
            alerts, '_post_pinned',
            lambda *a, **k: hits.append(1) or True)
        return alerts._post_json(url, {'x': 1}), hits

    def test_file_scheme_rejected(self, monkeypatch):
        ok, hits = self._post('file:///etc/passwd', monkeypatch)
        assert ok is False
        assert hits == []

    def test_gopher_scheme_rejected(self, monkeypatch):
        ok, hits = self._post('gopher://x/1', monkeypatch)
        assert ok is False
        assert hits == []

    def test_http_and_https_allowed(self, monkeypatch):
        from vnc_remote_secure.monitoring import alerts
        # https:// always permitted (public host); http:// requires
        # the explicit ALERT_WEBHOOK_ALLOW_HTTP opt-in.
        monkeypatch.setattr(http_client, '_resolved_addrs_public',
                            lambda host: True)
        monkeypatch.setattr(alerts, '_post_pinned',
                            lambda *a, **k: True)
        assert alerts._post_json('https://h/x', {}) is True
        # http:// without opt-in is rejected.
        assert alerts._post_json('http://h/x', {}) is False
        monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_HTTP', 'true')
        assert alerts._post_json('http://h/x', {}) is True

    def test_transport_exception_returns_false(self, monkeypatch):
        from vnc_remote_secure.monitoring import alerts
        monkeypatch.setattr(http_client, '_resolved_addrs_public',
                            lambda host: True)
        monkeypatch.setattr(
            alerts, '_post_pinned',
            lambda *a, **k: (_ for _ in ()).throw(OSError('no')))
        assert alerts._post_json('https://h/x', {}) is False


class TestRedactUrl:
    def test_token_path_never_logged(self, caplog):
        from vnc_remote_secure.monitoring import alerts
        url = 'https://discord.com/api/webhooks/123/SECRET_TOKEN'
        out = alerts._redact_url(url)
        assert 'SECRET_TOKEN' not in out
        assert 'discord.com' in out

    def test_malformed_url_no_crash(self):
        from vnc_remote_secure.monitoring import alerts
        out = alerts._redact_url('http://[bad')
        assert 'bad' not in out or 'invalid' in out


class TestWebhookHmac:
    """ALERT_WEBHOOK_SECRET signs the body — a leaked URL alone
    cannot forge alerts."""

    def _capture(self, monkeypatch, secret):
        captured = {}
        from vnc_remote_secure.monitoring import alerts
        monkeypatch.setattr(
            alerts, '_post_pinned',
            lambda url, body, headers: captured.update(
                url=url, body=body, headers=headers) or True)
        monkeypatch.setattr(http_client, '_resolved_addrs_public',
                            lambda host: True)
        monkeypatch.setenv('ALERT_WEBHOOK_URL', 'https://hook.local/x')
        if secret:
            monkeypatch.setenv('ALERT_WEBHOOK_SECRET', secret)
        else:
            monkeypatch.delenv('ALERT_WEBHOOK_SECRET', raising=False)
        return alerts, captured

    def test_signature_header_present(self, monkeypatch):
        import hashlib
        import hmac
        import json as _json
        alerts, captured = self._capture(monkeypatch, 's3cret')
        assert alerts.send_webhook_alert('t', 'm') is True
        sig = captured['headers']['X-VncRemote-Signature']
        assert sig is not None
        assert sig.startswith('sha256=')
        body = _json.loads(captured['body'].decode())
        expected = hmac.new(b's3cret', captured['body'],
                            hashlib.sha256).hexdigest()
        assert sig == f'sha256={expected}'
        assert body['title'] == 't'

    def test_no_secret_no_header(self, monkeypatch):
        alerts, captured = self._capture(monkeypatch, '')
        alerts.send_webhook_alert('t', 'm')
        assert 'X-VncRemote-Signature' not in captured['headers']


def test_notify_correlation_id_shared(monkeypatch):
    """All channels receive the SAME correlation id — an inbound
    alert can then be tied back to the dispatching event."""
    seen = {}
    monkeypatch.setenv('ALERTS_ENABLED', 'true')
    monkeypatch.setenv('DISCORD_ENABLED', 'true')
    monkeypatch.setattr(alerts, '_last_sent', {})
    monkeypatch.setattr(
        alerts, 'send_discord_alert',
        lambda t, m, s, alert_id='': seen.setdefault(
            'discord', alert_id) or True)
    monkeypatch.setattr(
        alerts, 'send_webhook_alert',
        lambda t, m, s, alert_id='': seen.setdefault(
            'webhook', alert_id) or True)
    monkeypatch.setattr(
        alerts, 'send_email_alert', lambda t, m: False)
    alerts.notify('t', 'm', severity='warning')
    assert seen['discord'] == seen['webhook']
    assert len(seen['discord']) == 12


class TestWebhookUrlValidation:
    """SSRF policy on operator-configured webhook URLs.

    Default: HTTPS only, public unicast only, no redirect following.
    ALERT_WEBHOOK_ALLOW_HTTP / ALERT_WEBHOOK_ALLOW_PRIVATE are the
    explicit opt-outs for LAN receivers.
    """

    def _gai_private(self, monkeypatch, ip='10.0.0.5'):
        import socket
        monkeypatch.setattr(
            socket, 'getaddrinfo',
            lambda *a, **k: [(socket.AF_INET, 0, 0, '', (ip, 443))])

    def test_http_rejected_by_default(self, monkeypatch):
        self._gai_private(monkeypatch, '93.184.216.34')
        err = alerts._validate_webhook_url('http://example.com/hook')
        assert err is not None
        assert 'ALLOW_HTTP' in err

    def test_http_allowed_with_optin(self, monkeypatch):
        self._gai_private(monkeypatch, '93.184.216.34')
        monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_HTTP', 'true')
        assert alerts._validate_webhook_url(
            'http://example.com/hook') is None

    def test_non_http_scheme_rejected(self):
        assert alerts._validate_webhook_url(
            'file:///etc/passwd') is not None
        assert alerts._validate_webhook_url(
            'gopher://x/1') is not None

    def test_loopback_rejected(self, monkeypatch):
        self._gai_private(monkeypatch, '127.0.0.1')
        assert alerts._validate_webhook_url(
            'https://localhost/hook') is not None

    def test_private_ip_rejected(self, monkeypatch):
        self._gai_private(monkeypatch, '192.168.1.10')
        assert alerts._validate_webhook_url(
            'https://internal/hook') is not None

    def test_link_local_metadata_rejected(self, monkeypatch):
        """Cloud metadata endpoints (169.254.x) must be unreachable."""
        self._gai_private(monkeypatch, '169.254.169.254')
        assert alerts._validate_webhook_url(
            'https://metadata/hook') is not None

    def test_private_allowed_with_optin(self, monkeypatch):
        self._gai_private(monkeypatch, '192.168.1.10')
        monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_PRIVATE', 'true')
        assert alerts._validate_webhook_url(
            'https://internal/hook') is None

    def test_public_ip_accepted(self, monkeypatch):
        self._gai_private(monkeypatch, '93.184.216.34')
        assert alerts._validate_webhook_url(
            'https://example.com/hook') is None

    def test_one_bad_addr_fails_all(self, monkeypatch):
        """A hostname resolving to public AND private is rejected �
        urllib may pick either."""
        import socket
        monkeypatch.setattr(
            socket, 'getaddrinfo',
            lambda *a, **k: [
                (socket.AF_INET, 0, 0, '', ('93.184.216.34', 443)),
                (socket.AF_INET, 0, 0, '', ('10.0.0.5', 443))])
        assert alerts._validate_webhook_url(
            'https://mixed.example/hook') is not None

    def test_dns_failure_rejected(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, 'getaddrinfo',
            lambda *a, **k: (_ for _ in ()).throw(OSError('nxdomain')))
        assert alerts._validate_webhook_url(
            'https://no-such-host.invalid/hook') is not None

    def test_post_json_rejects_private_url(self, monkeypatch):
        self._gai_private(monkeypatch, '127.0.0.1')
        assert alerts._post_json(
            'https://localhost/hook', {'a': 1}) is False

    def test_no_redirect_following(self, monkeypatch):
        """A 302 is reported as failure — the pinned transport issues
        exactly one request and cannot follow Location at all."""
        self._gai_private(monkeypatch, '93.184.216.34')
        requests = []

        class _FakeResp:
            status = 302
            headers = {'Location': 'https://evil.internal/'}

            def getheaders(self):
                return [('Location', 'https://evil.internal/')]

            def read(self, amt=None):
                return b''

        class _FakeConn:
            def __init__(self, *a, **k):
                self.requests = requests

            def request(self, method, path, body=None, headers=None):
                requests.append((method, path))

            def getresponse(self):
                return _FakeResp()

            def close(self):
                pass

        monkeypatch.setattr(
            http_client, '_PinnedHTTPSConnection', _FakeConn)
        assert alerts._post_json(
            'https://example.com/hook', {'a': 1}) is False
        # Exactly one request — no redirect chase.
        assert requests == [('POST', '/hook')]

    def test_pinned_dial_uses_validated_ip(self, monkeypatch):
        """The connection must dial the IP that passed the public
        check — not re-resolve (DNS-rebinding window)."""
        self._gai_private(monkeypatch, '93.184.216.34')
        dialed = {}

        class _FakeConn:
            def __init__(self, ip, hostname, port, context, timeout):
                dialed['ip'] = ip
                dialed['sni'] = hostname

            def request(self, *a, **k):
                pass

            def getresponse(self):
                class R:
                    status = 200

                    def getheaders(self):
                        return []

                    def read(self, amt=None):
                        return b''
                return R()

            def close(self):
                pass

        monkeypatch.setattr(
            http_client, '_PinnedHTTPSConnection', _FakeConn)
        assert alerts._post_pinned(
            'https://example.com/hook', b'{}', {}) is True
        assert dialed['ip'] == '93.184.216.34'
        # SNI/Host still carry the real hostname for TLS verification.
        assert dialed['sni'] == 'example.com'

    def test_pinned_no_public_addr_refuses(self, monkeypatch):
        """If resolution yields no global address at connect time the
        request is refused — re-resolution to private can't connect."""
        self._gai_private(monkeypatch, '10.0.0.5')
        assert alerts._post_pinned(
            'https://internal/hook', b'{}', {}) is False
