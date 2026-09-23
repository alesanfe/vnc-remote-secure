"""Tests for the alert dispatch module (monitoring/alerts.py)."""
import pytest

from vnc_remote_secure.monitoring import alerts


@pytest.fixture(autouse=True)
def _clean_alert_env(monkeypatch):
    """Ensure no alert-related env leaks between tests."""
    for var in ('ALERTS_ENABLED', 'DISCORD_ENABLED', 'DISCORD_WEBHOOK_URL',
                'ALERT_WEBHOOK_URL', 'ALERT_EMAIL_TO', 'ALERT_SMTP_SERVER',
                'ALERT_EMAIL_FROM', 'ALERT_SMTP_USER', 'ALERT_SMTP_PASS'):
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
        import urllib.request
        hits = []
        monkeypatch.setattr(
            urllib.request, 'urlopen',
            lambda *a, **k: hits.append(1))
        from vnc_remote_secure.monitoring import alerts
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
        import urllib.request

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(urllib.request, 'urlopen',
                            lambda *a, **k: _Resp())
        from vnc_remote_secure.monitoring import alerts
        assert alerts._post_json('http://h/x', {}) is True
        assert alerts._post_json('https://h/x', {}) is True

    def test_urlopen_exception_returns_false(self, monkeypatch):
        import urllib.request
        monkeypatch.setattr(
            urllib.request, 'urlopen',
            lambda *a, **k: (_ for _ in ()).throw(OSError('no')))
        from vnc_remote_secure.monitoring import alerts
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

        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(
            'urllib.request.urlopen',
            lambda req, timeout=0: captured.update(
                req=req) or FakeResp())
        monkeypatch.setenv('ALERT_WEBHOOK_URL', 'https://hook.local/x')
        if secret:
            monkeypatch.setenv('ALERT_WEBHOOK_SECRET', secret)
        else:
            monkeypatch.delenv('ALERT_WEBHOOK_SECRET', raising=False)
        from vnc_remote_secure.monitoring import alerts
        return alerts, captured

    def test_signature_header_present(self, monkeypatch):
        import hashlib
        import hmac
        import json as _json
        alerts, captured = self._capture(monkeypatch, 's3cret')
        assert alerts.send_webhook_alert('t', 'm') is True
        req = captured['req']
        sig = req.get_header('X-vncremote-signature')
        assert sig is not None
        assert sig.startswith('sha256=')
        body = _json.loads(req.data.decode())
        expected = hmac.new(b's3cret', req.data,
                            hashlib.sha256).hexdigest()
        assert sig == f'sha256={expected}'
        assert body['title'] == 't'

    def test_no_secret_no_header(self, monkeypatch):
        alerts, captured = self._capture(monkeypatch, '')
        alerts.send_webhook_alert('t', 'm')
        assert captured['req'].get_header('X-vncremote-signature') is None
