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
