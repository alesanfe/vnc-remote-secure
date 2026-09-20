"""Unit tests for secret redaction module."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.redaction import (
    SECRET_VARS,
    get_secret_status,
    redact_dict,
    redact_text,
    redact_value,
)


class TestRedactValue:
    def test_empty_returns_empty(self):
        assert redact_value('TTYD_PASSWD', '') == 'empty'

    def test_secret_returns_configured(self):
        assert redact_value('VNC_PASSWORD', 'supersecret123') == 'configured'

    def test_non_secret_returned_as_is(self):
        assert redact_value('TTYD_USERNAME', 'alex0') == 'alex0'

    def test_fingerprint_shown_when_requested(self):
        result = redact_value('VNC_PASSWORD', 'supersecret123', show_fingerprint=True)
        assert result.startswith('configured (sha256:')
        assert len(result) == len('configured (sha256:') + 8 + 1  # 8 hex chars + )

    def test_fingerprint_is_consistent(self):
        r1 = redact_value('VNC_PASSWORD', 'secret', show_fingerprint=True)
        r2 = redact_value('VNC_PASSWORD', 'secret', show_fingerprint=True)
        assert r1 == r2

    def test_different_values_different_fingerprints(self):
        r1 = redact_value('VNC_PASSWORD', 'secret1', show_fingerprint=True)
        r2 = redact_value('VNC_PASSWORD', 'secret2', show_fingerprint=True)
        assert r1 != r2


class TestRedactDict:
    def test_redacts_secret_keys(self):
        data = {
            'VNC_PASSWORD': 'supersecret',
            'TTYD_USERNAME': 'alex0',
            'port': 5900,
        }
        redacted = redact_dict(data)
        assert redacted['VNC_PASSWORD'] == 'configured'
        assert redacted['TTYD_USERNAME'] == 'alex0'
        assert redacted['port'] == 5900

    def test_handles_nested_dicts(self):
        data = {
            'config': {
                'VNC_PASSWORD': 'secret',
                'port': 5900,
            }
        }
        redacted = redact_dict(data)
        assert redacted['config']['VNC_PASSWORD'] == 'configured'
        assert redacted['config']['port'] == 5900


class TestRedactText:
    def test_redacts_known_secrets(self, monkeypatch):
        monkeypatch.setenv('VNC_PASSWORD', 'MySecretPass123')
        text = "Connecting with password MySecretPass123 to server"
        redacted = redact_text(text)
        assert 'MySecretPass123' not in redacted
        assert '[REDACTED]' in redacted

    def test_preserves_non_secret_text(self):
        text = "This is a normal log message"
        assert redact_text(text) == text

    def test_handles_empty(self):
        assert redact_text('') == ''


class TestGetSecretStatus:
    def test_returns_all_secret_vars(self):
        status = get_secret_status()
        for var in SECRET_VARS:
            assert var in status

    def test_values_are_configured_or_empty(self):
        status = get_secret_status()
        for val in status.values():
            assert val in ('configured', 'empty')

    def test_no_actual_values_exposed(self):
        """Ensure no actual secret values appear in the status output."""
        status = get_secret_status()
        # The values should only be 'configured' or 'empty', never actual secrets
        for val in status.values():
            assert val in ('configured', 'empty')
            assert len(val) <= 12  # 'configured' is 10 chars
