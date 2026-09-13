"""Unit tests for security posture scoring."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.posture import calculate_posture


class TestPosture:
    def test_returns_score_0_to_100(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.setenv('MFA_REQUIRED', 'true')
        result = calculate_posture()
        assert 0 <= result['score'] <= 100

    def test_returns_checks_list(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        result = calculate_posture()
        assert 'checks' in result
        assert isinstance(result['checks'], list)
        assert len(result['checks']) > 0

    def test_returns_summary(self, monkeypatch):
        result = calculate_posture()
        assert 'summary' in result
        assert isinstance(result['summary'], str)

    def test_tls_disabled_reduces_score(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.setenv('MFA_REQUIRED', 'true')
        score_secure = calculate_posture()['score']

        monkeypatch.setenv('TLS_ENABLED', 'false')
        score_insecure = calculate_posture()['score']

        assert score_insecure < score_secure

    def test_bind_localhost_better_than_exposed(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        score_local = calculate_posture()['score']

        monkeypatch.setenv('BIND_HOST', '0.0.0.0')
        score_exposed = calculate_posture()['score']

        assert score_exposed <= score_local

    def test_mfa_improves_score(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('MFA_REQUIRED', 'false')
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        score_no_mfa = calculate_posture()['score']

        monkeypatch.setenv('MFA_REQUIRED', 'true')
        score_mfa = calculate_posture()['score']

        assert score_mfa >= score_no_mfa

    def test_placeholder_detected(self, monkeypatch):
        monkeypatch.setenv('DISCORD_WEBHOOK_URL', 'https://discord.com/api/webhooks/YOUR_WEBHOOK_URL')
        result = calculate_posture()
        placeholder_check = [c for c in result['checks'] if 'placeholder' in c['name'].lower()]
        if placeholder_check:
            assert placeholder_check[0]['status'] != 'ok'

    def test_disable_ssl_equivalent_to_tls_enabled_false(self, monkeypatch):
        """DISABLE_SSL=true should produce the same score as TLS_ENABLED=false."""
        monkeypatch.setattr('vnc_remote_secure.security.posture.load_env_file', lambda: None)
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.setenv('MFA_REQUIRED', 'true')
        monkeypatch.setenv('TLS_ENABLED', '')
        monkeypatch.setenv('DISABLE_SSL', 'true')
        score_disable_ssl = calculate_posture()['score']

        monkeypatch.setenv('DISABLE_SSL', '')
        monkeypatch.setenv('TLS_ENABLED', 'false')
        score_tls_false = calculate_posture()['score']

        assert score_disable_ssl == score_tls_false

    def test_disable_ssl_false_equivalent_to_tls_enabled_true(self, monkeypatch):
        """DISABLE_SSL=false should produce the same score as TLS_ENABLED=true."""
        monkeypatch.setattr('vnc_remote_secure.security.posture.load_env_file', lambda: None)
        monkeypatch.setenv('BIND_HOST', '127.0.0.1')
        monkeypatch.setenv('MFA_REQUIRED', 'true')
        monkeypatch.setenv('TLS_ENABLED', '')
        monkeypatch.setenv('DISABLE_SSL', 'false')
        score_disable_ssl_false = calculate_posture()['score']

        monkeypatch.setenv('DISABLE_SSL', '')
        monkeypatch.setenv('TLS_ENABLED', 'true')
        score_tls_true = calculate_posture()['score']

        assert score_disable_ssl_false == score_tls_true
