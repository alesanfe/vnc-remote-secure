"""Tests for TLS validation."""
import os
import ssl
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.tls_validation import (
    get_recommended_ssl_context,
    validate_tls_config,
)


class TestTLSValidation:
    def test_disabled_tls_skips_validation(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'false')
        findings = validate_tls_config()
        assert len(findings) == 1
        assert findings[0]['severity'] == 'info'

    def test_enabled_tls_no_cert(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.delenv('SSL_CERT', raising=False)
        monkeypatch.delenv('SSL_KEY', raising=False)
        findings = validate_tls_config()
        # Should not have critical errors about cert.
        criticals = [f for f in findings if f['severity'] == 'critical' and 'SSL_CERT' in f.get('message', '')]
        assert len(criticals) == 0

    def test_weak_cipher_in_env_rejected(self, monkeypatch):
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('SSL_CIPHERS', 'RC4-MD5:DES-CBC3-SHA')
        findings = validate_tls_config()
        criticals = [f for f in findings if f['severity'] == 'critical']
        assert any('RC4' in f['message'] for f in criticals)
        assert any('DES' in f['message'] for f in criticals)


class TestRecommendedSSLContext:
    def test_min_version_is_tls12(self):
        ctx = get_recommended_ssl_context()
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_no_compression(self):
        ctx = get_recommended_ssl_context()
        assert ctx.options & ssl.OP_NO_COMPRESSION

    def test_no_renegotiation(self):
        ctx = get_recommended_ssl_context()
        assert ctx.options & ssl.OP_NO_RENEGOTIATION
