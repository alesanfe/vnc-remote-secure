"""Tests for HTTP security headers."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.http_headers import get_security_headers


class TestSecurityHeaders:
    def test_default_headers_present(self):
        headers = get_security_headers(tls_enabled=False)
        assert 'X-Frame-Options' in headers
        assert headers['X-Frame-Options'] == 'DENY'
        assert 'X-Content-Type-Options' in headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert 'Content-Security-Policy' in headers
        assert 'Referrer-Policy' in headers
        assert 'Permissions-Policy' in headers

    def test_hsts_only_with_tls(self):
        headers_no_tls = get_security_headers(tls_enabled=False)
        headers_tls = get_security_headers(tls_enabled=True)
        assert 'Strict-Transport-Security' not in headers_no_tls
        assert 'Strict-Transport-Security' in headers_tls
        assert 'max-age' in headers_tls['Strict-Transport-Security']

    def test_csp_override(self, monkeypatch):
        monkeypatch.setenv('CSP_POLICY', "default-src 'none'")
        headers = get_security_headers()
        assert headers['Content-Security-Policy'] == "default-src 'none'"

    def test_hsts_override(self, monkeypatch):
        monkeypatch.setenv('HSTS_HEADER', 'max-age=86400')
        headers = get_security_headers(tls_enabled=True)
        assert headers['Strict-Transport-Security'] == 'max-age=86400'

    def test_no_hsts_over_http(self):
        """HSTS must never be sent over HTTP."""
        headers = get_security_headers(tls_enabled=False)
        assert 'Strict-Transport-Security' not in headers
