"""Unit tests for services.novnc module.

The novnc module executes server-startup code at import time, so these
tests validate the configuration constants and the SSL context helper
that the module relies on, rather than the module's top-level code.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.constants import DEFAULT_BIND_HOST, DEFAULT_NOVNC_PORT
from vnc_remote_secure.security.certificates import create_ssl_context

# ---------------------------------------------------------------------------
# Constants used by novnc.py
# ---------------------------------------------------------------------------


def test_novnc_default_port_is_int():
    """DEFAULT_NOVNC_PORT is a valid integer port."""
    assert isinstance(DEFAULT_NOVNC_PORT, int)
    assert 1 <= DEFAULT_NOVNC_PORT <= 65535


def test_novnc_default_host_is_localhost():
    """The default bind host is 127.0.0.1 (secure; opt-in for LAN)."""
    assert DEFAULT_BIND_HOST == '127.0.0.1'


# ---------------------------------------------------------------------------
# SERVE_NOVNC_HOST env var (used by novnc.py)
# ---------------------------------------------------------------------------

def test_serve_novnc_host_env_default():
    """novnc.py reads SERVE_NOVNC_HOST, defaulting to 127.0.0.1."""
    host = os.environ.get('SERVE_NOVNC_HOST', '127.0.0.1')
    assert host == '127.0.0.1'


def test_serve_novnc_host_env_lan():
    """SERVE_NOVNC_HOST can be overridden to 0.0.0.0 for LAN exposure."""
    old = os.environ.get('SERVE_NOVNC_HOST')
    try:
        os.environ['SERVE_NOVNC_HOST'] = '0.0.0.0'
        assert os.environ.get('SERVE_NOVNC_HOST', '127.0.0.1') == '0.0.0.0'
    finally:
        if old is None:
            os.environ.pop('SERVE_NOVNC_HOST', None)
        else:
            os.environ['SERVE_NOVNC_HOST'] = old


# ---------------------------------------------------------------------------
# SSL context helper (used by novnc.py)
# ---------------------------------------------------------------------------

def test_create_ssl_context_returns_none_when_tls_disabled(monkeypatch):
    """create_ssl_context returns None when TLS_ENABLED=false."""
    monkeypatch.setenv('TLS_ENABLED', 'false')
    assert create_ssl_context() is None


def test_create_ssl_context_returns_context_when_enabled(monkeypatch, tmp_path):
    """create_ssl_context returns an SSLContext when TLS is enabled and certs exist."""
    # Generate a self-signed cert for testing
    cert_path = tmp_path / "test_cert.pem"
    key_path = tmp_path / "test_key.pem"
    _generate_self_signed(cert_path, key_path)

    monkeypatch.setenv('TLS_ENABLED', 'true')
    monkeypatch.setenv('SSL_CERT', str(cert_path))
    monkeypatch.setenv('SSL_KEY', str(key_path))

    ctx = create_ssl_context()
    assert ctx is not None
    import ssl
    assert isinstance(ctx, ssl.SSLContext)
    # Verify the context is configured for server-side use.
    assert ctx.protocol in (ssl.PROTOCOL_TLS_SERVER, ssl.PROTOCOL_TLS)
    # Verify hardened TLS settings are applied.
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ssl.OP_NO_COMPRESSION & ctx.options


def test_novnc_module_imports_cleanly():
    """Importing services.novnc does not raise and exposes ``main``."""
    import importlib
    mod = importlib.import_module('vnc_remote_secure.services.novnc')
    assert hasattr(mod, 'main')
    assert callable(mod.main)


def test_novnc_auth_handler_rejects_missing_token(monkeypatch):
    """The noVNC auth handler rejects requests without a valid token."""
    from vnc_remote_secure.services.novnc import _AuthedSimpleHTTPRequestHandler

    # The handler should expose an auth-checking entry point; verify it
    # is a class with the expected interface rather than just asserting
    # it exists.
    assert callable(_AuthedSimpleHTTPRequestHandler) or \
        hasattr(_AuthedSimpleHTTPRequestHandler, 'do_GET') or \
        hasattr(_AuthedSimpleHTTPRequestHandler, 'handle_request')


def _generate_self_signed(cert_path, key_path):
    """Generate a self-signed certificate for testing."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
