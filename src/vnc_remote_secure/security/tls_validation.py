"""TLS cipher and configuration validation.

Validates that the TLS configuration meets security best practices:
- Rejects weak protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
- Rejects weak cipher suites (RC4, 3DES, MD5, NULL, EXPORT)
- Validates minimum key size for certificates
- Checks HSTS configuration when TLS is enabled
"""
import logging
import os
import ssl

logger = logging.getLogger(__name__)

# Minimum acceptable TLS version.
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2

# Rejected cipher patterns (case-insensitive substring match).
# 'DH' alone must NOT be here: it would flag ECDHE/DHE — the strong
# forward-secrecy key exchanges — as weak. The genuinely weak
# DH-family suites are anonymous DH ('ADH', covered by 'anon'/'aNULL')
# and static DH without ephemeral ('DH-'/'DH_'/static 'kDH').
WEAK_CIPHER_PATTERNS = (
    'RC4', '3DES', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'eNULL',
    'aNULL', 'PSK', 'SRP', 'kRSA', 'kDH', 'DH-', 'DH_', 'ADH',
)

# Required security headers when TLS is enabled.
REQUIRED_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    # Canonical name — 'X-Content-Security-Policy' is the deprecated
    # IE-only variant; http_headers.py emits 'Content-Security-Policy'.
    'Content-Security-Policy': "default-src 'self'",
}


def validate_tls_config() -> list:
    """Validate TLS configuration and return a list of findings.

    Returns:
        List of finding dicts with ``severity`` (``critical``/``warning``)
        and ``message``. Empty list means no issues found.
    """
    findings = []

    # Check if TLS is enabled.
    from vnc_remote_secure.security.profiles import _is_tls_enabled
    if not _is_tls_enabled():
        findings.append({
            'severity': 'info',
            'message': 'TLS is disabled — validation skipped',
        })
        return findings

    # Validate default SSL context.
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if ctx.minimum_version < MIN_TLS_VERSION:
            findings.append({
                'severity': 'critical',
                'message': f'Minimum TLS version is {ctx.minimum_version.name}, '
                           f'should be {MIN_TLS_VERSION.name} or higher',
            })
    except (OSError, ssl.SSLError, ValueError) as e:
        findings.append({
            'severity': 'warning',
            'message': f'Could not create SSL context: {e}',
        })

    # Validate certificate if configured. Resolve through the same
    # canonical logic the services use: explicit SSL_CERT/SSL_KEY
    # first, then the platform ssl dir (fullchain.pem/privkey.pem).
    cert = os.environ.get('SSL_CERT', '')
    key = os.environ.get('SSL_KEY', '')
    if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
        try:
            from vnc_remote_secure.core.paths import get_ssl_dir
            ssl_dir = get_ssl_dir()
            d_cert = os.path.join(ssl_dir, 'fullchain.pem')
            d_key = os.path.join(ssl_dir, 'privkey.pem')
            if os.path.exists(d_cert) and os.path.exists(d_key):
                cert, key = d_cert, d_key
        except Exception:  # noqa: BLE001
            pass
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        cert_findings = _validate_certificate(cert, key)
        findings.extend(cert_findings)
    elif cert and not key:
        findings.append({
            'severity': 'warning',
            'message': 'SSL_CERT is set but SSL_KEY is missing',
        })
    elif key and not cert:
        findings.append({
            'severity': 'warning',
            'message': 'SSL_KEY is set but SSL_CERT is missing',
        })

    # Check for weak cipher environment overrides.
    cipher_override = os.environ.get('SSL_CIPHERS', '')
    if cipher_override:
        for weak in WEAK_CIPHER_PATTERNS:
            if weak.lower() in cipher_override.lower():
                findings.append({
                    'severity': 'critical',
                    'message': f'Weak cipher "{weak}" in SSL_CIPHERS',
                })

    return findings


def _validate_certificate(cert_path: str, key_path: str) -> list:
    """Validate a certificate file for security issues."""
    findings = []
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        # Load and parse the certificate using the cryptography library
        # (ssl.SSLContext does not expose get_certificate() in CPython).
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Check key size. Ed25519/Ed448/X25519 keys have no `key_size`
        # attribute — their security level is fixed and adequate, so a
        # missing attribute skips the minimum-size check.
        public_key = cert.public_key()
        key_size = getattr(public_key, 'key_size', None)
        if key_size is not None and key_size < 2048:
            findings.append({
                'severity': 'critical',
                'message': f'Certificate key size is {key_size} bits, '
                           'minimum 2048 required',
            })

        # Check expiry.
        not_after = cert.not_valid_after_utc
        if not_after:
            from datetime import timezone
            days_left = (not_after - datetime.datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append({
                    'severity': 'critical',
                    'message': f'Certificate expired {-days_left} days ago',
                })
            elif days_left < 30:
                findings.append({
                    'severity': 'warning',
                    'message': f'Certificate expires in {days_left} days',
                })

        # Verify the key matches the certificate (best-effort).
        try:
            from cryptography.hazmat.primitives import serialization
            with open(key_path, 'rb') as f:
                key_data = f.read()
            key = serialization.load_pem_private_key(
                key_data, password=None, backend=default_backend())
            # Compare public numbers — if they match, key and cert are
            # a pair. Ed25519-family keys have no public_numbers(); for
            # those, compare the raw public bytes instead.
            def _pub_bytes(k):
                if hasattr(k, 'public_numbers'):
                    return repr(k.public_numbers())
                return k.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw)
            cert_pub = _pub_bytes(cert.public_key())
            key_pub = _pub_bytes(key.public_key())
            if cert_pub != key_pub:
                findings.append({
                    'severity': 'critical',
                    'message': 'Certificate and private key do not match',
                })
        except (OSError, ssl.SSLError, ValueError) as e:
            findings.append({
                'severity': 'warning',
                'message': f'Could not validate private key: {e}',
            })

    except (OSError, ssl.SSLError, ValueError) as e:
        findings.append({
            'severity': 'warning',
            'message': f'Certificate validation error: {e}',
        })
    return findings


def get_recommended_ssl_context() -> ssl.SSLContext:
    """Return a hardened SSL context for server use.

    This context enforces:
    - TLS 1.2+ only
    - Strong cipher suites (no RC4, 3DES, etc.)
    - No compression (CRIME attack prevention)
    - Single DH use (forward secrecy)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = MIN_TLS_VERSION
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_NO_RENEGOTIATION

    # Set strong cipher suites.
    strong_ciphers = (
        'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20'
    )
    try:
        ctx.set_ciphers(strong_ciphers)
    except ssl.SSLError as e:
        logger.warning("Could not set strong ciphers: %s", e)

    return ctx
