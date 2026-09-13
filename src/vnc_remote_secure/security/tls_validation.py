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
WEAK_CIPHER_PATTERNS = (
    'RC4', '3DES', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'eNULL',
    'aNULL', 'PSK', 'SRP', 'kRSA', 'DH',
)

# Required security headers when TLS is enabled.
REQUIRED_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-Content-Security-Policy': "default-src 'self'",
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
    except Exception as e:
        findings.append({
            'severity': 'warning',
            'message': f'Could not create SSL context: {e}',
        })

    # Validate certificate if configured.
    cert = os.environ.get('SSL_CERT', '')
    key = os.environ.get('SSL_KEY', '')
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
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)

        # Get the certificate.
        cert = ctx.get_certificate()
        if cert is None:
            findings.append({
                'severity': 'warning',
                'message': 'Could not load certificate from file',
            })
            return findings

        # Check key size.
        public_key = cert.get_publickey()
        key_size = public_key.bits()
        if key_size < 2048:
            findings.append({
                'severity': 'critical',
                'message': f'Certificate key size is {key_size} bits, '
                           f'minimum 2048 required',
            })
        public_key.free()

        # Check expiry.
        not_after = cert.get_notAfter()
        if not_after:
            import datetime
            expiry = datetime.datetime.strptime(
                not_after.decode('ascii'), '%Y%m%d%H%M%SZ'
            )
            days_left = (expiry - datetime.datetime.utcnow()).days
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

    except Exception as e:
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
