"""SSL/TLS certificate management for VNC Remote Secure.

Generates self-signed certificates, validates existing certificates,
and reports their expiry dates. Uses the ``cryptography`` library when
available; falls back to the ``openssl`` CLI otherwise.
"""
import datetime
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


def create_ssl_context(cert_file=None, key_file=None):
    """Build an :class:`ssl.SSLContext` from env-configured cert/key paths.

    Reads ``SSL_CERT`` and ``SSL_KEY`` from the environment when the
    arguments are not provided. Returns ``None`` when TLS is disabled
    (no cert/key configured or files missing) so callers can fall back
    to plain HTTP/WSS gracefully.

    When ``TLS_ENABLED=false`` or ``DISABLE_SSL=true`` is set in the
    environment, TLS is explicitly disabled even if cert files exist.
    """
    import ssl

    # Allow explicit opt-out via TLS_ENABLED=false or DISABLE_SSL=true.
    if 'TLS_ENABLED' in os.environ:
        tls_enabled = os.environ['TLS_ENABLED'].lower()
        if tls_enabled in ('false', '0', 'no'):
            return None
    elif 'DISABLE_SSL' in os.environ:
        if os.environ['DISABLE_SSL'].lower() in ('true', '1', 'yes'):
            return None

    cert = cert_file or os.environ.get('SSL_CERT', '')
    key = key_file or os.environ.get('SSL_KEY', '')

    if not cert or not key:
        return None
    if not os.path.exists(cert) or not os.path.exists(key):
        logger.debug("SSL cert/key not found: %s / %s", cert, key)
        return None

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        logger.info("SSL context loaded from %s", cert)
        return context
    except Exception as exc:
        logger.warning("Failed to load SSL context: %s", exc)
        return None


def generate_self_signed(cert_path, key_path, common_name='vnc-remote-secure',
                         days_valid=365):
    """Generate a self-signed X.509 certificate and private key.

    Tries the ``cryptography`` library first, then falls back to the
    ``openssl`` command-line tool.

    Args:
        cert_path: Where to write the PEM certificate.
        key_path: Where to write the PEM private key.
        common_name: Subject CN for the certificate.
        days_valid: Certificate validity in days.

    Returns:
        ``True`` on success.

    Raises:
        RuntimeError: if neither backend is available.
    """
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return _generate_via_openssl(cert_path, key_path, common_name, days_valid)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    return True


def _generate_via_openssl(cert_path, key_path, common_name, days_valid):
    """Generate a certificate using the openssl CLI as a fallback."""
    cmd = [
        'openssl', 'req', '-x509', '-nodes', '-days', str(days_valid),
        '-newkey', 'rsa:2048',
        '-keyout', key_path,
        '-out', cert_path,
        '-subj', f'/CN={common_name}',
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl failed: {result.stderr.decode('utf-8', 'replace')}"
        )
    os.chmod(key_path, 0o600)
    return True


def validate_certificate(cert_path):
    """Return ``True`` if ``cert_path`` is a readable, non-expired cert."""
    expiry = get_cert_expiry(cert_path)
    if expiry is None:
        return False
    return expiry > datetime.datetime.utcnow()


def get_cert_expiry(cert_path):
    """Return the certificate's not-after datetime, or ``None``.

    Uses ``cryptography`` when available, falling back to ``openssl``.
    """
    if not os.path.exists(cert_path):
        return None
    try:
        from cryptography import x509
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert.not_valid_after
    except ImportError:
        pass
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-enddate', '-noout', '-in', cert_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None
        # Format: notAfter=May 15 12:00:00 2026 GMT
        line = result.stdout.strip()
        if '=' in line:
            line = line.split('=', 1)[1]
        return datetime.datetime.strptime(line, '%b %d %H:%M:%S %Y %Z')
    except (FileNotFoundError, ValueError):
        return None
