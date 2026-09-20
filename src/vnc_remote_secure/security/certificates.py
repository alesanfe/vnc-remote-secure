"""SSL/TLS certificate management for VNC Remote Secure.

Generates self-signed certificates, validates existing certificates,
and reports their expiry dates. Uses the ``cryptography`` library when
available; falls back to the ``openssl`` CLI otherwise.
"""
import datetime
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def request_letsencrypt(domain, email, ssl_dir=None):
    """Request a Let's Encrypt certificate via certbot.

    Tries the nginx plugin first (works while nginx is running via the
    ``python3-certbot-nginx`` package), then falls back to the standalone
    HTTP-01 server (requires port 80 free).

    Args:
        domain: FQDN to issue the certificate for (e.g.
            ``example.duckdns.org``).
        email: Contact email for the ACME account.
        ssl_dir: When provided, ``fullchain.pem`` and ``privkey.pem``
            are symlinked from ``/etc/letsencrypt/live/<domain>/`` into
            this directory so the app picks up renewals automatically.

    Returns:
        ``True`` when certificates were issued and are available.
    """
    certbot = shutil.which('certbot')
    if not certbot:
        logger.warning("certbot not installed; cannot request Let's Encrypt.")
        return False
    if not domain or not email:
        logger.warning("Domain and email are required for Let's Encrypt.")
        return False

    base_cmd = [
        certbot, 'certonly', '-n', '--agree-tos',
        '-m', email, '-d', domain,
    ]
    for plugin_args in (['--nginx'], ['--standalone']):
        result = subprocess.run(
            base_cmd + plugin_args, capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.info("Let's Encrypt certificate issued for %s", domain)
            break
        logger.debug("certbot %s failed: %s",
                     plugin_args[0], result.stderr.strip()[:300])
    else:
        logger.warning("Let's Encrypt issuance failed for %s", domain)
        return False

    live_dir = os.path.join('/etc/letsencrypt/live', domain)
    fullchain = os.path.join(live_dir, 'fullchain.pem')
    privkey = os.path.join(live_dir, 'privkey.pem')
    if not (os.path.exists(fullchain) and os.path.exists(privkey)):
        logger.warning("certbot succeeded but certs not found in %s", live_dir)
        return False

    if ssl_dir:
        os.makedirs(ssl_dir, exist_ok=True)
        for name in ('fullchain.pem', 'privkey.pem'):
            src = os.path.join(live_dir, name)
            dst = os.path.join(ssl_dir, name)
            if os.path.lexists(dst):
                os.remove(dst)
            os.symlink(src, dst)
        logger.info("Linked Let's Encrypt certificates into %s", ssl_dir)
    return True


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
    # Delegate to the canonical resolver — a third interpretation here
    # once disagreed on the TLS_ENABLED-vs-DISABLE_SSL precedence.
    try:
        from vnc_remote_secure.core.config import _is_tls_enabled_env
        if not _is_tls_enabled_env():
            return None
    except ImportError:
        # Mirror the canonical semantics: DISABLE_SSL=true is a
        # kill-switch that wins over TLS_ENABLED — checking TLS_ENABLED
        # first here would silently re-enable TLS when the operator
        # explicitly asked to disable it.
        disable_val = os.environ.get('DISABLE_SSL', '').strip()
        if disable_val and disable_val.lower() in ('true', '1', 'yes'):
            return None
        tls_val = os.environ.get('TLS_ENABLED', '').strip()
        if tls_val and tls_val.lower() in ('false', '0', 'no'):
            return None

    cert = cert_file or os.environ.get('SSL_CERT', '')
    key = key_file or os.environ.get('SSL_KEY', '')

    # Fall back to the canonical SSL dir (ProgramData on Windows,
    # XDG/FHS on Linux) and the legacy <project>/data/ssl location —
    # the same discovery ``config._get_ssl_config`` performs, so every
    # service terminates TLS consistently rather than only the ones
    # passing config-derived paths.
    if not cert or not key:
        try:
            from vnc_remote_secure.core.paths import find_project_root, get_ssl_dir
            for cert_dir in (
                    get_ssl_dir(),
                    os.path.join(find_project_root(), 'data', 'ssl')):
                default_cert = os.path.join(cert_dir, 'fullchain.pem')
                default_key = os.path.join(cert_dir, 'privkey.pem')
                if os.path.exists(default_cert) and os.path.exists(default_key):
                    cert = cert or default_cert
                    key = key or default_key
                    break
        except Exception:  # noqa: BLE001 - discovery is best-effort
            pass

    if not cert or not key:
        return None
    if not os.path.exists(cert) or not os.path.exists(key):
        logger.debug("SSL cert/key not found: %s / %s", cert, key)
        return None

    try:
        # Use the hardened TLS context from tls_validation when available
        # so all servers share the same minimum version, cipher policy,
        # and compression disabling.
        try:
            from vnc_remote_secure.security.tls_validation import (
                get_recommended_ssl_context,
            )
            context = get_recommended_ssl_context()
        except Exception:  # noqa: BLE001 - fallback to a sane default
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                context.options |= ssl.OP_NO_COMPRESSION
            except AttributeError:
                pass
        context.load_cert_chain(cert, key)
        logger.info("SSL context loaded from %s", cert)
        return context
    except Exception as exc:
        logger.warning("Failed to load SSL context: %s", exc)
        return None


def _restrict_key_permissions(key_path, writable=False):
    """Restrict a secret file to owner/administrators only.

    POSIX: ``chmod 0o600``. Windows: ``os.chmod`` only toggles the
    read-only attribute, so the ACL must be restricted explicitly —
    otherwise a key under ``%ProgramData%`` stays readable by the
    ``Users`` group. Uses universal SIDs so the call works on any
    system locale (e.g. ``Administradores`` on es-ES).

    ``writable=True`` grants (R,W) instead of (R) — required for
    files the service rewrites (audit log, session store, shared
    state db); a read-only grant would break the app's own writes.
    """
    if os.name == 'nt':
        import subprocess
        user = os.environ.get('USERNAME', '')
        rights = '(R,W)' if writable else '(R)'
        grants = [f'*S-1-5-18:{rights}', f'*S-1-5-32-544:{rights}']
        if user:
            grants.append(f'{user}:{rights}')
        try:
            # '/grant:r' only replaces ACEs belonging to the granted
            # principals — explicit ACEs for other principals (e.g. an
            # earlier Everyone grant) would survive. '/reset' first
            # restores the inherited ACL, wiping every explicit ACE,
            # so the file ends up with exactly the grants below.
            subprocess.run(
                ['icacls', key_path, '/reset'],
                capture_output=True, timeout=15, check=False,
            )
            subprocess.run(
                ['icacls', key_path, '/inheritance:r',
                 '/grant:r', *grants],
                capture_output=True, timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning(
                "Could not restrict key ACL at %s: %s", key_path, exc)
    else:
        os.chmod(key_path, 0o600)


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
    san_entries = [x509.DNSName(common_name)]
    if common_name == 'vnc-remote-secure':
        # Useful default SANs for the localhost dev/fallback cert.
        import ipaddress
        san_entries = [
            x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
        ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False,
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
    _restrict_key_permissions(key_path)
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
    _restrict_key_permissions(key_path)
    return True
