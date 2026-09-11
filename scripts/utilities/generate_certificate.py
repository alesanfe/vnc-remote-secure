#!/usr/bin/env python3
"""Generate self-signed SSL certificate for the VNC remote app."""
import subprocess
import sys
import os
import datetime
import ipaddress


def generate_cert(cert_path, key_path):
    """Generate self-signed cert using Python cryptography library."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("cryptography library not installed. Installing...")
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', 'cryptography'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"ERROR: Failed to install cryptography: {result.stderr}",
                  file=sys.stderr)
            sys.exit(1)
        # Re-import after install (no recursion)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Use timezone-aware datetime (utcnow is deprecated)
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write cert
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write key with restrictive permissions
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Set restrictive permissions on private key
    try:
        os.chmod(key_path, 0o600)
    except (OSError, NotImplementedError):
        pass  # Windows may not support chmod

    print(f"Certificate generated: {cert_path}")
    print(f"Private key generated: {key_path}")


if __name__ == '__main__':
    project_dir = os.path.dirname(os.path.abspath(__file__))
    ssl_dir = os.path.join(project_dir, 'data', 'ssl')
    os.makedirs(ssl_dir, exist_ok=True)

    cert = os.path.join(ssl_dir, 'fullchain.pem')
    key = os.path.join(ssl_dir, 'privkey.pem')

    # Remove old certs
    for f in [cert, key]:
        if os.path.exists(f):
            os.remove(f)

    generate_cert(cert, key)
