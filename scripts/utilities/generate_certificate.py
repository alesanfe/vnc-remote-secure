#!/usr/bin/env python3
"""Generate a self-signed SSL certificate — thin delegator.

DEPRECATED: retained for convenience only. The canonical implementation
is ``vnc_remote_secure.security.certificates.generate_self_signed`` and
certificates are created automatically by ``vnc-remote install``
(Let's Encrypt when DUCK_DOMAIN+EMAIL are set, self-signed otherwise).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vnc_remote_secure.core.paths import get_ssl_dir
from vnc_remote_secure.security.certificates import generate_self_signed


def main():
    ssl_dir = get_ssl_dir()
    os.makedirs(ssl_dir, exist_ok=True)
    cert = os.path.join(ssl_dir, 'fullchain.pem')
    key = os.path.join(ssl_dir, 'privkey.pem')

    if os.path.exists(cert) and os.path.exists(key):
        print(f"Certificates already exist: {cert}")
        return 0

    generate_self_signed(cert, key)
    print(f"Certificate generated: {cert}")
    print(f"Private key generated: {key}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
