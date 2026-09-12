#!/usr/bin/env python3
"""Generate VNC password hash using d3des (correct VNC encryption).

Supports two modes:
- Standard VNC (TigerVNC, TightVNC, RealVNC): uses bit-reversed DES key
- UltraVNC: uses DES key directly (no bit reversal)

UltraVNC 1.4.x uses a different key transformation than standard VNC.
This script generates both formats so the correct one can be used.
"""
import sys
import os
import binascii

# Add project root to path for vendor import
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_src_path = os.path.join(_project_root, 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

from vnc_remote_secure.vendor import d3des as d


def vnc_encrypt_password(password):
    """Encrypt password using standard VNC d3des with bit-reversed key.

    Used by TigerVNC, TightVNC, RealVNC, and most VNC clients.
    """
    passpadd = (password + '\x00' * 8)[:8].encode('latin-1')
    key = bytes(d.vnckey)
    dk = d.deskey(key, False)
    crypted = d.desfunc(passpadd, dk)
    return binascii.hexlify(crypted).decode('ascii').upper()


def ultravnc_encrypt_password(password):
    """Encrypt password using UltraVNC's DES (no bit reversal).

    UltraVNC 1.4.x uses the VNC fixed key directly without reversing
    the bit order in each byte, unlike standard VNC.
    """
    try:
        from Crypto.Cipher import DES
    except ImportError:
        # Fallback: use pycryptodome or manual DES
        raise ImportError(
            "pycryptodome is required for UltraVNC password generation. "
            "Install with: pip install pycryptodome"
        )

    passpadd = (password + '\x00' * 8)[:8].encode('latin-1')
    # UltraVNC uses the VNC key directly (no bit reversal)
    key = bytes(d.vnckey)
    cipher = DES.new(key, DES.MODE_ECB)
    crypted = cipher.encrypt(passpadd)
    return binascii.hexlify(crypted).decode('ascii').upper()


if __name__ == '__main__':
    # Prefer reading the password from the VNC_PASSWORD env var to avoid
    # exposing it in the process argument list (visible via `ps`).
    password = os.environ.get('VNC_PASSWORD', '')
    if not password and len(sys.argv) >= 2 and not sys.argv[1].startswith('--'):
        password = sys.argv[1]
    use_ultravnc = '--ultravnc' in sys.argv

    if not password:
        print(
            "Usage: VNC_PASSWORD=<password> python3 generate_vnc_password.py [--ultravnc]",
            file=sys.stderr,
        )
        print(
            "Error: password is required (set VNC_PASSWORD env var)",
            file=sys.stderr,
        )
        sys.exit(1)

    pw_8 = password[:8]

    # Only print the truncated and encrypted forms, not the plaintext
    print(f"Truncated to 8 chars: {pw_8}")

    if use_ultravnc:
        encrypted = ultravnc_encrypt_password(password)
        print(f"UltraVNC encrypted (hex): {encrypted}")
        print(f"ultravnc.ini line: passwd={encrypted}")
    else:
        encrypted = vnc_encrypt_password(password)
        print(f"Standard VNC encrypted (hex): {encrypted}")
        # Also show UltraVNC format for convenience
        try:
            uv_encrypted = ultravnc_encrypt_password(password)
            print(f"UltraVNC encrypted (hex): {uv_encrypted}")
            print(f"ultravnc.ini line: passwd={uv_encrypted}")
        except ImportError:
            pass
        print(f"Standard VNC ini line: Password={encrypted}")
