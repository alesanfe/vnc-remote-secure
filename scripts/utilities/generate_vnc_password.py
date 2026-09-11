#!/usr/bin/env python3
"""Generate VNC password hash using d3des (correct VNC encryption)."""
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
    """Encrypt password using VNC's d3des with fixed key."""
    passpadd = (password + '\x00' * 8)[:8].encode('latin-1')
    key = bytes(d.vnckey)
    dk = d.deskey(key, False)
    crypted = d.desfunc(passpadd, dk)
    return binascii.hexlify(crypted).decode('ascii').upper()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 generate_vnc_password.py <password>", file=sys.stderr)
        print("Error: password argument is required (do not use defaults)", file=sys.stderr)
        sys.exit(1)
    password = sys.argv[1]
    pw_8 = password[:8]
    # Only print the truncated and encrypted forms, not the plaintext
    print(f"Truncated to 8 chars: {pw_8}")
    encrypted = vnc_encrypt_password(password)
    print(f"Encrypted (hex): {encrypted}")
    print(f"ultravnc.ini line: Password={encrypted}")
