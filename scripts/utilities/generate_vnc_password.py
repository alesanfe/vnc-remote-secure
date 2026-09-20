#!/usr/bin/env python3
"""Generate a VNC password hash in the real ``vncpasswd`` format.

There is exactly ONE algorithm: the password is truncated/zero-padded
to 8 bytes and DES-encrypted under the fixed VNC key (each key byte
bit-reversed before use). The same stored form is used by TigerVNC
(-PasswordFile), TightVNC, RealVNC AND UltraVNC (``ultravnc.ini``
``passwd``). The canonical implementation is
``vnc_remote_secure.vendor.d3des.encrypt_vnc_password`` — this script
is a thin CLI wrapper around it.

Verified vector (matches a real ultravnc.ini):
    vnc12345 -> F50F904B11EE3F7C
"""
import os
import sys

# Add project root to path for vendor import
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_src_path = os.path.join(_project_root, 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

from vnc_remote_secure.vendor.d3des import encrypt_vnc_password


def vnc_encrypt_password(password):
    """Return the hex-encoded vncpasswd form (the only VNC format)."""
    return encrypt_vnc_password(password).hex().upper()


def ultravnc_encrypt_password(password):
    """Alias kept for backwards compatibility — UltraVNC uses the
    same vncpasswd format as every other VNC flavour."""
    return vnc_encrypt_password(password)


if __name__ == '__main__':
    # Prefer reading the password from the VNC_PASSWORD env var to avoid
    # exposing it in the process argument list (visible via `ps`).
    password = os.environ.get('VNC_PASSWORD', '')
    if not password and len(sys.argv) >= 2 and not sys.argv[1].startswith('--'):
        password = sys.argv[1]

    if not password:
        print(
            "Usage: VNC_PASSWORD=<password> python3 generate_vnc_password.py",
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
    encrypted = vnc_encrypt_password(password)
    print(f"VNC encrypted (hex): {encrypted}")
    print(f"ultravnc.ini line: passwd={encrypted}")
    print(f"TigerVNC ini line: Password={encrypted}")
