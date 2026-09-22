"""VNC password encryption using DES.

VNC authentication uses DES with a fixed key where each byte's bits are
reversed. This module provides the VNC-specific key handling and delegates
the actual DES encryption to pycryptodome.
"""
try:
    from Crypto.Cipher import DES as _DES
except ImportError:
    _DES = None  # type: ignore[assignment]

# VNC fixed key (all zeros before bit reversal).
vnckey = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]

# Fixed key used to obfuscate stored VNC passwords (the ``vncpasswd``
# file format and UltraVNC's ``ultravnc.ini`` ``passwd`` value).
# This is the EFFECTIVE DES key 0xE84AD660C4721AE0 — i.e. UltraVNC's
# ``fixedkey`` {23,82,107,6,35,78,88,7} after the bit reversal that
# the original VNC d3des ``deskey`` applies internally. When using
# pycryptodome (which does NOT reverse key bits) the key must be used
# as-is; passing it through ``deskey`` would reverse it a second time
# and produce a blob UltraVNC cannot decrypt.
VNC_PASSWD_FIXED_KEY = bytes(
    [0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0])


def _bit_reverse(byte):
    """Reverse the bit order of a single byte."""
    result = 0
    for i in range(8):
        result = (result << 1) | ((byte >> i) & 1)
    return result


def deskey(key, decrypt):
    """Return a subkey schedule compatible with d3des.

    For pycryptodome-backed encryption the key is preprocessed (bit-reversed
    for standard VNC) and returned as a tuple ``(processed_key, decrypt)``
    so :func:`desfunc` can perform the actual DES operation.
    """
    processed = bytes(_bit_reverse(b) for b in key)
    return (processed, decrypt)


def desfunc(data, subkeys):
    """Encrypt or decrypt 8 bytes of data using the subkey schedule.

    ``subkeys`` is the tuple returned by :func:`deskey`.
    """
    if _DES is None:
        raise ImportError(
            "pycryptodome is required for VNC password encryption. "
            "Install with: pip install pycryptodome"
        )
    key, _decrypt = subkeys
    cipher = _DES.new(key, _DES.MODE_ECB)
    return cipher.encrypt(data)


def encrypt_vnc_password(password: str) -> bytes:
    """Return the 8-byte ``vncpasswd``-format obfuscated password.

    The stored form is the password truncated/zero-padded to 8 bytes
    and DES-encrypted under the fixed VNC key — NOT DES with the
    password as its own key (a common mistake: that produces bytes no
    VNC server can match against the RFB challenge).
    """
    if _DES is None:
        raise ImportError(
            "pycryptodome is required for VNC password encryption. "
            "Install with: pip install pycryptodome"
        )
    padded = password.encode('latin-1')[:8].ljust(8, b'\x00')
    cipher = _DES.new(VNC_PASSWD_FIXED_KEY, _DES.MODE_ECB)
    return cipher.encrypt(padded)
