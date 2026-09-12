"""Multi-factor authentication using TOTP (RFC 6238).

Provides TOTP secret generation, verification, and recovery codes.
Integrates with the existing session model in authentication.py.
"""
import hashlib
import hmac
import os
import secrets
import struct
import time
from typing import Optional

from vnc_remote_secure.core.config import load_env_file

# TOTP parameters (RFC 6238 defaults)
TOTP_INTERVAL = 30  # seconds
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # allow 1 step before/after current time


def _base32_encode(data: bytes) -> str:
    """Base32-encode without padding (RFC 4648)."""
    import base64
    return base64.b32encode(data).decode('ascii').rstrip('=')


def _base32_decode(data: str) -> bytes:
    """Base32-decode, adding padding if needed."""
    import base64
    padding = (8 - len(data) % 8) % 8
    return base64.b32decode(data + '=' * padding)


def generate_totp_secret() -> str:
    """Generate a new TOTP secret (Base32-encoded, 20 bytes = 160 bits)."""
    return _base32_encode(secrets.token_bytes(20))


def generate_totp_uri(secret: str, account: str, issuer: str = 'VNC Remote Secure') -> str:
    """Generate an otpauth:// URI for QR code generation."""
    from urllib.parse import quote, urlencode
    label = f"{issuer}:{account}"
    params = urlencode({
        'secret': secret,
        'issuer': issuer,
        'algorithm': 'SHA1',
        'digits': str(TOTP_DIGITS),
        'period': str(TOTP_INTERVAL),
    })
    return f"otpauth://totp/{quote(label)}?{params}"


def _hotp(secret: bytes, counter: int) -> int:
    """Compute HOTP value (RFC 4226)."""
    msg = struct.pack('>Q', counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7FFFFFFF
    return code % (10 ** TOTP_DIGITS)


def verify_totp(secret: str, code: str, timestamp: Optional[int] = None) -> bool:
    """Verify a TOTP code against the secret.

    Allows a window of +/- TOTP_WINDOW steps to account for clock drift.
    """
    if not code or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    try:
        key = _base32_decode(secret)
    except Exception:
        return False
    ts = timestamp or int(time.time())
    step = ts // TOTP_INTERVAL
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        candidate = _hotp(key, step + delta)
        if hmac.compare_digest(f"{candidate:0{TOTP_DIGITS}d}", code):
            return True
    return False


def generate_recovery_codes(count: int = 8) -> list:
    """Generate one-time recovery codes (format: XXXX-XXXX)."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(4)  # 8 hex chars
        codes.append(f"{raw[:4]}-{raw[4:]}".upper())
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for secure storage (SHA-256)."""
    return hashlib.sha256(code.upper().encode('utf-8')).hexdigest()


def verify_recovery_code(code: str, stored_hashes: list) -> bool:
    """Verify a recovery code against a list of stored hashes.

    Returns True if the code matches any stored hash. Caller should
    remove the used hash after successful verification.
    """
    if not code:
        return False
    code_hash = hash_recovery_code(code)
    for stored in stored_hashes:
        if hmac.compare_digest(code_hash, stored):
            return True
    return False


def is_mfa_enabled() -> bool:
    """Check if MFA is configured for the current user."""
    load_env_file()
    return bool(os.environ.get('TOTP_SECRET'))


def mfa_required_for_login() -> bool:
    """Check if MFA should be required at login time.

    MFA is required when:
    - TOTP_SECRET is configured, OR
    - MFA_REQUIRED env var is set to true
    """
    load_env_file()
    if os.environ.get('MFA_REQUIRED', 'false').lower() in ('true', '1', 'yes'):
        return True
    return is_mfa_enabled()
