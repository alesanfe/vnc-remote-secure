"""Multi-factor authentication using TOTP (RFC 6238).

Provides TOTP secret generation, verification, and recovery codes.
Integrates with the existing session model in authentication.py.
"""
import hashlib
import hmac
import logging
import os
import secrets
import struct
import time

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)

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


_NS_TOTP = 'mfa_last_step'


def _secret_id(secret: str) -> str:
    """Return a short stable identifier for a TOTP secret."""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _last_step(secret: str):
    """Return the highest TOTP counter consumed for this secret.

    Namespaced per secret — a global high-water mark would let one
    user's successful login reject another user's legitimate code
    (they share timesteps, not secrets).
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        val = get_backend().get(_NS_TOTP, f'last:{_secret_id(secret)}')
        return int(val) if val is not None else -1
    except Exception:  # noqa: BLE001
        return -1


def _record_step(step: int, secret: str = ''):
    """Persist the consumed TOTP counter so it cannot be replayed.

    ``secret`` may be empty for legacy/test callers — the key then
    degrades to the old global bucket.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        key = f'last:{_secret_id(secret)}' if secret else 'last'
        get_backend().set(_NS_TOTP, key, step)
    except Exception:  # noqa: BLE001
        pass


def _claim_step(secret: str, step: int) -> bool:
    """Atomically claim a TOTP timestep for a secret (single-use).

    ``_last_step`` blocks counters at or below the highest consumed
    one, but two processes could still verify the same code before
    either records it — the per-step claim closes that race with an
    atomic insert. The key is namespaced by a digest of the secret:
    different users' devices legitimately share timesteps. Steps are
    retained for two windows past the drift allowance so an ancient
    claim never blocks a future legitimate code (counters are
    monotonic).
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        sid = _secret_id(secret)
        ttl = (TOTP_WINDOW * 2 + 1) * TOTP_INTERVAL * 2
        return bool(get_backend().set_if_absent(
            'mfa_used_steps', f'{sid}:{step}', True, ttl))
    except Exception:  # noqa: BLE001 - fail closed
        # Backend down and the step is within the drift window but
        # above _last_step (the last-step check passed). Returning True
        # here would allow a code captured and replayed within its
        # window across two processes — deny instead.
        logger.exception(
            "TOTP step claim backend unavailable — denying")
        return False


def _metric_replay() -> None:
    """Emit the TOTP-replay counter (best-effort)."""
    try:
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_totp_replays_total')
    except Exception:  # noqa: BLE001
        pass


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    """Verify a TOTP code against the secret.

    Allows a window of +/- TOTP_WINDOW steps to account for clock drift.
    The matched counter is recorded and any code at that counter or
    below is rejected afterwards — a captured code cannot be replayed
    within its validity window (NIST 800-63B single-use guidance).
    """
    # isdigit() alone accepts non-ASCII digits ('١٢٣٤٥٦', '１２３４５６')
    # which then crash str-form compare_digest — require ASCII digits.
    if (not isinstance(code, str) or not code.isascii()
            or not code.isdigit() or len(code) != TOTP_DIGITS):
        return False
    try:
        key = _base32_decode(secret)
    except (ValueError, KeyError) as exc:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure (logs decode error, not the secret)
        logger.debug("TOTP secret decode failed: %s", exc)
        return False
    ts = timestamp or int(time.time())
    step = ts // TOTP_INTERVAL
    last = _last_step(secret)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        candidate = _hotp(key, step + delta)
        if hmac.compare_digest(f"{candidate:0{TOTP_DIGITS}d}", code):
            matched = step + delta
            if matched <= last:
                # Already consumed — replay within the drift window.
                # A replay attempt is a security signal: the code was
                # captured somewhere. Metric, not just a debug log.
                logger.debug("TOTP replay rejected (counter %d <= %d)",
                             matched, last)
                _metric_replay()
                return False
            if not _claim_step(secret, matched):
                # Lost a cross-process race for this timestep.
                logger.debug("TOTP replay rejected (step %d claimed)",
                             matched)
                _metric_replay()
                return False
            _record_step(matched, secret)
            return True
    return False


def generate_recovery_codes(count: int = 8) -> list:
    """Generate one-time recovery codes (format: XXXX-XXXX-XXXX).

    Uses 6 bytes (48 bits) of entropy per code, formatted as three
    4-char hex groups. This balances human-typability with sufficient
    entropy to resist brute force.
    """
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6)  # 12 hex chars = 48 bits
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}".upper())
    return codes


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for secure storage (SHA-256)."""
    return hashlib.sha256(code.upper().encode('utf-8')).hexdigest()


def verify_recovery_code(code: str, stored_hashes: list) -> bool:
    """Verify a recovery code against a list of stored hashes.

    Returns True if the code matches any stored hash. Caller should
    remove the used hash after successful verification.
    """
    if not code or not isinstance(code, str):
        return False
    code_hash = hash_recovery_code(code)
    for stored in stored_hashes:
        # compare as bytes — a non-ASCII stored value would otherwise
        # raise TypeError in str-form compare_digest (fail closed).
        if hmac.compare_digest(
                code_hash.encode('ascii'),
                str(stored).encode('utf-8', 'replace')):
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
