"""Encryption utilities for VNC Remote Secure.

Symmetric authenticated encryption using the ``cryptography`` library's
Fernet construction (AES-128-CBC + HMAC-SHA256). The key must be a
URL-safe base64-encoded 32-byte string as produced by
``Fernet.generate_key()``.

When the ``cryptography`` library is not installed, a fallback based on
``hashlib`` + ``hmac`` is used. This fallback is **not** as strong as
Fernet and should only be used for non-secret data; install
``cryptography`` for production use.
"""
import base64
import hashlib
import hmac
import os

from vnc_remote_secure.core.exceptions import SecurityError


def _derive_key(key):
    """Derive a 32-byte key from an arbitrary passphrase/string."""
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hashlib.sha256(key).digest()


def encrypt_data(data, key):
    """Encrypt ``data`` (bytes or str) with ``key``.

    Returns the ciphertext as bytes. When ``cryptography`` is available
    the output is a Fernet token; otherwise a simple XOR+HMAC envelope
    is used.

    Raises:
        SecurityError: if the data cannot be encrypted.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        from cryptography.fernet import Fernet
        fernet_key = base64.urlsafe_b64encode(_derive_key(key))
        return Fernet(fernet_key).encrypt(data)
    except ImportError:
        pass
    # Fallback: XOR stream with HMAC-SHA256 tag.
    derived = _derive_key(key)
    nonce = os.urandom(16)
    keystream = hashlib.sha256(derived + nonce).digest()
    keystream += hashlib.sha256(keystream + nonce).digest()
    ciphertext = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data))
    tag = hmac.new(derived, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + tag + ciphertext


def decrypt_data(data, key):
    """Decrypt ``data`` (bytes) with ``key``.

    Returns the plaintext as bytes. Raises :class:`SecurityError` if
    decryption fails (e.g. wrong key or tampered data).
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        from cryptography.fernet import Fernet, InvalidToken
        fernet_key = base64.urlsafe_b64encode(_derive_key(key))
        try:
            return Fernet(fernet_key).decrypt(data)
        except InvalidToken as exc:
            raise SecurityError("Decryption failed: invalid token") from exc
    except ImportError:
        pass
    # Fallback envelope: nonce(16) + tag(32) + ciphertext
    if len(data) < 48:
        raise SecurityError("Decryption failed: data too short")
    derived = _derive_key(key)
    nonce = data[:16]
    tag = data[16:48]
    ciphertext = data[48:]
    expected_tag = hmac.new(derived, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise SecurityError("Decryption failed: authentication tag mismatch")
    keystream = hashlib.sha256(derived + nonce).digest()
    keystream += hashlib.sha256(keystream + nonce).digest()
    return bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(ciphertext))
