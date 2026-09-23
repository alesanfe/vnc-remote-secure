"""Shared HMAC-SHA256 token signing utility.

Both persistent browser sessions (``security.sessions``) and ephemeral
access tokens (``security.ephemeral_sessions``) use HMAC-SHA256 with
the same secret to sign their payloads. This module centralises the
signing and verification logic and adds a **type tag** so that a
persistent session cookie cannot be replayed as an ephemeral access
token (or vice versa).

Token format::

    <type>:<payload>.<hex_signature>

The type tag is part of the signed material, so an attacker cannot
strip it and substitute a different type.
"""
import hashlib
import hmac

# Type tags. Adding a new token type requires a new tag here so that
# existing verifiers reject unknown types.
TOKEN_TYPE_SESSION = 'session'
TOKEN_TYPE_EPHEMERAL = 'ephemeral'
TOKEN_TYPE_BEARER = 'bearer'


def _get_secret() -> bytes:
    """Return the shared signing secret."""
    from vnc_remote_secure.security.authentication import _get_secret as _auth_secret
    return _auth_secret()


def _get_verify_secrets() -> list:
    """Return signing secrets accepted for verification.

    The current secret first, then retired secrets still inside their
    coexistence window — key rotation must not invalidate in-flight
    tokens (see ``authentication.rotate_signing_secret``).
    """
    from vnc_remote_secure.security.authentication import (
        _get_secret as _auth_secret, previous_signing_secrets)
    return [_auth_secret(), *previous_signing_secrets()]


def sign_token(token_type: str, payload: str) -> str:
    """Sign a payload and return ``<type>:<payload>.<signature>``.

    Args:
        token_type: One of the ``TOKEN_TYPE_*`` constants. The tag is
            included in the signed material so it cannot be tampered
            with.
        payload: The payload string to sign.

    Returns:
        The signed token string.
    """
    secret = _get_secret()
    signed_material = f"{token_type}:{payload}"
    sig = hmac.new(secret, signed_material.encode('utf-8'),
                   hashlib.sha256).hexdigest()
    return f"{token_type}:{payload}.{sig}"


def verify_token(token_type: str, token: str) -> str | None:
    """Verify a signed token and return the payload if valid.

    Args:
        token_type: The expected token type. If the token carries a
            different type tag, verification fails (returns ``None``).
        token: The signed token string.

    Returns:
        The payload string if the signature is valid and the type tag
        matches. ``None`` otherwise.
    """
    if not token or ':' not in token or '.' not in token:
        return None
    # Split off the type tag first: <type>:<payload>.<sig>
    try:
        tag, rest = token.split(':', 1)
    except ValueError:
        return None
    if tag != token_type:
        return None
    if '.' not in rest:
        return None
    payload, sig = rest.rsplit('.', 1)
    signed_material = f"{token_type}:{payload}"
    # The token is client-controlled — a non-ASCII sig makes
    # compare_digest(str, str) raise TypeError instead of failing
    # closed. Encode both sides to bytes.
    sig_bytes = sig.encode('utf-8', 'replace')
    for secret in _get_verify_secrets():
        expected_sig = hmac.new(
            secret, signed_material.encode('utf-8'),
            hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig_bytes, expected_sig.encode('ascii')):
            return payload
    return None
