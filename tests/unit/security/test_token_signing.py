"""Tests for the shared token signing utility.

Verifies that:
- Tokens are correctly signed and verified.
- Type tags prevent cross-type token replay (a session cookie cannot
  be used as an ephemeral token and vice versa).
- Tampered signatures are rejected.
- Tampered type tags are rejected.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_BEARER,
    TOKEN_TYPE_EPHEMERAL,
    TOKEN_TYPE_SESSION,
    sign_token,
    verify_token,
)

# ---------------------------------------------------------------------------
# Round-trip sign/verify
# ---------------------------------------------------------------------------

def test_sign_verify_roundtrip_session():
    payload = "alice:1700000000:1700003600"
    token = sign_token(TOKEN_TYPE_SESSION, payload)
    assert verify_token(TOKEN_TYPE_SESSION, token) == payload


def test_sign_verify_roundtrip_ephemeral():
    payload = "abc123:1700003600:1"
    token = sign_token(TOKEN_TYPE_EPHEMERAL, payload)
    assert verify_token(TOKEN_TYPE_EPHEMERAL, token) == payload


def test_token_contains_type_prefix():
    token = sign_token(TOKEN_TYPE_SESSION, "data")
    assert token.startswith("session:")


def test_token_contains_signature_separator():
    token = sign_token(TOKEN_TYPE_EPHEMERAL, "data")
    assert "." in token


# ---------------------------------------------------------------------------
# Cross-type rejection (INC-092 regression)
# ---------------------------------------------------------------------------

def test_session_token_rejected_as_ephemeral():
    """A persistent session cookie cannot be used as an ephemeral token."""
    token = sign_token(TOKEN_TYPE_SESSION, "alice:1:2")
    assert verify_token(TOKEN_TYPE_EPHEMERAL, token) is None


def test_ephemeral_token_rejected_as_session():
    """An ephemeral token cannot be used as a persistent session cookie."""
    token = sign_token(TOKEN_TYPE_EPHEMERAL, "tok:1:0")
    assert verify_token(TOKEN_TYPE_SESSION, token) is None


def test_bearer_token_rejected_as_session():
    """A bearer token cannot be used as a persistent session cookie."""
    token = sign_token(TOKEN_TYPE_BEARER, "alice:1700000000")
    assert verify_token(TOKEN_TYPE_SESSION, token) is None


def test_bearer_token_rejected_as_ephemeral():
    """A bearer token cannot be used as an ephemeral access token."""
    token = sign_token(TOKEN_TYPE_BEARER, "alice:1700000000")
    assert verify_token(TOKEN_TYPE_EPHEMERAL, token) is None


def test_session_token_rejected_as_bearer():
    """A session cookie cannot be used as a bearer token."""
    token = sign_token(TOKEN_TYPE_SESSION, "alice:1:2")
    assert verify_token(TOKEN_TYPE_BEARER, token) is None


def test_ephemeral_token_rejected_as_bearer():
    """An ephemeral token cannot be used as a bearer token."""
    token = sign_token(TOKEN_TYPE_EPHEMERAL, "tok:1:0")
    assert verify_token(TOKEN_TYPE_BEARER, token) is None


def test_unknown_type_tag_rejected():
    """A token with an unknown type tag is rejected."""
    token = sign_token(TOKEN_TYPE_SESSION, "data")
    assert verify_token("unknown", token) is None


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_tampered_signature_rejected():
    token = sign_token(TOKEN_TYPE_SESSION, "data")
    # Flip the last character of the signature.
    tampered = token[:-1] + ('0' if token[-1] != '0' else '1')
    assert verify_token(TOKEN_TYPE_SESSION, tampered) is None


def test_tampered_payload_rejected():
    token = sign_token(TOKEN_TYPE_SESSION, "alice:1:2")
    # Replace the payload while keeping the signature.
    prefix, sig = token.rsplit('.', 1)
    tampered = prefix + "X." + sig
    assert verify_token(TOKEN_TYPE_SESSION, tampered) is None


def test_tampered_type_tag_rejected():
    """Changing the type tag in the token string breaks verification."""
    token = sign_token(TOKEN_TYPE_SESSION, "data")
    # Replace 'session:' prefix with 'ephemeral:'.
    tampered = TOKEN_TYPE_EPHEMERAL + ":" + token[len(TOKEN_TYPE_SESSION) + 1:]
    # The signature was computed over 'session:data', so 'ephemeral:data'
    # will not match.
    assert verify_token(TOKEN_TYPE_EPHEMERAL, tampered) is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_token_rejected():
    assert verify_token(TOKEN_TYPE_SESSION, "") is None


def test_none_token_rejected():
    assert verify_token(TOKEN_TYPE_SESSION, None) is None


def test_token_without_dot_rejected():
    assert verify_token(TOKEN_TYPE_SESSION, "session:data") is None


def test_token_without_colon_rejected():
    assert verify_token(TOKEN_TYPE_SESSION, "data.sig") is None


def test_empty_payload_signed():
    """An empty payload is still signable (edge case)."""
    token = sign_token(TOKEN_TYPE_SESSION, "")
    assert verify_token(TOKEN_TYPE_SESSION, token) == ""


def test_non_ascii_signature_fails_closed():
    """A client-controlled non-ASCII signature must not crash.

    compare_digest(str, str) raises TypeError on non-ASCII — an
    attacker fuzzing the cookie with UTF-8 bytes would turn every
    auth check into a 500. The verify must return None instead.
    """
    token = sign_token(TOKEN_TYPE_SESSION, "data")
    prefix = token.rsplit('.', 1)[0]
    assert verify_token(TOKEN_TYPE_SESSION, prefix + '.café') is None
    assert verify_token(TOKEN_TYPE_SESSION, 'session:dätä.0' * 1) is None


def test_non_ascii_username_authenticate_fails_closed(monkeypatch):
    """authenticate() must not raise TypeError on non-ASCII input.

    hmac.compare_digest(str, str) rejects non-ASCII — a login attempt
    with a UTF-8 username/password used to crash the auth path.
    """
    from vnc_remote_secure.security import authentication
    monkeypatch.setenv('USER_UI_USERNAME', 'admin')
    monkeypatch.setenv('USER_UI_PASSWORD', 'Str0ng!Pass')
    assert authentication.authenticate('ádmin', 'Str0ng!Pass') is False
    assert authentication.authenticate('admin', 'Pássw0rd!') is False
    # A UTF-8 configured credential still works when the input matches.
    monkeypatch.setenv('USER_UI_PASSWORD', 'Café-Päss1!')
    assert authentication.authenticate('admin', 'Café-Päss1!') is True
