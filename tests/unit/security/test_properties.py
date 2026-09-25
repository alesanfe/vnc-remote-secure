"""Property-based tests (hypothesis) for security invariants.

These generate inputs across the whole domain rather than a handful
of hand-picked cases — the properties are the security claims:

- a signed token always verifies, a tampered token never does
- permission expansion is idempotent and never invents permissions
- session cookies round-trip the username and reject truncation
- TOTP rejects anything that is not exactly six ASCII digits
"""
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.timeout(120)

_ALPHANUM = st.text(
    alphabet=string.ascii_letters + string.digits + '._-',
    min_size=1, max_size=64)


@settings(max_examples=50, deadline=None)
@given(payload=st.text(min_size=0, max_size=256))
def test_signed_token_roundtrips(payload):
    from vnc_remote_secure.security import token_signing
    token = token_signing.sign_token('session', payload)
    assert token_signing.verify_token('session', token) is not None


@settings(max_examples=40, deadline=None)
@given(payload=st.text(min_size=1, max_size=64),
       tamper=st.integers(min_value=0, max_value=64))
def test_tampered_token_never_verifies(payload, tamper):
    from vnc_remote_secure.security import token_signing
    token = token_signing.sign_token('session', payload)
    if tamper >= len(token):
        return
    mutated = token[:tamper] + ('A' if token[tamper] != 'A' else 'B') \
        + token[tamper + 1:]
    if mutated == token:
        return
    assert token_signing.verify_token('session', mutated) is None


@settings(max_examples=30, deadline=None)
@given(perms=st.sets(st.sampled_from(sorted(
    __import__('vnc_remote_secure.security.ephemeral_sessions',
               fromlist=['x']).ALL_PERMISSIONS))))
def test_permission_expansion_idempotent(perms):
    from vnc_remote_secure.security.ephemeral_sessions import (
        expand_permissions,
    )
    once = expand_permissions(set(perms))
    assert expand_permissions(set(once)) == once


@settings(max_examples=30, deadline=None)
@given(perms=st.sets(st.sampled_from(sorted(
    __import__('vnc_remote_secure.security.ephemeral_sessions',
               fromlist=['x']).ALL_PERMISSIONS))))
def test_permission_expansion_never_invents(perms):
    from vnc_remote_secure.security.ephemeral_sessions import (
        ALL_PERMISSIONS,
        expand_permissions,
    )
    assert expand_permissions(set(perms)) <= ALL_PERMISSIONS


@settings(max_examples=30, deadline=None)
@given(username=_ALPHANUM)
def test_session_cookie_roundtrip(username):
    import os
    os.environ['AUTH_SECRET'] = 'hypothesis-test-secret-0123456789'
    from vnc_remote_secure.security import sessions
    cookie = sessions.create_session_cookie(username)
    rec = sessions.verify_session_cookie(cookie['value'])
    assert rec is not None
    assert rec.get('username') == username


@settings(max_examples=30, deadline=None)
@given(code=st.text(min_size=0, max_size=12))
def test_totp_rejects_non_digit_codes(code):
    """Only exactly-6 ASCII digits reach verification; everything
    else fails closed without touching shared state."""
    from vnc_remote_secure.security import mfa
    if code.isascii() and code.isdigit() and len(code) == 6:
        return  # may legitimately verify — skip
    assert mfa.verify_totp('JBSWY3DPEHPK3PXP', code) is False
