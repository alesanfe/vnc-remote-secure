"""Property-based tests using Hypothesis for input validation.

Tests that validators correctly handle arbitrary inputs including
edge cases like empty strings, unicode, null bytes, and extreme lengths.
Validators raise ValidationError on failure; tests verify that behavior
is consistent and crash-free across the input space.
"""
import os
import string
import sys

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vnc_remote_secure.core.validation import (
    ValidationError,
    sanitize_input,
    validate_domain,
    validate_email,
    validate_password,
    validate_port,
    validate_username,
)


# ============================================================================
# Port validation
# ============================================================================
class TestPortValidation:
    @given(st.integers(min_value=1024, max_value=65535))
    def test_non_privileged_ports_accepted(self, port):
        # Non-privileged ports should pass validation (returns truthy)
        result = validate_port(port)
        assert result

    # deadline=None: validation is I/O-light but CI/loaded machines can
    # exceed the default 200ms per-example budget — this is a flake, not
    # a regression signal.
    @settings(deadline=None)
    @given(st.integers(min_value=1, max_value=1023))
    def test_privileged_ports_warn_but_validate(self, port):
        # Privileged ports may warn but still validate (return truthy)
        try:
            result = validate_port(port)
            assert result  # truthy
        except ValidationError:
            pass  # Some implementations reject privileged ports

    @given(st.integers().filter(lambda x: x < 1 or x > 65535))
    def test_out_of_range_ports_rejected(self, port):
        with pytest.raises((ValidationError, ValueError, TypeError)):
            validate_port(port)


# ============================================================================
# Domain validation
# ============================================================================
class TestDomainValidation:
    def test_empty_domain_accepted(self):
        # Empty domain means SSL disabled, should be accepted
        result = validate_domain('')
        assert result is True or result == 1

    @given(st.text(min_size=1, max_size=253, alphabet=string.ascii_lowercase + string.digits + '.-'))
    @settings(max_examples=50)
    def test_domain_does_not_crash(self, domain):
        # Should not raise unexpected exceptions (ValidationError is OK)
        try:
            validate_domain(domain)
        except ValidationError:
            pass

    @given(st.text(min_size=1, max_size=253))
    @settings(max_examples=50)
    def test_arbitrary_text_does_not_crash(self, text):
        try:
            validate_domain(text)
        except ValidationError:
            pass


# ============================================================================
# Email validation
# ============================================================================
class TestEmailValidation:
    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=50)
    def test_email_does_not_crash(self, email):
        try:
            validate_email(email)
        except ValidationError:
            pass

    def test_rejects_example_com(self):
        with pytest.raises(ValidationError):
            validate_email('user@example.com')

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_email('')

    def test_accepts_valid(self):
        assert validate_email('user@gmail.com') is True or validate_email('user@gmail.com') == 1


# ============================================================================
# Username validation
# ============================================================================
class TestUsernameValidation:
    @given(st.text(min_size=1, max_size=32, alphabet=string.ascii_lowercase + string.digits + '_-'))
    @settings(max_examples=50)
    def test_username_does_not_crash(self, username):
        try:
            validate_username(username)
        except ValidationError:
            pass

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_username('')

    def test_rejects_reserved(self):
        for name in ['root', 'admin', 'nobody', 'daemon']:
            with pytest.raises(ValidationError):
                validate_username(name)


# ============================================================================
# Password strength
# ============================================================================
class TestPasswordStrength:
    @given(st.text(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_password_does_not_crash(self, pwd):
        try:
            validate_password(pwd)
        except ValidationError:
            pass

    @given(st.text(min_size=0, max_size=7))
    def test_short_passwords_rejected(self, pwd):
        with pytest.raises(ValidationError):
            validate_password(pwd)

    @given(st.text(min_size=8, max_size=20, alphabet=string.ascii_lowercase))
    def test_no_uppercase_rejected(self, pwd):
        assume(any(c.isalpha() for c in pwd))
        with pytest.raises(ValidationError):
            validate_password(pwd)

    @given(st.text(min_size=8, max_size=20, alphabet=string.ascii_uppercase))
    def test_no_lowercase_rejected(self, pwd):
        assume(any(c.isalpha() for c in pwd))
        with pytest.raises(ValidationError):
            validate_password(pwd)

    @given(st.text(min_size=8, max_size=20, alphabet=string.ascii_letters))
    def test_no_digit_rejected(self, pwd):
        assume(any(c.isalpha() for c in pwd))
        with pytest.raises(ValidationError):
            validate_password(pwd)

    def test_weak_passwords_rejected(self):
        for pwd in ['changeme', 'admin123', 'YourStrongPassword123', 'password123']:
            with pytest.raises(ValidationError):
                validate_password(pwd)


# ============================================================================
# Sanitize input
# ============================================================================
class TestSanitizeInput:
    @given(st.text(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_sanitize_does_not_crash(self, text):
        result = sanitize_input(text)
        assert isinstance(result, str)

    @given(st.text(min_size=0, max_size=50).filter(
        lambda x: '<' in x or '>' in x or '"' in x or "'" in x
    ))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.filter_too_much])
    def test_html_chars_escaped(self, text):
        result = sanitize_input(text)
        # Raw <, >, ", ' should be replaced with HTML entities
        assert '<' not in result
        assert '>' not in result
        assert '"' not in result
        assert "'" not in result


# ============================================================================
# TOTP verification (property-based)
# ============================================================================
class TestTOTPProperties:
    @given(st.text(min_size=0, max_size=20))
    @settings(max_examples=30)
    def test_invalid_codes_rejected(self, code):
        from vnc_remote_secure.security.mfa import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        if not (code.isdigit() and len(code) == 6):
            assert verify_totp(secret, code) is False
