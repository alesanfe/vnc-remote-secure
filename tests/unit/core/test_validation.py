"""Unit tests for core.validation module."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.validation import (
    ValidationError,
    validate_domain,
    validate_email,
    validate_password,
    validate_port,
    validate_username,
)


def test_validate_port_valid():
    assert validate_port(5900) == 5900
    assert validate_port(1) == 1
    assert validate_port(65535) == 65535


def test_validate_port_invalid():
    for bad in (0, 65536, -1, "abc"):
        with pytest.raises(ValidationError):
            validate_port(bad)


def test_validate_password_strong():
    assert validate_password("Str0ng!Pass") is True


def test_validate_password_weak():
    for bad in ("changeme", "short", "password", "admin123"):
        with pytest.raises(ValidationError):
            validate_password(bad)


def test_validate_username_valid():
    assert validate_username("remote") is True
    assert validate_username("user123") is True


def test_validate_username_reserved():
    for bad in ("root", "admin"):
        with pytest.raises(ValidationError):
            validate_username(bad)


class TestEmailDomainBoundary:
    """Invalid-domain check must compare the domain PART, not a suffix —
    'user@notexample.com' was falsely rejected by endswith()."""

    def test_suffix_lookalike_domain_allowed(self):
        assert validate_email('ops@notexample.com') is True
        assert validate_email('ops@mytest.com') is True
        assert validate_email('ops@invalid-domain.com') is True

    def test_exact_invalid_domain_rejected(self):
        for dom in ('example.com', 'test.com', 'invalid.com'):
            with pytest.raises(ValidationError,
                               match='not valid for production'):
                validate_email(f'ops@{dom}')

    def test_subdomain_of_invalid_allowed(self):
        # mail.example.com is a different domain than example.com.
        assert validate_email('ops@mail.example.com') is True


class TestDomainLocalhostBoundary:
    """localhost-style domains warn and are ALLOWED (SSL caveat), not
    rejected as malformed — the regex check must come second."""

    def test_localhost_allowed_with_warning(self):
        assert validate_domain('localhost') is True
        assert validate_domain('127.0.0.1') is True

    def test_truly_invalid_domain_rejected(self):
        import pytest
        with pytest.raises(ValidationError):
            validate_domain('-bad-.com')
        with pytest.raises(ValidationError):
            validate_domain('a' * 254)


class TestPortBoundaries:
    """BVA on the 1..65535 range: neighbors of both bounds."""

    @pytest.mark.parametrize('port', [1, 1023, 1024, 65534, 65535])
    def test_valid_boundary_ports(self, port):
        assert validate_port(port) == port

    @pytest.mark.parametrize('port', ['0', '-1', '65536', '99999', '1.5'])
    def test_invalid_boundary_ports(self, port):
        with pytest.raises(ValidationError):
            validate_port(port)


class TestUsernameBoundaries:
    """BVA on the 3..32 length range."""

    def test_min_length_accepted(self):
        assert validate_username('abc') is True

    def test_below_min_rejected(self):
        with pytest.raises(ValidationError):
            validate_username('ab')

    def test_max_length_accepted(self):
        assert validate_username('a' * 32) is True

    def test_above_max_rejected(self):
        with pytest.raises(ValidationError):
            validate_username('a' * 33)

    def test_leading_digit_rejected(self):
        with pytest.raises(ValidationError):
            validate_username('1abc')

    def test_leading_hyphen_rejected(self):
        with pytest.raises(ValidationError):
            validate_username('-abc')
