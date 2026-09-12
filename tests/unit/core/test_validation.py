"""Unit tests for core.validation module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.validation import (
    ValidationError,
    validate_port,
    validate_password,
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
