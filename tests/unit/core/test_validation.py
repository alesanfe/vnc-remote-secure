"""Unit tests for core.validation module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.validation import validate_port, validate_password, validate_username

def test_validate_port_valid():
    assert validate_port(5900) is True
    assert validate_port(1) is True
    assert validate_port(65535) is True

def test_validate_port_invalid():
    assert validate_port(0) is False
    assert validate_port(65536) is False
    assert validate_port(-1) is False
    assert validate_port("abc") is False

def test_validate_password_strong():
    assert validate_password("Str0ng!Pass") is True

def test_validate_password_weak():
    assert validate_password("changeme") is False
    assert validate_password("short") is False

def test_validate_username_valid():
    assert validate_username("remote") is True
    assert validate_username("user123") is True

def test_validate_username_reserved():
    assert validate_username("root") is False
    assert validate_username("admin") is False
