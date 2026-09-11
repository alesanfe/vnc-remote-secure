"""Unit tests for security.credentials module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.credentials import generate_password, validate_password_strength

def test_generate_password_default_length():
    pwd = generate_password()
    assert len(pwd) == 16

def test_validate_password_strength_strong():
    assert validate_password_strength("Str0ng!Pass") is True

def test_validate_password_strength_weak():
    assert validate_password_strength("weak") is False
