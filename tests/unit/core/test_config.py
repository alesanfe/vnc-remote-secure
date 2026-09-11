"""Unit tests for core.config module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import load_env_file, generate_random_password, get_config

def test_generate_random_password_length():
    pwd = generate_random_password(16)
    assert len(pwd) == 16

def test_generate_random_password_strength():
    pwd = generate_random_password(20)
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)

def test_get_config_returns_dict():
    config = get_config()
    assert isinstance(config, dict)
    assert 'vnc_port' in config
    assert 'novnc_port' in config
