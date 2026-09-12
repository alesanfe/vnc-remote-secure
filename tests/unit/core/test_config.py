"""Unit tests for core.config module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import get_config, generate_random_password


def test_get_config_returns_dict():
    """get_config should return a dictionary."""
    config = get_config()
    assert isinstance(config, dict)


def test_get_config_has_required_keys():
    """Config should contain all required keys."""
    config = get_config()
    required_keys = [
        'vnc_port', 'novnc_port', 'ttyd_port', 'health_port', 'landing_port',
        'vnc_http_port', 'vnc_password', 'ttyd_username', 'ttyd_password',
        'ssl_cert', 'ssl_key', 'health_host', 'landing_host', 'webterm_shell',
    ]
    for key in required_keys:
        assert key in config, f"Missing required config key: {key}"


def test_get_config_ports_are_integers():
    """All port values should be integers."""
    config = get_config()
    port_keys = ['vnc_port', 'novnc_port', 'ttyd_port', 'health_port', 'landing_port', 'vnc_http_port']
    for key in port_keys:
        assert isinstance(config[key], int), f"{key} should be int, got {type(config[key])}"
        assert config[key] > 0


def test_generate_random_password_length():
    """generate_random_password should return a string of the specified length."""
    pw = generate_random_password(16)
    assert isinstance(pw, str)
    assert len(pw) == 16


def test_generate_random_password_default_length():
    """Default password length should be 16."""
    pw = generate_random_password()
    assert len(pw) == 16


def test_generate_random_password_uniqueness():
    """Two generated passwords should be different."""
    pw1 = generate_random_password()
    pw2 = generate_random_password()
    assert pw1 != pw2


def test_get_config_hosts_are_strings():
    """Host values should be strings."""
    config = get_config()
    assert isinstance(config['health_host'], str)
    assert isinstance(config['landing_host'], str)
