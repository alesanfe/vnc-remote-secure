"""Unit tests for core.config module."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import _safe_int, generate_random_password, get_config


def test_safe_int_returns_default_when_unset(monkeypatch):
    """_safe_int returns the default when the env var is unset."""
    monkeypatch.delenv('TEST_INT_VAR', raising=False)
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_returns_default_when_empty(monkeypatch):
    """_safe_int returns the default when the env var is empty."""
    monkeypatch.setenv('TEST_INT_VAR', '')
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_returns_value_when_valid(monkeypatch):
    """_safe_int returns the parsed value when it is a valid integer."""
    monkeypatch.setenv('TEST_INT_VAR', '100')
    assert _safe_int('TEST_INT_VAR', 42) == 100


def test_safe_int_returns_default_when_invalid(monkeypatch):
    """_safe_int returns the default when the value is not an integer."""
    monkeypatch.setenv('TEST_INT_VAR', 'abc')
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_enforces_minimum(monkeypatch):
    """_safe_int returns the default when the value is below the minimum."""
    monkeypatch.setenv('TEST_INT_VAR', '0')
    assert _safe_int('TEST_INT_VAR', 42, minimum=1) == 42


def test_safe_int_enforces_maximum(monkeypatch):
    """_safe_int returns the default when the value is above the maximum."""
    monkeypatch.setenv('TEST_INT_VAR', '99999')
    assert _safe_int('TEST_INT_VAR', 42, maximum=65535) == 42


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
