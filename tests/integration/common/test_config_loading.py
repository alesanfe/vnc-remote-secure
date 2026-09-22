"""Integration test: config loading works on all platforms."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import get_config


def test_config_loads_without_error():
    """Config should load without raising exceptions."""
    config = get_config()
    assert config is not None
    assert 'vnc_port' in config


def test_config_has_all_required_keys():
    """Config should have all required keys."""
    config = get_config()
    required_keys = ['vnc_port', 'novnc_port', 'novnc_ws_port',
                     'ttyd_port', 'health_port', 'landing_port']
    for key in required_keys:
        assert key in config, f"Missing key: {key}"


def test_env_override_wins_over_default(monkeypatch):
    """An env var must override the platform default — the precedence
    chain (env > .env > profile > defaults) is the core contract."""
    monkeypatch.setenv('TTYD_PORT', '4321')
    config = get_config()
    assert config['ttyd_port'] == 4321


def test_env_restored_after_test():
    """The conftest env-restore fixture must undo a sibling test's
    TTYD_PORT=4321 — leaked env would flip every later get_config()."""
    config = get_config()
    assert config['ttyd_port'] != 4321


def test_ports_are_valid_ints():
    """Every port key must be a usable integer 1-65535 — a config that
    yields a non-port value crashes binds downstream."""
    config = get_config()
    for key, val in config.items():
        if key.endswith('_port'):
            assert isinstance(val, int), f'{key}={val!r} not int'
            assert 1 <= val <= 65535, f'{key}={val} out of range'
