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
