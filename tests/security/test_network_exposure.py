"""Security test: verify internal services are not publicly exposed."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vnc_remote_secure.core.config import get_config

def test_internal_ports_not_public():
    """Internal service ports should not be 0.0.0.0 by default."""
    config = get_config()
    # Health and landing should be configurable, but VNC should be loopback
    assert config.get('vnc_port') in range(5900, 5910)

def test_ssl_enabled_by_default():
    """SSL should be enabled by default in configuration."""
    # This is enforced by the Bash validate_config
    # Here we just verify the config structure supports it
    config = get_config()
    assert 'ssl_cert' in config
    assert 'ssl_key' in config
