"""Unit tests for core.constants module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import constants


def test_app_version_is_string():
    """APP_VERSION should be a non-empty string."""
    assert isinstance(constants.APP_VERSION, str)
    assert len(constants.APP_VERSION) > 0


def test_app_name_is_string():
    """APP_NAME should be a non-empty string."""
    assert isinstance(constants.APP_NAME, str)
    assert len(constants.APP_NAME) > 0


def test_default_ports_are_integers():
    """All default ports should be positive integers."""
    ports = [
        constants.DEFAULT_VNC_PORT,
        constants.DEFAULT_VNC_HTTP_PORT,
        constants.DEFAULT_NOVNC_PORT,
        constants.DEFAULT_TTYD_PORT,
        constants.DEFAULT_HEALTH_PORT,
        constants.DEFAULT_LANDING_PORT,
        constants.DEFAULT_AUDIO_STREAM_PORT,
        constants.DEFAULT_GAMEPAD_PORT,
    ]
    for port in ports:
        assert isinstance(port, int)
        assert port > 0
        assert port < 65536


def test_min_password_length_is_positive():
    """MIN_PASSWORD_LENGTH should be a positive integer."""
    assert isinstance(constants.MIN_PASSWORD_LENGTH, int)
    assert constants.MIN_PASSWORD_LENGTH > 0


def test_weak_passwords_contains_common_defaults():
    """WEAK_PASSWORDS should contain known weak passwords."""
    assert 'changeme' in constants.WEAK_PASSWORDS
    assert 'admin123' in constants.WEAK_PASSWORDS
    assert 'password' in constants.WEAK_PASSWORDS


def test_reserved_usernames_contains_root():
    """RESERVED_USERNAMES should contain 'root'."""
    assert 'root' in constants.RESERVED_USERNAMES
    assert 'admin' in constants.RESERVED_USERNAMES


def test_default_bind_host_is_localhost():
    """DEFAULT_BIND_HOST should default to localhost for security."""
    assert constants.DEFAULT_BIND_HOST == '127.0.0.1'


def test_default_vnc_geometry_format():
    """DEFAULT_VNC_GEOMETRY should be in WxH format."""
    geom = constants.DEFAULT_VNC_GEOMETRY
    assert 'x' in geom
    parts = geom.split('x')
    assert len(parts) == 2
    for part in parts:
        assert part.isdigit()
