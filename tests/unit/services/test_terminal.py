"""Unit tests for the terminal service auth and configuration.

The terminal.py module executes server-startup code at import time, so
these tests validate the shared auth helpers (check_terminal_auth) and
the configuration constants that the terminal service relies on, rather
than the module's top-level code.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_CMD_TIMEOUT,
    DEFAULT_MAX_OUTPUT,
    DEFAULT_TTYD_PORT,
    DEFAULT_TTYD_USERNAME,
)
from vnc_remote_secure.security.http_auth import (
    check_basic_auth,
    check_terminal_auth,
)

# ---------------------------------------------------------------------------
# Constants used by terminal.py
# ---------------------------------------------------------------------------

def test_terminal_default_port_is_int():
    """DEFAULT_TTYD_PORT is a valid integer port."""
    assert isinstance(DEFAULT_TTYD_PORT, int)
    assert 1 <= DEFAULT_TTYD_PORT <= 65535


def test_terminal_default_host_is_localhost():
    """The default bind host is 127.0.0.1 (secure; opt-in for LAN)."""
    assert DEFAULT_BIND_HOST == '127.0.0.1'


def test_terminal_cmd_timeout_is_positive():
    """DEFAULT_CMD_TIMEOUT is a positive integer."""
    assert isinstance(DEFAULT_CMD_TIMEOUT, int)
    assert DEFAULT_CMD_TIMEOUT > 0


def test_terminal_max_output_is_positive():
    """DEFAULT_MAX_OUTPUT is a positive integer."""
    assert isinstance(DEFAULT_MAX_OUTPUT, int)
    assert DEFAULT_MAX_OUTPUT > 0


# ---------------------------------------------------------------------------
# check_basic_auth
# ---------------------------------------------------------------------------

def _basic_header(username, password):
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode('utf-8')).decode('ascii')
    return f"Basic {encoded}"


def test_check_basic_auth_valid():
    """check_basic_auth returns True for matching credentials."""
    header = _basic_header('admin', 'secret123!')
    assert check_basic_auth(header, 'admin', 'secret123!') is True


def test_check_basic_auth_wrong_password():
    """check_basic_auth returns False for a wrong password."""
    header = _basic_header('admin', 'wrong')
    assert check_basic_auth(header, 'admin', 'secret123!') is False


def test_check_basic_auth_wrong_username():
    """check_basic_auth returns False for a wrong username."""
    header = _basic_header('root', 'secret123!')
    assert check_basic_auth(header, 'admin', 'secret123!') is False


def test_check_basic_auth_missing_header():
    """check_basic_auth returns False when the header is missing."""
    assert check_basic_auth('', 'admin', 'secret123!') is False
    assert check_basic_auth(None, 'admin', 'secret123!') is False


def test_check_basic_auth_wrong_scheme():
    """check_basic_auth returns False for a non-Basic scheme."""
    assert check_basic_auth('Bearer token123', 'admin', 'secret123!') is False


def test_check_basic_auth_malformed_base64():
    """check_basic_auth returns False for malformed base64."""
    assert check_basic_auth('Basic !!!not-base64!!!', 'admin', 'secret123!') is False


# ---------------------------------------------------------------------------
# check_terminal_auth
# ---------------------------------------------------------------------------

def test_check_terminal_auth_no_password_rejects(monkeypatch):
    """check_terminal_auth returns False when TTYD_PASSWD is not set."""
    monkeypatch.delenv('TTYD_PASSWD', raising=False)
    assert check_terminal_auth('') is False


def test_check_terminal_auth_valid(monkeypatch):
    """check_terminal_auth returns True for matching credentials."""
    monkeypatch.setenv('TTYD_USERNAME', 'admin')
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header('admin', 'StrongPass1!')
    assert check_terminal_auth(header) is True


def test_check_terminal_auth_wrong_password(monkeypatch):
    """check_terminal_auth returns False for a wrong password."""
    monkeypatch.setenv('TTYD_USERNAME', 'admin')
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header('admin', 'wrong')
    assert check_terminal_auth(header) is False


def test_check_terminal_auth_uses_default_username(monkeypatch):
    """check_terminal_auth falls back to DEFAULT_TTYD_USERNAME when unset."""
    # Prevent load_env_file() from repopulating TTYD_USERNAME from .env
    import vnc_remote_secure.security.http_auth as auth_mod
    monkeypatch.setattr(auth_mod, 'load_env_file', lambda *a, **kw: None)
    monkeypatch.delenv('TTYD_USERNAME', raising=False)
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header(DEFAULT_TTYD_USERNAME, 'StrongPass1!')
    assert check_terminal_auth(header) is True
