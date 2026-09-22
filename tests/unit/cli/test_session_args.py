"""Regression tests for `session create` argument validation."""
import os
import sys
from argparse import Namespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.cli.commands.session import cmd_session


def _args(**over):
    base = {
        'session_action': 'create', 'expires': '30m', 'role': 'viewer',
        'view_only': False, 'no_terminal': False, 'single_use': False,
        'max_uses': 0, 'allowed_ip': None, 'resource': None, 'json': False,
        'verbose': False,
    }
    base.update(over)
    return Namespace(**base)


def test_max_uses_negative_rejected(capsys):
    rc = cmd_session(_args(max_uses=-1))
    assert rc == 1
    assert '--max-uses' in capsys.readouterr().out


def test_allowed_ip_malformed_rejected(capsys):
    rc = cmd_session(_args(allowed_ip='not-an-ip'))
    assert rc == 1
    assert '--allowed-ip' in capsys.readouterr().out


def _patched_store():
    """Patch the store at its source module (cmd_session imports it
    lazily inside the function)."""
    return patch(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store')


def test_allowed_ip_valid_accepted(capsys):
    with _patched_store() as gs:
        store = gs.return_value
        store.create.return_value = (object(), 'tok')
        rc = cmd_session(_args(allowed_ip='10.0.0.5'))
        assert rc == 0
        store.create.assert_called_once()
        assert store.create.call_args.kwargs['allowed_ip'] == '10.0.0.5'


def test_allowed_ip_ipv6_accepted(capsys):
    with _patched_store() as gs:
        store = gs.return_value
        store.create.return_value = (object(), 'tok')
        rc = cmd_session(_args(allowed_ip='::1'))
        assert rc == 0


class TestParseDuration:
    """Duration parsing — BVA on unit suffixes and edge values."""

    @pytest.mark.parametrize(('s', 'expected'), [
        ('30m', 1800), ('2h', 7200), ('1d', 86400), ('3600', 3600),
        ('3600s', 3600), (' 30m ', 1800), ('30M', 1800),
    ])
    def test_valid_durations(self, s, expected):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        assert _parse_duration(s) == expected

    @pytest.mark.parametrize('s', ['0', '-5m', '0m', 'abc', '10x', 'x'])
    def test_invalid_durations_raise(self, s):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        with pytest.raises(SystemExit):
            _parse_duration(s)

    def test_empty_returns_default(self):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        from vnc_remote_secure.core.constants import (
            DEFAULT_SESSION_IDLE_TIMEOUT)
        assert _parse_duration('') == DEFAULT_SESSION_IDLE_TIMEOUT
        assert _parse_duration(None) == DEFAULT_SESSION_IDLE_TIMEOUT
