"""Tests for ``vnc-remote security check``."""
import argparse
from unittest.mock import patch

from vnc_remote_secure.cli.commands.security import cmd_security


def _args():
    return argparse.Namespace(security_action='check')


def test_security_check_runs():
    """security check must run all sub-audits without crashing and
    return a proper exit code (0 clean / 1 critical)."""
    # Neutralise the real environment-dependent audits: the dev
    # machine's actual sockets must not decide the test outcome.
    with patch(
            'vnc_remote_secure.core.service_manager.'
            'audit_internal_listeners', return_value=[]), patch(
            'vnc_remote_secure.core.doctor.run_doctor',
            return_value={'checks': []}), patch(
            'vnc_remote_secure.core.config_inspector.'
            'validate_config', return_value=[]):
        code = cmd_security(_args())
    assert code in (0, 1)


def test_security_check_critical_fails(capsys):
    """A critical listener finding must fail the check."""
    with patch(
            'vnc_remote_secure.core.service_manager.'
            'audit_internal_listeners',
            return_value=['vnc port 5900 listening on 0.0.0.0']), \
            patch(
            'vnc_remote_secure.core.doctor.run_doctor',
            return_value={'checks': []}), patch(
            'vnc_remote_secure.core.config_inspector.'
            'validate_config', return_value=[]):
        code = cmd_security(_args())
    assert code == 1
    assert 'FAILED' in capsys.readouterr().out


def test_security_unknown_action(capsys):
    args = argparse.Namespace(security_action='bogus')
    assert cmd_security(args) == 1
    assert 'Unknown security action' in capsys.readouterr().out
