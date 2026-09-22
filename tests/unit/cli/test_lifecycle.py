"""Unit tests for cli.commands.lifecycle — --no-ssl guard and friends."""
import os
import sys
from argparse import Namespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.cli.commands.lifecycle import _apply_no_ssl  # noqa: E402


class TestApplyNoSsl:
    """--no-ssl must be refused on every hardened profile — including
    legacy aliases — and applied only on development."""

    def test_no_flag_noop(self, monkeypatch):
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        monkeypatch.delenv('DISABLE_SSL', raising=False)
        assert _apply_no_ssl(Namespace(no_ssl=False)) is True
        # The flag was absent — the env var must not be written.
        assert os.environ.get('DISABLE_SSL') is None

    @pytest.mark.parametrize('profile', [
        'public-hardened', 'private-overlay', 'trusted-lan',
        'internet-hardened', 'home-lan',  # legacy aliases
    ])
    def test_refused_on_hardened_profiles(self, monkeypatch, profile,
                                          capsys):
        monkeypatch.setenv('SECURITY_PROFILE', profile)
        assert _apply_no_ssl(Namespace(no_ssl=True)) is False
        # No partial application: neither var may be written.
        assert os.environ.get('TLS_ENABLED') != 'false'
        assert 'incompatible' in capsys.readouterr().err

    def test_applied_on_development(self, monkeypatch):
        monkeypatch.setenv('SECURITY_PROFILE', 'development')
        monkeypatch.delenv('TLS_ENABLED', raising=False)
        monkeypatch.delenv('DISABLE_SSL', raising=False)
        assert _apply_no_ssl(Namespace(no_ssl=True)) is True
        assert os.environ['TLS_ENABLED'] == 'false'
        assert os.environ['DISABLE_SSL'] == 'true'

    def test_applied_when_no_profile(self, monkeypatch):
        monkeypatch.delenv('SECURITY_PROFILE', raising=False)
        monkeypatch.delenv('VNC_REMOTE_PROFILE', raising=False)
        monkeypatch.delenv('TLS_ENABLED', raising=False)
        monkeypatch.delenv('DISABLE_SSL', raising=False)
        assert _apply_no_ssl(Namespace(no_ssl=True)) is True
        assert os.environ['DISABLE_SSL'] == 'true'


class TestCmdStop:
    def test_stop_error_key_returns_1(self, monkeypatch, capsys):
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(
            'vnc_remote_secure.core.service_manager.stop_all',
            lambda force=False: {'error': 'lock held'})
        assert lifecycle.cmd_stop(
            Namespace(dry_run=False, force=False)) == 1
        assert 'lock held' in capsys.readouterr().err

    def test_stop_partial_failure_returns_1(self, monkeypatch, capsys):
        """A service that survives stop_all must flip the exit code —
        'Stopped: x' alone would mask a still-running service."""
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(
            'vnc_remote_secure.core.service_manager.stop_all',
            lambda force=False: {'vnc': True, 'terminal': False})
        assert lifecycle.cmd_stop(
            Namespace(dry_run=False, force=False)) == 1
        err = capsys.readouterr().err
        assert 'terminal' in err

    def test_stop_all_ok(self, monkeypatch):
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(
            'vnc_remote_secure.core.service_manager.stop_all',
            lambda force=False: {'vnc': True})
        assert lifecycle.cmd_stop(
            Namespace(dry_run=False, force=False)) == 0


class TestCmdService:
    def test_service_without_run_flag_fails(self, monkeypatch, capsys):
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(
            lifecycle, '_find_project_root', lambda: '.')
        assert lifecycle.cmd_service(
            Namespace(dry_run=False, run=False)) == 1
        assert '--run' in capsys.readouterr().err

    def test_service_run_delegates_to_start(self, monkeypatch):
        """service --run must set foreground and delegate — the watchdog
        loop exists only in cmd_start."""
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(
            lifecycle, '_find_project_root', lambda: '.')
        seen = {}
        monkeypatch.setattr(
            lifecycle, 'cmd_start',
            lambda a: seen.update(foreground=a.foreground) or 0)
        args = Namespace(dry_run=False, run=True, foreground=False)
        assert lifecycle.cmd_service(args) == 0
        assert seen['foreground'] is True


class TestCmdRestart:
    def test_restart_blocked_by_findings(self, monkeypatch, capsys):
        """A blocking security finding must refuse restart."""
        from vnc_remote_secure.cli.commands import lifecycle
        monkeypatch.setattr(lifecycle, '_apply_no_ssl', lambda a: True)
        monkeypatch.setattr(
            'vnc_remote_secure.core.lifecycle.startup', lambda: {},
            raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.get_blocking_findings',
            lambda: [{'code': 'TLS', 'message': 'TLS off'}],
            raising=False)
        assert lifecycle.cmd_restart(
            Namespace(dry_run=False, no_ssl=False)) == 1
        assert 'blocking' in capsys.readouterr().err.lower()
