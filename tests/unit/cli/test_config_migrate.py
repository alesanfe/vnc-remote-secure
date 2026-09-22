"""Unit tests for `vnc-remote config migrate` (_config_migrate)."""
import argparse

from vnc_remote_secure.cli.commands.config import _config_migrate


def _args(dry_run=False):
    return argparse.Namespace(dry_run=dry_run)


def _env(tmp_path, monkeypatch, content):
    env = tmp_path / '.env'
    env.write_text(content, encoding='utf-8')
    monkeypatch.setattr(
        'vnc_remote_secure.cli.commands.config._find_project_root',
        lambda: str(tmp_path))
    return env


def test_migrate_no_env_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        'vnc_remote_secure.cli.commands.config._find_project_root',
        lambda: str(tmp_path))
    assert _config_migrate(_args()) == 1
    assert 'No .env file' in capsys.readouterr().out


def test_migrate_renames_legacy_key(tmp_path, monkeypatch, capsys):
    env = _env(tmp_path, monkeypatch,
               'VNC_REMOTE_PROFILE=home-lan\nVNC_PORT=5901\n')
    assert _config_migrate(_args()) == 0
    text = env.read_text(encoding='utf-8')
    # Key renamed AND the profile value alias migrated in one pass.
    assert 'SECURITY_PROFILE=trusted-lan' in text
    assert 'VNC_REMOTE_PROFILE' not in text
    assert 'VNC_PORT=5901' in text


def test_migrate_does_not_touch_substring_keys(tmp_path, monkeypatch):
    """A var whose name CONTAINS a legacy key must survive intact."""
    env = _env(tmp_path, monkeypatch,
               'MY_CERT_FILE=/x\nCERT_FILE=/y\n')
    assert _config_migrate(_args()) == 0
    text = env.read_text(encoding='utf-8')
    assert 'MY_CERT_FILE=/x' in text
    assert 'SSL_CERT=/y' in text


def test_migrate_dry_run_changes_nothing(tmp_path, monkeypatch, capsys):
    env = _env(tmp_path, monkeypatch, 'KEY_FILE=/k\n')
    assert _config_migrate(_args(dry_run=True)) == 0
    assert env.read_text(encoding='utf-8') == 'KEY_FILE=/k\n'
    assert 'Dry run' in capsys.readouterr().out


def test_migrate_comments_and_blank_lines_preserved(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch,
               '# comment\n\nNOVNC_HOST=0.0.0.0\n')
    assert _config_migrate(_args()) == 0
    text = env.read_text(encoding='utf-8')
    assert text.startswith('# comment\n\n')
    assert 'SERVE_NOVNC_HOST=0.0.0.0' in text


def test_migrate_clean_config_reports_nothing(tmp_path, monkeypatch, capsys):
    _env(tmp_path, monkeypatch, 'SECURITY_PROFILE=development\n')
    assert _config_migrate(_args()) == 0
    assert 'No migrations needed' in capsys.readouterr().out


class TestConfigValidateRc:
    """config validate rc: critical findings -> 1, warnings-only -> 0."""

    def _run(self, monkeypatch, severities):
        from argparse import Namespace
        from vnc_remote_secure.cli.commands import config as cc
        monkeypatch.setattr(
            'vnc_remote_secure.core.config_inspector.validate_config',
            lambda **kw: [{'severity': sv, 'message': 'm'}
                          for sv in severities],
            raising=False)
        args = Namespace(config_action='validate', profile=None, json=False)
        return cc._config_validate(args)

    def test_warnings_only_rc0(self, monkeypatch):
        assert self._run(monkeypatch, ['warning', 'info']) == 0

    def test_critical_rc1(self, monkeypatch):
        assert self._run(monkeypatch, ['warning', 'critical']) == 1
