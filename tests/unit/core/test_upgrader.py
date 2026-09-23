"""Tests for core.upgrader — backup-first upgrade + rollback."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


def test_upgrade_aborts_when_backup_fails(monkeypatch, tmp_path):
    """No backup -> no upgrade. Installing without a rollback receipt
    is exactly the failure mode this flow exists to prevent."""
    from vnc_remote_secure.core import upgrader
    monkeypatch.setattr(
        'vnc_remote_secure.core.backup.create_backup',
        lambda: (_ for _ in ()).throw(RuntimeError('disk full')))
    res = upgrader.perform_upgrade()
    assert res['ok'] is False
    assert 'backup' in res['error']
    assert res['rolled_back'] is False


def test_upgrade_rolls_back_on_pip_failure(monkeypatch, tmp_path):
    from vnc_remote_secure.core import upgrader
    backup_file = tmp_path / 'pre.tar.gz'
    backup_file.write_bytes(b'x')
    monkeypatch.setattr(
        'vnc_remote_secure.core.backup.create_backup',
        lambda: str(backup_file))
    monkeypatch.setattr(upgrader, '_pip_install',
                        lambda spec: (False, 'compile error'))
    rolled = {'called': False}

    def _fake_rollback():
        rolled['called'] = True
        return {'ok': True}

    monkeypatch.setattr(upgrader, 'perform_rollback', _fake_rollback)
    monkeypatch.setattr(
        'vnc_remote_secure.core.upgrader._state_path',
        lambda: str(tmp_path / 'upgrade_state.json'), raising=False)
    res = upgrader.perform_upgrade()
    assert res['ok'] is False
    assert res['rolled_back'] is True
    assert rolled.get('called') is True


def test_upgrade_rolls_back_on_verify_failure(monkeypatch, tmp_path):
    from vnc_remote_secure.core import upgrader
    monkeypatch.setattr(
        'vnc_remote_secure.core.backup.create_backup',
        lambda: str(tmp_path / 'pre.tar.gz'))
    monkeypatch.setattr(upgrader, '_pip_install', lambda spec: (True, 'ok'))
    monkeypatch.setattr(upgrader, '_verify_new_install',
                        lambda prev: (False, 'import error'))
    monkeypatch.setattr(upgrader, 'perform_rollback',
                        lambda: {'ok': True})
    monkeypatch.setattr(
        'vnc_remote_secure.core.upgrader._state_path',
        lambda: str(tmp_path / 'upgrade_state.json'), raising=False)
    res = upgrader.perform_upgrade()
    assert res['ok'] is False
    assert res['rolled_back'] is True


def test_upgrade_success_records_state(monkeypatch, tmp_path):
    """A successful upgrade leaves the rollback receipt with the
    previous version and the backup path."""
    import json
    from vnc_remote_secure.core import upgrader
    state_file = tmp_path / 'upgrade_state.json'
    monkeypatch.setattr(
        'vnc_remote_secure.core.paths.get_run_dir',
        lambda: str(tmp_path), raising=False)
    monkeypatch.setattr(upgrader, '_state_path', lambda: str(state_file))
    monkeypatch.setattr(
        'vnc_remote_secure.core.backup.create_backup',
        lambda: str(tmp_path / 'pre.tar.gz'))
    monkeypatch.setattr(upgrader, '_pip_install', lambda spec: (True, 'ok'))
    monkeypatch.setattr(upgrader, '_verify_new_install',
                        lambda prev: (True, '9.9.9'))
    res = upgrader.perform_upgrade()
    assert res['ok'] is True
    assert res['version'] == '9.9.9'
    state = json.loads(state_file.read_text())
    assert state['previous_version'] == res['previous']
    assert state['backup'] == res['backup']


def test_rollback_without_state_fails(tmp_path, monkeypatch):
    from vnc_remote_secure.core import upgrader
    monkeypatch.setattr(upgrader, '_state_path',
                        lambda: str(tmp_path / 'none.json'))
    res = upgrader.perform_rollback()
    assert res['ok'] is False
    assert 'nothing to roll back' in res['error']


def test_rollback_restores_and_reinstalls(tmp_path, monkeypatch):
    import json
    from vnc_remote_secure.core import upgrader
    backup_file = tmp_path / 'pre.tar.gz'
    backup_file.write_bytes(b'x')
    state = {'previous_version': '0.1.0', 'backup': str(backup_file)}
    state_file = tmp_path / 'upgrade_state.json'
    state_file.write_text(json.dumps(state))
    monkeypatch.setattr(upgrader, '_state_path', lambda: str(state_file))
    restored = []
    monkeypatch.setattr(
        'vnc_remote_secure.core.backup.restore_backup',
        lambda p: restored.append(p))
    installs = []
    monkeypatch.setattr(upgrader, '_pip_install',
                        lambda spec: installs.append(spec) or (True, 'ok'))
    res = upgrader.perform_rollback()
    assert res['ok'] is True
    assert restored == [str(backup_file)]
    assert installs == ['vnc-remote-secure==0.1.0']


def test_rollback_missing_backup_fails(tmp_path, monkeypatch):
    import json
    from vnc_remote_secure.core import upgrader
    state_file = tmp_path / 'upgrade_state.json'
    state_file.write_text(json.dumps(
        {'previous_version': '0.1.0',
         'backup': str(tmp_path / 'gone.tar.gz')}))
    monkeypatch.setattr(upgrader, '_state_path', lambda: str(state_file))
    res = upgrader.perform_rollback()
    assert res['ok'] is False
    assert 'backup missing' in res['error']
