"""Unit tests for core.uninstall — the destructive teardown path."""
import pytest

from vnc_remote_secure.core import uninstall as un


class _FakeAdapter:
    """Adapter that records every removal call."""

    def __init__(self):
        self.calls = []

    def remove_service(self, name):
        self.calls.append(('remove_service', name))
        return True

    def remove_firewall_rule(self, name):
        self.calls.append(('remove_firewall_rule', name))
        return True

    def remove_runtime_user(self, name):
        self.calls.append(('remove_runtime_user', name))
        return True


@pytest.fixture
def patched(monkeypatch, tmp_path):
    """Patch paths + adapter so uninstall touches nothing real."""
    adapter = _FakeAdapter()
    monkeypatch.setattr(un, 'get_adapter', lambda: adapter)
    monkeypatch.setattr(un, 'get_config_dir', lambda: str(tmp_path / 'config'))
    monkeypatch.setattr(un, 'get_data_dir', lambda: str(tmp_path / 'data'))
    monkeypatch.setattr(un, 'get_log_dir', lambda: str(tmp_path / 'logs'))
    monkeypatch.setattr(un, 'get_run_dir', lambda: str(tmp_path / 'run'))
    monkeypatch.setattr(un, 'get_ssl_dir', lambda: str(tmp_path / 'ssl'))
    monkeypatch.setattr(un, 'is_windows', lambda: False)
    monkeypatch.setattr(
        'vnc_remote_secure.core.service_manager.stop_all', lambda: None,
        raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.core.config.load_env_file', lambda: None,
        raising=False)
    return adapter, tmp_path


def test_uninstall_calls_adapter_steps(patched):
    adapter, _ = patched
    results = un.uninstall(force=True)
    assert results['stop_services'] is True
    assert results['remove_service'] is True
    assert results['remove_firewall'] is True
    assert results['remove_user'] is True
    assert ('remove_service', 'vnc-remote') in adapter.calls
    assert ('remove_firewall_rule', 'vnc-remote') in adapter.calls


def test_uninstall_removes_dirs(patched, tmp_path):
    for d in ('config', 'data', 'logs', 'run', 'ssl'):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / 'f.txt').write_text('x')
    results = un.uninstall(force=True)
    for name in ('config', 'data', 'logs', 'run', 'ssl'):
        assert results[f'remove_{name}'] is True
        assert not (tmp_path / name).exists()


def test_uninstall_keep_data_preserves_dirs(patched, tmp_path):
    for d in ('config', 'data'):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / 'f.txt').write_text('x')
    results = un.uninstall(keep_data=True, force=True)
    assert (tmp_path / 'config' / 'f.txt').exists()
    assert (tmp_path / 'data' / 'f.txt').exists()
    for name in ('config', 'data', 'logs', 'run', 'ssl'):
        assert results[f'remove_{name}'] is True


def test_uninstall_linux_removes_service_user_and_group(
        patched, monkeypatch):
    adapter, _ = patched
    ran = []
    monkeypatch.setattr(
        'vnc_remote_secure.core.processes.run_cmd',
        lambda cmd, **kw: ran.append(cmd), raising=False)
    results = un.uninstall(force=True)
    assert results['remove_service_user'] is True
    assert ('remove_runtime_user', 'vnc-remote') in adapter.calls


def test_uninstall_failure_isolated(patched, monkeypatch):
    """A failing adapter step must not abort the rest of the uninstall."""
    adapter, _ = patched

    def _boom(name):
        raise RuntimeError('no systemd')

    adapter.remove_service = _boom
    results = un.uninstall(force=True)
    assert results['remove_service'] is False
    # The failure must not cascade: later steps still ran.
    assert results['remove_user'] is True


def test_per_dir_removal_failure_isolated(patched, tmp_path, monkeypatch):
    """rmtree failing on one dir must not skip the others."""
    for d in ('config', 'data', 'logs', 'run', 'ssl'):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d / 'f.txt').write_text('x')

    import shutil
    real_rmtree = shutil.rmtree

    def flaky(path, *a, **kw):
        if path.endswith('data'):
            raise OSError('locked')
        return real_rmtree(path, *a, **kw)

    monkeypatch.setattr(un.shutil, 'rmtree', flaky)
    results = un.uninstall(force=True)
    assert results['remove_data'] is False
    for name in ('config', 'logs', 'run', 'ssl'):
        assert results[f'remove_{name}'] is True


def test_stop_all_failure_does_not_abort(patched, monkeypatch):
    """stop_all raising must mark stop_services False but continue."""
    monkeypatch.setattr(
        'vnc_remote_secure.core.service_manager.stop_all',
        lambda: (_ for _ in ()).throw(RuntimeError('sm down')),
        raising=False)
    results = un.uninstall(force=True)
    assert results['stop_services'] is False
    assert 'remove_service' in results


def test_windows_artifacts_removed(patched, monkeypatch, tmp_path):
    """Windows: ProgramData config.env + LocalAppData sweep must run."""
    monkeypatch.setattr(un, 'is_windows', lambda: True)
    cfg_env = tmp_path / 'config.env'
    cfg_env.write_text('SECRET=x')
    # get_config_dir is tmp/'config' -> dirname gives tmp_path.
    results = un.uninstall(force=True)
    assert results.get('remove_config.env') is True
    assert not cfg_env.exists()
