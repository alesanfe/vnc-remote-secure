"""Tests for core.paths — platform-aware directory resolution."""
import sys

import pytest

from vnc_remote_secure.core import paths


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    return


class TestIsMsixPackaged:
    def test_non_windows_is_false(self, monkeypatch):
        monkeypatch.setattr(paths.os, 'name', 'posix')
        assert paths._is_msix_packaged() is False

    def test_windowsapps_executable_detected(self, monkeypatch):
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(
            sys, 'executable',
            r'C:\Program Files\WindowsApps\PythonSoftwareFoundation.'
            r'Python.3.11_3.11.0.0_x64__qbz5n2kfra8p0\python.exe')
        assert paths._is_msix_packaged() is True

    def test_venv_executable_not_packaged(self, monkeypatch):
        # A venv created from Store Python runs an un-packaged
        # interpreter — detection must use sys.executable, not
        # sys.base_prefix.
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(sys, 'executable',
                            r'C:\proj\.venv\Scripts\python.exe')
        assert paths._is_msix_packaged() is False


class TestWinBase:
    def test_elevated_uses_programdata(self, monkeypatch):
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(paths, '_is_elevated_windows', lambda: True)
        monkeypatch.setenv('ProgramData', r'C:\ProgramData')
        assert paths._win_base() == r'C:\ProgramData'

    def test_non_elevated_uses_localappdata(self, monkeypatch):
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(paths, '_is_elevated_windows', lambda: False)
        monkeypatch.setattr(paths, '_is_msix_packaged', lambda: False)
        monkeypatch.setenv('LOCALAPPDATA', r'C:\Users\u\AppData\Local')
        assert paths._win_base() == r'C:\Users\u\AppData\Local'

    def test_msix_uses_locallow(self, monkeypatch, tmp_path):
        """Store Python must not use virtualized LOCALAPPDATA."""
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(paths, '_is_elevated_windows', lambda: False)
        monkeypatch.setattr(paths, '_is_msix_packaged', lambda: True)
        appdata = tmp_path / 'AppData'
        local = appdata / 'Local'
        locallow = appdata / 'LocalLow'
        local.mkdir(parents=True)
        locallow.mkdir()
        monkeypatch.setenv('LOCALAPPDATA', str(local))
        assert paths._win_base() == str(locallow)

    def test_msix_falls_back_when_locallow_missing(self, monkeypatch,
                                                   tmp_path):
        monkeypatch.setattr(paths.os, 'name', 'nt')
        monkeypatch.setattr(paths, '_is_elevated_windows', lambda: False)
        monkeypatch.setattr(paths, '_is_msix_packaged', lambda: True)
        local = tmp_path / 'AppData' / 'Local'
        local.mkdir(parents=True)
        monkeypatch.setenv('LOCALAPPDATA', str(local))
        assert paths._win_base() == str(local)


class TestRunDirSquatGuard:
    """The /tmp-fallback squat guard in ensure_dirs must refuse a
    foreign-owned run dir. Exercised cross-platform by rebinding the
    module's ``os`` to a fake POSIX-flavoured namespace — patching the
    real ``os.name`` would break pathlib inside pytest itself."""

    def _posix_env(self, monkeypatch, tmp_path, uid, owner_uid):
        import os as _os
        import types
        from vnc_remote_secure.core import paths
        for name in ('config', 'data', 'log', 'run', 'ssl'):
            d = tmp_path / name
            d.mkdir(exist_ok=True)
            monkeypatch.setattr(
                paths, f'get_{name}_dir', lambda d=d: str(d))
        monkeypatch.setattr(paths, 'is_windows', lambda: False)
        monkeypatch.setattr(paths, '_is_root', lambda: False)
        monkeypatch.delenv('XDG_RUNTIME_DIR', raising=False)
        fake_os = types.SimpleNamespace(
            name='posix',
            environ=_os.environ,
            lstat=lambda p: types.SimpleNamespace(st_uid=owner_uid),
            geteuid=lambda: uid,
            makedirs=_os.makedirs,
            chmod=_os.chmod,
            path=_os.path,
        )
        monkeypatch.setattr(paths, 'os', fake_os)
        return paths

    def test_foreign_owned_run_dir_refused(self, tmp_path, monkeypatch):
        paths = self._posix_env(monkeypatch, tmp_path,
                                uid=1000, owner_uid=9999)
        with pytest.raises(RuntimeError, match='owned by uid'):
            paths.ensure_dirs()

    def test_own_run_dir_accepted(self, tmp_path, monkeypatch):
        paths = self._posix_env(monkeypatch, tmp_path,
                                uid=1000, owner_uid=1000)
        paths.ensure_dirs()  # must not raise
