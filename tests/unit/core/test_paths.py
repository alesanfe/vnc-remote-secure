"""Tests for core.paths — platform-aware directory resolution."""
import sys

import pytest

from vnc_remote_secure.core import paths


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    yield


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
