"""Unit tests for services.vnc module.

All external dependencies (PATH lookups, subprocess, port availability,
session registry, platform adapter) are mocked so the tests are
deterministic and do not require UltraVNC/TigerVNC to be installed.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import vnc
from vnc_remote_secure.core.exceptions import ServiceError


class _FakeLinuxAdapter:
    """Fake Linux adapter for testing."""
    def start_vnc_server(self, display, geometry, depth, password):
        import shutil
        exe = shutil.which('tigervncserver') or shutil.which('vncserver')
        if not exe:
            raise ServiceError("VNC server binary not found on PATH")
        import subprocess
        return subprocess.Popen([exe, display, '-geometry', geometry, '-depth', str(depth)])

    def stop_vnc_process(self, pid):
        import subprocess
        subprocess.run(['kill', '-TERM', str(pid)], capture_output=True)


class _FakeWindowsAdapter:
    """Fake Windows adapter for testing."""
    def start_vnc_server(self, display, geometry, depth, password):
        import shutil
        exe = shutil.which('winvnc')
        if not exe:
            raise ServiceError("UltraVNC winvnc.exe not found on PATH")
        import subprocess
        return subprocess.Popen([exe])

    def stop_vnc_process(self, pid):
        import subprocess
        subprocess.run(['taskkill', '/PID', str(pid), '/F'], capture_output=True)


def _patch_adapter(monkeypatch, adapter):
    """Patch get_adapter() to return the given fake adapter."""
    monkeypatch.setattr(vnc, 'get_adapter', lambda: adapter)


# ---------------------------------------------------------------------------
# _vnc_port
# ---------------------------------------------------------------------------

def test_vnc_port_from_display_number():
    base = vnc.DEFAULT_VNC_PORT
    assert vnc._vnc_port(':1') == base + 1
    assert vnc._vnc_port(':0') == base
    assert vnc._vnc_port('5') == base + 5


def test_vnc_port_none_defaults_to_base():
    assert vnc._vnc_port(None) == vnc.DEFAULT_VNC_PORT


# ---------------------------------------------------------------------------
# start_vnc (Linux path)
# ---------------------------------------------------------------------------

def test_start_vnc_linux_returns_popen(monkeypatch):
    """On Linux, start_vnc returns the Popen instance when the binary exists."""
    _patch_adapter(monkeypatch, _FakeLinuxAdapter())
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: True)
    monkeypatch.setattr(vnc, 'create_session', lambda *a, **k: None)
    import shutil
    monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/tigervncserver')

    class _FakeProc:
        pid = 12345

    import subprocess
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd: _FakeProc())
    # Force platform.system() to return 'Linux' so vnc.py returns Popen
    import platform as _pf
    monkeypatch.setattr(_pf, 'system', lambda: 'Linux')
    result = vnc.start_vnc(display=':1', geometry='1280x720', depth=24, password='secret')
    assert isinstance(result, _FakeProc)


def test_start_vnc_linux_missing_binary_raises(monkeypatch):
    """On Linux, start_vnc raises ServiceError if no VNC binary is on PATH."""
    _patch_adapter(monkeypatch, _FakeLinuxAdapter())
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: True)
    import shutil
    monkeypatch.setattr(shutil, 'which', lambda name: None)

    with pytest.raises(ServiceError, match="VNC server binary not found"):
        vnc.start_vnc(display=':1', password='secret')


# ---------------------------------------------------------------------------
# start_vnc (Windows path)
# ---------------------------------------------------------------------------

def test_start_vnc_windows_returns_pid(monkeypatch):
    """On Windows, start_vnc returns the PID when winvnc is found."""
    _patch_adapter(monkeypatch, _FakeWindowsAdapter())
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: True)
    monkeypatch.setattr(vnc, 'create_session', lambda *a, **k: None)
    import shutil
    monkeypatch.setattr(shutil, 'which', lambda name: 'C:/ultravnc/winvnc.exe')

    class _FakeProc:
        pid = 9999

    import subprocess
    monkeypatch.setattr(subprocess, 'Popen', lambda cmd: _FakeProc())
    # Force platform.system() to return 'Windows' so vnc.py returns PID
    import platform as _pf
    monkeypatch.setattr(_pf, 'system', lambda: 'Windows')

    result = vnc.start_vnc(display=':0', password='secret')
    assert result == 9999


def test_start_vnc_windows_missing_binary_raises(monkeypatch):
    """On Windows, start_vnc raises ServiceError if winvnc is not on PATH."""
    _patch_adapter(monkeypatch, _FakeWindowsAdapter())
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: True)
    import shutil
    monkeypatch.setattr(shutil, 'which', lambda name: None)

    with pytest.raises(ServiceError, match="UltraVNC winvnc.exe not found"):
        vnc.start_vnc(display=':0', password='secret')


# ---------------------------------------------------------------------------
# start_vnc (port already in use)
# ---------------------------------------------------------------------------

def test_start_vnc_port_in_use_raises(monkeypatch):
    """start_vnc raises ServiceError when the VNC port is already taken."""
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: False)
    with pytest.raises(ServiceError, match="already running"):
        vnc.start_vnc(display=':1', password='secret')


# ---------------------------------------------------------------------------
# stop_vnc
# ---------------------------------------------------------------------------

def test_stop_vnc_returns_true_when_no_process(monkeypatch):
    """stop_vnc returns True when no process is found on the port."""
    monkeypatch.setattr(vnc, 'find_process', lambda port: None)
    monkeypatch.setattr(vnc, 'destroy_session', lambda display: None)
    assert vnc.stop_vnc(display=':1') is True


def test_stop_vnc_kills_process_on_linux(monkeypatch):
    """stop_vnc kills the process and returns True on Linux."""
    _patch_adapter(monkeypatch, _FakeLinuxAdapter())
    monkeypatch.setattr(vnc, 'find_process', lambda port: 4321)
    monkeypatch.setattr(vnc, 'destroy_session', lambda display: None)

    called = {}
    def _fake_run(cmd, **k):
        called['cmd'] = cmd
        return None
    import subprocess
    monkeypatch.setattr(subprocess, 'run', _fake_run)

    assert vnc.stop_vnc(display=':1') is True
    assert 'kill' in called['cmd']


def test_stop_vnc_kills_process_on_windows(monkeypatch):
    """stop_vnc uses taskkill on Windows."""
    _patch_adapter(monkeypatch, _FakeWindowsAdapter())
    monkeypatch.setattr(vnc, 'find_process', lambda port: 4321)
    monkeypatch.setattr(vnc, 'destroy_session', lambda display: None)

    called = {}
    def _fake_run(cmd, **k):
        called['cmd'] = cmd
        return None
    import subprocess
    monkeypatch.setattr(subprocess, 'run', _fake_run)

    assert vnc.stop_vnc(display=':1') is True
    assert 'taskkill' in called['cmd']


# ---------------------------------------------------------------------------
# vnc_status
# ---------------------------------------------------------------------------

def test_vnc_status_not_running(monkeypatch):
    """vnc_status reports running=False when the port is available."""
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: True)
    monkeypatch.setattr(vnc, 'find_process', lambda port: None)
    status = vnc.vnc_status(display=':1')
    assert status['display'] == ':1'
    assert status['port'] == vnc.DEFAULT_VNC_PORT + 1
    assert status['running'] is False
    assert status['pid'] is None


def test_vnc_status_running(monkeypatch):
    """vnc_status reports running=True when the port is taken."""
    monkeypatch.setattr(vnc, 'is_port_available', lambda port: False)
    monkeypatch.setattr(vnc, 'find_process', lambda port: 4321)
    status = vnc.vnc_status(display=':1')
    assert status['running'] is True
    assert status['pid'] == 4321
