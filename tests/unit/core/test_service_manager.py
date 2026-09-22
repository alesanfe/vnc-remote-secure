"""Unit tests for the unified service manager.

These tests verify the canonical lifecycle behavior:
- PID tracking (start records PID, stop kills by PID, no pkill -f)
- Cross-process lock prevents duplicate starts
- status_all reflects real process liveness, not port probes
- restart cleans up the temporary user
- stop does not kill unrelated processes
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import service_manager as sm
from vnc_remote_secure.platform.detection import is_windows

# ---------------------------------------------------------------------------
# PID file helpers
# ---------------------------------------------------------------------------


def test_write_and_read_pid_roundtrip(tmp_path, monkeypatch):
    """_write_pid / _read_pid persist and recover PIDs."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    sm._write_pid('vnc', 12345)
    assert sm._read_pid('vnc') == 12345


def test_read_pid_returns_none_when_missing(tmp_path, monkeypatch):
    """_read_pid returns None when no PID file exists."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    assert sm._read_pid('nonexistent') is None


def test_clear_pid_removes_file(tmp_path, monkeypatch):
    """_clear_pid deletes the PID file."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    sm._write_pid('vnc', 999)
    sm._clear_pid('vnc')
    assert sm._read_pid('vnc') is None


def test_clear_pid_by_value_removes_matching_files(tmp_path, monkeypatch):
    """_clear_pid_by_value removes only PID files pointing to the given PID."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    sm._write_pid('vnc', 111)
    sm._write_pid('novnc', 222)
    sm._clear_pid_by_value(111)
    assert sm._read_pid('vnc') is None
    assert sm._read_pid('novnc') == 222


# ---------------------------------------------------------------------------
# Process liveness
# ---------------------------------------------------------------------------

def test_pid_alive_current_process():
    """_pid_alive returns True for the current process."""
    assert sm._pid_alive(os.getpid()) is True


def test_pid_alive_dead_pid():
    """_pid_alive returns False for a PID that does not exist."""
    # PID 0 is never a real user process; on Linux os.kill(0,0) signals
    # the whole process group, so use a very high unlikely PID.
    assert sm._pid_alive(999999) is False


def test_pid_alive_invalid_pid():
    """_pid_alive returns False for invalid PIDs."""
    assert sm._pid_alive(0) is False
    assert sm._pid_alive(-1) is False


# ---------------------------------------------------------------------------
# status_all
# ---------------------------------------------------------------------------

def test_status_all_reports_no_pid_as_not_running(tmp_path, monkeypatch):
    """status_all reports services without PIDs as not running."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    status = sm.status_all()
    assert 'vnc' in status
    assert status['vnc']['running'] is False
    assert status['vnc']['pid'] is None


def test_status_all_clears_stale_pid(tmp_path, monkeypatch):
    """status_all clears PID files pointing to dead processes."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    sm._write_pid('vnc', 999999)  # dead PID
    status = sm.status_all()
    assert status['vnc']['running'] is False
    # The stale PID file should have been cleared.
    assert sm._read_pid('vnc') is None


def test_status_all_reports_live_pid(tmp_path, monkeypatch):
    """status_all reports a live PID as running."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    # The pytest process is not a vnc_remote_secure service, and it does
    # not listen on the VNC port — stub identity and port probes so the
    # test exercises only PID liveness.
    monkeypatch.setattr(sm, '_pid_is_ours', lambda *a, **k: True)
    monkeypatch.setattr(sm, '_port_accepting', lambda *a, **k: True)
    sm._write_pid('vnc', os.getpid())
    status = sm.status_all()
    assert status['vnc']['running'] is True
    assert status['vnc']['pid'] == os.getpid()


def test_status_all_dead_port_means_not_running(tmp_path, monkeypatch):
    """A live PID whose port stopped accepting is reported not running."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    monkeypatch.setattr(sm, '_pid_is_ours', lambda *a, **k: True)
    monkeypatch.setattr(sm, '_port_accepting', lambda *a, **k: False)
    sm._write_pid('terminal', os.getpid())
    status = sm.status_all()
    assert status['terminal']['running'] is False


def test_status_all_foreign_pid_means_not_running(tmp_path, monkeypatch):
    """A pid file pointing at a foreign live process is not 'running'."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    monkeypatch.setattr(sm, '_pid_is_ours', lambda *a, **k: False)
    monkeypatch.setattr(sm, '_port_accepting', lambda *a, **k: True)
    sm._write_pid('landing', os.getpid())
    status = sm.status_all()
    assert status['landing']['running'] is False


def test_status_all_vnc_port_display_derived_on_linux(tmp_path, monkeypatch):
    """On Linux the reported VNC port is 5900+display, not VNC_PORT.

    TigerVNC ignores VNC_PORT for binding (the adapter never passes
    -rfbport), so status_all must agree with doctor/websockify/landing
    on the effective RFB port.
    """
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    monkeypatch.setattr(sm, 'is_windows', lambda: False)
    monkeypatch.setenv('VNC_DISPLAY', ':3')
    status = sm.status_all()
    assert status['vnc']['port'] == 5903


def test_status_all_vnc_port_configured_on_windows(tmp_path, monkeypatch):
    """On Windows UltraVNC honours the configured VNC_PORT verbatim."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    monkeypatch.setattr(sm, 'is_windows', lambda: True)
    monkeypatch.setenv('VNC_PORT', '5912')
    status = sm.status_all()
    assert status['vnc']['port'] == 5912


# ---------------------------------------------------------------------------
# _enabled_services
# ---------------------------------------------------------------------------

def test_enabled_services_includes_core():
    """Core services are always enabled."""
    config = {'user_ui_enabled': False, 'audio_stream_enabled': False,
              'gamepad_enabled': False, 'nginx_enabled': False}
    services = sm._enabled_services(config)
    assert 'vnc' in services
    assert 'terminal' in services
    assert 'novnc' in services
    assert 'health' in services
    assert 'landing' in services


def test_enabled_services_respects_feature_flags():
    """Optional services appear only when their flag is set."""
    config = {'user_ui_enabled': True, 'audio_stream_enabled': True,
              'gamepad_enabled': True, 'nginx_enabled': True}
    services = sm._enabled_services(config)
    assert 'user_ui' in services
    assert 'audio' in services
    assert 'gamepad' in services
    # nginx is Linux-only — on Windows the landing portal is the public
    # entry point and nginx is never supervised by the service manager.
    if is_windows():
        assert 'nginx' not in services
    else:
        assert 'nginx' in services
    # Prometheus and Grafana are external binaries managed by the platform
    # adapter, not Python services. They are NOT in _enabled_services().
    assert 'prometheus' not in services
    assert 'grafana' not in services


def test_enabled_services_excludes_disabled_optional():
    """Optional services are excluded when their flag is False."""
    config = {'user_ui_enabled': False, 'audio_stream_enabled': False,
              'gamepad_enabled': False, 'nginx_enabled': False}
    services = sm._enabled_services(config)
    assert 'user_ui' not in services
    assert 'audio' not in services
    assert 'gamepad' not in services


# ---------------------------------------------------------------------------
# Global lock
# ---------------------------------------------------------------------------

def test_global_lock_acquires(tmp_path, monkeypatch):
    """The global lock acquires when no other instance holds it."""
    monkeypatch.setattr(sm, '_lock_path', lambda: str(tmp_path / 'lock'))
    lock = sm._GlobalLock()
    with lock:
        assert lock.acquired is True


def test_global_lock_blocks_second_acquirer(tmp_path, monkeypatch):
    """A second lock cannot acquire while the first is held."""
    monkeypatch.setattr(sm, '_lock_path', lambda: str(tmp_path / 'lock'))
    lock1 = sm._GlobalLock()
    with lock1:
        lock2 = sm._GlobalLock()
        with lock2:
            assert lock2.acquired is False


# ---------------------------------------------------------------------------
# stop_all does not kill unrelated processes
# ---------------------------------------------------------------------------

def test_stop_all_does_not_touch_unrelated_pid(tmp_path, monkeypatch):
    """stop_all only kills PIDs it recorded, not arbitrary processes."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    # Record a dead PID so _kill_pid returns True without touching anything.
    sm._write_pid('vnc', 999999)
    results = sm.stop_all()
    assert results['vnc'] is True
    # The current test process must still be alive (not killed).
    assert sm._pid_alive(os.getpid()) is True


# ---------------------------------------------------------------------------
# save_state / restore_state
# ---------------------------------------------------------------------------

def test_save_and_restore_state_roundtrip(tmp_path, monkeypatch):
    """save_state captures PIDs and restore_state recovers live ones."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    # restore_state verifies the PID belongs to this deployment before
    # adopting it — stub identity so the pytest process qualifies.
    monkeypatch.setattr(sm, '_pid_is_ours', lambda *a, **k: True)
    sm._write_pid('vnc', os.getpid())
    state = sm.save_state()
    assert state['pids']['vnc'] == os.getpid()
    # Clear and restore.
    sm._clear_pid('vnc')
    sm.restore_state(state)
    assert sm._read_pid('vnc') == os.getpid()


# ---------------------------------------------------------------------------
# watchdog auto-restart throttling
# ---------------------------------------------------------------------------

def test_watchdog_restart_throttled_after_limit(tmp_path, monkeypatch):
    """After _RESTART_MAX restarts in the window the watchdog stops
    retrying -- a permanently broken service must not respawn forever."""
    monkeypatch.setattr(sm, '_pid_dir', lambda: str(tmp_path))
    sm._restart_history.clear()
    sm._last_throttled.clear()
    monkeypatch.setattr(sm, '_pid_alive', lambda pid: False)
    monkeypatch.setattr(sm, '_enabled_services', lambda c: ['vnc'])
    sm._write_pid('vnc', 999999)
    calls = []
    monkeypatch.setattr(sm, '_start_service',
                        lambda s, c: calls.append(s) or 1234)
    cfg = {'healthcheck_enabled': True, 'auto_restart': True}
    for _ in range(sm._RESTART_MAX + 2):
        sm.watchdog_tick(cfg)
    assert len(calls) == sm._RESTART_MAX
    assert 'vnc' in sm._last_throttled
