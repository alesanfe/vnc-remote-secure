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
    # not listen on the VNC port â€” stub identity and port probes so the
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
    # nginx is Linux-only â€” on Windows the landing portal is the public
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
    # adopting it â€” stub identity so the pytest process qualifies.
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


class TestPidIdentityGuards:
    """PID-reuse protection: a recycled PID belonging to a foreign
    process must never be killed."""

    def test_kill_refuses_unverified_pid(self, monkeypatch):
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, '_pid_alive', lambda p: True)
        monkeypatch.setattr(sm, '_pid_is_ours', lambda p, s=None: None)
        killed = []
        monkeypatch.setattr(sm.os, 'kill',
                            lambda p, sig: killed.append(p))
        monkeypatch.setattr(sm, 'run_cmd',
                            lambda *a, **k: None)
        assert sm._kill_pid(4321) is False
        assert killed == []

    def test_kill_drops_foreign_pid_without_killing(self, monkeypatch):
        """identity=False (PID reuse) -> record cleared, no signal sent."""
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, '_pid_alive', lambda p: True)
        monkeypatch.setattr(sm, '_pid_is_ours', lambda p, s=None: False)
        cleared = []
        monkeypatch.setattr(sm, '_clear_pid_by_value',
                            lambda p: cleared.append(p))
        killed = []
        monkeypatch.setattr(sm.os, 'kill',
                            lambda p, sig: killed.append(p))
        monkeypatch.setattr(sm, 'run_cmd', lambda *a, **k: None)
        assert sm._kill_pid(4321) is True
        assert cleared == [4321]
        assert killed == []

    def test_kill_unknown_identity_with_force_proceeds(self, monkeypatch):
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, '_pid_alive',
                            lambda p: True)
        monkeypatch.setattr(sm, '_pid_is_ours', lambda p, s=None: None)
        monkeypatch.setattr(sm, '_kill_descendants', lambda p: None)
        killed = []
        monkeypatch.setattr(sm.os, 'kill',
                            lambda p, sig: killed.append(p))
        # Process dies on first check after SIGTERM.
        alive = [True]

        def _alive(p):
            return alive[0] and not killed

        monkeypatch.setattr(sm, '_pid_alive', _alive)
        monkeypatch.setattr(sm, 'is_windows', lambda: False)
        monkeypatch.setattr(sm, '_clear_pid_by_value', lambda p: None)
        assert sm._kill_pid(4321, timeout=0.2, force=True) is True
        assert killed  # SIGTERM sent

    def test_pid_alive_windows_exact_match(self, monkeypatch):
        """tasklist CSV match must be exact â€” pid 12 must not match
        a row for pid 12345."""
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, 'is_windows', lambda: True)

        class R:
            stdout = '"python.exe","12345","Services","0","1 K"'

        monkeypatch.setattr(sm, 'run_cmd', lambda *a, **k: R())
        assert sm._pid_alive(12) is False
        assert sm._pid_alive(12345) is True

    def test_pid_is_ours_needles(self, monkeypatch):
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, 'is_windows', lambda: False)
        # /proc read fails -> None (unknown), never False.
        assert sm._pid_is_ours(999999999) is None


class TestAuditInternalListeners:
    """A service that bound publicly when it must be loopback-only
    is a perimeter breach â€” the post-start audit must catch it."""

    def _cfg(self, **kw):
        cfg = {'vnc_port': 5901, 'novnc_ws_port': 5700,
               'ttyd_port': 7681, 'landing_port': 8080,
               'nginx_enabled': False}
        cfg.update(kw)
        return cfg

    def _with_listeners(self, monkeypatch, listeners):
        import vnc_remote_secure.core.doctor as doc
        import vnc_remote_secure.core.service_manager as sm
        monkeypatch.setattr(
            doc, '_list_listeners', lambda: listeners)
        monkeypatch.setattr(
            'vnc_remote_secure.core.doctor._list_listeners',
            lambda: listeners)
        return sm

    def test_rfb_public_flagged(self, monkeypatch):
        sm = self._with_listeners(
            monkeypatch,
            [('0.0.0.0', 5901), ('127.0.0.1', 5700)])
        findings = sm.audit_internal_listeners(self._cfg())
        assert any('vnc' in f and '0.0.0.0' in f for f in findings)

    def test_websockify_public_flagged(self, monkeypatch):
        sm = self._with_listeners(
            monkeypatch,
            [('127.0.0.1', 5901), ('0.0.0.0', 5700)])
        findings = sm.audit_internal_listeners(self._cfg())
        assert any('websockify' in f for f in findings)

    def test_loopback_clean(self, monkeypatch):
        sm = self._with_listeners(
            monkeypatch,
            [('127.0.0.1', 5901), ('::1', 5700)])
        assert sm.audit_internal_listeners(self._cfg()) == []

    def test_backend_public_only_with_nginx(self, monkeypatch):
        """Without nginx the backends ARE the public entry points â€”
        flagging them would be a false positive."""
        sm = self._with_listeners(
            monkeypatch,
            [('0.0.0.0', 8080), ('127.0.0.1', 5901),
             ('127.0.0.1', 5700)])
        cfg = self._cfg(nginx_enabled=False)
        assert sm.audit_internal_listeners(cfg) == []
        cfg = self._cfg(nginx_enabled=True)
        findings = sm.audit_internal_listeners(cfg)
        assert any('8080' in f for f in findings)

    def test_enumeration_failure_no_findings(self, monkeypatch):
        sm = self._with_listeners(monkeypatch, None)
        assert sm.audit_internal_listeners(self._cfg()) == []


class TestStaleTempUserSweep:
    """A crashed run never ran stop â€” the temp user must be swept at
    the next start, but ONLY when it owns no processes (a live
    orphaned session may still need the account)."""

    def _linux(self, monkeypatch, user_exists=True, procs=b''):
        import sys
        import types

        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, 'is_windows', lambda: False)
        monkeypatch.delenv('KEEP_TEMP_USER', raising=False)
        monkeypatch.setenv('TEMP_USER', 'remote')
        pwd = types.ModuleType('pwd')
        if user_exists:
            pwd.getpwnam = lambda u: object()
        else:
            def _missing(u):
                raise KeyError(u)
            pwd.getpwnam = _missing
        monkeypatch.setitem(sys.modules, 'pwd', pwd)

        class R:
            returncode = 0 if procs else 1
            stdout = procs
        monkeypatch.setattr(
            sm.subprocess, 'run', lambda *a, **k: R())
        removed = []
        monkeypatch.setattr(
            'vnc_remote_secure.platform.base.get_adapter',
            lambda: type('A', (), {
                'remove_runtime_user': staticmethod(
                    lambda u: removed.append(u) or True)})(),
            raising=False)
        return sm, removed

    def test_stale_user_removed(self, monkeypatch):
        sm, removed = self._linux(monkeypatch, procs=b'')
        sm._sweep_stale_temp_user()
        assert removed == ['remote']

    def test_user_with_processes_kept(self, monkeypatch):
        """pgrep -u returns PIDs â†’ the account is in use â€” deleting
        it would orphan live processes."""
        sm, removed = self._linux(monkeypatch, procs=b'1234\n')
        sm._sweep_stale_temp_user()
        assert removed == []

    def test_absent_user_noop(self, monkeypatch):
        sm, removed = self._linux(monkeypatch, user_exists=False)
        sm._sweep_stale_temp_user()
        assert removed == []

    def test_keep_temp_user_noop(self, monkeypatch):
        sm, removed = self._linux(monkeypatch)
        monkeypatch.setenv('KEEP_TEMP_USER', 'true')
        sm._sweep_stale_temp_user()
        assert removed == []

    def test_non_linux_noop(self, monkeypatch):
        from vnc_remote_secure.core import service_manager as sm
        monkeypatch.setattr(sm, 'is_windows', lambda: True)
        calls = []
        monkeypatch.setattr(
            sm.subprocess, 'run',
            lambda *a, **k: calls.append(1))
        sm._sweep_stale_temp_user()
        assert calls == []
