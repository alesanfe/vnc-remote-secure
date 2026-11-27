"""Unit tests for service_manager spawn/stop/watchdog internals —
the paths start_all/stop_all/restart_all delegate to."""

import os
import subprocess
import sys
import time
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.core import service_manager as sm


class _FakeProc:
    def __init__(self, pid=4242, rc=None):
        self.pid = pid
        self.returncode = rc
        self.killed = False

    def poll(self):
        return self.returncode


@pytest.fixture
def spawn_env(monkeypatch, tmp_path):
    """Neutralize every side-effecting seam of _start_python_service."""
    monkeypatch.setattr(sm, "_read_pid", lambda s: None)
    monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
    monkeypatch.setattr(sm, "_pid_is_ours", lambda p, s: True)
    monkeypatch.setattr(sm, "_port_in_use", lambda p: False)
    monkeypatch.setattr(sm, "_port_accepting", lambda p: True)
    monkeypatch.setattr(sm, "_write_pid", lambda s, p: None)
    monkeypatch.setattr(sm, "_clear_pid", lambda s: None)
    monkeypatch.setattr(sm, "is_windows", lambda: False)
    monkeypatch.setattr(sm.time, "sleep", lambda s: None)
    written = []
    monkeypatch.setattr(sm, "_write_pid", lambda s, p: written.append((s, p)))
    return written


class TestStartPythonService:
    def test_starts_and_records_pid(self, spawn_env, monkeypatch):
        proc = _FakeProc(pid=7777)
        with mock.patch.object(subprocess, "Popen", return_value=proc) as popen:
            pid = sm._start_python_service("vnc_remote_secure.services.health", "health", port=9)
        assert pid == 7777
        assert spawn_env == [("health", 7777)]
        args, kwargs = popen.call_args
        assert args[0][:3] == [sys.executable, "-m", "vnc_remote_secure.services.health"]
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["start_new_session"] is True  # POSIX detach

    def test_existing_our_pid_short_circuits(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_read_pid", lambda s: 555)
        with mock.patch.object(subprocess, "Popen") as popen:
            assert sm._start_python_service("mod", "svc") == 555
        popen.assert_not_called()

    def test_foreign_pid_record_cleared_then_spawn(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_read_pid", lambda s: 555)
        monkeypatch.setattr(sm, "_pid_is_ours", lambda p, s: False)
        cleared = []
        monkeypatch.setattr(sm, "_clear_pid", lambda s: cleared.append(s))
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc()):
            sm._start_python_service("mod", "svc")
        assert cleared == ["svc"]

    def test_port_busy_foreign_fails_loudly(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_port_in_use", lambda p: True)
        monkeypatch.setattr(sm, "_reap_stale_service", lambda *a: None)
        with mock.patch.object(subprocess, "Popen") as popen:
            assert sm._start_python_service("mod", "svc", port=80) is None
        popen.assert_not_called()

    def test_port_busy_orphan_reaped_then_spawn(self, spawn_env, monkeypatch):
        uses = iter([True, False])
        monkeypatch.setattr(sm, "_port_in_use", lambda p: next(uses))
        reaped = []
        monkeypatch.setattr(sm, "_reap_stale_service", lambda m, s, p: reaped.append((m, s, p)))
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc()):
            assert sm._start_python_service("mod.x", "svc", port=80) is not None
        assert reaped == [("mod.x", "svc", 80)]

    def test_popen_oserror_returns_none(self, spawn_env, monkeypatch):
        with mock.patch.object(subprocess, "Popen", side_effect=OSError("no exec")):
            assert sm._start_python_service("mod", "svc") is None

    def test_port_never_binds_kills_and_fails(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_port_accepting", lambda p: False)
        killed = []
        monkeypatch.setattr(
            sm, "_kill_pid", lambda pid, service=None, force=False: killed.append(pid) or True
        )
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc(pid=3131)):
            assert sm._start_python_service("mod", "svc", port=80) is None
        assert killed == [3131]
        assert ("svc", 3131) not in spawn_env  # failure must not record a pid

    def test_proc_exits_during_startup_fails(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_port_accepting", lambda p: False)
        proc = _FakeProc(pid=1, rc=1)
        proc.poll = lambda: 1
        with mock.patch.object(subprocess, "Popen", return_value=proc):
            assert sm._start_python_service("mod", "svc", port=80) is None

    def test_no_port_skips_bind_verification(self, spawn_env, monkeypatch):
        monkeypatch.setattr(sm, "_port_accepting", lambda p: pytest.fail("must not probe"))
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc()):
            assert sm._start_python_service("mod", "svc") == 4242

    def test_websockify_gets_scrubbed_env(self, spawn_env, monkeypatch):
        monkeypatch.setenv("VNC_PASSWORD", "supersecret")

        def fake_sanitize():
            return {"PATH": "/usr/bin", "SAFE": "1"}

        import vnc_remote_secure.security.redaction as red

        monkeypatch.setattr(red, "sanitized_child_env", fake_sanitize)
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc()) as popen:
            sm._start_python_service("websockify", "websockify")
        env = popen.call_args.kwargs["env"]
        assert env == {"PATH": "/usr/bin", "SAFE": "1"}
        assert "VNC_PASSWORD" not in env

    def test_non_websockify_keeps_full_env(self, spawn_env, monkeypatch):
        with mock.patch.object(subprocess, "Popen", return_value=_FakeProc()) as popen:
            sm._start_python_service("vnc_remote_secure.services.health", "health")
        assert popen.call_args.kwargs["env"] is None  # inherit — service reads .env


class TestStartServiceDispatch:
    @pytest.mark.parametrize(
        "service,attr",
        [
            ("vnc", "_start_vnc"),
            ("terminal", "_start_terminal"),
            ("novnc", "_start_novnc"),
            ("websockify", "_start_websockify"),
            ("nginx", "_start_nginx"),
        ],
    )
    def test_dispatch(self, monkeypatch, service, attr):
        called = []
        monkeypatch.setattr(sm, attr, lambda c: called.append(service) or 42)
        assert sm._start_service(service, {}) == 42
        assert called == [service]

    def test_python_services_dispatch_with_port(self, monkeypatch):
        spawned = []
        monkeypatch.setattr(
            sm,
            "_start_python_service",
            lambda mod, name, extra_args=None, port=None: spawned.append((name, port)) or 7,
        )
        cfg = {
            "ttyd_port": 1,
            "novnc_port": 2,
            "landing_port": 3,
            "user_ui_port": 4,
            "audio_stream_port": 5,
            "gamepad_port": 6,
            "health_port": 8,
        }
        for svc, want_port in [
            ("terminal", 1),
            ("novnc", 2),
            ("landing", 3),
            ("user_ui", 4),
            ("audio", 5),
            ("gamepad", 6),
            ("health", 8),
        ]:
            sm._start_service(svc, cfg)
        assert dict((n, p) for n, p in spawned) == {
            "terminal": 1,
            "novnc": 2,
            "landing": 3,
            "user_ui": 4,
            "audio": 5,
            "gamepad": 6,
            "health": 8,
        }

    def test_unknown_service_returns_none(self):
        assert sm._start_service("bogus", {}) is None


class TestResolveNovncDir:
    def test_env_dir_wins(self, monkeypatch, tmp_path):
        d = tmp_path / "nv"
        d.mkdir()
        monkeypatch.setenv("NOVNC_DIR", str(d))
        assert sm._resolve_novnc_dir() == str(d)

    def test_env_dir_invalid_falls_to_project(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NOVNC_DIR", str(tmp_path / "nope"))
        root = tmp_path / "root"
        (root / "novnc").mkdir(parents=True)
        monkeypatch.setattr(sm, "find_project_root", lambda: str(root))
        assert sm._resolve_novnc_dir() == str(root / "novnc")

    def test_no_dir_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NOVNC_DIR", raising=False)
        monkeypatch.setattr(sm, "find_project_root", lambda: str(tmp_path))
        assert sm._resolve_novnc_dir() is None


class TestStartWebsockify:
    def test_forces_loopback_both_ends(self, monkeypatch):
        spawned = []
        monkeypatch.setattr(
            sm,
            "_start_python_service",
            lambda mod, name, extra, port=None: spawned.append(extra) or 1,
        )
        monkeypatch.setattr(sm, "is_windows", lambda: True)  # skip _vnc_port derivation
        sm._start_websockify({"novnc_ws_port": 5700, "vnc_port": 5901})
        assert spawned == [["127.0.0.1:5700", "127.0.0.1:5901"]]

    def test_bind_host_override_warns_but_stays_loopback(self, monkeypatch):
        spawned = []
        monkeypatch.setattr(
            sm,
            "_start_python_service",
            lambda mod, name, extra, port=None: spawned.append(extra) or 1,
        )
        monkeypatch.setattr(sm, "is_windows", lambda: True)
        monkeypatch.setenv("BIND_HOST", "0.0.0.0")
        sm._start_websockify({})
        assert spawned[0][0].startswith("127.0.0.1:")


class TestStopPlan:
    def test_unlisted_pid_file_services_stop_first(self, monkeypatch, tmp_path):
        pid_dir = tmp_path / "pids"
        pid_dir.mkdir()
        (pid_dir / "plugin_x.pid").write_text("1")
        (pid_dir / "vnc.pid").write_text("2")
        monkeypatch.setattr(sm, "_pid_dir", lambda: str(pid_dir))
        plan = sm._stop_plan()
        assert plan[0] == "plugin_x"
        assert plan[-1] == "vnc"  # canonical order preserved after extras


class TestRestartThrottle:
    def test_allows_then_throttles(self, monkeypatch):
        monkeypatch.setattr(sm, "_restart_history", {})
        now = time.monotonic()
        for _ in range(sm._RESTART_MAX):
            assert sm._restart_allowed("svc", now) is True
            sm._record_restart("svc", now)
        assert sm._restart_allowed("svc", now) is False

    def test_old_restarts_pruned(self, monkeypatch):
        monkeypatch.setattr(sm, "_restart_history", {})
        now = time.monotonic()
        old = now - sm._RESTART_WINDOW_S - 1
        for _ in range(sm._RESTART_MAX + 2):
            sm._record_restart("svc", old)
        assert sm._restart_allowed("svc", now) is True


class TestFindDeadServices:
    def _cfg(self):
        return {"healthcheck_enabled": True, "auto_restart": False}

    def test_dead_pid_is_dead(self, monkeypatch):
        monkeypatch.setattr(sm, "_enabled_services", lambda c: ["health"])
        monkeypatch.setattr(sm, "_read_pid", lambda s: 111)
        monkeypatch.setattr(sm, "_pid_alive", lambda p: False)
        monkeypatch.setattr(sm, "_service_port_map", lambda c: {"health": 8080})
        assert sm._find_dead_services(self._cfg()) == ["health"]

    def test_alive_pid_dead_port_is_dead(self, monkeypatch):
        monkeypatch.setattr(sm, "_enabled_services", lambda c: ["health"])
        monkeypatch.setattr(sm, "_read_pid", lambda s: 111)
        monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
        monkeypatch.setattr(sm, "_port_accepting", lambda p: False)
        monkeypatch.setattr(sm, "_service_port_map", lambda c: {"health": 8080})
        assert sm._find_dead_services(self._cfg()) == ["health"]

    def test_healthy_service_not_dead(self, monkeypatch):
        monkeypatch.setattr(sm, "_enabled_services", lambda c: ["health"])
        monkeypatch.setattr(sm, "_read_pid", lambda s: 111)
        monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
        monkeypatch.setattr(sm, "_port_accepting", lambda p: True)
        monkeypatch.setattr(sm, "_service_port_map", lambda c: {"health": 8080})
        assert sm._find_dead_services(self._cfg()) == []


class TestAutoRestartDead:
    def test_restarts_dead_service(self, monkeypatch):
        monkeypatch.setattr(sm, "_restart_history", {})
        monkeypatch.setattr(sm, "_restart_allowed", lambda s, n: True)
        monkeypatch.setattr(sm, "_record_restart", lambda s, n: None)
        monkeypatch.setattr(sm, "_read_pid", lambda s: 111)
        monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
        killed = []
        monkeypatch.setattr(
            sm, "_kill_pid", lambda pid, service=None, force=False: killed.append(pid) or True
        )
        cleared = []
        monkeypatch.setattr(sm, "_clear_pid", lambda s: cleared.append(s))
        started = []
        monkeypatch.setattr(sm, "_start_service", lambda s, c: started.append(s) or 999)
        out = sm._auto_restart_dead(["health"], {})
        assert out == {"health": 999}
        assert killed == [111] and cleared == ["health"] and started == ["health"]

    def test_throttled_service_not_restarted(self, monkeypatch):
        monkeypatch.setattr(sm, "_restart_history", {})
        monkeypatch.setattr(sm, "_restart_allowed", lambda s, n: False)
        monkeypatch.setattr(sm, "_metric", lambda *a: None)
        monkeypatch.setattr(sm, "_alert_throttled", lambda t: None)
        monkeypatch.setattr(sm, "_start_service", lambda s, c: pytest.fail("must not start"))
        assert sm._auto_restart_dead(["health"], {}) == {}


class TestWatchdogTick:
    def test_disabled_returns_empty(self, monkeypatch):
        assert sm.watchdog_tick({"healthcheck_enabled": False}) == {}

    def test_dedup_skips_unchanged_dead_set(self, monkeypatch):
        monkeypatch.setattr(sm, "_last_watchdog_dead", {"health"})
        monkeypatch.setattr(sm, "_find_dead_services", lambda c: ["health"])
        monkeypatch.setattr(sm, "_alert_new_blocking_findings", lambda: None)
        assert sm.watchdog_tick({"healthcheck_enabled": True, "auto_restart": False}) == {}

    def test_auto_restart_runs_for_dead(self, monkeypatch):
        monkeypatch.setattr(sm, "_last_watchdog_dead", set())
        monkeypatch.setattr(sm, "_find_dead_services", lambda c: ["health"])
        monkeypatch.setattr(sm, "_alert_new_blocking_findings", lambda: None)
        monkeypatch.setattr(sm, "_auto_restart_dead", lambda d, c: {"health": 5})
        monkeypatch.setattr(sm, "_alert_watchdog_transitions", lambda *a: None)
        out = sm.watchdog_tick({"healthcheck_enabled": True, "auto_restart": True})
        assert out == {"health": 5}


class TestRestoreState:
    def test_foreign_pid_not_adopted(self, monkeypatch):
        written = []
        monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
        monkeypatch.setattr(sm, "_pid_is_ours", lambda p, s: False)
        monkeypatch.setattr(sm, "_write_pid", lambda s, p: written.append((s, p)))
        sm.restore_state({"pids": {"vnc": 4242}})
        assert written == []

    def test_own_pid_restored(self, monkeypatch):
        written = []
        monkeypatch.setattr(sm, "_pid_alive", lambda p: True)
        monkeypatch.setattr(sm, "_pid_is_ours", lambda p, s: True)
        monkeypatch.setattr(sm, "_write_pid", lambda s, p: written.append((s, p)))
        sm.restore_state({"pids": {"vnc": 4242}})
        assert written == [("vnc", 4242)]


class _FakeConn:
    def __init__(self, port, status="LISTEN"):
        self.laddr = type("A", (), {"port": port})()
        self.status = status


class _FakePsutilProc:
    def __init__(self, pid, cmdline, conns=(), kill_exc=None):
        self.info = {"pid": pid, "name": "x", "cmdline": cmdline}
        self._conns = list(conns)
        self.killed = False
        self._kill_exc = kill_exc

    def connections(self, kind="inet"):
        return list(self._conns)

    def kill(self):
        if self._kill_exc:
            raise self._kill_exc
        self.killed = True

    def wait(self, timeout=None):
        return None


class TestReapStaleService:
    """_reap_stale_service kills only OUR orphan holding the port —
    foreign processes and self are untouchable."""

    def _psutil(self, monkeypatch, procs):
        import psutil

        monkeypatch.setattr(psutil, "process_iter", lambda attrs: iter(procs))
        return psutil

    def test_orphan_on_port_is_killed(self, monkeypatch):
        psutil = self._psutil(monkeypatch, [])
        orphan = _FakePsutilProc(
            9001, ["python", "-m", "vnc_remote_secure.services.health"], conns=[_FakeConn(8080)]
        )
        foreign = _FakePsutilProc(9002, ["nginx"], conns=[_FakeConn(8080)])
        self_pid = _FakePsutilProc(
            os.getpid(),
            ["python", "-m", "vnc_remote_secure.services.health"],
            conns=[_FakeConn(8080)],
        )
        psutil.process_iter = lambda attrs: iter([self_pid, orphan, foreign])
        sm._reap_stale_service("vnc_remote_secure.services.health", "health", 8080)
        assert orphan.killed is True
        assert foreign.killed is False

    def test_module_marker_must_match(self, monkeypatch):
        import psutil

        proc = _FakePsutilProc(9003, ["python", "-m", "other.module"], conns=[_FakeConn(8080)])
        monkeypatch.setattr(psutil, "process_iter", lambda attrs: iter([proc]))
        sm._reap_stale_service("vnc_remote_secure.services.health", "health", 8080)
        assert proc.killed is False

    def test_listen_on_other_port_not_killed(self, monkeypatch):
        import psutil

        proc = _FakePsutilProc(9004, ["python", "-m", "svc"], conns=[_FakeConn(9999)])
        monkeypatch.setattr(psutil, "process_iter", lambda attrs: iter([proc]))
        sm._reap_stale_service("svc", "svc", 8080)
        assert proc.killed is False

    def test_psutil_missing_is_noop(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "psutil", None)
        # import inside function → ImportError path → silent return
        sm._reap_stale_service("svc", "svc", 8080)

    def test_access_denied_skipped(self, monkeypatch):
        import psutil

        class _Denied(_FakePsutilProc):
            def connections(self, kind="inet"):
                raise psutil.AccessDenied(1234)

        proc = _Denied(9005, ["python", "-m", "svc"], conns=[_FakeConn(8080)])
        monkeypatch.setattr(psutil, "process_iter", lambda attrs: iter([proc]))
        sm._reap_stale_service("svc", "svc", 8080)  # must not raise
        assert proc.killed is False
