"""Unit tests for core.deferred_lifecycle — the detached runner that
claims a persisted job and executes it so the REST response is
guaranteed even when the operation kills the portal serving it."""

import subprocess
import sys
from unittest import mock

import pytest

from vnc_remote_secure.core import deferred_lifecycle as dl


@pytest.fixture(autouse=True)
def _allow_spawn(monkeypatch):
    monkeypatch.setenv("VRS_TEST_ALLOW_SPAWN", "1")


def test_spawn_detaches_child():
    with mock.patch.object(subprocess, "Popen") as popen:
        proc = popen.return_value
        proc.pid = 4321
        pid = dl.spawn_job_runner("jid-1", delay=0.5)
    assert pid == 4321
    args, kwargs = popen.call_args
    assert args[0][0] == sys.executable
    assert args[0][2] == "vnc_remote_secure.core.deferred_lifecycle"
    assert args[0][3:5] == ["run", "jid-1"]
    # Detached — the child survives when stop/restart kills the parent.
    assert kwargs["stdin"] is not None and kwargs["close_fds"] is True
    if sys.platform == "win32":
        assert kwargs["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
        assert kwargs["creationflags"] & subprocess.DETACHED_PROCESS
    else:
        assert kwargs["start_new_session"] is True


def test_spawn_blocked_in_test_mode_without_optin(monkeypatch):
    monkeypatch.delenv("VRS_TEST_ALLOW_SPAWN")
    with pytest.raises(dl.__dict__.get("TestIsolationError", RuntimeError)):
        dl.spawn_job_runner("jid-x")


def test_main_usage_error():
    assert dl.main([]) == 2
    assert dl.main(["nope"]) == 2
    assert dl.main(["run"]) == 2


def test_main_runs_job_after_delay(monkeypatch):
    slept = []
    ran = []
    monkeypatch.setattr(dl.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(dl, "run_job", lambda j: ran.append(j) or 0)
    assert dl.main(["run", "abc123", "0.01"]) == 0
    assert slept == [0.01]
    assert ran == ["abc123"]


def test_main_delay_is_bounded(monkeypatch):
    """A huge delay must not park a hidden process for days."""
    slept = []
    monkeypatch.setattr(dl.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(dl, "run_action", lambda a: 0)
    # Legacy direct mode is opt-in — without the flag the action is
    # refused (the audited path is `run <job_id>`).
    dl.main(["stop", "999999"])
    assert slept[0] <= 60.0
    monkeypatch.setenv("VRS_DEFERRED_LEGACY", "1")
    dl.main(["stop", "999999"])
    assert slept[0] <= 60.0


def test_run_action_stop(monkeypatch):
    calls = []
    import vnc_remote_secure.core.service_manager as sm

    monkeypatch.setattr(sm, "stop_all", lambda: calls.append("stop") or {"landing": True})
    assert dl.run_action("stop") == 0
    assert calls == ["stop"]


def test_run_action_start(monkeypatch):
    called = []
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.core.service_manager as sm
    import vnc_remote_secure.security.profiles as prof

    monkeypatch.setattr(lc, "startup", lambda: called.append("startup"))
    monkeypatch.setattr(prof, "get_blocking_findings", lambda: [])
    monkeypatch.setattr(sm, "start_all", lambda: called.append("start") or {"vnc": 1})
    assert dl.run_action("start") == 0
    assert "startup" in called and "start" in called


def test_run_action_start_refused_on_blockers(monkeypatch):
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.security.profiles as prof

    monkeypatch.setattr(lc, "startup", lambda: None)
    monkeypatch.setattr(
        prof, "get_blocking_findings", lambda: [{"code": "X", "message": "blocked"}]
    )
    assert dl.run_action("start") == 1


# --- Job claim semantics -----------------------------------------------------


def _jobs(monkeypatch, record=None, claim=True):
    import vnc_remote_secure.security.jobs as jobs

    monkeypatch.setattr(jobs, "job_get", lambda j: record)
    monkeypatch.setattr(jobs, "job_claim", lambda j, w="": claim)
    finished = []
    monkeypatch.setattr(jobs, "job_finish", lambda j, d="": finished.append(("ok", j, d)))
    monkeypatch.setattr(jobs, "job_fail", lambda j, e="": finished.append(("fail", j, e)))
    monkeypatch.setattr(jobs, "job_progress", lambda *a, **k: None)
    monkeypatch.setattr(jobs, "job_unlock", lambda *a: None)
    return finished


def test_run_job_unknown_returns_2(monkeypatch):
    _jobs(monkeypatch, record=None)
    assert dl.run_job("nope") == 2


def test_run_job_double_claim_does_not_rerun(monkeypatch):
    """A retried spawn must NEVER re-execute the payload."""
    ran = []
    finished = _jobs(
        monkeypatch,
        record={"id": "j1", "actor": "op", "payload": {"op": "lifecycle.action", "action": "stop"}},
        claim=False,
    )
    monkeypatch.setattr(dl, "run_action", lambda a: ran.append(a) or 0)
    assert dl.run_job("j1") == 2
    assert ran == [] and finished == []


def test_run_job_executes_and_finishes(monkeypatch):
    finished = _jobs(
        monkeypatch,
        record={"id": "j1", "actor": "op", "payload": {"op": "lifecycle.action", "action": "stop"}},
    )
    monkeypatch.setattr(dl, "run_action", lambda a: 0)
    assert dl.run_job("j1") == 0
    assert finished[0][0] == "ok"


def test_run_job_failure_marks_failed(monkeypatch):
    finished = _jobs(
        monkeypatch,
        record={"id": "j1", "actor": "op", "payload": {"op": "lifecycle.action", "action": "stop"}},
    )
    monkeypatch.setattr(dl, "run_action", lambda a: 1)
    assert dl.run_job("j1") == 1
    assert finished[0][0] == "fail"


def test_run_job_unknown_op(monkeypatch):
    finished = _jobs(
        monkeypatch, record={"id": "j1", "actor": "op", "payload": {"op": "does.not.exist"}}
    )
    assert dl.run_job("j1") == 2
    assert finished and finished[0][0] == "fail"


def test_run_job_executor_exception_releases_lock(monkeypatch):
    unlocked = []
    import vnc_remote_secure.security.jobs as jobs

    _jobs(
        monkeypatch,
        record={"id": "j1", "actor": "op", "payload": {"op": "lifecycle.action", "action": "stop"}},
    )
    monkeypatch.setattr(jobs, "job_unlock", lambda n, j: unlocked.append((n, j)))
    monkeypatch.setattr(dl, "run_action", lambda a: (_ for _ in ()).throw(RuntimeError("boom")))
    assert dl.run_job("j1") == 1
    assert ("destructive", "j1") in unlocked


# --- Executor bodies ---------------------------------------------------------


def test_run_action_restart(monkeypatch):
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.core.service_manager as sm
    import vnc_remote_secure.security.profiles as prof

    calls = []
    monkeypatch.setattr(lc, "startup", lambda: calls.append("startup"))
    monkeypatch.setattr(prof, "get_blocking_findings", lambda: [])
    monkeypatch.setattr(sm, "restart_all", lambda: calls.append("restart") or {"vnc": True})
    assert dl.run_action("restart") == 0
    assert calls == ["startup", "restart"]


def test_run_action_restart_partial_failure(monkeypatch):
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.core.service_manager as sm
    import vnc_remote_secure.security.profiles as prof

    monkeypatch.setattr(lc, "startup", lambda: None)
    monkeypatch.setattr(prof, "get_blocking_findings", lambda: [])
    monkeypatch.setattr(sm, "restart_all", lambda: {"vnc": True, "landing": False})
    assert dl.run_action("restart") == 1


def test_run_action_restart_refused_on_blockers(monkeypatch):
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.security.profiles as prof

    monkeypatch.setattr(lc, "startup", lambda: None)
    monkeypatch.setattr(
        prof, "get_blocking_findings", lambda: [{"code": "X", "message": "blocked"}]
    )
    assert dl.run_action("restart") == 1


def test_run_action_unknown_returns_2():
    assert dl.run_action("selfdestruct") == 2


def test_exec_restore_empty_path():
    ok, detail = dl._exec_restore({}, lambda *a, **k: None)
    assert ok is False and detail == "empty backup path"


def test_exec_restore_success(monkeypatch):
    import vnc_remote_secure.core.backup as backup

    calls = []
    monkeypatch.setattr(backup, "restore_backup", lambda p: calls.append(p) or True)
    progress = []
    ok, detail = dl._exec_restore(
        {"path": "/tmp/b.tar.zst"}, lambda ph, d="", pct=None: progress.append((ph, pct))
    )
    assert ok is True and "b.tar.zst" in detail
    assert calls == ["/tmp/b.tar.zst"]
    assert progress and progress[-1][1] == 90


def test_exec_restore_failure(monkeypatch):
    import vnc_remote_secure.core.backup as backup

    monkeypatch.setattr(backup, "restore_backup", lambda p: False)
    ok, detail = dl._exec_restore({"path": "/tmp/b.tar.zst"}, lambda *a, **k: None)
    assert ok is False and detail == "restore failed"


def test_exec_upgrade_success(monkeypatch):
    import vnc_remote_secure.core.upgrader as up

    monkeypatch.setattr(
        up, "perform_upgrade", lambda src: {"ok": True, "previous": "1.0", "version": "2.0"}
    )
    ok, detail = dl._exec_upgrade({}, lambda *a, **k: None)
    assert ok is True and detail == "1.0 → 2.0"


def test_exec_upgrade_failure_reports_error(monkeypatch):
    import vnc_remote_secure.core.upgrader as up

    monkeypatch.setattr(up, "perform_upgrade", lambda src: {"ok": False, "error": "net down"})
    ok, detail = dl._exec_upgrade({}, lambda *a, **k: None)
    assert ok is False and detail == "net down"


def test_exec_rollback_success(monkeypatch):
    import vnc_remote_secure.core.upgrader as up

    monkeypatch.setattr(up, "perform_rollback", lambda: {"ok": True, "restored": "1.0"})
    ok, detail = dl._exec_rollback({}, lambda *a, **k: None)
    assert ok is True and detail == "restored=1.0"


def test_exec_rollback_failure(monkeypatch):
    import vnc_remote_secure.core.upgrader as up

    monkeypatch.setattr(up, "perform_rollback", lambda: {"ok": False, "error": "no snapshot"})
    ok, detail = dl._exec_rollback({}, lambda *a, **k: None)
    assert ok is False and detail == "no snapshot"


def test_main_empty_argv_shows_usage(monkeypatch):
    """argv=None must fall back to sys.argv — with no args the usage
    path (not a crash) must run."""
    monkeypatch.setattr(sys, "argv", ["prog"])
    assert dl.main([]) == 2


def test_main_bad_delay_defaults(monkeypatch):
    slept = []
    ran = []
    monkeypatch.setattr(dl.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(dl, "run_job", lambda j: ran.append(j) or 0)
    assert dl.main(["run", "j1", "not-a-number"]) == 0
    assert slept == [dl._DEFAULT_DELAY]
    assert ran == ["j1"]
