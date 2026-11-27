"""Linux adapter VNC spawn contract — stdio detachment + session.

Regression coverage for the stdio-inheritance bug: the spawned
``tigervncserver -fg`` used to inherit the caller's stdout/stderr and
stay in its process group — ``vnc-remote start | <filter>` hung
until the server exited and SIGHUP could reach the daemon. The spawn
must now match _start_python_service's contract: own session,
stdin/stdout/stderr routed away, sanitized env.
"""

import subprocess

from vnc_remote_secure.platform.linux.adapter import LinuxAdapter


def _capture(monkeypatch, tmp_path):
    captured = {}
    log_dir = tmp_path / "logs"

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            self.pid = 4242

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tigervncserver")
    monkeypatch.setattr("vnc_remote_secure.core.paths.get_log_dir", lambda: str(log_dir))
    monkeypatch.setattr(
        "vnc_remote_secure.security.redaction.sanitized_child_env",
        lambda: {"PATH": "/usr/bin"},
    )
    monkeypatch.setattr(
        "vnc_remote_secure.vendor.d3des.encrypt_vnc_password", lambda pw: b"\x00" * 8
    )
    monkeypatch.setenv("VRS_RUN_DIR", str(tmp_path / "run"))
    return captured


def test_spawn_detaches_stdio_and_session(monkeypatch, tmp_path):
    captured = _capture(monkeypatch, tmp_path)
    LinuxAdapter().start_vnc_server(":2", "1280x720", 24, "secret")
    kw = captured["kwargs"]
    assert kw["stdin"] is subprocess.DEVNULL
    assert kw["stderr"] is subprocess.STDOUT
    assert kw["start_new_session"] is True
    # stdout routed to the service log file, never inherited.
    out = kw["stdout"]
    assert out is not subprocess.DEVNULL
    assert out.name.endswith("vnc.log")
    assert "logs" in out.name


def test_log_file_created_and_closed(monkeypatch, tmp_path):
    _capture(monkeypatch, tmp_path)
    LinuxAdapter().start_vnc_server(":2", "1280x720", 24, "secret")
    log = tmp_path / "logs" / "vnc.log"
    assert log.exists()
    # Parent copy must be closed after Popen dup'd it into the child.
    import os

    before = len(os.listdir("/proc/self/fd"))
    LinuxAdapter().start_vnc_server(":2", "1280x720", 24, "secret")
    after = len(os.listdir("/proc/self/fd"))
    assert after == before


def test_cmdline_and_sanitized_env(monkeypatch, tmp_path):
    captured = _capture(monkeypatch, tmp_path)
    LinuxAdapter().start_vnc_server(":2", "1280x720", 24, "secret")
    cmd = captured["cmd"]
    assert cmd[:4] == ["/usr/bin/tigervncserver", ":2", "-geometry", "1280x720"]
    assert "-fg" in cmd  # foreground so the tracked PID owns the server
    assert "-PasswordFile" in cmd
    assert captured["kwargs"]["env"] == {"PATH": "/usr/bin"}
