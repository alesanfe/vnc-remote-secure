"""Windows VNC server AppContainer sandboxing (``VNC_WINDOWS_SANDBOX``).

``start_vnc_server`` spawns winvnc.exe inside a dedicated
``VncRemoteSecure.VncServer`` AppContainer carrying the network
capabilities needed to bind the RFB port and accept clients. Mode
resolution follows the terminal policy: ``auto`` (default) falls back
to an unsandboxed Popen with a loud warning, ``strict`` propagates,
``off`` skips the sandbox entirely, and hardened profiles promote
``auto`` to ``strict``.

Everything that would touch the real OS — icacls grants, SID
derivation, CreateProcessW — is mocked. No host state is modified.
"""

import ctypes
import logging
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="sandbox.py imports msvcrt/wintypes — Windows only"
)


@pytest.fixture
def sandbox():
    """The real sandbox module with all mutable caches isolated."""
    from vnc_remote_secure.platform.windows import sandbox as sb

    saved = (dict(sb._appcontainer_sids), dict(sb._capability_sid_cache), set(sb._granted_dirs))
    yield sb
    for cache, keep in zip(
        (sb._appcontainer_sids, sb._capability_sid_cache, sb._granted_dirs), saved
    ):
        cache.clear()
        cache.update(keep)


@pytest.fixture
def winvnc(tmp_path):
    exe = tmp_path / "UltraVNC" / "winvnc.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"fake")
    return str(exe)


@pytest.fixture
def adapter_calls(monkeypatch, winvnc):
    """Intercept everything start_vnc_server delegates to."""
    import subprocess

    calls = {"popen": [], "spawn": []}
    monkeypatch.setattr(
        "vnc_remote_secure.platform.windows.installer._find_ultravnc",
        lambda: winvnc,
    )
    monkeypatch.setattr(
        "vnc_remote_secure.platform.windows.adapter.WindowsAdapter._write_ultravnc_ini",
        staticmethod(lambda exe, password: None),
    )
    monkeypatch.setattr(
        "vnc_remote_secure.security.redaction.sanitized_child_env",
        lambda: {"PATH": os.environ.get("PATH", "")},
        raising=False,
    )
    monkeypatch.setattr(
        "vnc_remote_secure.security.profiles.resolve_profile",
        lambda: "development",
        raising=False,
    )

    class _FakePopen:
        def __init__(self, args, env=None, **kw):
            self.args = args
            self.env = env
            self.pid = 4242
            calls["popen"].append({"args": args, "env": env, "kw": kw})

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    return calls


def _patch_spawn(monkeypatch, calls, result=None, error=None):
    def _spawn(args, cwd=None, env=None, **kw):
        calls["spawn"].append({"args": args, "cwd": cwd, "env": env, "kw": kw})
        if error is not None:
            raise error
        return result

    monkeypatch.setattr("vnc_remote_secure.platform.windows.sandbox.spawn_sandboxed", _spawn)


def _adapter():
    from vnc_remote_secure.platform.windows.adapter import WindowsAdapter

    return WindowsAdapter()


class TestVncSandboxSpawnPolicy:
    def test_off_goes_straight_to_popen(self, adapter_calls, monkeypatch):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "off")
        _patch_spawn(monkeypatch, adapter_calls, error=AssertionError("must not spawn"))

        proc = _adapter().start_vnc_server("", "1280x720", 24, "secret1")

        assert adapter_calls["spawn"] == []
        assert len(adapter_calls["popen"]) == 1
        assert proc.pid == 4242

    def test_auto_falls_back_with_warning(self, adapter_calls, monkeypatch, caplog):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "auto")
        _patch_spawn(monkeypatch, adapter_calls, error=OSError("no AppContainer APIs"))
        # setup_logging() sets propagate=False on the package logger —
        # caplog's root handler sees nothing unless propagation is on.
        monkeypatch.setattr(
            logging.getLogger("vnc_remote_secure"), "propagate", True, raising=False
        )

        with caplog.at_level(logging.WARNING, logger="vnc_remote_secure.platform.windows.adapter"):
            proc = _adapter().start_vnc_server("", "1280x720", 24, "secret1")

        assert len(adapter_calls["spawn"]) == 1
        assert len(adapter_calls["popen"]) == 1
        assert proc.pid == 4242
        assert any("unsandboxed" in r.getMessage() for r in caplog.records)

    def test_strict_propagates_spawn_failure(self, adapter_calls, monkeypatch):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "strict")
        _patch_spawn(monkeypatch, adapter_calls, error=OSError("no AppContainer APIs"))

        with pytest.raises(OSError, match="no AppContainer APIs"):
            _adapter().start_vnc_server("", "1280x720", 24, "secret1")
        assert adapter_calls["popen"] == []

    def test_hardened_profile_promotes_auto_to_strict(self, adapter_calls, monkeypatch):
        """Under public-hardened an unsandboxed winvnc could read the
        service account's secrets — auto must behave as strict."""
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "auto")
        monkeypatch.setattr(
            "vnc_remote_secure.security.profiles.resolve_profile",
            lambda: "public-hardened",
            raising=False,
        )
        _patch_spawn(monkeypatch, adapter_calls, error=OSError("no AppContainer APIs"))

        with pytest.raises(OSError):
            _adapter().start_vnc_server("", "1280x720", 24, "secret1")
        assert adapter_calls["popen"] == []

    def test_auto_spawn_uses_dedicated_vnc_container(self, adapter_calls, monkeypatch, winvnc):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "auto")
        sentinel = SimpleNamespace(pid=7777)
        _patch_spawn(monkeypatch, adapter_calls, result=sentinel)

        proc = _adapter().start_vnc_server("", "1280x720", 24, "secret1")

        assert proc is sentinel
        assert adapter_calls["popen"] == []
        kw = adapter_calls["spawn"][0]["kw"]
        assert kw["app_container_name"] == "VncRemoteSecure.VncServer"
        # RFB listener needs inbound+outbound network capabilities.
        assert "privateNetworkClientServer" in kw["capabilities"]
        assert "internetClientServer" in kw["capabilities"]
        # winvnc reads ultravnc.ini and writes its log next to the exe.
        exe_dir = os.path.dirname(os.path.realpath(winvnc))
        assert kw["grant_dirs"] == ((exe_dir, True),)
        # GUI child in the interactive session; PID-only lifetime
        # tracking (no KILL_ON_JOB_CLOSE handle to GC away).
        assert kw["hidden_window"] is False
        assert kw["job"] is False
        assert kw["capture_output"] is False


class TestVncSandboxModeEnvVar:
    def test_reads_vnc_env_var(self, sandbox, monkeypatch):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "strict")
        assert sandbox.sandbox_mode("VNC_WINDOWS_SANDBOX") == "strict"

    def test_unset_defaults_to_auto(self, sandbox, monkeypatch):
        monkeypatch.delenv("VNC_WINDOWS_SANDBOX", raising=False)
        monkeypatch.setattr(
            "vnc_remote_secure.security.profiles.resolve_profile",
            lambda: "development",
            raising=False,
        )
        assert sandbox.sandbox_mode("VNC_WINDOWS_SANDBOX") == "auto"

    def test_invalid_value_defaults_to_auto(self, sandbox, monkeypatch):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "bogus")
        monkeypatch.setattr(
            "vnc_remote_secure.security.profiles.resolve_profile",
            lambda: "development",
            raising=False,
        )
        assert sandbox.sandbox_mode("VNC_WINDOWS_SANDBOX") == "auto"

    def test_vnc_var_does_not_affect_terminal(self, sandbox, monkeypatch):
        monkeypatch.setenv("VNC_WINDOWS_SANDBOX", "off")
        monkeypatch.setenv("TERMINAL_WINDOWS_SANDBOX", "auto")
        monkeypatch.setattr(
            "vnc_remote_secure.security.profiles.resolve_profile",
            lambda: "development",
            raising=False,
        )
        assert sandbox.sandbox_mode() == "auto"


class TestCapabilitySids:
    def test_well_known_names_use_documented_sid_literals(self, sandbox, monkeypatch):
        seen = {}

        def _fake_conv(sid_str):
            seen[sid_str] = ctypes.c_void_p(0x1000 + len(seen))
            return seen[sid_str]

        monkeypatch.setattr(sandbox, "_sid_from_string", _fake_conv)
        psids = sandbox._capability_sids(
            ["internetClientServer", "privateNetworkClientServer", "internetClient"]
        )
        assert list(seen) == ["S-1-15-3-2", "S-1-15-3-3", "S-1-15-3-1"]
        assert psids == [seen["S-1-15-3-2"], seen["S-1-15-3-3"], seen["S-1-15-3-1"]]

    def test_unknown_capability_derives_via_userenv(self, sandbox, monkeypatch):
        derived = []
        monkeypatch.setattr(
            sandbox,
            "_derive_capability_sids",
            lambda name: derived.append(name) or [ctypes.c_void_p(0x2222)],
        )
        psids = sandbox._capability_sids(["enterpriseAuthentication"])
        assert derived == ["enterpriseAuthentication"]
        assert [p.value for p in psids] == [0x2222]

    def test_capability_cache_avoids_repeat_resolution(self, sandbox, monkeypatch):
        calls = []
        monkeypatch.setattr(
            sandbox,
            "_sid_from_string",
            lambda sid_str: calls.append(sid_str) or ctypes.c_void_p(0x9999),
        )
        sandbox._capability_sids(["internetClientServer"])
        sandbox._capability_sids(["internetClientServer"])
        assert calls == ["S-1-15-3-2"]


def _fake_kernel32(rec):
    """Minimal kernel32 stand-in recording every call — no real API."""

    def _set_size(size_p, value):
        ctypes.cast(size_p, ctypes.POINTER(ctypes.c_size_t)).contents.value = value

    def _init_attr_list(buf, count, flags, size_p):
        if not buf:
            _set_size(size_p, 256)
            return 0
        return 1

    def _update_attr(buf, flags, attr, value_p, size, prev, ret):
        rec["updates"].append((attr, value_p._obj))
        return 1

    def _create_process(app, cmd, psec, tsec, inherit, flags, env, cwd, si_p, pi_p):
        rec["create"].append({"cmd": cmd, "flags": flags, "cwd": cwd})
        pi = pi_p._obj
        pi.dwProcessId = 4321
        pi.hProcess = 0x1111
        pi.hThread = 0x2222
        return 1

    def _create_job(attr, name):
        rec["job_created"] = True
        return 0x3333

    return SimpleNamespace(
        InitializeProcThreadAttributeList=_init_attr_list,
        UpdateProcThreadAttribute=_update_attr,
        DeleteProcThreadAttributeList=lambda buf: rec["deletes"].append(buf),
        CreateProcessW=_create_process,
        CreateJobObjectW=_create_job,
        SetInformationJobObject=lambda h, cls, info, size: 1,
        AssignProcessToJobObject=lambda job, proc: rec.setdefault("assigned", True),
        WaitForSingleObject=lambda h, ms: 0,
        GetExitCodeProcess=lambda h, code_p: 1,
        TerminateProcess=lambda h, code: 1,
        TerminateJobObject=lambda h, code: 1,
        CloseHandle=lambda h: rec["closed"].append(h) or 1,
    )


def _patch_os_layer(sandbox, monkeypatch, rec, tmp_path, cap_psids=None):
    monkeypatch.setattr(sandbox, "_proto", lambda: _fake_kernel32(rec))
    monkeypatch.setattr(
        sandbox,
        "_get_sid",
        lambda name=sandbox._APP_CONTAINER_NAME: (
            ctypes.c_void_p(0xDEAD),
            "S-1-15-2-0000",
        ),
    )
    monkeypatch.setattr(sandbox, "_scratch_dir", lambda name="x": str(tmp_path))
    monkeypatch.setattr(
        sandbox,
        "_grant_dir",
        lambda path, write=False, sid_str=None: rec["grants"].append((path, write, sid_str)),
    )
    monkeypatch.setattr(
        sandbox,
        "_capability_sids",
        lambda names: cap_psids if cap_psids is not None else [],
    )


class TestSpawnSandboxedAttributes:
    def _record(self):
        return {
            "updates": [],
            "create": [],
            "deletes": [],
            "closed": [],
            "grants": [],
        }

    def _caps(self, sandbox, rec):
        """Extract the SECURITY_CAPABILITIES struct seen by the mock."""
        attr, value = rec["updates"][0]
        assert attr == sandbox._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
        return value

    def test_capabilities_reach_attribute_list(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        psids = [ctypes.c_void_p(0xBEEF), ctypes.c_void_p(0xCAFE)]
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path, cap_psids=psids)

        proc = sandbox.spawn_sandboxed(
            ["winvnc.exe"],
            app_container_name="VncRemoteSecure.VncServer",
            capabilities=("internetClientServer", "privateNetworkClientServer"),
            capture_output=False,
            job=False,
        )

        caps = self._caps(sandbox, rec)
        assert caps.AppContainerSid == 0xDEAD
        assert caps.CapabilityCount == 2
        arr = ctypes.cast(
            caps.Capabilities,
            ctypes.POINTER(sandbox._SID_AND_ATTRIBUTES * 2),
        ).contents
        assert [arr[i].Sid for i in range(2)] == [0xBEEF, 0xCAFE]
        assert all(arr[i].Attributes == 0 for i in range(2))
        assert proc.pid == 4321

    def test_default_spawn_has_no_capabilities(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path)

        proc = sandbox.spawn_sandboxed(["cmd.exe"], capture_output=False, job=False)

        caps = self._caps(sandbox, rec)
        assert caps.CapabilityCount == 0
        assert proc.stdout is None  # capture_output=False → NUL stdio

    def test_hidden_window_controls_create_no_window(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path)
        sandbox.spawn_sandboxed(["a.exe"], hidden_window=False, capture_output=False)
        gui_flags = rec["create"][0]["flags"]
        assert not (gui_flags & sandbox._CREATE_NO_WINDOW)
        assert gui_flags & sandbox._CREATE_UNICODE_ENVIRONMENT

        sandbox.spawn_sandboxed(["b.exe"], capture_output=False)
        assert rec["create"][1]["flags"] & sandbox._CREATE_NO_WINDOW

    def test_job_false_skips_job_object(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path)
        proc = sandbox.spawn_sandboxed(["a.exe"], job=False, capture_output=False)
        assert "job_created" not in rec
        assert proc._h_job is None

    def test_job_true_wraps_in_kill_on_close_job(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path)
        proc = sandbox.spawn_sandboxed(["a.exe"], job=True, capture_output=False)
        assert rec.get("job_created")
        assert rec.get("assigned")
        assert proc._h_job == 0x3333

    def test_grant_dirs_scoped_to_container_sid(self, sandbox, monkeypatch, tmp_path):
        rec = self._record()
        _patch_os_layer(sandbox, monkeypatch, rec, tmp_path)
        sandbox.spawn_sandboxed(
            ["winvnc.exe"],
            app_container_name="VncRemoteSecure.VncServer",
            grant_dirs=((r"C:\\UltraVNC", True), (r"C:\\share", False)),
            capture_output=False,
            job=False,
        )
        assert rec["grants"] == [
            (r"C:\\UltraVNC", True, "S-1-15-2-0000"),
            (r"C:\\share", False, "S-1-15-2-0000"),
        ]
