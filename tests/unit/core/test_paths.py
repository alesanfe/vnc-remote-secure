"""Tests for core.paths — platform-aware directory resolution."""

import sys

import pytest

from vnc_remote_secure.core import paths

# The autouse _isolate_run_dir conftest fixture replaces the get_*_dir
# module attributes with lambdas during EVERY test — the real
# implementations would otherwise never execute in this suite (their
# root/XDG/override branches show 0% coverage). Capture them at import
# time, before any fixture runs, so the tests below exercise the real
# code paths while still patching is_windows/_is_root/os.environ.
_ORIG_DIRS = {
    name: getattr(paths, name)
    for name in (
        "get_config_dir",
        "get_data_dir",
        "get_log_dir",
        "get_run_dir",
        "get_ssl_dir",
    )
}


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    return


class TestIsMsixPackaged:
    def test_non_windows_is_false(self, monkeypatch):
        monkeypatch.setattr(paths.os, "name", "posix")
        assert paths._is_msix_packaged() is False

    def test_windowsapps_executable_detected(self, monkeypatch):
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(
            sys,
            "executable",
            r"C:\Program Files\WindowsApps\PythonSoftwareFoundation."
            r"Python.3.11_3.11.0.0_x64__qbz5n2kfra8p0\python.exe",
        )
        assert paths._is_msix_packaged() is True

    def test_venv_executable_not_packaged(self, monkeypatch):
        # A venv created from Store Python runs an un-packaged
        # interpreter — detection must use sys.executable, not
        # sys.base_prefix.
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(sys, "executable", r"C:\proj\.venv\Scripts\python.exe")
        assert paths._is_msix_packaged() is False


class TestWinBase:
    def test_elevated_uses_programdata(self, monkeypatch):
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(paths, "_is_elevated_windows", lambda: True)
        monkeypatch.setenv("ProgramData", r"C:\ProgramData")
        assert paths._win_base() == r"C:\ProgramData"

    def test_non_elevated_uses_localappdata(self, monkeypatch):
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(paths, "_is_elevated_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_msix_packaged", lambda: False)
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\u\AppData\Local")
        assert paths._win_base() == r"C:\Users\u\AppData\Local"

    def test_msix_uses_locallow(self, monkeypatch, tmp_path):
        """Store Python must not use virtualized LOCALAPPDATA."""
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(paths, "_is_elevated_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_msix_packaged", lambda: True)
        appdata = tmp_path / "AppData"
        local = appdata / "Local"
        locallow = appdata / "LocalLow"
        local.mkdir(parents=True)
        locallow.mkdir()
        monkeypatch.setenv("LOCALAPPDATA", str(local))
        assert paths._win_base() == str(locallow)

    def test_msix_falls_back_when_locallow_missing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(paths.os, "name", "nt")
        monkeypatch.setattr(paths, "_is_elevated_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_msix_packaged", lambda: True)
        local = tmp_path / "AppData" / "Local"
        local.mkdir(parents=True)
        monkeypatch.setenv("LOCALAPPDATA", str(local))
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

        for name in ("config", "data", "log", "run", "ssl"):
            d = tmp_path / name
            d.mkdir(exist_ok=True)
            monkeypatch.setattr(paths, f"get_{name}_dir", lambda d=d: str(d))
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        fake_os = types.SimpleNamespace(
            name="posix",
            environ=_os.environ,
            lstat=lambda p: types.SimpleNamespace(st_uid=owner_uid),
            geteuid=lambda: uid,
            makedirs=_os.makedirs,
            chmod=_os.chmod,
            path=_os.path,
        )
        monkeypatch.setattr(paths, "os", fake_os)
        return paths

    def test_foreign_owned_run_dir_refused(self, tmp_path, monkeypatch):
        paths = self._posix_env(monkeypatch, tmp_path, uid=1000, owner_uid=9999)
        with pytest.raises(RuntimeError, match="owned by uid"):
            paths.ensure_dirs()

    def test_own_run_dir_accepted(self, tmp_path, monkeypatch):
        paths = self._posix_env(monkeypatch, tmp_path, uid=1000, owner_uid=1000)
        paths.ensure_dirs()  # must not raise

    def test_run_dir_that_is_a_file_refused(self, tmp_path, monkeypatch):
        """A non-directory squat (plain file at the run-dir path) is
        refused even when owned by us — os.makedirs(exist_ok=True)
        would already have failed, but the guard must still see it."""
        import os as _os
        import types

        from vnc_remote_secure.core import paths

        for name in ("config", "data", "log", "ssl"):
            d = tmp_path / name
            d.mkdir(exist_ok=True)
            monkeypatch.setattr(paths, f"get_{name}_dir", lambda d=d: str(d))
        run_file = tmp_path / "run-squat"
        run_file.write_text("squat")
        monkeypatch.setattr(paths, "get_run_dir", lambda: str(run_file))
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        fake_os = types.SimpleNamespace(
            name="posix",
            environ=_os.environ,
            lstat=lambda p: types.SimpleNamespace(st_uid=_os.geteuid()),
            geteuid=_os.geteuid,
            makedirs=_os.makedirs,
            chmod=_os.chmod,
            path=_os.path,
        )
        monkeypatch.setattr(paths, "os", fake_os)
        # makedirs(exist_ok=True) on an existing file raises
        # FileExistsError before the guard — acceptable: it still
        # refuses rather than running on squatted state.
        with pytest.raises((RuntimeError, FileExistsError)):
            paths.ensure_dirs()


class TestFindProjectRoot:
    def test_marker_file_found(self, tmp_path, monkeypatch):
        root = tmp_path / "proj"
        (root / ".env.example").parent.mkdir(parents=True, exist_ok=True)
        (root / ".env.example").write_text("#")
        deep = root / "a" / "b" / "c"
        deep.mkdir(parents=True)
        monkeypatch.setattr(paths, "__file__", str(deep / "x.py"))
        assert paths.find_project_root() == str(root)

    def test_fallback_to_package_grandparent(self, tmp_path, monkeypatch):
        """With no marker anywhere upward the fallback is three levels
        above the module file (package grandparent)."""
        deep = tmp_path / "pkg" / "a" / "b"
        deep.mkdir(parents=True)
        monkeypatch.setattr(paths, "__file__", str(deep / "x.py"))
        assert paths.find_project_root() == str(deep.parent.parent)


class TestDirResolution:
    """Exercise the REAL get_*_dir implementations captured in
    _ORIG_DIRS — the conftest isolation fixture replaces them on the
    module, so these call the originals directly."""

    def test_config_dir_root(self, monkeypatch):
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: True)
        assert _ORIG_DIRS["get_config_dir"]() == "/etc/vnc-remote-secure"

    def test_data_dir_root(self, monkeypatch):
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: True)
        assert _ORIG_DIRS["get_data_dir"]() == "/var/lib/vnc-remote-secure"

    def test_log_dir_override_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
        assert _ORIG_DIRS["get_log_dir"]() == str(tmp_path / "logs")

    def test_log_dir_root(self, monkeypatch):
        monkeypatch.delenv("LOG_DIR", raising=False)
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: True)
        assert _ORIG_DIRS["get_log_dir"]() == "/var/log/vnc-remote-secure"

    def test_log_dir_xdg_state(self, monkeypatch, tmp_path):
        monkeypatch.delenv("LOG_DIR", raising=False)
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
        assert _ORIG_DIRS["get_log_dir"]() == str(tmp_path / "state" / "vnc-remote-secure")

    def test_run_dir_override_wins_over_root(self, monkeypatch, tmp_path):
        """VRS_RUN_DIR beats even the root/system paths — portable
        deployments and tests pin an explicit location."""
        monkeypatch.setattr(paths, "_is_root", lambda: True)
        monkeypatch.setenv("VRS_RUN_DIR", str(tmp_path / "run"))
        assert _ORIG_DIRS["get_run_dir"]() == str(tmp_path / "run")

    def test_run_dir_root(self, monkeypatch):
        monkeypatch.delenv("VRS_RUN_DIR", raising=False)
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: True)
        assert _ORIG_DIRS["get_run_dir"]() == "/run/vnc-remote-secure"

    def test_run_dir_xdg_runtime(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VRS_RUN_DIR", raising=False)
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: False)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "xdg"))
        assert _ORIG_DIRS["get_run_dir"]() == str(tmp_path / "xdg" / "vnc-remote-secure")

    def test_run_dir_tmp_fallback(self, monkeypatch):
        monkeypatch.delenv("VRS_RUN_DIR", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "_is_root", lambda: False)
        assert _ORIG_DIRS["get_run_dir"]() == "/tmp/vnc-remote-secure"

    def test_ssl_dir_under_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(paths, "is_windows", lambda: False)
        monkeypatch.setattr(paths, "get_data_dir", lambda: str(tmp_path / "data"))
        assert _ORIG_DIRS["get_ssl_dir"]() == str(tmp_path / "data" / "ssl")


class TestIsRoot:
    def test_geteuid_zero(self, monkeypatch):
        monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
        assert paths._is_root() is True

    def test_geteuid_nonzero(self, monkeypatch):
        monkeypatch.setattr(paths.os, "geteuid", lambda: 1000)
        assert paths._is_root() is False

    def test_no_geteuid_degrades_to_false(self, monkeypatch):
        monkeypatch.delattr(paths.os, "geteuid")
        assert paths._is_root() is False


class TestIsElevatedWindows:
    def test_non_windows_is_false(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        assert paths._is_elevated_windows() is False

    def test_windows_admin_probe(self, monkeypatch):
        import ctypes
        import types

        monkeypatch.setattr(sys, "platform", "win32")
        fake = types.SimpleNamespace(shell32=types.SimpleNamespace(IsUserAnAdmin=lambda: 1))
        monkeypatch.setattr(ctypes, "windll", fake, raising=False)
        assert paths._is_elevated_windows() is True

    def test_windows_probe_failure_is_false(self, monkeypatch):
        import ctypes

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delattr(ctypes, "windll", raising=False)
        assert paths._is_elevated_windows() is False


class TestXdgPath:
    def test_env_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_TEST_HOME", str(tmp_path))
        assert paths._xdg_path("XDG_TEST_HOME", ".fallback") == str(tmp_path / "vnc-remote-secure")

    def test_env_unset_uses_home_default(self, monkeypatch, tmp_path):
        monkeypatch.delenv("XDG_TEST_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert paths._xdg_path("XDG_TEST_HOME", ".fallback") == str(
            tmp_path / ".fallback" / "vnc-remote-secure"
        )


class TestRestrictDirPosix:
    def test_chmod_700(self, tmp_path, monkeypatch):
        calls = []
        import types

        fake_os = types.SimpleNamespace(name="posix", chmod=lambda p, m: calls.append((p, m)))
        monkeypatch.setattr(paths, "os", fake_os)
        paths._restrict_dir(str(tmp_path))
        assert calls == [(str(tmp_path), 0o700)]

    def test_chmod_failure_suppressed(self, tmp_path, monkeypatch):
        import types

        def _boom(p, m):
            raise OSError("perm denied")

        fake_os = types.SimpleNamespace(name="posix", chmod=_boom)
        monkeypatch.setattr(paths, "os", fake_os)
        paths._restrict_dir(str(tmp_path))  # must not raise


class TestRepairStateFileAcls:
    def _stub_run(self, monkeypatch, tmp_path):
        monkeypatch.setattr(paths, "get_run_dir", lambda: str(tmp_path))
        calls = []

        def _run_cmd(cmd, **kw):
            calls.append(cmd)

        monkeypatch.setattr("vnc_remote_secure.core.processes.run_cmd", _run_cmd, raising=False)
        return calls

    def test_durable_files_repaired_transients_skipped(self, tmp_path, monkeypatch):
        (tmp_path / "shared_state.db").write_text("x")
        (tmp_path / "ephemeral.json").write_text("x")
        (tmp_path / "wip.tmp").write_text("x")
        (tmp_path / "svc.lock").write_text("x")
        (tmp_path / "subdir").mkdir()
        calls = self._stub_run(monkeypatch, tmp_path)
        monkeypatch.setenv("USERNAME", "alice")
        paths._repair_state_file_acls()
        # two icacls invocations per durable file, none for .tmp/.lock/dirs
        assert len(calls) == 4
        touched = {c[1] for c in calls}
        assert touched == {
            str(tmp_path / "shared_state.db"),
            str(tmp_path / "ephemeral.json"),
        }
        grant_call = [c for c in calls if "/grant:r" in c]
        for c in grant_call:
            assert "alice:(M)" in c
            assert "*S-1-5-18:(M)" in c

    def test_listdir_failure_returns(self, tmp_path, monkeypatch):
        self._stub_run(monkeypatch, tmp_path / "nonexistent")
        paths._repair_state_file_acls()  # no run dir → silent return
