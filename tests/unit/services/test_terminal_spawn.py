"""Sandbox spawn contract: bwrap nproc placement and preexec bounds.

Regression coverage for the RLIMIT_NPROC/bwrap bug — a preexec nproc
cap on the bwrap supervisor kills unshare(CLONE_NEWUSER) on hosts
whose service uid already exceeds the cap, so the bound must live
inside the namespace via ``prlimit`` instead.
"""

import os

import pytest

from vnc_remote_secure.services import terminal_spawn as ts

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX-only paths")


class TestChildRlimits:
    def _applied(self, monkeypatch, apply_nproc):
        """Return the (resource, cap) pairs the preexec fn sets."""
        import resource

        applied = []
        monkeypatch.setattr(resource, "setrlimit", lambda res, lim: applied.append((res, lim[0])))
        monkeypatch.setattr(resource, "getrlimit", lambda res: (0, resource.RLIM_INFINITY))
        ts._child_rlimits(apply_nproc=apply_nproc)()
        return applied

    def test_default_applies_nproc(self, monkeypatch):
        import resource

        applied = self._applied(monkeypatch, True)
        assert (resource.RLIMIT_NPROC, ts._RLIMIT_NPROC) in applied

    def test_bwrap_skips_nproc_keeps_others(self, monkeypatch):
        """apply_nproc=False: every limit except NPROC still applies."""
        import resource

        applied = self._applied(monkeypatch, False)
        resources = [r for r, _ in applied]
        assert resource.RLIMIT_NPROC not in resources
        for expected in (
            resource.RLIMIT_AS,
            resource.RLIMIT_CPU,
            resource.RLIMIT_NOFILE,
            resource.RLIMIT_FSIZE,
            resource.RLIMIT_CORE,
        ):
            assert expected in resources

    def test_hard_floor_respected(self, monkeypatch):
        """A lower inherited hard limit wins over the configured cap."""
        import resource

        monkeypatch.setattr(resource, "getrlimit", lambda res: (0, 4))
        applied = dict()
        monkeypatch.setattr(resource, "setrlimit", lambda res, lim: applied.update({res: lim}))
        ts._child_rlimits()()
        # Every applied cap honours the hard floor (4); CORE's
        # configured 0 stays 0 — caps only ever shrink.
        for res, (soft, hard) in applied.items():
            assert soft == hard <= 4
        assert applied[resource.RLIMIT_NPROC] == (4, 4)


class TestSandboxPrefix:
    def _enable(self, monkeypatch, prlimit="/usr/bin/prlimit"):
        monkeypatch.setattr(ts, "_BWRAP_USABLE", True)

        def _which(name):
            return {"bwrap": "/usr/bin/bwrap", "prlimit": prlimit}.get(name)

        monkeypatch.setattr("shutil.which", _which)
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_run_dir", lambda: "/run/x")
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_ssl_dir", lambda: "/ssl/x")
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_config_dir", lambda: "/cfg/x")
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_data_dir", lambda: "/data/x")
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_log_dir", lambda: "/log/x")

    def test_prefix_shape(self, monkeypatch):
        self._enable(monkeypatch)
        args = ts._sandbox_prefix()
        assert args[0] == "/usr/bin/bwrap"
        assert args[1:4] == ["--dev-bind", "/", "/"]
        # prlimit lands INSIDE the namespace, after "--".
        assert args[-3:] == ["/usr/bin/prlimit", f"--nproc={ts._RLIMIT_NPROC}", "--"]
        inner = args[-3]
        assert args.index(inner) > args.index("--")

    def test_sensitive_dirs_masked(self, monkeypatch):
        self._enable(monkeypatch)
        args = ts._sandbox_prefix()
        masked = {args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"}
        assert masked == {
            os.path.realpath(d) for d in ("/run/x", "/ssl/x", "/cfg/x", "/data/x", "/log/x")
        }

    def test_no_prlimit_declines_sandbox(self, monkeypatch):
        """Without prlimit the mask is declined so preexec still bounds."""
        self._enable(monkeypatch, prlimit=None)
        assert ts._sandbox_prefix() is None

    def test_no_bwrap_returns_none(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        monkeypatch.setattr(ts, "_BWRAP_USABLE", None)
        assert ts._sandbox_prefix() is None


class TestBuildSubprocessArgs:
    def test_sandbox_prefix_prepended(self, monkeypatch):
        monkeypatch.setattr(ts, "_restricted_user_prefix", lambda: None)
        monkeypatch.setattr(ts, "_sandbox_prefix", lambda: ["bwrap", "--"])
        monkeypatch.setattr("shutil.which", lambda name: "/bin/bash")
        args = ts._build_subprocess_args("echo hi", "", "/tmp")
        assert args == ["bwrap", "--", "/bin/bash", "-c", "echo hi"]

    def test_disallowed_shell_falls_back(self, monkeypatch):
        monkeypatch.setattr(ts, "_restricted_user_prefix", lambda: None)
        monkeypatch.setattr(ts, "_sandbox_prefix", lambda: None)
        monkeypatch.setattr("shutil.which", lambda name: "/bin/bash")
        args = ts._build_subprocess_args("x", "/usr/bin/python3", "/tmp")
        assert args[0] == "/bin/bash"

    def test_child_env_strips_secrets(self, monkeypatch):
        from vnc_remote_secure.security.redaction import SECRET_VARS

        monkeypatch.setenv("VNC_PASSWORD", "secret")
        monkeypatch.setenv("KEEP_ME", "ok")
        env = ts._build_child_env()
        assert "VNC_PASSWORD" in SECRET_VARS  # sanity: var is secret-class
        assert "VNC_PASSWORD" not in env
        assert env["KEEP_ME"] == "ok"
