"""Tests for core.processes — port probe and the credential-scrubbed
run_cmd wrapper."""

import socket
import subprocess
import sys

import pytest

from vnc_remote_secure.core.processes import is_port_available, run_cmd


class TestIsPortAvailable:
    def test_listening_port_reported_unavailable(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            assert is_port_available(port) is False
        finally:
            srv.close()

    def test_free_port_reported_available(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert is_port_available(port) is True

    def test_ipv6_literal_uses_inet6(self, monkeypatch):
        """A ':' host must select AF_INET6 — an AF_INET socket cannot
        reach '::1' and would falsely report the port free."""
        seen = []
        real = socket.socket

        def spy(family, *a, **kw):
            seen.append(family)
            return real(family, *a, **kw)

        monkeypatch.setattr(socket, "socket", spy)
        # Nothing on ::1 high port → available, but family must be v6.
        is_port_available(1, host="::1")
        assert seen == [socket.AF_INET6]

    def test_ipv4_uses_inet(self, monkeypatch):
        seen = []
        real = socket.socket

        def spy(family, *a, **kw):
            seen.append(family)
            return real(family, *a, **kw)

        monkeypatch.setattr(socket, "socket", spy)
        is_port_available(1, host="127.0.0.1")
        assert seen == [socket.AF_INET]


class TestRunCmdEnvScrub:
    """run_cmd must never hand SECRET_VARS to helper binaries."""

    @pytest.fixture
    def secret_env(self, monkeypatch):
        monkeypatch.setenv("VNC_PASSWORD", "leak-me-not-123")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        return monkeypatch

    def _py(self, code):
        return [sys.executable, "-c", code]

    def test_default_env_strips_secrets_keeps_path(self, secret_env):
        res = run_cmd(
            self._py(
                "import os;print(os.environ.get('VNC_PASSWORD',''));print(os.environ.get('PATH',''))"
            ),
            capture_output=True,
            text=True,
        )
        lines = res.stdout.splitlines()
        assert lines[0] == ""  # VNC_PASSWORD absent
        assert "/usr/bin" in lines[1]

    def test_explicit_env_none_is_scrubbed(self, secret_env):
        """env=None means 'inherit everything' in subprocess.run —
        run_cmd must treat it as absent, not as a scrub bypass."""
        res = run_cmd(
            self._py("import os;print('VNC_PASSWORD' in os.environ)"),
            capture_output=True,
            text=True,
            env=None,
        )
        assert res.stdout.strip() == "False"

    def test_explicit_env_respected(self, secret_env):
        res = run_cmd(
            self._py("import os;print(os.environ.get('FOO',''))"),
            capture_output=True,
            text=True,
            env={"FOO": "bar", "PATH": "/usr/bin:/bin"},
        )
        assert res.stdout.strip() == "bar"


class TestRunCmdTimeout:
    def test_timeout_returns_minus_one(self):
        res = run_cmd(["sleep", "30"], timeout=0.3, capture_output=True)
        assert res.returncode == -1

    def test_timeout_check_true_raises(self):
        with pytest.raises(subprocess.TimeoutExpired):
            run_cmd(["sleep", "30"], timeout=0.3, check=True)

    def test_timeout_text_mode_returns_str(self):
        res = run_cmd(["sleep", "30"], timeout=0.3, text=True, capture_output=True)
        assert res.returncode == -1
        assert isinstance(res.stdout, str) and isinstance(res.stderr, str)

    def test_normal_command_passes_through(self):
        res = run_cmd(["echo", "hi"], capture_output=True, text=True)
        assert res.returncode == 0
        assert res.stdout.strip() == "hi"
