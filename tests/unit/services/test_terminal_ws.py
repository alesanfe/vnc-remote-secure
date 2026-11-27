"""Unit tests for TerminalWebSocket internals left uncovered by
test_terminal.py — rate limiting, builtins, RBAC command gate,
completion dispatch, prompts, and the credential-less auth branches."""

import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.services import terminal as term


def _ws(**attrs):
    """Bare TerminalWebSocket with mocked I/O seams."""
    ws = object.__new__(term.TerminalWebSocket)
    ws.write_message = mock.MagicMock()
    ws.close = mock.MagicMock()
    ws._send_prompt = mock.MagicMock()
    ws._set_busy = mock.MagicMock()
    ws._execute_command = mock.MagicMock()
    ws._handle_completion = mock.MagicMock()
    ws.current_process = None
    ws.history = []
    ws.cwd = "/tmp"
    ws._terminal_write = True
    ws._msg_times = None
    ws._msg_rate = 30
    ws.request = mock.MagicMock(remote_ip="127.0.0.1")
    for k, v in attrs.items():
        setattr(ws, k, v)
    return ws


class TestRateLimited:
    def test_zero_rate_never_limits(self):
        ws = _ws(_msg_rate=0)
        assert ws._rate_limited() is False

    def test_under_limit_passes(self, monkeypatch):
        import collections

        (
            monkeypatch.setattr(term.time, "monotonic", lambda: 1000.0)
            if hasattr(term, "time")
            else None
        )
        ws = _ws(_msg_rate=3, _msg_times=collections.deque())
        with mock.patch("time.monotonic", return_value=1000.0):
            for _ in range(3):
                assert ws._rate_limited() is False

    def test_flood_closes_socket(self):
        import collections

        ws = _ws(_msg_rate=2, _msg_times=collections.deque())
        with mock.patch("time.monotonic", return_value=1000.0):
            ws._rate_limited()
            ws._rate_limited()
            assert ws._rate_limited() is True
        ws.close.assert_called_once()
        assert ws.close.call_args.kwargs.get("code") == 1008

    def test_old_messages_pruned(self):
        import collections

        ws = _ws(_msg_rate=2, _msg_times=collections.deque([999.0]))
        with mock.patch("time.monotonic", return_value=1000.5):
            # 999.0 is >1s old → pruned → only current counts
            assert ws._rate_limited() is False


class TestBuiltinCommand:
    def test_exit_closes(self):
        ws = _ws()
        assert ws._builtin_command("exit") is True
        ws.close.assert_called()

    def test_cls_sends_clear_and_prompt(self):
        ws = _ws()
        assert ws._builtin_command("cls") is True
        assert ws.write_message.call_args_list[0].args[0] == "\x1b[2J\x1b[H"
        ws._send_prompt.assert_called_once()

    def test_help_and_history(self):
        ws = _ws(history=["ls", "pwd"])
        assert ws._builtin_command("help") is True
        assert ws._builtin_command("history") is True
        out = " ".join(str(c) for c in ws.write_message.call_args_list)
        assert "ls" in out and "pwd" in out

    def test_unknown_returns_false(self):
        ws = _ws()
        assert ws._builtin_command("rm -rf /") is False


class TestOnCommandRbac:
    def test_view_only_denies_subprocess(self):
        ws = _ws(_terminal_write=False)
        ws._on_command({"cmd": "ls -la"})
        ws._execute_command.assert_not_called()
        assert any("View-only" in str(c) for c in ws.write_message.call_args_list)

    def test_view_only_still_gets_builtins(self):
        ws = _ws(_terminal_write=False)
        ws._on_command({"cmd": "help"})
        ws._execute_command.assert_not_called()
        assert any("Available commands" in str(c) for c in ws.write_message.call_args_list)

    def test_history_recorded_before_gate(self):
        ws = _ws(_terminal_write=False)
        ws._on_command({"cmd": "whoami"})
        assert ws.history == ["whoami"]


class TestOnMessageDispatch:
    def test_complete_gated_by_write_permission(self):
        ws = _ws(_terminal_write=False)
        ws.on_message(json.dumps({"type": "complete", "input": "ls"}))
        ws._handle_completion.assert_not_called()

    def test_complete_runs_when_write_allowed(self):
        ws = _ws(_terminal_write=True)
        ws.on_message(json.dumps({"type": "complete", "input": "ls"}))
        ws._handle_completion.assert_called_once_with("ls")


class TestHandleCompletion:
    def test_command_prefix_uses_command_completion(self):
        ws = _ws()
        with mock.patch.object(term, "_complete_windows_command", return_value=["ls"]):
            term.TerminalWebSocket._handle_completion(ws, "l")
        out = json.loads(ws.write_message.call_args.args[0])
        assert out["type"] == "completion" and out["suggestions"] == ["ls"]

    def test_path_completion_none_returns_empty(self):
        ws = _ws()
        with mock.patch.object(term, "_complete_path_glob", return_value=None):
            term.TerminalWebSocket._handle_completion(ws, "cd /tm")
        out = json.loads(ws.write_message.call_args.args[0])
        assert out["suggestions"] == []

    def test_suggestions_capped_at_20(self):
        ws = _ws()
        with mock.patch.object(
            term, "_complete_windows_command", return_value=[f"c{i}" for i in range(50)]
        ):
            term.TerminalWebSocket._handle_completion(ws, "c")
        out = json.loads(ws.write_message.call_args.args[0])
        assert len(out["suggestions"]) == 20


class TestSendPrompt:
    def test_powershell_prompt(self, monkeypatch):
        monkeypatch.setattr(term, "_config", lambda: {"webterm_shell": "powershell.exe"})
        ws = _ws()
        term.TerminalWebSocket._send_prompt(ws)
        assert "PS /tmp>" in ws.write_message.call_args.args[0]

    def test_posix_prompt_truncates_long_cwd(self, monkeypatch):
        monkeypatch.setattr(term, "_config", lambda: {"webterm_shell": "bash"})
        ws = _ws(cwd="/" + "a" * 50)
        term.TerminalWebSocket._send_prompt(ws)
        out = ws.write_message.call_args.args[0]
        assert "..." in out and len(out) < 80


class TestAuthenticateNoCredentials:
    def _ws_stub(self):
        ws = _ws()
        ws.request = mock.MagicMock()
        ws.request.headers = {}
        ws.request.remote_ip = "127.0.0.1"
        return ws

    def test_basic_disabled_closes_1008(self, monkeypatch):
        monkeypatch.setattr(term, "_basic_auth_enabled", lambda: False)
        ws = self._ws_stub()
        assert ws._authenticate() is False
        assert ws.close.call_args.kwargs.get("code") == 1008

    def test_basic_auth_rejects_bad_credentials(self, monkeypatch):
        monkeypatch.setattr(term, "_basic_auth_enabled", lambda: True)
        monkeypatch.setattr(term, "check_terminal_auth", lambda *a, **k: False)
        ws = self._ws_stub()
        assert ws._authenticate() is False
        assert ws.close.call_args.kwargs.get("code") == 1008

    def test_basic_auth_accepts_and_skips_registry(self, monkeypatch):
        """Legacy Basic path never touches the WS revocation registry —
        _ws_conn_id stays None so on_close is a no-op."""
        monkeypatch.setattr(term, "_basic_auth_enabled", lambda: True)
        monkeypatch.setattr(term, "check_terminal_auth", lambda *a, **k: True)
        ws = self._ws_stub()
        assert ws._authenticate() is True
        assert ws._ws_conn_id is None


class TestModuleHelpers:
    def test_basic_auth_enabled_env(self, monkeypatch):
        monkeypatch.setenv("TERMINAL_BASIC_AUTH", "false")
        assert term._basic_auth_enabled() is False
        monkeypatch.setenv("TERMINAL_BASIC_AUTH", "true")
        assert term._basic_auth_enabled() is True

    def test_portal_terminal_url_https(self, monkeypatch):
        monkeypatch.setattr(
            term, "_config", lambda: {"landing_port": 8000, "ssl_cert": "x", "ssl_key": "y"}
        )
        import vnc_remote_secure.security.certificates as certs

        monkeypatch.setattr(certs, "create_ssl_context", lambda *a: object())
        url = term._portal_terminal_url("example.com:8443")
        assert url == "https://example.com:8000/terminal"

    def test_portal_terminal_url_http_and_host_fallback(self, monkeypatch):
        monkeypatch.setattr(term, "_config", lambda: {"landing_port": 8000})
        import vnc_remote_secure.security.certificates as certs

        monkeypatch.setattr(certs, "create_ssl_context", lambda *a: None)
        assert term._portal_terminal_url("") == "http://127.0.0.1:8000/terminal"

    def test_root_security_headers_csp_default(self, monkeypatch):
        monkeypatch.delenv("CSP_POLICY", raising=False)
        headers = term._root_security_headers(tls_enabled=True)
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    def test_root_security_headers_env_override_wins(self, monkeypatch):
        monkeypatch.setenv("CSP_POLICY", "default-src *")
        headers = term._root_security_headers(tls_enabled=False)
        assert headers["Content-Security-Policy"] == "default-src *"

    def test_is_origin_allowed_empty_rejected(self):
        assert term._is_origin_allowed("") is False

    def test_is_origin_allowed_delegates_to_gateway(self, monkeypatch):
        import vnc_remote_secure.security.auth_gateway as gw

        monkeypatch.setattr(gw, "get_allowed_origins", lambda: ["https://ok.example"])
        monkeypatch.setattr(gw, "check_origin", lambda o, a: o == "https://ok.example")
        assert term._is_origin_allowed("https://ok.example") is True
        assert term._is_origin_allowed("https://evil.example") is False
