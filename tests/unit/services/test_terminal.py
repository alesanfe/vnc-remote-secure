"""Unit tests for the terminal service auth and configuration.

The terminal.py module executes server-startup code at import time, so
these tests validate the shared auth helpers (check_terminal_auth) and
the configuration constants that the terminal service relies on, rather
than the module's top-level code.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_CMD_TIMEOUT,
    DEFAULT_MAX_OUTPUT,
    DEFAULT_TTYD_PORT,
    DEFAULT_TTYD_USERNAME,
)
from vnc_remote_secure.security.http_auth import (
    check_basic_auth,
    check_terminal_auth,
)

# ---------------------------------------------------------------------------
# Constants used by terminal.py
# ---------------------------------------------------------------------------


def test_terminal_default_port_is_int():
    """DEFAULT_TTYD_PORT is a valid integer port."""
    assert isinstance(DEFAULT_TTYD_PORT, int)
    assert 1 <= DEFAULT_TTYD_PORT <= 65535


def test_terminal_default_host_is_localhost():
    """The default bind host is 127.0.0.1 (secure; opt-in for LAN)."""
    assert DEFAULT_BIND_HOST == '127.0.0.1'


def test_terminal_cmd_timeout_is_positive():
    """DEFAULT_CMD_TIMEOUT is a positive integer."""
    assert isinstance(DEFAULT_CMD_TIMEOUT, int)
    assert DEFAULT_CMD_TIMEOUT > 0


def test_terminal_max_output_is_positive():
    """DEFAULT_MAX_OUTPUT is a positive integer."""
    assert isinstance(DEFAULT_MAX_OUTPUT, int)
    assert DEFAULT_MAX_OUTPUT > 0


# ---------------------------------------------------------------------------
# check_basic_auth
# ---------------------------------------------------------------------------

def _basic_header(username, password):
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode('utf-8')).decode('ascii')
    return f"Basic {encoded}"


def test_check_basic_auth_valid():
    """check_basic_auth returns True for matching credentials."""
    header = _basic_header('admin', 'secret123!')
    assert check_basic_auth(header, 'admin', 'secret123!') is True


def test_check_basic_auth_wrong_password():
    """check_basic_auth returns False for a wrong password."""
    header = _basic_header('admin', 'wrong')
    assert check_basic_auth(header, 'admin', 'secret123!') is False


def test_check_basic_auth_wrong_username():
    """check_basic_auth returns False for a wrong username."""
    header = _basic_header('root', 'secret123!')
    assert check_basic_auth(header, 'admin', 'secret123!') is False


def test_check_basic_auth_missing_header():
    """check_basic_auth returns False when the header is missing."""
    assert check_basic_auth('', 'admin', 'secret123!') is False
    assert check_basic_auth(None, 'admin', 'secret123!') is False


def test_check_basic_auth_wrong_scheme():
    """check_basic_auth returns False for a non-Basic scheme."""
    assert check_basic_auth('Bearer token123', 'admin', 'secret123!') is False


def test_check_basic_auth_malformed_base64():
    """check_basic_auth returns False for malformed base64."""
    assert check_basic_auth('Basic !!!not-base64!!!', 'admin', 'secret123!') is False


# ---------------------------------------------------------------------------
# check_terminal_auth
# ---------------------------------------------------------------------------

def test_check_terminal_auth_no_password_rejects(monkeypatch):
    """check_terminal_auth returns False when TTYD_PASSWD is not set."""
    monkeypatch.delenv('TTYD_PASSWD', raising=False)
    assert check_terminal_auth('') is False


def test_check_terminal_auth_valid(monkeypatch):
    """check_terminal_auth returns True for matching credentials."""
    monkeypatch.setenv('TTYD_USERNAME', 'admin')
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header('admin', 'StrongPass1!')
    assert check_terminal_auth(header) is True


def test_check_terminal_auth_wrong_password(monkeypatch):
    """check_terminal_auth returns False for a wrong password."""
    monkeypatch.setenv('TTYD_USERNAME', 'admin')
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header('admin', 'wrong')
    assert check_terminal_auth(header) is False


def test_check_terminal_auth_uses_default_username(monkeypatch):
    """check_terminal_auth falls back to DEFAULT_TTYD_USERNAME when unset."""
    # Prevent load_env_file() from repopulating TTYD_USERNAME from .env
    import vnc_remote_secure.security.http_auth as auth_mod
    monkeypatch.setattr(auth_mod, 'load_env_file', lambda *a, **kw: None)
    monkeypatch.delenv('TTYD_USERNAME', raising=False)
    monkeypatch.setenv('TTYD_PASSWD', 'StrongPass1!')
    header = _basic_header(DEFAULT_TTYD_USERNAME, 'StrongPass1!')
    assert check_terminal_auth(header) is True


# ---------------------------------------------------------------------------
# _execute_command: streaming commands must still honour CMD_TIMEOUT
# ---------------------------------------------------------------------------

def _ws_stub(tmp_path):
    """Minimal TerminalWebSocket double: no real socket, callbacks run
    inline so the test observes the final state synchronously."""
    from unittest.mock import MagicMock

    from vnc_remote_secure.services import terminal as term
    ws = object.__new__(term.TerminalWebSocket)
    ws.cwd = str(tmp_path)
    ws.current_process = None
    ws.write_message = MagicMock()
    ws._send_output = MagicMock()
    ws._after_command = MagicMock()
    ws._send_prompt = MagicMock()
    ws._set_busy = MagicMock()
    loop = MagicMock()
    loop.add_callback = lambda fn, *a, **k: fn(*a, **k)
    term.TerminalWebSocket.main_ioloop = loop
    return ws


def test_infinite_command_is_killed_by_timeout(tmp_path, monkeypatch):
    """`read()` before wait(timeout) let endless commands (`yes`,
    `tail -f`) bypass the timeout and buffer output forever. The
    incremental drain must kill them after CMD_TIMEOUT."""
    import time

    from vnc_remote_secure.services import terminal as term
    monkeypatch.setattr(term, 'DEFAULT_CMD_TIMEOUT', 1)
    ws = _ws_stub(tmp_path)
    t0 = time.monotonic()
    # Long-running command that also works inside the AppContainer
    # sandbox (ping is blocked: ICMP needs a network capability the
    # sandboxed shell lacks; Start-Sleep needs nothing external).
    sleeper = ('powershell -NoProfile -NonInteractive -Command '
               'Start-Sleep 60' if os.name == 'nt'
               else 'sleep 60')
    ws._execute_command(sleeper)
    # The drain thread is daemonised; give it a moment past timeout.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not ws._after_command.called:
        time.sleep(0.05)
    assert time.monotonic() - t0 < 10
    ws._after_command.assert_called_once()
    assert ws._after_command.call_args[0][1] == -1  # timed out


def test_fast_command_returns_output(tmp_path, monkeypatch):
    from vnc_remote_secure.services import terminal as term
    monkeypatch.setattr(term, 'DEFAULT_CMD_TIMEOUT', 10)
    ws = _ws_stub(tmp_path)
    ws._execute_command('echo hello-world-42')
    import time
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not ws._after_command.called:
        time.sleep(0.05)
    ws._after_command.assert_called_once()
    texts = ''.join(c.args[0] for c in ws._send_output.call_args_list)
    assert 'hello-world-42' in texts


def test_open_enforces_step_up_for_operator_session(tmp_path, monkeypatch):
    """Step-up failure must close the socket BEFORE registration.

    Without this the open_terminal sensitive action loses its re-auth
    gate entirely — a stolen operator session cookie opens a shell.
    """
    from unittest.mock import MagicMock

    from vnc_remote_secure.services import terminal as term

    ws = object.__new__(term.TerminalWebSocket)
    ws.request = MagicMock()
    ws.request.headers = {
        'Cookie': 'vnc_session=op-sess',
        'Origin': 'http://127.0.0.1:8000',
        'Authorization': '',
    }
    ws.request.remote_ip = '127.0.0.1'
    closed = []
    ws.close = MagicMock(
        side_effect=lambda code=None, reason=None: closed.append(
            (code, reason)))
    ws.write_message = MagicMock()
    ws._send_prompt = MagicMock()

    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        lambda **kw: (True, 'OK'), raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_authenticated',
        lambda c, b: (True, 'admin'), raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.step_up_auth.require_step_up',
        lambda user, action: 'step-up required', raising=False)

    assert ws._authenticate() is False
    assert closed
    assert closed[0][0] == 1008
    assert 'step-up' in closed[0][1]


def test_open_step_up_pass_registers_connection(tmp_path, monkeypatch):
    """A passing step-up proceeds to registry + watcher."""
    from unittest.mock import MagicMock

    from vnc_remote_secure.services import terminal as term

    ws = object.__new__(term.TerminalWebSocket)
    ws.request = MagicMock()
    ws.request.headers = {
        'Cookie': 'vnc_session=op-sess',
        'Origin': 'http://127.0.0.1:8000',
        'Authorization': '',
    }
    ws.request.remote_ip = '127.0.0.1'
    ws.close = MagicMock()

    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        lambda **kw: (True, 'OK'), raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_authenticated',
        lambda c, b: (True, 'admin'), raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.step_up_auth.require_step_up',
        lambda user, action: None, raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
        lambda *a, **kw: 42, raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.websocket_registry.start_revocation_watcher',
        lambda *a, **kw: None, raising=False)

    assert ws._authenticate() is True
    assert ws._ws_conn_id == 42


def test_open_ephemeral_only_skips_step_up(tmp_path, monkeypatch):
    """Ephemeral-only credential has no operator username — no step-up."""
    from unittest.mock import MagicMock

    from vnc_remote_secure.services import terminal as term

    ws = object.__new__(term.TerminalWebSocket)
    ws.request = MagicMock()
    ws.request.headers = {
        'Cookie': 'vnc_ephemeral=eph-tok',
        'Origin': 'http://127.0.0.1:8000',
        'Authorization': '',
    }
    ws.request.remote_ip = '127.0.0.1'
    ws.close = MagicMock()

    step_up_calls = []
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        lambda **kw: (True, 'OK'), raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.step_up_auth.require_step_up',
        lambda *a: step_up_calls.append(a) or 'should not run',
        raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
        lambda *a, **kw: 7, raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.security.websocket_registry.start_revocation_watcher',
        lambda *a, **kw: None, raising=False)

    assert ws._authenticate() is True
    assert step_up_calls == []
    assert ws._ws_conn_id == 7


class TestOnMessage:
    """on_message dispatch — malformed input and the command allowlist
    (defense-in-depth control with zero prior coverage)."""

    def _ws(self):
        from unittest.mock import MagicMock
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws.write_message = MagicMock()
        ws._send_prompt = MagicMock()
        ws._after_command = MagicMock()
        ws._execute_command = MagicMock()
        ws.current_process = None
        ws.history = []
        return ws

    def test_malformed_json_ignored(self):
        self._ws().on_message('not json {{{')
        # must not raise, must not execute
        ws = self._ws()
        ws.on_message('not json {{{')
        ws._execute_command.assert_not_called()

    def test_empty_command_no_exec(self):
        import json
        ws = self._ws()
        ws.on_message(json.dumps({'type': 'command', 'cmd': '   '}))
        ws._execute_command.assert_not_called()

    def test_allowlist_denies_nonmatching(self, monkeypatch):
        import json
        monkeypatch.setenv('TERMINAL_COMMAND_ALLOWLIST', 'uptime|ls -l')
        ws = self._ws()
        ws.on_message(json.dumps({'type': 'command', 'cmd': 'rm -rf /'}))
        ws._execute_command.assert_not_called()
        assert any('not allowed' in str(c) for c in
                   ws.write_message.call_args_list)

    def test_allowlist_allows_matching(self, monkeypatch):
        import json
        monkeypatch.setenv('TERMINAL_COMMAND_ALLOWLIST', 'uptime')
        ws = self._ws()
        ws.on_message(json.dumps({'type': 'command', 'cmd': 'uptime'}))
        ws._execute_command.assert_called_once_with('uptime')

    def test_invalid_allowlist_regex_fails_closed(self, monkeypatch):
        """A malformed regex must DENY — fail-open would silently
        disable the allowlist."""
        import json
        monkeypatch.setenv('TERMINAL_COMMAND_ALLOWLIST', '([invalid')
        ws = self._ws()
        ws.on_message(json.dumps({'type': 'command', 'cmd': 'uptime'}))
        ws._execute_command.assert_not_called()


class TestGatewayReject:
    """_authenticate reject paths — the gateway deny/TOCTOU branches."""

    def _ws_stub(self):
        from unittest.mock import MagicMock
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws.request = MagicMock()
        ws.request.headers = {'Cookie': '', 'Origin': '', 'Authorization': ''}
        ws.request.remote_ip = '127.0.0.1'
        ws.close = MagicMock()
        ws.write_message = MagicMock()
        return ws

    def test_gateway_deny_closes_1008(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
            lambda **kw: (False, 'nope'), raising=False)
        ws = self._ws_stub()
        assert ws._authenticate() is False
        ws.close.assert_called_once()
        args, kwargs = ws.close.call_args
        code = kwargs.get('code') or (args[0] if args else None)
        assert code == 1008

    def test_toctou_revoke_closes_1008(self, monkeypatch):
        """register_websocket_connection -> None (session revoked
        between check and register) must close."""
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
            lambda **kw: (True, 'OK'), raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_authenticated',
            lambda c, b: (True, 'admin'), raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.step_up_auth.require_step_up',
            lambda u, a: None, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
            lambda *a, **kw: None, raising=False)
        ws = self._ws_stub()
        assert ws._authenticate() is False


class TestOnCloseCleanup:
    """on_close must unregister the ws connection AND kill the child
    process — a socket drop must never orphan a shell."""

    def test_close_unregisters_and_terminates(self):
        from unittest.mock import MagicMock
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws._ws_conn_id = 'ws_7'
        proc = MagicMock()
        ws.current_process = proc
        calls = []
        from unittest import mock
        with mock.patch(
                'vnc_remote_secure.security.auth_gateway.'
                'unregister_websocket_connection',
                lambda cid: calls.append(cid)):
            ws.on_close()
        assert calls == ['ws_7']
        assert ws._ws_conn_id is None
        proc.terminate.assert_called_once()
        assert ws.current_process is None

    def test_close_without_conn_id_no_crash(self):
        """Sockets rejected during open() have no _ws_conn_id —
        on_close must not raise."""
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws.current_process = None
        ws.on_close()


class TestInterrupt:
    def test_interrupt_terminates_running_process(self):
        import json
        from unittest.mock import MagicMock
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws.write_message = MagicMock()
        ws._send_prompt = MagicMock()
        ws._set_busy = MagicMock()
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        ws.current_process = proc
        ws.on_message(json.dumps({'type': 'interrupt'}))
        proc.terminate.assert_called_once()

    def test_interrupt_no_process_just_prompt(self):
        import json
        from unittest.mock import MagicMock
        from vnc_remote_secure.services import terminal as term
        ws = object.__new__(term.TerminalWebSocket)
        ws.write_message = MagicMock()
        ws._send_prompt = MagicMock()
        ws._set_busy = MagicMock()
        ws.current_process = None
        ws.on_message(json.dumps({'type': 'interrupt'}))
        ws._send_prompt.assert_called_once()


class TestIdleTimeout:
    """An unattended terminal is an authenticated shell — the idle
    timeout must close it; activity (input OR output) resets it."""

    def _ws(self, monkeypatch, timeout='10'):
        from unittest.mock import MagicMock
        monkeypatch.setenv('TERMINAL_IDLE_TIMEOUT', timeout)
        from vnc_remote_secure.services.terminal import (
            TerminalWebSocket)
        ws = object.__new__(TerminalWebSocket)
        ws._idle_timeout = int(timeout)
        ws._last_activity = 0.0
        ws._idle_cb = None
        ws._closed_with = []
        ws.write_message = MagicMock()
        ws.close = lambda **kw: ws._closed_with.append(kw)
        return ws

    def test_idle_close(self, monkeypatch):
        import tornado.ioloop
        ws = self._ws(monkeypatch)
        monkeypatch.setattr(
            tornado.ioloop.IOLoop, 'current',
            staticmethod(lambda: type('L', (), {'time':
                                                lambda s: 20.0})()))
        ws._check_idle()
        assert ws._closed_with == [
            {'code': 1000, 'reason': 'idle timeout'}]

    def test_activity_prevents_close(self, monkeypatch):
        import tornado.ioloop
        ws = self._ws(monkeypatch)
        ws._last_activity = 15.0
        monkeypatch.setattr(
            tornado.ioloop.IOLoop, 'current',
            staticmethod(lambda: type('L', (), {'time':
                                                lambda s: 20.0})()))
        ws._check_idle()
        assert ws._closed_with == []

    def test_zero_disables(self, monkeypatch):
        ws = self._ws(monkeypatch, timeout='0')
        # With timeout=0 the PeriodicCallback is never installed.
        assert ws._idle_cb is None

    def test_touch_updates_activity(self, monkeypatch):
        import tornado.ioloop
        ws = self._ws(monkeypatch)
        monkeypatch.setattr(
            tornado.ioloop.IOLoop, 'current',
            staticmethod(lambda: type('L', (), {'time':
                                                lambda s: 42.0})()))
        ws._touch_activity()
        assert ws._last_activity == 42.0


class TestMessageRateLimit:
    """A sustained message flood is a fork-bomb attempt against the
    shell channel — the socket must close, not queue commands."""

    def _ws(self, monkeypatch):
        from collections import deque
        from unittest.mock import MagicMock
        from vnc_remote_secure.services.terminal import (
            TerminalWebSocket)
        ws = object.__new__(TerminalWebSocket)
        ws._msg_times = deque()
        ws._msg_rate = 5
        ws._last_activity = 0
        ws.request = MagicMock(remote_ip='10.0.0.1')
        ws._closed = []
        ws.close = lambda **kw: ws._closed.append(kw)
        # Bypass the real command execution path.
        ws._handle_message = MagicMock()
        return ws

    def test_flood_closes(self, monkeypatch):
        import vnc_remote_secure.services.terminal as t
        ws = self._ws(monkeypatch)
        for _ in range(6):
            # on_message calls _touch_activity then rate check, then
            # the JSON parse — feed invalid JSON so it exits early
            # after the rate logic.
            try:
                t.TerminalWebSocket.on_message(ws, 'x')
            except Exception:
                pass
        assert ws._closed == [{'code': 1008, 'reason': 'rate limit'}]

    def test_under_rate_ok(self, monkeypatch):
        import vnc_remote_secure.services.terminal as t
        ws = self._ws(monkeypatch)
        for _ in range(5):
            try:
                t.TerminalWebSocket.on_message(ws, 'x')
            except Exception:
                pass
        assert ws._closed == []
