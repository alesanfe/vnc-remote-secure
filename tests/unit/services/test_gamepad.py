"""Unit tests for services.gamepad module.

External dependencies (platform adapter, websockets) are mocked so the
tests are deterministic and do not require evdev or a running server.
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import gamepad


class _FakeInjector:
    """Fake gamepad injector for testing."""
    available = True

    def __init__(self):
        self.buttons = []
        self.axes = []
        self.closed = False
        self.device_created = False

    def create_device(self):
        self.device_created = True
        return True

    def inject_button(self, button, value):
        self.buttons.append((button, value))

    def inject_axis(self, axis, value):
        self.axes.append((axis, value))

    def close(self):
        self.closed = True


class _UnavailableInjector:
    """Fake injector that is not available."""
    available = False

    def close(self):
        pass


def _patch_adapter(monkeypatch, injector):
    """Patch get_adapter() to return an adapter with the given injector."""
    class _Adapter:
        def create_gamepad_injector(self):
            return injector
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', lambda: _Adapter()
    )


# ---------------------------------------------------------------------------
# GamepadServer.__init__
# ---------------------------------------------------------------------------

def test_gamepad_server_creates_injector(monkeypatch):
    """GamepadServer obtains the injector from the platform adapter."""
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)
    server = gamepad.GamepadServer('127.0.0.1', 7788)
    assert server.injector is injector
    assert server.host == '127.0.0.1'
    assert server.port == 7788


def test_gamepad_server_handles_unavailable_injector(monkeypatch):
    """GamepadServer survives when the adapter returns None."""
    class _Adapter:
        def create_gamepad_injector(self):
            return None
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', lambda: _Adapter()
    )
    server = gamepad.GamepadServer('127.0.0.1', 7788)
    assert server.injector is None


def test_gamepad_server_handles_adapter_exception(monkeypatch):
    """GamepadServer survives when get_adapter() raises."""
    def _raise():
        raise RuntimeError("platform not supported")
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', _raise
    )
    server = gamepad.GamepadServer('127.0.0.1', 7788)
    assert server.injector is None


# ---------------------------------------------------------------------------
# GamepadServer.handle_client
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _FakeWebSocket:
    """Fake websocket for testing handle_client.

    Mirrors the real ``websockets`` library API: ``close()`` accepts
    ``code`` and ``reason`` keyword arguments, and the connection
    exposes ``handler.request.headers`` for auth-gateway inspection.
    """
    def __init__(self, messages=None, remote_ip='127.0.0.1'):
        self._messages = list(messages or [])
        self.sent = []
        self.closed = False
        self.close_code = None
        self.close_reason = None
        self.remote_address = (remote_ip, 12345)
        # Mimic the websockets library's request headers accessor so the
        # auth gateway can read Origin/Cookie/Authorization.

        class _Req:
            headers = {}

        class _Handler:
            request = _Req()
        self.handler = _Handler()

    async def send(self, msg):
        self.sent.append(msg)

    async def close(self, code=None, reason=None):
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._messages:
            return self._messages.pop(0)
        raise StopAsyncIteration


@pytest.fixture(autouse=True)
def _bypass_auth_gateway(monkeypatch):
    """Bypass the central auth gateway in gamepad unit tests.

    The gamepad tests exercise gamepad logic (injector, event forwarding,
    malformed-message handling). Authentication is enforced in
    production by ``services.gamepad.handle_client`` via
    ``auth_gateway.check_websocket_upgrade`` and has dedicated tests in
    ``tests/security``. Here we stub the gateway at the boundary so the
    gamepad logic is tested in isolation without weakening the real
    security model.
    """
    async def _noop_close(code=None, reason=None):
        pass

    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        lambda **kw: (True, 'OK'),
    )
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
        lambda *a, **kw: 'test-conn-id',
    )
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.unregister_websocket_connection',
        lambda *a, **kw: None,
    )


def test_handle_client_rejects_when_injector_unavailable(monkeypatch):
    """handle_client sends an error and closes when no injector."""
    class _Adapter:
        def create_gamepad_injector(self):
            return _UnavailableInjector()
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', lambda: _Adapter()
    )
    server = gamepad.GamepadServer('127.0.0.1', 7788)
    ws = _FakeWebSocket()
    _run(server.handle_client(ws))
    assert ws.closed is True
    assert any('"type": "error"' in m for m in ws.sent)


def test_handle_client_creates_device_and_processes_events(monkeypatch):
    """handle_client creates the device and forwards button/axis events."""
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)
    server = gamepad.GamepadServer('127.0.0.1', 7788)

    messages = [
        json.dumps({"type": "button", "button": "button_0", "value": 1}),
        json.dumps({"type": "axis", "axis": "axis_0", "value": 0.5}),
        json.dumps({"type": "ping"}),
    ]
    ws = _FakeWebSocket(messages=messages)
    _run(server.handle_client(ws))

    assert injector.device_created is True
    assert ("button_0", 1) in injector.buttons
    assert ("axis_0", 0.5) in injector.axes
    assert any('"type": "pong"' in m for m in ws.sent)
    assert any('"type": "connected"' in m for m in ws.sent)


def test_handle_client_ignores_malformed_messages(monkeypatch):
    """handle_client ignores malformed JSON without crashing."""
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)
    server = gamepad.GamepadServer('127.0.0.1', 7788)

    messages = ["not-json", json.dumps({"type": "button", "button": "button_1", "value": 0})]
    ws = _FakeWebSocket(messages=messages)
    _run(server.handle_client(ws))
    assert ("button_1", 0) in injector.buttons


def test_handle_client_requires_control_permission(monkeypatch):
    """The gateway call must demand desktop:control — a view-only
    session must not inject gamepad input (control is control)."""
    captured = {}
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)

    # Override the autouse bypass to capture the real call args.
    def _fake_upgrade(**kw):
        captured.update(kw)
        return True, 'OK'
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        _fake_upgrade)

    server = gamepad.GamepadServer('127.0.0.1', 7788)
    ws = _FakeWebSocket(messages=[json.dumps({"type": "ping"})])
    _run(server.handle_client(ws))
    assert captured.get('required_permission') == 'desktop:control'
    assert captured.get('resource') == 'gamepad'


def test_handle_client_rejects_unauthenticated(monkeypatch):
    """A gateway rejection closes the socket with 1008 and no injector
    is created."""
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
        lambda **kw: (False, 'nope'))

    server = gamepad.GamepadServer('127.0.0.1', 7788)
    ws = _FakeWebSocket(messages=[json.dumps({"type": "ping"})])
    _run(server.handle_client(ws))
    assert ws.closed is True
    assert ws.close_code == 1008
    assert injector.device_created is False


def test_handle_client_toctou_revoke_closes(monkeypatch):
    """register_websocket_connection -> None (revoked between gateway
    check and registration) must close 1008, never reach the injector."""
    injector = _FakeInjector()
    _patch_adapter(monkeypatch, injector)
    monkeypatch.setattr(
        'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
        lambda *a, **kw: None)
    server = gamepad.GamepadServer('127.0.0.1', 7788)
    ws = _FakeWebSocket(messages=[json.dumps({"type": "ping"})])
    _run(server.handle_client(ws))
    assert ws.closed is True
    assert ws.close_code == 1008
    assert injector.device_created is False
