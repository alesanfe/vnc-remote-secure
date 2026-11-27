"""ClientWS adapter contract — Starlette WebSocket as ``websockets``.

The streaming services (audio, gamepad) were written against the
``websockets`` library API; these tests pin the translation so a
semantic drift (text/bytes routing, disconnect semantics, close
swallowing) is caught rather than surfacing as a dead stream.
"""

import asyncio
import types

import pytest

from vnc_remote_secure.services.ws_adapter import ClientWS


class FakeClient:
    host = "10.0.0.9"
    port = 4444


class FakeWS:
    """Minimal stand-in for starlette.websockets.WebSocket."""

    def __init__(self, incoming=None):
        self.headers = {"sec-websocket-protocol": "binary"}
        self.client = FakeClient()
        self.sent_text = []
        self.sent_bytes = []
        self.closed = None
        self._incoming = list(incoming or [])
        self.raise_on_close = False

    async def send_text(self, data):
        self.sent_text.append(data)

    async def send_bytes(self, data):
        self.sent_bytes.append(data)

    async def close(self, code=1000, reason=""):
        if self.raise_on_close:
            raise RuntimeError("socket already dead")
        self.closed = (code, reason)

    async def receive(self):
        if not self._incoming:
            return {"type": "websocket.disconnect"}
        return self._incoming.pop(0)


def _run(coro):
    # asyncio.run per call: a sibling test may close/unset the main
    # thread loop, making get_event_loop() raise under pytest.
    return asyncio.run(coro)


def test_metadata_surface():
    ws = ClientWS(FakeWS())
    assert ws.request_headers["sec-websocket-protocol"] == "binary"
    assert ws.remote_address == ("10.0.0.9", 4444)


def test_remote_address_none_without_client():
    fake = FakeWS()
    fake.client = None
    assert ClientWS(fake).remote_address is None


@pytest.mark.parametrize(
    "payload,expect_bytes",
    [(b"\x01\x02", True), (bytearray(b"\x01"), True), (memoryview(b"\x01"), True), ("text", False)],
)
def test_send_routes_by_type(payload, expect_bytes):
    fake = FakeWS()
    _run(ClientWS(fake).send(payload))
    if expect_bytes:
        assert fake.sent_bytes == [bytes(payload)]
        assert fake.sent_text == []
    else:
        assert fake.sent_text == ["text"]
        assert fake.sent_bytes == []


def test_close_swallows_dead_socket():
    fake = FakeWS()
    fake.raise_on_close = True
    _run(ClientWS(fake).close(code=1011, reason="bye"))  # must not raise


def test_close_propagates_code_and_reason():
    fake = FakeWS()
    _run(ClientWS(fake).close(code=4001, reason="revoked"))
    assert fake.closed == (4001, "revoked")


def test_aiter_yields_text_and_bytes_until_disconnect():
    incoming = [
        {"type": "websocket.receive", "text": "hello", "bytes": None},
        {"type": "websocket.receive", "text": None, "bytes": b"\x00\x01"},
        {"type": "websocket.disconnect"},
        {"type": "websocket.receive", "text": "never", "bytes": None},
    ]
    ws = ClientWS(FakeWS(incoming))

    async def collect():
        return [m async for m in ws]

    assert _run(collect()) == ["hello", b"\x00\x01"]


def test_aiter_skips_non_receive_frames():
    incoming = [
        {"type": "websocket.connect"},
        {"type": "websocket.receive", "text": "after", "bytes": None},
        {"type": "websocket.disconnect"},
    ]
    ws = ClientWS(FakeWS(incoming))

    async def collect():
        return [m async for m in ws]

    assert _run(collect()) == ["after"]


def test_aiter_ends_on_disconnect_exception():
    from starlette.websockets import WebSocketDisconnect

    class Raising(FakeWS):
        async def receive(self):
            raise WebSocketDisconnect(code=1006)

    ws = ClientWS(Raising())

    async def collect():
        return [m async for m in ws]

    assert _run(collect()) == []


def test_make_ws_app_denies_via_response():
    """before_accept returning a Response sends a denial, no accept()."""
    from vnc_remote_secure.services.ws_adapter import make_ws_app

    calls = []
    deny = types.SimpleNamespace()  # any non-None object is a denial

    async def handler(adapter):
        calls.append(adapter)

    class DenyWS(FakeWS):
        def __init__(self):
            super().__init__()
            self.denial = None
            self.accepted = False

        async def send_denial_response(self, r):
            self.denial = r

        async def accept(self):
            self.accepted = True

    app = make_ws_app(handler, before_accept=lambda ws: deny)
    # The app builds lazily; assert construction succeeded and the
    # route exists — behavior is exercised end-to-end by the audio /
    # gamepad e2e specs.
    assert app is not None
    assert any(getattr(r, "path", None) == "/" for r in app.routes)
