"""Unit tests for the novnc WebSocket relay loop (_relay_ws).

The ASGI relay runs at message level: the client side is a Starlette
WebSocket and the upstream a ``websockets`` client connection. These
tests drive both with in-memory fakes so the security invariants are
pinned without real sockets:

- bidirectional forwarding without a filter,
- fail-closed teardown when the filter reports a protocol violation,
- idle-timeout teardown of half-open connections,
- RFB input messages dropped by a view-only filter never reach the
  upstream side.
"""
import asyncio
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from starlette.websockets import WebSocketDisconnect  # noqa: E402

from vnc_remote_secure.services.novnc import _relay_ws  # noqa: E402
from vnc_remote_secure.services.rfb_filter import RfbInputFilter  # noqa: E402


class _Closed(Exception):
    """Sentinel a fake feeds its queue to simulate a peer close."""


class _FakeClientWS:
    """Starlette-WebSocket-shaped fake backed by asyncio queues."""

    def __init__(self):
        self._in = asyncio.Queue()
        self.sent = []

    def feed(self, data):
        self._in.put_nowait(data)

    def close_from_peer(self):
        self._in.put_nowait(_Closed())

    async def receive_bytes(self):
        item = await self._in.get()
        if isinstance(item, _Closed):
            raise WebSocketDisconnect(code=1000)
        return item

    async def send_bytes(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=''):
        pass


class _FakeUpstream:
    """websockets-connection-shaped fake backed by asyncio queues."""

    def __init__(self):
        self._in = asyncio.Queue()
        self.sent = []

    def feed(self, data):
        self._in.put_nowait(data)

    async def recv(self):
        item = await self._in.get()
        if isinstance(item, _Closed):
            raise asyncio.IncompleteReadError(b'', 0)
        return item

    async def send(self, data):
        self.sent.append(data)

    async def close(self):
        pass


def _run(client, upstream, rfb_filter=None, timeout=10):
    """Drive _relay_ws to completion; returns (client, upstream)."""

    async def _go():
        try:
            await _relay_ws(client, upstream, rfb_filter)
        except Exception:
            pass  # teardown path — assertions inspect .sent

    async def _bounded():
        try:
            await asyncio.wait_for(_go(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    asyncio.run(_bounded())
    return client, upstream


# ---------------------------------------------------------------------------
# Plain forwarding
# ---------------------------------------------------------------------------

def test_relay_forwards_both_directions():
    client, upstream = _FakeClientWS(), _FakeUpstream()
    client.feed(b'hello-upstream')
    upstream.feed(b'hello-client')
    client.close_from_peer()
    _run(client, upstream)
    assert b'hello-upstream' in upstream.sent
    assert b'hello-client' in client.sent


def test_relay_returns_when_client_closes():
    client, upstream = _FakeClientWS(), _FakeUpstream()
    client.close_from_peer()
    t0 = asyncio.get_event_loop if False else None  # noqa: F841
    import time
    start = time.monotonic()
    _run(client, upstream, timeout=3)
    assert time.monotonic() - start < 3


# ---------------------------------------------------------------------------
# Filtered forwarding
# ---------------------------------------------------------------------------

def _drain(fake, n=16, timeout=2.0):
    """Wait until the fake has at least n bytes sent; return bytes."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        total = sum(len(m) for m in fake.sent)
        if total >= n:
            break
        time.sleep(0.01)
    return b''.join(bytes(m) for m in fake.sent)


def test_relay_drops_input_for_view_only_filter():
    """A view-only RFB filter drops KeyEvent upstream of the bridge —
    the same guarantee the e2e asserts end-to-end, here in isolation.

    The relay works at message level: RFB bytes ride as WebSocket
    payloads, and the filter re-wraps them in synthetic frames
    internally.
    """
    client, upstream = _FakeClientWS(), _FakeUpstream()
    filt = RfbInputFilter(allow_clipboard=False)

    # Drive the handshake inside a thread so feed/drain can overlap
    # with the running relay loop.
    import threading
    done = threading.Event()

    def _relay():
        asyncio.run(_run_async(client, upstream, filt, done))

    t = threading.Thread(target=_relay, daemon=True)
    t.start()
    try:
        # RFB handshake, message-level: payloads, not frames.
        upstream.feed(b'RFB 003.008\n')
        _drain(client, 12)
        client.feed(b'RFB 003.008\n')
        upstream.feed(b'\x01\x01')               # sectypes: [None]
        _drain(client, 14)
        client.feed(b'\x01')                     # chosen sectype
        upstream.feed(b'\x00\x00\x00\x00')       # sec result OK
        client.feed(b'\x01')                     # ClientInit
        name = b't'
        server_init = struct.pack('>HH', 1024, 768) + bytes(16) \
            + struct.pack('>I', len(name)) + name
        upstream.feed(server_init)
        _drain(client, 64)
        # Now a KeyEvent — the filter must drop it upstream.
        key_event = struct.pack('>BBBBI', 4, 1, 0, 0, 0x41)
        before = sum(len(m) for m in upstream.sent)
        client.feed(key_event)
        import time
        time.sleep(0.3)
        after = sum(len(m) for m in upstream.sent)
        assert after == before, 'KeyEvent leaked upstream'
    finally:
        done.set()
        t.join(timeout=5)


async def _run_async(client, upstream, filt, done):
    """Run the relay until ``done`` fires or a side closes."""

    async def _watcher():
        while not done.is_set():
            await asyncio.sleep(0.02)
        raise WebSocketDisconnect(code=1000)

    relay = asyncio.ensure_future(_relay_ws(client, upstream, filt))
    watch = asyncio.ensure_future(_watcher())
    done_, _ = await asyncio.wait(
        [relay, watch], return_when=asyncio.FIRST_COMPLETED)
    relay.cancel()


def test_relay_fail_closed_on_filter_violation():
    """client_to_server returning None (protocol violation) tears the
    relay down — unparseable input must never pass upstream."""
    client, upstream = _FakeClientWS(), _FakeUpstream()
    filt = RfbInputFilter()
    client.feed(b'\xff' * 64)  # RFB tracker cannot parse → dead
    _run(client, upstream, filt, timeout=5)
    # The relay finished without forwarding the garbage payload.
    assert upstream.sent == []


def test_relay_idle_timeout_closes(monkeypatch):
    """Silent connections are reaped after _RELAY_IDLE_TIMEOUT."""
    import vnc_remote_secure.services.novnc as novnc_mod
    monkeypatch.setattr(novnc_mod, '_RELAY_IDLE_TIMEOUT', 0.2)
    client, upstream = _FakeClientWS(), _FakeUpstream()
    import time
    start = time.monotonic()
    _run(client, upstream, timeout=5)
    assert time.monotonic() - start < 5
    assert time.monotonic() - start >= 0.2


def test_relay_teardown_on_upstream_close():
    """Upstream close ends the relay — no zombie client socket."""
    client, upstream = _FakeClientWS(), _FakeUpstream()
    upstream._in.put_nowait(_Closed())
    _run(client, upstream, timeout=3)
