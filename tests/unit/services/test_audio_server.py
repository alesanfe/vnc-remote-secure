"""Unit tests for AudioStreamServer — the async pieces of audio.py.

Existing test_audio.py covers find_ffmpeg/list_audio_devices/
get_ffmpeg_capture_cmd. These cover the server lifecycle: env
sanitization for the ffmpeg child, terminate→kill escalation on a
wedged encoder, broadcast with disconnected-client reaping, and the
auth gate in handle_client.

No pytest-asyncio dependency: each async path runs via asyncio.run().
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.services.audio as audio_mod  # noqa: E402
from vnc_remote_secure.services.audio import AudioStreamServer  # noqa: E402


def _server():
    return AudioStreamServer('127.0.0.1', 8090, None, 128)


class _FakeProc:
    """Minimal async subprocess stand-in."""

    def __init__(self, chunks=b'x' * 100, hang_wait=False):
        self.pid = 4242
        self.stdout = _FakeStdout(chunks)
        self.terminated = False
        self.killed = False
        self._hang_wait = hang_wait

    async def wait(self):
        if self._hang_wait and not self.killed:
            await asyncio.sleep(60)
        return 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class _FakeStdout:
    def __init__(self, chunks):
        self._chunks = chunks

    async def read(self, n):
        data, self._chunks = self._chunks[:n], self._chunks[n:]
        return data


class _FakeWS:
    """websockets stand-in: tracks sends and close."""

    def __init__(self, headers=None):
        self.sent = []
        self.closed = None
        self.remote_address = ('127.0.0.1', 55555)
        h = headers or {}
        self.request = type('R', (), {'headers': h})()

    async def send(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=''):
        self.closed = (code, reason)

    def __aiter__(self):
        return self

    async def __anext__(self):
        await asyncio.sleep(60)
        raise StopAsyncIteration


# ---------------------------------------------------------------------------
# start_ffmpeg
# ---------------------------------------------------------------------------

def test_start_ffmpeg_strips_secret_env(monkeypatch):
    """The ffmpeg child must not inherit credential env vars."""
    captured = {}

    async def fake_exec(*cmd, **kw):
        captured['cmd'] = cmd
        captured['env'] = kw.get('env')
        return _FakeProc()

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_exec)
    monkeypatch.setattr(
        audio_mod, 'get_ffmpeg_capture_cmd',
        lambda device, bitrate: ['ffmpeg', '-i', 'x'])
    monkeypatch.setenv('VNC_PASSWORD', 'supersecret')
    monkeypatch.setenv('HARMLESS', 'ok')

    srv = _server()
    assert asyncio.run(srv.start_ffmpeg()) is True
    env = captured['env']
    assert env is not None
    assert 'VNC_PASSWORD' not in env
    assert env.get('HARMLESS') == 'ok'
    assert srv.ffmpeg_process is not None


def test_start_ffmpeg_returns_false_without_cmd(monkeypatch):
    monkeypatch.setattr(
        audio_mod, 'get_ffmpeg_capture_cmd', lambda d, b: None)
    srv = _server()
    assert asyncio.run(srv.start_ffmpeg()) is False


def test_start_ffmpeg_returns_false_on_spawn_error(monkeypatch):
    async def boom(*a, **kw):
        raise OSError('spawn failed')

    monkeypatch.setattr(asyncio, 'create_subprocess_exec', boom)
    monkeypatch.setattr(
        audio_mod, 'get_ffmpeg_capture_cmd',
        lambda d, b: ['ffmpeg', '-i', 'x'])
    srv = _server()
    assert asyncio.run(srv.start_ffmpeg()) is False


# ---------------------------------------------------------------------------
# stop_ffmpeg
# ---------------------------------------------------------------------------

def test_stop_ffmpeg_terminates_cleanly():
    srv = _server()
    srv.ffmpeg_process = _FakeProc()
    srv._ffmpeg_running.set()
    asyncio.run(srv.stop_ffmpeg())
    assert srv.ffmpeg_process is None
    assert not srv._ffmpeg_running.is_set()


def test_stop_ffmpeg_escalates_to_kill_on_hang():
    """A wedged encoder that ignores SIGTERM must be SIGKILLed — the
    shutdown path cannot hang forever."""
    srv = _server()
    proc = _FakeProc(hang_wait=True)
    srv.ffmpeg_process = proc
    srv._ffmpeg_running.set()
    asyncio.run(srv.stop_ffmpeg())
    assert proc.killed is True
    assert srv.ffmpeg_process is None


def test_stop_ffmpeg_noop_without_process():
    srv = _server()
    asyncio.run(srv.stop_ffmpeg())  # must not raise
    assert srv.ffmpeg_process is None
    assert not srv._ffmpeg_running.is_set()


# ---------------------------------------------------------------------------
# audio_reader broadcast
# ---------------------------------------------------------------------------

def test_audio_reader_broadcasts_to_clients():
    srv = _server()
    srv.ffmpeg_process = _FakeProc(chunks=b'abc' * 10)
    srv._ffmpeg_running.set()
    ws = _FakeWS()
    srv.clients.add(ws)

    async def run_once():
        task = asyncio.ensure_future(srv.audio_reader())
        # Let the reader drain the fake stdout then cancel.
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_once())
    assert ws.sent, 'client received no audio chunks'
    assert all(isinstance(c, bytes) for c in ws.sent)


def test_audio_reader_removes_disconnected_client():
    srv = _server()
    srv.ffmpeg_process = _FakeProc(chunks=b'z' * 500)
    srv._ffmpeg_running.set()
    dead = _FakeWS()

    import websockets

    async def closed_send(data):
        raise websockets.ConnectionClosed(None, None)
    dead.send = closed_send
    srv.clients.add(dead)

    async def run_once():
        task = asyncio.ensure_future(srv.audio_reader())
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_once())
    assert dead not in srv.clients


def test_audio_reader_waits_for_ffmpeg_before_reading():
    """With no ffmpeg running the reader must block on the event, not
    spin or exit — this is what keeps the stdout pipe drained once a
    client triggers the lazy start."""
    srv = _server()
    proc = _FakeProc(chunks=b'q' * 20)

    async def scenario():
        task = asyncio.ensure_future(srv.audio_reader())
        await asyncio.sleep(0.1)
        assert srv.ffmpeg_process is None
        # Lazy start mid-read: the reader picks it up.
        srv.ffmpeg_process = proc
        srv._ffmpeg_running.set()
        ws = _FakeWS()
        srv.clients.add(ws)
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # The reader broadcast real audio payload bytes (chunks of b'q')
        # — a bare truthiness assert would pass on any noise frame.
        assert ws.sent
        assert any(b'q' in m for m in ws.sent)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# handle_client auth gate
# ---------------------------------------------------------------------------

def test_handle_client_rejects_unauthorized(monkeypatch):
    async def scenario():
        async def deny(**kw):
            return False, 'no auth'
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
            lambda **kw: (False, 'no auth'))
        srv = _server()
        ws = _FakeWS(headers={'Origin': 'http://127.0.0.1'})
        await srv.handle_client(ws)
        assert ws.closed is not None
        assert ws.closed[0] == 1008
        assert ws not in srv.clients

    asyncio.run(scenario())


def test_handle_client_registers_and_serves(monkeypatch):
    async def scenario():
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
            lambda **kw: (True, ''))
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
            lambda token, close, resource='x', client_ip='': 1)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.unregister_websocket_connection',
            lambda cid: None)
        srv = _server()
        srv.ffmpeg_process = _FakeProc()  # pretend already running
        ws = _FakeWS(headers={
            'Origin': 'http://127.0.0.1',
            'Cookie': 'vnc_session=tok'})
        task = asyncio.ensure_future(srv.handle_client(ws))
        await asyncio.sleep(0.2)
        assert ws in srv.clients
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(scenario())
