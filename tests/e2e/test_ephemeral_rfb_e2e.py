"""End-to-end: ephemeral session → noVNC relay → websockify → RFB.

Spins up a real noVNC service process, a real websockify bridge and a
fake RFB server, then drives a real WebSocket upgrade through the whole
chain. Verifies:

* An activated ephemeral *view-only* session gets protocol-level
  view-only enforcement — KeyEvent messages are dropped inside the
  relay even though the client sends them.
* A *control* session's KeyEvent reaches the RFB server.
* An unauthenticated upgrade is rejected with 401 (no 101).

Requires: websockify importable (declared dependency) and loopback TCP.
Marked ``e2e``; runs on Linux and Windows.
"""
import base64
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------
# Minimal helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _ws_send(sock: socket.socket, payload: bytes):
    """Send a masked binary WebSocket frame (client side)."""
    header = bytearray([0x82])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack('>H', n)
    else:
        header.append(0x80 | 127)
        header += struct.pack('>Q', n)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf += chunk
    return buf


def _ws_recv(sock: socket.socket) -> bytes:
    """Receive one (possibly fragmented) binary WS message payload."""
    payload = b''
    while True:
        b1, b2 = _recv_exact(sock, 2)
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack('>H', _recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack('>Q', _recv_exact(sock, 8))[0]
        if b2 & 0x80:  # server frames shouldn't be masked, tolerate anyway
            mask = _recv_exact(sock, 4)
            data = _recv_exact(sock, length)
            data = bytes(d ^ mask[i % 4] for i, d in enumerate(data))
        else:
            data = _recv_exact(sock, length)
        if opcode == 0x8:
            raise ConnectionError('WS close frame')
        if opcode in (0x0, 0x1, 0x2):
            payload += data
            if fin:
                return payload
        # ping/pong ignored for this test


class _FakeRfbServer(threading.Thread):
    """Speaks RFB 3.8 (None security) and records post-handshake bytes."""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.received = bytearray()
        self._lock = threading.Lock()
        self.handshake_done = threading.Event()

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', self.port))
        srv.listen(4)
        srv.settimeout(20)
        try:
            conn, _ = srv.accept()
        except OSError:
            srv.close()
            return
        srv.close()
        conn.settimeout(20)
        try:
            conn.sendall(b'RFB 003.008\n')
            conn.recv(12)                       # client version
            conn.sendall(b'\x01\x01')           # 1 sectype: None(1)
            conn.recv(1)                        # chosen sectype
            conn.sendall(b'\x00\x00\x00\x00')   # SecurityResult OK
            conn.recv(1)                        # ClientInit
            name = b'fake-rfb'
            server_init = struct.pack('>HH', 1024, 768) + bytes(16) \
                + struct.pack('>I', len(name)) + name
            conn.sendall(server_init)
            self.handshake_done.set()
            while True:                         # record client messages
                data = conn.recv(4096)
                if not data:
                    break
                with self._lock:
                    self.received += data
        except OSError:
            pass
        finally:
            conn.close()

    def got(self, payload: bytes, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if payload in self.received:
                    return True
            time.sleep(0.05)
        return False


def _run_dir_for(env_extra: dict) -> str:
    """Compute the run dir the subprocess will resolve for its state."""
    base = env_extra.get('XDG_RUNTIME_DIR') or env_extra.get('LOCALAPPDATA')
    return os.path.join(str(base), 'VncRemoteSecure', 'run')


@pytest.fixture
def stack(tmp_path, monkeypatch):
    """Fake RFB + real websockify + real novnc service on loopback."""
    rfb_port = _free_port()
    ws_port = _free_port()
    novnc_port = _free_port()
    webroot = tmp_path / 'webroot'
    webroot.mkdir()
    (webroot / 'vnc.html').write_text('<html>novnc</html>')

    # Redirect the subprocess state dirs into tmp_path so the ephemeral
    # session created in-test is visible to the novnc process.
    if sys.platform == 'win32':
        env_extra = {'LOCALAPPDATA': str(tmp_path / 'appdata')}
    else:
        env_extra = {'XDG_RUNTIME_DIR': str(tmp_path / 'xdg')}
    run_dir = _run_dir_for(env_extra)
    os.makedirs(run_dir, exist_ok=True)

    # Point the IN-PROCESS session store at the same run dir.
    # ephemeral_sessions imports get_run_dir lazily inside its
    # functions, so patching the paths module covers both.
    from vnc_remote_secure.core import paths as paths_mod
    monkeypatch.setattr(paths_mod, 'get_run_dir', lambda: run_dir)
    import vnc_remote_secure.security.ephemeral_sessions as ephem_mod
    monkeypatch.setattr(ephem_mod, '_INSTANCE_ID', None)

    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    env = dict(os.environ)
    env.update(env_extra)
    env['PYTHONPATH'] = os.path.join(repo, 'src') + os.pathsep + env.get('PYTHONPATH', '')
    env['NOVNC_PORT'] = str(novnc_port)
    env['NOVNC_WS_PORT'] = str(ws_port)
    env['SHARED_STATE_BACKEND'] = 'sqlite'
    # The subprocess auto-discovers certs under <data_dir>/ssl — the dev
    # machine has real ones, which would wrap the test socket in TLS.
    env['DISABLE_SSL'] = 'true'
    env['TLS_ENABLED'] = 'false'
    env.pop('SSL_CERT', None)
    env.pop('SSL_KEY', None)

    rfb = _FakeRfbServer(rfb_port)
    rfb.start()

    ws_log = open(tmp_path / 'websockify.log', 'wb')
    nv_log = open(tmp_path / 'novnc.log', 'wb')
    wsp = subprocess.Popen(
        [sys.executable, '-m', 'websockify',
         f'127.0.0.1:{ws_port}', f'127.0.0.1:{rfb_port}'],
        env=env, stdout=ws_log, stderr=ws_log)
    np_ = subprocess.Popen(
        [sys.executable, '-m', 'vnc_remote_secure.services.novnc',
         str(webroot), str(novnc_port)],
        env=env, stdout=nv_log, stderr=nv_log)
    try:
        assert _wait_port(ws_port), 'websockify did not start'
        assert _wait_port(novnc_port), 'novnc did not start'
        yield {
            'novnc_port': novnc_port,
            'rfb': rfb,
            'run_dir': run_dir,
        }
    finally:
        for p in (np_, wsp):
            p.terminate()
        for p in (np_, wsp):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in (ws_log, nv_log):
            f.close()


def _ws_upgrade(port: int, cookie: str = '', bearer: str = ''):
    """Open a raw WebSocket upgrade to /websockify; returns socket."""
    key = base64.b64encode(os.urandom(16)).decode()
    headers = [
        'GET /websockify HTTP/1.1',
        f'Host: 127.0.0.1:{port}',
        'Upgrade: websocket',
        'Connection: Upgrade',
        f'Sec-WebSocket-Key: {key}',
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Protocol: binary',
        f'Origin: http://127.0.0.1:{port}',
    ]
    if cookie:
        headers.append(f'Cookie: {cookie}')
    if bearer:
        headers.append(f'Authorization: Bearer {bearer}')
    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
    sock.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode())
    # Read response headers
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    status = buf.split(b'\r\n', 1)[0]
    return sock, status


def _rfb_handshake(sock: socket.socket):
    """Drive the client side of the RFB handshake over WS frames."""
    assert _ws_recv(sock) == b'RFB 003.008\n'
    _ws_send(sock, b'RFB 003.008\n')
    sectypes = _ws_recv(sock)
    assert sectypes[0] >= 1
    _ws_send(sock, b'\x01')                    # pick 'None' security
    assert _ws_recv(sock) == b'\x00\x00\x00\x00'  # SecurityResult OK
    _ws_send(sock, b'\x01')                    # ClientInit (shared)
    server_init = _ws_recv(sock)
    assert len(server_init) >= 24


def _make_ephemeral(run_dir: str, role: str) -> str:
    """Create+activate an ephemeral session; return the internal token."""
    from vnc_remote_secure.security.ephemeral_sessions import (
        activate_ephemeral_session,
        get_session_store,
    )
    store = get_session_store()
    _sess, signed = store.create(role=role, expires_in=600)
    internal = activate_ephemeral_session(signed)
    assert internal, 'ephemeral activation failed'
    return internal


def test_view_only_ephemeral_drops_key_events(stack):
    """A view-only share link cannot send keyboard input — enforced
    inside the relay at the RFB protocol layer, not just hidden in UI."""
    rfb = stack['rfb']
    internal = _make_ephemeral(stack['run_dir'], role='viewer')
    sock, status = _ws_upgrade(
        stack['novnc_port'], cookie=f'vnc_ephemeral={internal}')
    try:
        assert b'101' in status, f'expected 101, got {status!r}'
        _rfb_handshake(sock)
        key_event = struct.pack('>BBBBI', 4, 1, 0, 0, 0x41)  # KeyEvent 'A'
        _ws_send(sock, key_event)
        # Give the relay time to forward — then assert it did NOT.
        assert not rfb.got(key_event, timeout=3.0), \
            'view-only KeyEvent reached the RFB server'
    finally:
        sock.close()


def test_control_ephemeral_key_events_forwarded(stack):
    """A control session's KeyEvent must reach the RFB server — the
    filter passes messages for sessions with desktop:control."""
    rfb = stack['rfb']
    internal = _make_ephemeral(stack['run_dir'], role='support')
    sock, status = _ws_upgrade(
        stack['novnc_port'], cookie=f'vnc_ephemeral={internal}')
    try:
        assert b'101' in status, f'expected 101, got {status!r}'
        _rfb_handshake(sock)
        key_event = struct.pack('>BBBBI', 4, 1, 0, 0, 0x41)
        _ws_send(sock, key_event)
        assert rfb.got(key_event), \
            'control KeyEvent did not reach the RFB server'
    finally:
        sock.close()


def test_unauthenticated_upgrade_rejected(stack):
    """No credentials → no 101; the relay must not proxy."""
    sock, status = _ws_upgrade(stack['novnc_port'])
    try:
        assert b'101' not in status
        assert b'401' in status or b'403' in status
    finally:
        sock.close()
