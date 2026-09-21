"""Unit tests for the extracted novnc relay loop (relay_rfb_stream).

The relay was pulled out of the request handler specifically so it
can be driven over ``socket.socketpair()`` — no subprocesses, no
websockify. These tests pin down the behaviors that matter for
security and resource lifecycle:

- bidirectional forwarding without a filter,
- the upstream 101-header skip (HTTP bytes must not enter the RFB
  tracker's WS-frame parser),
- fail-closed teardown when the filter reports a protocol violation,
- idle-timeout teardown of half-open connections,
- RFB input messages dropped by a view-only filter never reach the
  upstream side.
"""
import os
import socket
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services.novnc import relay_rfb_stream  # noqa: E402
from vnc_remote_secure.services.rfb_filter import RfbInputFilter  # noqa: E402


def _pair():
    """Two connected socketpairs: (client, client_end) & (up, up_end).

    ``client``/``up`` are the sockets the relay pumps; the *_end sockets
    are driven by the test as the browser/upstream-bridge stand-ins.
    """
    client, client_end = socket.socketpair()
    up, up_end = socket.socketpair()
    return client, client_end, up, up_end


def _run_relay(client, up, rfb_filter=None):
    t = threading.Thread(
        target=relay_rfb_stream, args=(client, up, rfb_filter),
        daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Plain forwarding
# ---------------------------------------------------------------------------

def test_relay_forwards_both_directions():
    client, client_end, up, up_end = _pair()
    t = _run_relay(client, up)
    try:
        client_end.sendall(b'hello-upstream')
        assert up_end.recv(64) == b'hello-upstream'
        up_end.sendall(b'hello-client')
        assert client_end.recv(64) == b'hello-client'
    finally:
        client_end.close()
        up_end.close()
        t.join(timeout=5)
    assert not t.is_alive()


def test_relay_returns_when_client_closes():
    client, client_end, up, up_end = _pair()
    t = _run_relay(client, up)
    client_end.close()
    t.join(timeout=5)
    assert not t.is_alive()
    up_end.close()


# ---------------------------------------------------------------------------
# Filtered forwarding
# ---------------------------------------------------------------------------

def _ws_frame(payload: bytes) -> bytes:
    """Build a masked client WS binary frame (what the relay sees)."""
    mask = b'\x01\x02\x03\x04'
    header = bytearray([0x82])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack('>H', n)
    else:
        header += bytes([0x80 | 127]) + struct.pack('>Q', n)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def test_relay_skips_upstream_101_headers_for_tracker():
    """The upstream's own 101 response must be forwarded to the client
    but NOT fed to the RFB handshake tracker."""
    client, client_end, up, up_end = _pair()
    filt = RfbInputFilter()
    t = _run_relay(client, up, filt)
    try:
        up_end.sendall(b'HTTP/1.1 101 Switching Protocols\r\n'
                       b'Upgrade: websocket\r\n\r\n')
        # Client receives the header verbatim.
        got = client_end.recv(256)
        assert b'101 Switching Protocols' in got
        # The tracker's state machine was NOT fed HTTP bytes — it is
        # still waiting for the RFB version line.
        assert filt._srv.state == 'version'
    finally:
        client_end.close()
        up_end.close()
        t.join(timeout=5)


def test_relay_drops_input_for_view_only_filter():
    """A view-only RFB filter drops KeyEvent upstream of the bridge —
    the same guarantee the e2e asserts end-to-end, here in isolation."""
    client, client_end, up, up_end = _pair()
    filt = RfbInputFilter(allow_clipboard=False)
    t = _run_relay(client, up, filt)
    try:
        up_end.sendall(b'HTTP/1.1 101\r\n\r\n')
        client_end.recv(64)  # drain the 101
        # Drive the client side of the handshake far enough that the
        # filter accepts message traffic (its client-side tracker
        # needs version → sectype → clientinit first).
        client_end.sendall(_ws_frame(b'RFB 003.008\n'))
        up_end.recv(128)     # forwarded version
        up_end.sendall(_ws_frame(b'\x01\x01'))  # sectypes: None
        client_end.recv(128)
        client_end.sendall(_ws_frame(b'\x01'))
        up_end.recv(128)                        # chosen sectype
        up_end.sendall(_ws_frame(b'\x00\x00\x00\x00'))  # sec result OK
        client_end.recv(128)
        client_end.sendall(_ws_frame(b'\x01'))   # ClientInit
        up_end.recv(128)
        # ServerInit (24B + name) completes the handshake tracking.
        name = b't'
        server_init = struct.pack('>HH', 1024, 768) + bytes(16) \
            + struct.pack('>I', len(name)) + name
        up_end.sendall(_ws_frame(server_init))
        client_end.recv(256)
        # Now a KeyEvent — the filter must drop it.
        key_event = struct.pack('>BBBBI', 4, 1, 0, 0, 0x41)
        client_end.sendall(_ws_frame(key_event))
        up_end.settimeout(1.5)
        with pytest.raises((socket.timeout, TimeoutError)):
            up_end.recv(64)
    finally:
        client_end.close()
        up_end.close()
        t.join(timeout=5)


def test_relay_fail_closed_on_filter_violation():
    """client_to_server returning None (protocol violation) tears the
    relay down — unparseable input must never pass upstream."""
    client, client_end, up, up_end = _pair()
    filt = RfbInputFilter()
    t = _run_relay(client, up, filt)
    up_end.sendall(b'HTTP/1.1 101\r\n\r\n')
    client_end.recv(64)
    # Garbage that the client-side RFB tracker cannot parse → dead.
    client_end.sendall(b'\xff' * 64)
    t.join(timeout=5)
    assert not t.is_alive(), 'relay survived a protocol violation'
    up_end.close()


def test_relay_idle_timeout_closes(monkeypatch):
    """Half-open connections are reaped after _RELAY_IDLE_TIMEOUT."""
    import vnc_remote_secure.services.novnc as novnc_mod
    monkeypatch.setattr(novnc_mod, '_RELAY_IDLE_TIMEOUT', 0.3)
    # Make select's 60s tick cheap for the test.
    real_select = novnc_mod.select.select
    monkeypatch.setattr(
        novnc_mod.select, 'select',
        lambda r, w, x, t: real_select(r, w, x, min(t, 0.05)))
    client, client_end, up, up_end = _pair()
    t = _run_relay(client, up)
    t.join(timeout=10)
    assert not t.is_alive(), 'idle connection was not reaped'
    client_end.close()
    up_end.close()
