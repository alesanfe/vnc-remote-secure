"""Unit tests for the RFB capture client (screenshot + recording).

A scripted ``FakeSock`` replays a canned RFB 3.8 server conversation —
handshake, ServerInit and framebuffer updates — so the decoder is
exercised byte-exactly without a live VNC server.
"""
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest  # noqa: E402

from vnc_remote_secure.core import rfb_capture  # noqa: E402
from vnc_remote_secure.core.rfb_capture import (  # noqa: E402
    RfbConnection,
    RfbError,
    _Framebuffer,
    _png_encode,
    _vnc_auth_response,
)


class FakeSock:
    """Scripted socket: reads consume ``script``, writes accumulate."""

    def __init__(self, script: bytes):
        self._in = bytearray(script)
        self.out = bytearray()
        self._timeout = None

    def recv(self, n: int) -> bytes:
        if not self._in:
            raise TimeoutError('script exhausted')
        chunk = bytes(self._in[:n])
        del self._in[:n]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.out += data

    def settimeout(self, t) -> None:
        self._timeout = t

    def close(self) -> None:
        pass


def _server_init(w=4, h=3, name=b'test-host') -> bytes:
    """ServerInit for security type 1 (none): no challenge."""
    pf = bytes(16)
    return (struct.pack('>HH', w, h) + pf
            + len(name).to_bytes(4, 'big') + name)


def _handshake_noauth(w=4, h=3, name=b'test-host') -> bytes:
    """Server bytes for a none-auth RFB 3.8 session."""
    return (b'RFB 003.008\n'
            + b'\x01\x01'                       # sectypes: [none]
            + b'\x00\x00\x00\x00'               # SecurityResult OK
            + _server_init(w, h, name))


def _fbu(*rects: bytes) -> bytes:
    return (b'\x00\x00' + len(rects).to_bytes(2, 'big')
            + b''.join(rects))


def _raw_rect(x, y, w, h, pixels: bytes) -> bytes:
    return (struct.pack('>HHHHi', x, y, w, h, 0) + pixels)


def test_framebuffer_blit_and_copy():
    fb = _Framebuffer(4, 2)
    # Fill top row (0,0,4x1) red-ish bytes.
    fb.blit(0, 0, 4, 1, b'\x01\x02\x03\x04' * 4)
    assert fb.px[0:4] == b'\x01\x02\x03\x04'
    # Copy the top row into the bottom row.
    fb.copy_rect(0, 1, 4, 1, 0, 0)
    assert fb.px[16:20] == b'\x01\x02\x03\x04'
    assert fb.rect_pixels(0, 1, 4, 1) == b'\x01\x02\x03\x04' * 4


def test_png_encode_structure():
    fb = _Framebuffer(2, 2)
    fb.px[:] = b'\x11\x22\x33\x00' * 4  # BGRX
    png = _png_encode(fb)
    assert png.startswith(b'\x89PNG\r\n\x1a\n')
    assert b'IHDR' in png and b'IDAT' in png and png.endswith(
        b'IEND\xaeB`\x82')


def test_vnc_auth_response_uses_des():
    pytest.importorskip('Crypto')
    resp = _vnc_auth_response('passw0rd', b'\x00' * 16)
    assert len(resp) == 16


def test_handshake_noauth_and_pixel_format():
    script = _handshake_noauth(w=8, h=6, name=b'box')
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    w, h, name = conn.connect()
    assert (w, h, name) == (8, 6, 'box')
    out = conn.sock.out
    assert out[:12] == b'RFB 003.008\n'
    assert out[12] == 1          # security type: none
    assert out[13] == 1          # ClientInit shared=1
    assert out[14] == 0          # SetPixelFormat
    assert out[18] == 32         # bpp 32


def test_pump_applies_raw_rect_and_fires_hook():
    px = bytes(range(48))  # 4x3 BGRX pixels
    script = (_handshake_noauth()
              + _fbu(_raw_rect(0, 0, 4, 3, px)))
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    conn.connect()
    seen = []
    conn.on_rect = lambda x, y, w, h, data: seen.append((x, y, w, h))
    conn.request_update(incremental=False)
    assert conn.pump_frame() == 1
    assert seen == [(0, 0, 4, 3)]
    assert conn.fb.px == px


def test_pump_copyrect_resolves_to_pixels():
    """Recorded CopyRects carry resolved pixels — playback needs no
    framebuffer history."""
    px = b'\xaa' * 16  # 2x2 block
    copyrect = struct.pack('>HHHHi', 2, 0, 2, 2, 1) + \
        struct.pack('>HH', 0, 0)
    script = (_handshake_noauth()
              + _fbu(_raw_rect(0, 0, 2, 2, px))
              + _fbu(copyrect))
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    conn.connect()
    got = []
    conn.on_rect = lambda x, y, w, h, data: got.append(
        (x, y, w, h, data))
    conn.pump()  # first FBU
    conn.pump()  # second FBU (copyrect)
    assert got[1][:4] == (2, 0, 2, 2)
    assert got[1][4] == px  # resolved pixels, not the 4-byte src coords


def test_desktopsize_resizes_framebuffer():
    dsr = struct.pack('>HHHHi', 0, 0, 8, 8, -223)
    script = _handshake_noauth() + _fbu(dsr)
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    conn.connect()
    resized = []
    conn.on_resize = lambda w, h: resized.append((w, h))
    conn.pump()
    assert resized == [(8, 8)]
    assert conn.fb.w == 8 and len(conn.fb.px) == 8 * 8 * 4


def test_unknown_message_type_fails_closed():
    script = _handshake_noauth() + b'\x99'
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    conn.connect()
    with pytest.raises(RfbError):
        conn.pump()


def test_unnegotiated_encoding_fails_closed():
    tight = struct.pack('>HHHHi', 0, 0, 4, 3, 7)  # Tight — never sent
    script = _handshake_noauth() + _fbu(tight)
    conn = RfbConnection('127.0.0.1', 5900, '',
                         connect_fn=lambda: FakeSock(script))
    conn.connect()
    with pytest.raises(RfbError):
        conn.pump()


def test_auth_failure_raises():
    script = (b'RFB 003.008\n' + b'\x01\x02' + b'\x00' * 16
              + b'\x00\x00\x00\x01')  # auth failed
    pytest.importorskip('Crypto')
    conn = RfbConnection('127.0.0.1', 5900, 'pw',
                         connect_fn=lambda: FakeSock(script))
    with pytest.raises(RfbError, match='authentication failed'):
        conn.connect()


# --- recording file format ---------------------------------------------

def test_recording_file_round_trip(tmp_path, monkeypatch):
    """A recorder fed by a scripted socket produces a parseable
    .vrsrec: magic + JSON header + R records + E terminator."""
    monkeypatch.setenv('VRS_RECORD_MAX_SECONDS', '30')
    monkeypatch.setattr(rfb_capture, 'recordings_dir',
                        lambda: str(tmp_path))
    # One Raw rect per update; the second request exhausts the script
    # → the thread ends via error path but the file must be readable.
    px = b'\x01\x02\x03\x04' * 4
    script = (_handshake_noauth()
              + _fbu(_raw_rect(0, 0, 4, 1, px))
              + _fbu(_raw_rect(0, 1, 4, 1, px)))

    monkeypatch.setattr(rfb_capture, '_vnc_target',
                        lambda: ('x', 1, ''))
    monkeypatch.setattr(rfb_capture.socket, 'create_connection',
                        lambda *a, **k: FakeSock(script))

    meta = rfb_capture.start_recording('tester')
    import time
    for _ in range(50):
        if not rfb_capture._LIVE.get(meta['id'], None) or \
                rfb_capture._LIVE[meta['id']].error:
            break
        time.sleep(0.1)
    rfb_capture.stop_recording(meta['id'])

    data, name = rfb_capture.recording_file(meta['id'])
    assert name.endswith('.vrsrec')
    assert data.startswith(b'VRSREC01')
    hlen = int.from_bytes(data[8:12], 'big')
    import json
    hdr = json.loads(data[12:12 + hlen])
    assert hdr['operator'] == 'tester' and hdr['channels'] == 'bgrx'
    # At least one rect record must have landed.
    body = data[12 + hlen:]
    blen = int.from_bytes(body[:4], 'big')
    assert body[4] == ord('R')
    t = int.from_bytes(body[5:9], 'big')
    x, y, w, h = struct.unpack('>HHHH', body[9:17])
    assert (w, h) == (4, 1) and t >= 0
    assert zlib.decompress(body[17:4 + blen]) == px


def test_recording_list_and_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(rfb_capture, 'recordings_dir',
                        lambda: str(tmp_path))
    # Hand-write a minimal finished recording.
    path = tmp_path / 'rec_1.vrsrec'
    hdr = b'{"id":"rec_1","created":1,"operator":"op","width":4,' \
          b'"height":3,"name":"h","channels":"bgrx"}'
    path.write_bytes(b'VRSREC01' + len(hdr).to_bytes(4, 'big') + hdr
                     + (5).to_bytes(4, 'big') + b'E' + (0).to_bytes(4, 'big'))
    items = rfb_capture.list_recordings()
    assert len(items) == 1
    assert items[0]['ended'] and not items[0]['running']
    assert rfb_capture.delete_recording('rec_1')
    assert rfb_capture.list_recordings() == []
    assert not rfb_capture.delete_recording('rec_1')
