"""Regression tests for the RFB input filter (view-only enforcement)."""
import secrets

from vnc_remote_secure.services.rfb_filter import (
    RfbInputFilter,
    _ws_frame,
)


def ws_client_frame(payload: bytes, opcode=0x2, fin=True,
                    mask=b'\x01\x02\x03\x04') -> bytes:
    """Build a masked WebSocket frame like a browser sends."""
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    out = bytearray([b0])
    if n < 126:
        out.append(0x80 | n)
    elif n <= 0xFFFF:
        out.append(0x80 | 126)
        out += n.to_bytes(2, 'big')
    else:
        out.append(0x80 | 127)
        out += n.to_bytes(8, 'big')
    out += mask
    out += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(out)


def ws_server_frame(payload: bytes, opcode=0x2, fin=True) -> bytes:
    """Build an unmasked WebSocket frame like websockify sends."""
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    out = bytearray([b0])
    if n < 126:
        out.append(n)
    elif n <= 0xFFFF:
        out.append(126)
        out += n.to_bytes(2, 'big')
    else:
        out.append(127)
        out += n.to_bytes(8, 'big')
    out += payload
    return bytes(out)


def decode_ws_payload(frame: bytes) -> bytes:
    """Decode a single masked client->server frame to payload."""
    b1 = frame[1]
    ln = b1 & 0x7F
    pos = 2
    if ln == 126:
        ln = int.from_bytes(frame[pos:pos + 2], 'big')
        pos += 2
    elif ln == 127:
        ln = int.from_bytes(frame[pos:pos + 8], 'big')
        pos += 8
    mask = frame[pos:pos + 4]
    pos += 4
    return bytes(c ^ mask[i % 4] for i, c in enumerate(frame[pos:pos + ln]))


def decode_all_payloads(data: bytes) -> bytes:
    """Concatenate payloads of all frames in ``data``."""
    out = bytearray()
    while data:
        b1 = data[1]
        ln = b1 & 0x7F
        pos = 2
        if ln == 126:
            ln = int.from_bytes(data[pos:pos + 2], 'big')
            pos += 2
        elif ln == 127:
            ln = int.from_bytes(data[pos:pos + 8], 'big')
            pos += 8
        if b1 & 0x80:
            mask = data[pos:pos + 4]
            pos += 4
            out += bytes(c ^ mask[i % 4]
                         for i, c in enumerate(data[pos:pos + ln]))
            pos += ln
        else:
            out += data[pos:pos + ln]
            pos += ln
        data = data[pos:]
    return bytes(out)


def rfb_server_handshake() -> bytes:
    """A complete RFB 3.8 server handshake (VncAuth)."""
    return (b'RFB 003.008\n'            # protocol version
            b'\x01\x02'                # 1 security type: VncAuth(2)
            + secrets.token_bytes(16)   # challenge
            + b'\x00\x00\x00\x00'       # SecurityResult OK
            + secrets.token_bytes(20)   # ServerInit: fb + pixel-format
            + b'\x00\x00\x00\x03desk')  # name-len + name


def rfb_client_handshake() -> bytes:
    """Client handshake bytes for VncAuth: version echo + type +
    challenge response + ClientInit."""
    return (b'RFB 003.008\n'            # protocol version echo
            b'\x02'                   # chosen security type: VncAuth
            + secrets.token_bytes(16)  # challenge response
            + b'\x01')                 # ClientInit (shared)


def key_event(key=0xFF0D) -> bytes:
    return b'\x04\x01\x00\x00' + key.to_bytes(4, 'big')


def pointer_event() -> bytes:
    return b'\x05\x01\x00\x64\x00\x64'


def cut_text(text=b'hello') -> bytes:
    return b'\x06\x00\x00\x00' + len(text).to_bytes(4, 'big') + text


def fb_update_request() -> bytes:
    return b'\x03\x01\x00\x00\x00\x00\x07\x80\x04\x38'


def drive_handshake(f: RfbInputFilter, client_hs=None):
    """Push a full handshake through the filter."""
    client_hs = client_hs or rfb_client_handshake()
    f.track_server(ws_server_frame(rfb_server_handshake()))
    return f.client_to_server(ws_client_frame(client_hs))


class TestRfbInputFilter:
    def test_handshake_passes_through(self):
        f = RfbInputFilter()
        client_hs = rfb_client_handshake()
        out = drive_handshake(f, client_hs)
        assert out is not None
        # Handshake bytes forwarded (re-framed but identical content)
        assert decode_all_payloads(out) == client_hs

    def test_key_event_dropped_after_handshake(self):
        f = RfbInputFilter()
        drive_handshake(f)
        out = f.client_to_server(ws_client_frame(key_event()))
        assert out == b''  # dropped entirely

    def test_pointer_event_dropped(self):
        f = RfbInputFilter()
        drive_handshake(f)
        out = f.client_to_server(ws_client_frame(pointer_event()))
        assert out == b''

    def test_cut_text_dropped_without_clipboard(self):
        f = RfbInputFilter(allow_clipboard=False)
        drive_handshake(f)
        out = f.client_to_server(ws_client_frame(cut_text()))
        assert out == b''

    def test_cut_text_allowed_with_clipboard(self):
        f = RfbInputFilter(allow_clipboard=True)
        drive_handshake(f)
        out = f.client_to_server(ws_client_frame(cut_text()))
        assert out is not None
        assert decode_all_payloads(out) == cut_text()

    def test_display_messages_forwarded(self):
        f = RfbInputFilter()
        drive_handshake(f)
        req = fb_update_request()
        out = f.client_to_server(ws_client_frame(req))
        assert decode_all_payloads(out) == req

    def test_unknown_message_type_closes(self):
        f = RfbInputFilter()
        drive_handshake(f)
        # 0xEE is not a defined RFB client message type
        out = f.client_to_server(ws_client_frame(b'\xee' + b'x' * 8))
        assert out is None

    def test_unknown_security_type_closes(self):
        f = RfbInputFilter()
        # 12B version echo + unsupported security type 0x10
        out = f.client_to_server(
            ws_client_frame(b'RFB 003.008\n\x10'
                            + secrets.token_bytes(4)))
        assert out is None

    def test_split_frame_reassembles(self):
        f = RfbInputFilter()
        drive_handshake(f)
        frame = ws_client_frame(key_event())
        half = len(frame) // 2
        out1 = f.client_to_server(frame[:half])
        out2 = f.client_to_server(frame[half:])
        assert out1 is not None
        assert out2 is not None
        assert out1 + out2 == b''  # key event still dropped

    def test_fragmented_ws_message(self):
        f = RfbInputFilter()
        drive_handshake(f)
        req = fb_update_request()
        part1 = ws_client_frame(req[:5], fin=False)
        part2 = ws_client_frame(req[5:], opcode=0x0, fin=True)
        out = f.client_to_server(part1 + part2)
        assert decode_all_payloads(out) == req

    def test_ping_pong_forwarded_verbatim(self):
        f = RfbInputFilter()
        drive_handshake(f)
        ping = ws_client_frame(b'ping!', opcode=0x9)
        out = f.client_to_server(ping)
        assert out == ping

    def test_messages_before_serverinit_are_not_smuggled(self):
        f = RfbInputFilter()
        # Client completes its handshake but server hasn't sent
        # ServerInit yet — input must be buffered, not forwarded.
        out = f.client_to_server(
            ws_client_frame(rfb_client_handshake() + key_event()))
        # handshake bytes emitted; key event held until serverinit
        assert out is not None
        assert key_event() not in decode_all_payloads(out)
        # Now finish server handshake — key event must be DROPPED
        f.track_server(ws_server_frame(rfb_server_handshake()))
        out2 = f.client_to_server(ws_client_frame(fb_update_request()))
        assert decode_all_payloads(out2) == fb_update_request()

    def test_multiple_messages_in_one_frame(self):
        f = RfbInputFilter()
        drive_handshake(f)
        combo = fb_update_request() + key_event() + fb_update_request()
        out = f.client_to_server(ws_client_frame(combo))
        payloads = decode_all_payloads(out)
        # Both FBUpdateRequests forwarded, KeyEvent dropped
        assert payloads == fb_update_request() + fb_update_request()

    def test_no_mask_server_frame_track(self):
        # Server frames are unmasked; track_server must still parse
        f = RfbInputFilter()
        f.track_server(ws_server_frame(b'RFB 003.008\n\x01\x02'))
        # Not done yet — handshake incomplete
        assert not f._srv.done

    def test_reframed_output_is_masked(self):
        f = RfbInputFilter()
        drive_handshake(f)
        out = f.client_to_server(ws_client_frame(fb_update_request()))
        assert out[1] & 0x80  # mask bit set on emitted frame

    def test_dead_filter_stays_dead(self):
        f = RfbInputFilter()
        drive_handshake(f)
        assert f.client_to_server(
            ws_client_frame(b'\xee' + b'x' * 8)) is None
        # Even valid input afterwards must not revive the filter
        assert f.client_to_server(
            ws_client_frame(fb_update_request())) is None

    def test_ws_frame_encode_masked(self):
        payload = b'hello'
        frame = _ws_frame(payload)
        assert frame[0] == 0x82
        assert frame[1] & 0x80
        assert decode_ws_payload(frame) == payload
