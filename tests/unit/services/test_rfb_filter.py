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
    """A complete RFB 3.8 server handshake (VncAuth, 32bpp pixels)."""
    pixfmt = (b'\x20\x18\x00\x01'          # bpp=32 depth=24 truecolor
              + b'\x00\xff\x00\xff\x00\xff'  # r/g/b max = 255
              + b'\x10\x08\x00'            # shifts 16/8/0
              + b'\x00\x00\x00')           # pad
    server_init = (b'\x02\x80\x01\xe0'     # fb 640x480
                   + pixfmt
                   + b'\x00\x00\x00\x04'   # name length
                   + b'desk')
    return (b'RFB 003.008\n'            # protocol version
            b'\x01\x02'                # 1 security type: VncAuth(2)
            + secrets.token_bytes(16)   # challenge
            + b'\x00\x00\x00\x00'       # SecurityResult OK
            + server_init)


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

    def test_cut_text_control_bytes_stripped(self):
        """Terminal-escape bytes in a cut text must not reach the
        remote clipboard — they can execute on paste (paste-jacking).
        The length field must be rewritten to the sanitized size or
        the stream desynchronises."""
        f = RfbInputFilter(allow_clipboard=True)
        drive_handshake(f)
        evil = b'ls\x1b]8;;http://x\x07rm -rf\x1b[31m'
        out = f.client_to_server(ws_client_frame(cut_text(evil)))
        assert out is not None
        forwarded = decode_all_payloads(out)
        assert forwarded.startswith(b'\x06')
        mlen = int.from_bytes(forwarded[4:8], 'big')
        payload = forwarded[8:8 + mlen]
        assert b'\x1b' not in payload
        assert b'\x07' not in payload
        # Whole sanitized message — stream stays in sync.
        assert len(forwarded) == 8 + mlen

    def test_cut_text_newlines_and_tab_kept(self):
        """Legitimate whitespace (LF/CR/TAB) is clipboard content,
        not control flow — it survives sanitization."""
        f = RfbInputFilter(allow_clipboard=True)
        drive_handshake(f)
        text = b'line1\nline2\ttabbed\rend'
        out = f.client_to_server(ws_client_frame(cut_text(text)))
        assert decode_all_payloads(out) == cut_text(text)

    def test_cut_text_all_controls_dropped(self):
        """A payload that is nothing but control bytes produces an
        empty cut text — dropped entirely."""
        f = RfbInputFilter(allow_clipboard=True)
        drive_handshake(f)
        out = f.client_to_server(
            ws_client_frame(cut_text(b'\x1b\x07\x00')))
        assert out == b''


class TestGranularPermissions:
    """keyboard/pointer/clipboard_write can be granted independently —
    the umbrella flags keep backwards compatibility."""

    def _filtered(self, filt, mtype_payloads):
        """Drive client_to_server through handshake + messages."""
        return filt

    def test_pointer_without_keyboard(self):
        """pointer-only session: PointerEvent passes, KeyEvent drops."""
        from vnc_remote_secure.services.rfb_filter import RfbInputFilter
        f = RfbInputFilter(allow_pointer=True)
        assert f.allow_pointer is True
        assert f.allow_keyboard is False
        assert f.allow_control is False

    def test_keyboard_without_pointer(self):
        from vnc_remote_secure.services.rfb_filter import RfbInputFilter
        f = RfbInputFilter(allow_keyboard=True)
        assert f.allow_keyboard is True
        assert f.allow_pointer is False

    def test_control_umbrella_sets_both(self):
        from vnc_remote_secure.services.rfb_filter import RfbInputFilter
        f = RfbInputFilter(allow_control=True)
        assert f.allow_keyboard is True
        assert f.allow_pointer is True
        assert f.allow_control is True

    def test_clipboard_umbrella_sets_write(self):
        from vnc_remote_secure.services.rfb_filter import RfbInputFilter
        f = RfbInputFilter(allow_clipboard=True)
        assert f.allow_clipboard_write is True
        assert f.allow_clipboard is True


def test_oversized_clipboard_dropped_with_permission(monkeypatch):
    """A ClientCutText past RFB_MAX_CLIPBOARD is dropped even when
    the session HAS clipboard_write — the cap bounds server memory
    and the exfil channel."""
    from vnc_remote_secure.services.rfb_filter import RfbInputFilter
    monkeypatch.setenv("RFB_MAX_CLIPBOARD", "1024")
    f = RfbInputFilter(allow_clipboard_write=True)
    drive_handshake(f)
    big = b"x" * 2048
    out = f.client_to_server(ws_client_frame(cut_text(big)))
    assert out == b""
    # A small clipboard still passes — cap drops, does not kill.
    out2 = f.client_to_server(ws_client_frame(cut_text(b"ok")))
    assert decode_all_payloads(out2) == cut_text(b"ok")


# ---------------------------------------------------------------------------
# Server -> client decoder (desktop:clipboard_read)
# ---------------------------------------------------------------------------

def srv_cut_text(text=b'hello') -> bytes:
    return b'\x03\x00\x00\x00' + len(text).to_bytes(4, 'big') + text


def rect(enc, w, h, data=b'', x=0, y=0) -> bytes:
    return (x.to_bytes(2, 'big') + y.to_bytes(2, 'big')
            + w.to_bytes(2, 'big') + h.to_bytes(2, 'big')
            + enc.to_bytes(4, 'big', signed=True) + data)


def fb_update(*rects) -> bytes:
    return (b'\x00\x00' + len(rects).to_bytes(2, 'big')
            + b''.join(rects))


def set_encodings(*encs) -> bytes:
    return (b'\x02\x00' + len(encs).to_bytes(2, 'big')
            + b''.join(e.to_bytes(4, 'big', signed=True) for e in encs))


class TestServerSideFilter:
    """The server->client stream is decoded: ServerCutText is gated
    by desktop:clipboard_read, FBUpdates re-emit one rect per
    message, un-negotiated encodings kill the connection."""

    def test_cut_text_dropped_without_read(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        out = f.track_server(ws_server_frame(srv_cut_text()))
        assert decode_all_payloads(out) == b''

    def test_cut_text_forwarded_with_read(self):
        f = RfbInputFilter(allow_clipboard_read=True)
        drive_handshake(f)
        out = f.track_server(ws_server_frame(srv_cut_text()))
        assert decode_all_payloads(out) == srv_cut_text()

    def test_cut_text_sanitized_with_read(self):
        """Escape sequences in the REMOTE clipboard must not land in
        the viewer\'s local clipboard either (paste-jacking)."""
        f = RfbInputFilter(allow_clipboard_read=True)
        drive_handshake(f)
        evil = b'ls\x1b[31m\x07rm'
        out = f.track_server(ws_server_frame(srv_cut_text(evil)))
        payloads = decode_all_payloads(out)
        assert payloads.startswith(b'\x03')
        mlen = int.from_bytes(payloads[4:8], 'big')
        assert b'\x1b' not in payloads[8:8 + mlen]
        assert b'\x07' not in payloads[8:8 + mlen]

    def test_cut_text_oversized_dropped(self):
        f = RfbInputFilter(allow_clipboard_read=True)
        drive_handshake(f)
        big = srv_cut_text(b'x' * (2 * 1024 * 1024))
        out = f.track_server(ws_server_frame(big))
        assert decode_all_payloads(out) == b''

    def test_bell_forwarded(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        out = f.track_server(ws_server_frame(b'\x02'))
        assert decode_all_payloads(out) == b'\x02'

    def test_end_of_continuous_forwarded(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        out = f.track_server(ws_server_frame(b'\x96'))
        assert decode_all_payloads(out) == b'\x96'

    def test_fence_forwarded(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        fence = b'\xf8\x00\x00\x00' + b'\x04' + b'\x00\x00\x00\x01' + b'abcd'
        out = f.track_server(ws_server_frame(fence))
        assert decode_all_payloads(out) == fence

    def test_unknown_server_type_dead(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        assert f.track_server(
            ws_server_frame(b'\xee' + b'x' * 8)) is None

    def test_set_encodings_rewritten_to_safe(self):
        """Tight(7)/TRLE(15)/unknown(-999) are stripped — the server
        can only send rects the decoder can size."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        out = f.client_to_server(
            ws_client_frame(set_encodings(7, 16, 5, 0, -999, -223)))
        payloads = decode_all_payloads(out)
        assert payloads == set_encodings(16, 5, 0, -223)

    def test_set_encodings_fallback_when_all_stripped(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        out = f.client_to_server(
            ws_client_frame(set_encodings(7, 15)))
        # Client still gets video: CopyRect + Raw injected.
        assert decode_all_payloads(out) == set_encodings(1, 0)

    def test_fbu_raw_rect_forwarded(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r = rect(0, 2, 2, b'P' * 16)       # Raw 2x2 @32bpp = 16B
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_multi_rect_split(self):
        """An N-rect update re-emits as N single-rect updates."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r1 = rect(1, 4, 4, b'\x00\x01\x00\x02')          # CopyRect
        r2 = rect(0, 1, 1, b'P' * 4)                     # Raw 1x1
        out = f.track_server(ws_server_frame(fb_update(r1, r2)))
        assert decode_all_payloads(out) == (
            b'\x00\x00\x00\x01' + r1
            + b'\x00\x00\x00\x01' + r2)

    def test_fbu_copyrect(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r = rect(1, 8, 8, b'\x00\x64\x00\x64')
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_rre(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        data = (b'\x00\x00\x00\x01' + b'BGPX'
                + b'FGPX' + b'\x00\x00\x00\x00\x00\x02\x00\x02')
        r = rect(2, 4, 4, data)
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_zrle(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        data = b'\x00\x00\x00\x05' + b'ZDATA'
        r = rect(16, 4, 4, data)
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_hextile_raw_tile(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        data = b'\x01' + b'T' * (4 * 4 * 4)   # subenc=Raw, 4x4 @32bpp
        r = rect(5, 4, 4, data)
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_hextile_encoded_tile(self):
        """bg + fg + 2 subrects + 1 coloured subrect per tile."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        data = (b'\x1e'                      # bg|fg|subrects|coloured
                + b'BGPX' + b'FGPX'
                + b'\x02' + b'\x00\x01' * 2
                + b'\x01' + b'SRPX' + b'\x00\x02')
        r = rect(5, 4, 4, data)
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_unknown_encoding_dead(self):
        """Tight(7) was stripped from SetEncodings — a server sending
        it anyway is a protocol violation: die, do not desync."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r = rect(7, 4, 4, b'whatever')
        assert f.track_server(
            ws_server_frame(fb_update(r))) is None

    def test_fbu_desktop_size_pseudo(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r = rect(-223, 800, 600)             # DesktopSize: no data
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_cursor_pseudo(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        # 2x2 cursor @32bpp: 16B pixels + 2B mask ((2+7)//8 * 2)
        r = rect(-239, 2, 2, b'C' * 16 + b'\x03\x03')
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fbu_desktop_name_pseudo(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        r = rect(-307, 0, 0, b'\x00\x00\x00\x04name')
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_fragmented_server_cut_text(self):
        """A cut text split across WS frames is still dropped —
        partial data must not leak."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        msg = srv_cut_text(b'secret-clipboard-data')
        out1 = f.track_server(ws_server_frame(msg[:6], fin=False))
        out2 = f.track_server(
            ws_server_frame(msg[6:], opcode=0x0, fin=True))
        assert decode_all_payloads(out1 + out2) == b''

    def test_handshake_tail_plus_msg_same_frame(self):
        """The WS payload completing ServerInit may carry a cut text
        in the same frame — it must still be filtered, not pass
        verbatim with the handshake tail."""
        f = RfbInputFilter(allow_clipboard_read=False)
        hs = rfb_server_handshake()
        f.track_server(ws_server_frame(hs[:-8]))   # all but last 8B
        # The client handshake frees the parked server tracker
        # (sec_type) — then one server frame carries both the
        # handshake tail and a cut text.
        f.client_to_server(ws_client_frame(rfb_client_handshake()))
        out = f.track_server(
            ws_server_frame(hs[-8:] + srv_cut_text(b'leak')))
        payloads = decode_all_payloads(out)
        # Handshake tail forwarded; the cut text is NOT.
        assert payloads == hs[-8:]

    def test_pixel_format_change_mid_stream(self):
        """SetPixelFormat post-handshake changes rect byte sizes —
        the server parser must track it (16bpp Raw = w*h*2, not *4)."""
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        # Client switches to 16bpp (bpp field = byte 0 of pixfmt).
        pixfmt16 = (b'\x10\x10\x00\x01'
                    + b'\x00\x1f\x00\x3f\x00\x1f'
                    + b'\x0b\x05\x00' + b'\x00\x00\x00')
        f.client_to_server(
            ws_client_frame(b'\x00\x00\x00\x00' + pixfmt16))
        r = rect(0, 4, 4, b'P' * 32)          # Raw 4x4 @16bpp = 32B
        out = f.track_server(ws_server_frame(fb_update(r)))
        assert decode_all_payloads(out) == b'\x00\x00\x00\x01' + r

    def test_server_stream_mixed_messages(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        drive_handshake(f)
        stream = (b'\x02'                       # Bell
                  + srv_cut_text(b'hidden')
                  + b'\x02')                    # Bell
        out = f.track_server(ws_server_frame(stream))
        assert decode_all_payloads(out) == b'\x02\x02'

    def test_handshake_bytes_pass_verbatim(self):
        f = RfbInputFilter(allow_clipboard_read=False)
        hs = rfb_server_handshake()
        out = f.track_server(ws_server_frame(hs))
        assert decode_all_payloads(out) == hs
