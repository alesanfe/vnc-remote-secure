"""RFB protocol input filter for restricted (view-only) sessions.

The noVNC ``/websockify`` endpoint proxies raw bytes between the
browser's WebSocket connection and the loopback websockify bridge.
For sessions that only hold ``desktop:view`` (no ``desktop:control``),
hiding the UI controls is not a security boundary: a modified client
can still send RFB ``KeyEvent``/``PointerEvent``/``ClientCutText``
messages inside the WebSocket stream.

This module parses the client-to-server WebSocket frames, reassembles
the RFB client message stream, and re-emits only the messages the
session is allowed to send:

- ``KeyEvent`` (4) and ``PointerEvent`` (5) are dropped unless the
  session has ``desktop:control``.
- ``ClientCutText`` (6) is dropped unless the session has
  ``desktop:clipboard_write``; its payload is sanitised (terminal
  control bytes stripped) when it is.
- ``SetEncodings`` (2) is rewritten to the subset of encodings whose
  rect length the server-side decoder can determine — that is what
  makes the server->client direction parseable at all.
- Unknown message types close the connection (fail closed) — a message
  whose length cannot be determined would desynchronise the stream and
  could smuggle input messages past the filter.

The handshake phase (protocol version, security negotiation, client/
server init) is passed through verbatim; filtering only starts once
the server finishes ServerInit.

Server->client the stream is fully decoded: ``ServerCutText`` (3) is
dropped unless the session holds ``desktop:clipboard_read``
(sanitised when it does), FramebufferUpdate rectangles stream through
one per message, and un-negotiated or unknown encodings/message types
close the connection rather than pass unparseable bytes.
"""
import logging
import secrets

logger = logging.getLogger(__name__)

# RFB client-to-server message types with fixed lengths.
_FIXED_LEN = {
    0: 20,   # SetPixelFormat
    3: 10,   # FramebufferUpdateRequest
    4: 8,    # KeyEvent
    5: 6,    # PointerEvent
    150: 6,  # EnableContinuousUpdates: type pad w(2) h(2)
}

# Message types whose tail length is computed from a header field.
# Maps type -> (header_len, tail_fn(header_bytes)).
_VAR_LEN = {
    1: (6, lambda h: 6 * int.from_bytes(h[4:6], 'big')),   # FixColourMapEntries
    2: (4, lambda h: 4 * int.from_bytes(h[2:4], 'big')),   # SetEncodings
    6: (8, lambda h: int.from_bytes(h[4:8], 'big')),       # ClientCutText
    248: (9, lambda h: h[4]),                              # Fence: len@4
    251: (8, lambda h: 16 * h[4]),                          # SetDesktopSize
}

# SetDesktopSize resizes the remote framebuffer — control-plane input,
# gated like KeyEvent/PointerEvent for view-only sessions.
_TYPE_SET_DESKTOP_SIZE = 251

# Messages always permitted (display-related, not input).
_ALLOWED_TYPES = set(_FIXED_LEN) | set(_VAR_LEN)

# Input message types gated by session permissions.
_TYPE_SET_ENCODINGS = 2
_TYPE_KEY_EVENT = 4
_TYPE_POINTER_EVENT = 5
_TYPE_CUT_TEXT = 6

# Bound the reassembly buffers — a peer that never completes a frame
# or an RFB message must not grow memory without limit.
_MAX_WS_PAYLOAD = 8 * 1024 * 1024
_MAX_RFB_BUF = 8 * 1024 * 1024

# ---------------------------------------------------------------------------
# Server -> client decoder (desktop:clipboard_read enforcement)
#
# Filtering ServerCutText requires knowing where each server message
# ends. FramebufferUpdate rectangles are encoding-dependent, so the
# filter rewrites the client's SetEncodings to the subset whose rect
# lengths are statically decidable, then parses the stream:
#
#   Raw(0) w*h*bpp   CopyRect(1) 4B   RRE(2) counted
#   Hextile(5) tile state machine     ZRLE(16) length-prefixed
#   pseudo-encodings with known data layout (cursor, desktop size/name)
#
# Tight/TRLE/etc. are dropped from the negotiation — a zlib stream's
# end cannot be found without inflating it. A server that sends an
# un-negotiated or unknown encoding desynchronises the parse; the
# connection dies (fail closed), it never passes unparseable bytes.
# ---------------------------------------------------------------------------
_SRV_FIXED_LEN = {
    1: 6,    # SetColourMapEntries: type pad first(2) count(2)
    2: 1,    # Bell
    4: 6,    # ResizeFrameBuffer (UltraVNC)
    150: 1,  # EndOfContinuousUpdates
    173: 8,  # ServerState (UltraVNC)
}
_SRV_VAR_LEN = {
    3: (8, lambda h: int.from_bytes(h[4:8], 'big')),   # ServerCutText
    128: (8, lambda h: int.from_bytes(h[4:8], 'big')),  # TextChat (UltraVNC)
    248: (9, lambda h: h[4]),                          # Fence: type pad(3)
    # length(1) flags(4) payload[length]
}
_SRV_TYPE_FB_UPDATE = 0
_SRV_TYPE_CUT_TEXT = 3

# Encodings whose rect data length is decidable without decoding
# pixels. Anything else is stripped from SetEncodings, so it can never
# legitimately arrive; if it does anyway the stream is dead.
_SAFE_ENCODINGS = {
    0, 1, 2, 5, 16,           # Raw, CopyRect, RRE, Hextile, ZRLE
    -223, -224,               # DesktopSize, LastRect
    -239, -240, -241,         # Cursor, XCursor, RichCursor
    -307, -308,               # DesktopName, ExtendedDesktopSize
}

_INCOMPLETE = -1  # sentinel: need more bytes to size a rect


def _max_clipboard() -> int:
    """Max bytes for a single ClientCutText (default 1 MiB)."""
    import os
    try:
        return max(1024, int(
            os.environ.get('RFB_MAX_CLIPBOARD', str(1024 * 1024))))
    except (TypeError, ValueError):
        return 1024 * 1024


def _sanitize_cut_text(raw: bytes) -> bytes:
    """Strip control bytes from a ``ClientCutText`` RFB message.

    RFB cut text is Latin-1. C0 controls (except TAB/LF/CR), DEL and
    the C1 range can carry escape sequences that execute when the
    shared clipboard is pasted into a terminal on the remote side
    (paste-jacking). The message is rebuilt with the sanitized payload
    and a corrected length field; an all-control payload becomes an
    empty cut text, which the caller drops.
    """
    payload = bytes(
        b for b in raw[8:]
        if (b >= 0x20 and not 0x7F <= b <= 0x9F)
        or b in (0x09, 0x0A, 0x0D))
    return raw[:4] + len(payload).to_bytes(4, 'big') + payload


def _ws_frame(payload: bytes) -> bytes:
    """Encode ``payload`` as a single masked binary WebSocket frame.

    Client-to-server frames MUST be masked (RFC 6455); websockify
    rejects unmasked client traffic.
    """
    mask = secrets.token_bytes(4)
    n = len(payload)
    header = bytearray([0x82])
    if n < 126:
        header.append(0x80 | n)
    elif n <= 0xFFFF:
        header.append(0x80 | 126)
        header += n.to_bytes(2, 'big')
    else:
        header.append(0x80 | 127)
        header += n.to_bytes(8, 'big')
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def _ws_server_frame(payload: bytes) -> bytes:
    """Encode ``payload`` as an UNMASKED binary WebSocket frame.

    Server-to-client frames MUST NOT carry a mask (RFC 6455); the
    browser rejects masked server traffic.
    """
    n = len(payload)
    header = bytearray([0x82])
    if n < 126:
        header.append(n)
    elif n <= 0xFFFF:
        header.append(126)
        header += n.to_bytes(2, 'big')
    else:
        header.append(127)
        header += n.to_bytes(8, 'big')
    return bytes(header) + payload


def _rewrite_encodings(raw: bytes) -> bytes:
    """Intersect a ``SetEncodings`` message with ``_SAFE_ENCODINGS``.

    A session under server-side filtering can only receive rects whose
    length the parser can decide — negotiated unparseable encodings
    (Tight, TRLE, …) are stripped. Order is preserved; when nothing
    survives, CopyRect+Raw are injected so the client still gets
    video. The count field is rewritten to match.
    """
    count = int.from_bytes(raw[2:4], 'big')
    encs = [int.from_bytes(raw[4 + 4 * i:8 + 4 * i], 'big', signed=True)
            for i in range(count)]
    keep = [e for e in encs if e in _SAFE_ENCODINGS]
    if not keep:
        keep = [1, 0]  # CopyRect + Raw — every server implements them
    return (raw[:2] + len(keep).to_bytes(2, 'big')
            + b''.join(e.to_bytes(4, 'big', signed=True) for e in keep))


def _hextile_len(buf: bytearray | bytes, w: int, h: int,
                 pix: int) -> int:
    """Total data bytes of a Hextile rect, or ``_INCOMPLETE``.

    Tiles run row-major, each up to 16x16. Per tile: 1-byte
    subencoding; bit0 = raw (w*h*bpp pixels), otherwise optional
    bg/fg colours, subrects and coloured subrects follow per the
    remaining bits. A tile that runs out of bytes means the rect is
    not fully buffered yet — the caller retries when more arrives.
    """
    off = 0
    y = 0
    while y < h:
        th = min(16, h - y)
        x = 0
        while x < w:
            tw = min(16, w - x)
            if off >= len(buf):
                return _INCOMPLETE
            sub = buf[off]
            off += 1
            if sub & 0x01:                       # Raw tile
                need = tw * th * pix
                if len(buf) - off < need:
                    return _INCOMPLETE
                off += need
            else:
                if sub & 0x02:                   # background colour
                    if len(buf) - off < pix:
                        return _INCOMPLETE
                    off += pix
                if sub & 0x04:                   # foreground colour
                    if len(buf) - off < pix:
                        return _INCOMPLETE
                    off += pix
                if sub & 0x08:                   # AnySubrects
                    if off >= len(buf):
                        return _INCOMPLETE
                    n = buf[off]
                    off += 1
                    if len(buf) - off < 2 * n:
                        return _INCOMPLETE
                    off += 2 * n
                if sub & 0x10:                   # SubrectsColoured
                    if off >= len(buf):
                        return _INCOMPLETE
                    n = buf[off]
                    off += 1
                    if len(buf) - off < (pix + 2) * n:
                        return _INCOMPLETE
                    off += (pix + 2) * n
            x += 16
        y += 16
    return off


def _parse_ws_frames(buf: bytearray):
    """Pop complete WebSocket frames from ``buf``.

    Returns a list of ``(opcode, payload, raw_bytes, fin)`` tuples and
    consumes the parsed bytes. Returns ``None`` on protocol violation
    (oversized frame). Control frames keep their raw encoding so they
    can be forwarded verbatim.
    """
    frames = []
    i = 0
    while True:
        if len(buf) - i < 2:
            break
        b0, b1 = buf[i], buf[i + 1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        ln = b1 & 0x7F
        pos = i + 2
        if ln == 126:
            if len(buf) - pos < 2:
                break
            ln = int.from_bytes(buf[pos:pos + 2], 'big')
            pos += 2
        elif ln == 127:
            if len(buf) - pos < 8:
                break
            ln = int.from_bytes(buf[pos:pos + 8], 'big')
            pos += 8
        if ln > _MAX_WS_PAYLOAD:
            return None
        if masked:
            if len(buf) - pos < 4:
                break
            mask = bytes(buf[pos:pos + 4])
            pos += 4
        else:
            mask = None
        if len(buf) - pos < ln:
            break
        payload = bytes(buf[pos:pos + ln])
        pos += ln
        if mask is not None:
            payload = bytes(c ^ mask[j % 4] for j, c in enumerate(payload))
        frames.append((opcode, payload, bytes(buf[i:pos]), fin))
        i = pos
    del buf[:i]
    return frames


class _ServerHandshake:
    """Track the server-to-client RFB handshake to detect steady state.

    Consumes the RFB byte stream carried inside server WebSocket
    payloads. The handshake is:

        version(12) -> sec-types(1 + n) -> sec-data(0|16)
        -> result(4) -> server-init(24 + 4 + name)
    """

    def __init__(self):
        self.buf = bytearray()
        self.state = 'version'
        # None until the client's security-type byte is seen — the
        # sec-data phase length depends on it, and server bytes can
        # arrive before the client byte does.
        self.sec_type = None
        self._sec_count = 0
        self._name_len = 0
        # Bytes-per-pixel from ServerInit's pixel format — the rect
        # length of Raw/Hextile/RRE depends on it.
        self.pix_size = 4

    def feed(self, data: bytes):
        self.buf += data
        while self.state not in ('done', 'dead') and self.buf:
            if self.state == 'version':
                if len(self.buf) < 12:
                    return
                del self.buf[:12]
                self.state = 'sectypes'
            elif self.state == 'sectypes':
                self._sec_count = self.buf[0]
                del self.buf[0]
                if self._sec_count == 0:
                    # Server offers no security types — it sends a
                    # failure reason and closes. Nothing to filter.
                    self.state = 'dead'
                else:
                    self.state = 'sectype_list'
            elif self.state == 'sectype_list':
                if len(self.buf) < self._sec_count:
                    return
                del self.buf[:self._sec_count]
                self.state = 'secdata'
            elif self.state == 'secdata':
                # Length depends on the type the client picks
                # (recorded by RfbInputFilter when it sees the byte).
                if self.sec_type is None:
                    return  # wait for the client's type byte
                need = 16 if self.sec_type == 2 else 0
                if len(self.buf) < need:
                    return
                del self.buf[:need]
                self.state = 'result'
            elif self.state == 'result':
                if len(self.buf) < 4:
                    return
                result = int.from_bytes(self.buf[:4], 'big')
                del self.buf[:4]
                if result != 0:
                    # Auth failure — server sends a reason and closes.
                    self.state = 'dead'
                else:
                    self.state = 'serverinit'
            elif self.state == 'serverinit':
                # ServerInit fixed part is 24 bytes INCLUDING the
                # 4-byte name-length at offset 20 — read it before
                # consuming the block, then expect ``name`` bytes.
                if len(self.buf) < 24:
                    return
                self._name_len = int.from_bytes(self.buf[20:24], 'big')
                # Pixel-format byte 0 = bits-per-pixel.
                self.pix_size = max(1, self.buf[4] // 8)
                del self.buf[:24]
                self.state = 'name_data'
            elif self.state == 'name_data':
                if len(self.buf) < self._name_len:
                    return
                del self.buf[:self._name_len]
                self.state = 'done'

    @property
    def done(self):
        return self.state == 'done'


class _ServerMsgParser:
    """Streaming decoder for the server-to-client RFB stream.

    ``feed`` takes RFB bytes (WS payloads) and returns the RFB bytes
    to forward — ``None`` on an unparseable stream (fail closed).
    ServerCutText is dropped when the session lacks
    ``desktop:clipboard_read``, and sanitised when it has it.

    FramebufferUpdates are re-emitted one rectangle per message —
    valid RFB (num-rects=1) that lets a large update stream through
    without buffering it whole. Only encodings in ``_SAFE_ENCODINGS``
    may appear: the client SetEncodings is rewritten upstream, so any
    other encoding is a protocol violation.
    """

    def __init__(self, pix_size: int, allow_clipboard_read: bool):
        self.buf = bytearray()
        self.pix = max(1, pix_size)
        self.allow_read = allow_clipboard_read
        self.state = 'idle'   # idle | fbu_hdr | rect_hdr | rect_data
        self._rects_left = 0
        self._rect_pending = 0

    def feed(self, data: bytes) -> bytes | None:
        self.buf += data
        out = bytearray()
        while True:
            if self.state == 'idle':
                if not self.buf:
                    break
                t = self.buf[0]
                if t == _SRV_TYPE_FB_UPDATE:
                    self.state = 'fbu_hdr'
                    continue
                if t in _SRV_FIXED_LEN:
                    need = _SRV_FIXED_LEN[t]
                    if len(self.buf) < need:
                        break
                    out += self.buf[:need]
                    del self.buf[:need]
                    continue
                if t in _SRV_VAR_LEN:
                    hdr, tail = _SRV_VAR_LEN[t]
                    if len(self.buf) < hdr:
                        break
                    need = hdr + tail(bytes(self.buf[:hdr]))
                    if len(self.buf) < need:
                        break
                    raw = bytes(self.buf[:need])
                    del self.buf[:need]
                    if t == _SRV_TYPE_CUT_TEXT:
                        if not self.allow_read:
                            continue  # no desktop:clipboard_read
                        if need > _max_clipboard():
                            logger.warning(
                                "RFB filter: ServerCutText %d bytes "
                                "exceeds cap %d — dropped",
                                need, _max_clipboard())
                            continue
                        raw = _sanitize_cut_text(raw)
                        if len(raw) <= 8:
                            continue
                    out += raw
                    continue
                logger.warning(
                    "RFB filter: unknown server message type %d — "
                    "closing", t)
                return None
            if self.state == 'fbu_hdr':
                if len(self.buf) < 4:
                    break
                self._rects_left = int.from_bytes(
                    self.buf[2:4], 'big')
                del self.buf[:4]
                if self._rects_left == 0:
                    out += b'\x00\x00\x00\x00'  # empty update, verbatim
                    self.state = 'idle'
                else:
                    self.state = 'rect_hdr'
                continue
            if self.state == 'rect_hdr':
                if len(self.buf) < 12:
                    break
                w = int.from_bytes(self.buf[4:6], 'big')
                h = int.from_bytes(self.buf[6:8], 'big')
                enc = int.from_bytes(
                    self.buf[8:12], 'big', signed=True)
                datalen = self._rect_data_len(enc, w, h)
                if datalen == _INCOMPLETE:
                    break  # length field not fully buffered yet
                if datalen is None:
                    logger.warning(
                        "RFB filter: un-negotiated/unknown rect "
                        "encoding %d — closing", enc)
                    return None
                # Re-emit as a single-rect FramebufferUpdate.
                out += b'\x00\x00\x00\x01' + bytes(self.buf[:12])
                del self.buf[:12]
                self._rect_pending = datalen
                self._rects_left -= 1
                self.state = 'rect_data'
                continue
            if self.state == 'rect_data':
                n = min(len(self.buf), self._rect_pending)
                if n == 0:
                    break
                out += self.buf[:n]
                del self.buf[:n]
                self._rect_pending -= n
                if self._rect_pending == 0:
                    self.state = ('idle' if self._rects_left == 0
                                  else 'rect_hdr')
                continue
        return bytes(out)

    def _rect_data_len(self, enc: int, w: int, h: int):
        """Bytes of rect data after the 12-byte header.

        Returns the length, ``_INCOMPLETE`` when the bytes needed to
        know it aren't buffered, or ``None`` when the encoding is not
        in the negotiated safe set.
        """
        b = self.buf
        mask = ((w + 7) // 8) * h
        if enc == 0:                      # Raw
            return w * h * self.pix
        if enc == 1:                      # CopyRect
            return 4
        if enc == 2:                      # RRE
            if len(b) < 16:
                return _INCOMPLETE
            n = int.from_bytes(b[12:16], 'big')
            return 4 + self.pix + n * (self.pix + 8)
        if enc == 5:                      # Hextile
            return _hextile_len(b[12:], w, h, self.pix)
        if enc == 16:                     # ZRLE — length-prefixed
            if len(b) < 16:
                return _INCOMPLETE
            return 4 + int.from_bytes(b[12:16], 'big')
        if enc in (-223, -224):           # DesktopSize, LastRect
            return 0
        if enc in (-239, -241):           # Cursor, RichCursor
            return w * h * self.pix + mask
        if enc == -240:                   # XCursor: type pad rgb(6)
            return 8 + w * h * self.pix + mask
        if enc == -307:                   # DesktopName
            if len(b) < 16:
                return _INCOMPLETE
            return 4 + int.from_bytes(b[12:16], 'big')
        if enc == -308:                   # ExtendedDesktopSize
            if len(b) < 16:
                return _INCOMPLETE
            return 4 + 16 * int.from_bytes(b[12:16], 'big')
        return None


class RfbInputFilter:
    """Drop RFB input messages for sessions without control rights.

    Usage inside the byte-relay loop::

        filt = RfbInputFilter(allow_clipboard=False)
        out = filt.client_to_server(data)      # -> bytes or None
        filt.track_server(data)                # server -> client bytes

    ``client_to_server`` returns the bytes to forward upstream, or
    ``None`` when the stream violates the protocol (unknown RFB type,
    unknown security type, oversized frame) and the connection must
    be closed — fail closed, never pass unparseable input through.
    """

    def __init__(self, allow_clipboard: bool | None = None,
                 allow_control: bool | None = None,
                 allow_keyboard: bool = False,
                 allow_pointer: bool = False,
                 allow_clipboard_write: bool = False,
                 allow_clipboard_read: bool = True):
        # Umbrella flags set the fine-grained pair — fine-grained
        # kwargs let a session grant pointer-without-keyboard or
        # keyboard-without-pointer. allow_control/allow_clipboard
        # remain as convenience aliases for full input/clipboard.
        self.allow_keyboard = allow_keyboard or bool(allow_control)
        self.allow_pointer = allow_pointer or bool(allow_control)
        self.allow_clipboard_write = (
            allow_clipboard_write or bool(allow_clipboard))
        self.allow_clipboard_read = allow_clipboard_read
        # Introspection aliases (a permission is "full" only when all
        # its members are granted).
        self.allow_control = self.allow_keyboard and self.allow_pointer
        self.allow_clipboard = self.allow_clipboard_write
        self._ws_cbuf = bytearray()   # raw client WS bytes
        self._ws_sbuf = bytearray()   # raw server WS bytes
        self._rfb = bytearray()       # client RFB stream (payloads)
        self._srv = _ServerHandshake()
        # _ServerMsgParser post-handshake (created on transition).
        self._srv_parser: _ServerMsgParser | None = None
        self._frag_op = None
        self._frag = bytearray()
        self._sfrag_op = None
        self._sfrag = bytearray()
        # Client handshake: 'version'(12B echo) -> 'sectype'(1B)
        #   -> ['secresp'(16B)] -> 'clientinit'(1B)
        #   -> 'wait_serverinit' -> 'messages'
        self._cstate = 'version'
        self._dead = False

    # ------------------------------------------------------------------
    # Server -> client direction (filtered)
    # ------------------------------------------------------------------
    def track_server(self, data: bytes):
        """Filter server->client WS bytes; returns bytes to forward.

        The handshake passes verbatim. Once ServerInit completes the
        stream is decoded message-by-message: ServerCutText is dropped
        without ``desktop:clipboard_read`` (sanitised with it), and
        unknown message types or un-negotiated encodings return
        ``None`` — the caller must tear the connection down.
        """
        if self._dead:
            return None
        self._ws_sbuf += data
        out = bytearray()
        frames = _parse_ws_frames(self._ws_sbuf)
        if frames is None:
            logger.warning(
                "RFB filter: oversized/invalid server WS frame — "
                "closing")
            self._dead = True
            return None
        for opcode, payload, raw, fin in frames:
            if opcode in (0x8, 0x9, 0xA):
                out += raw      # close/ping/pong — verbatim
                continue
            if opcode == 0x0:
                if self._sfrag_op is None:
                    logger.warning(
                        "RFB filter: stray server continuation frame")
                    self._dead = True
                    return None
                self._sfrag += payload
                if not fin:
                    continue
                payload = bytes(self._sfrag)
                self._sfrag_op = None
                self._sfrag.clear()
            elif opcode in (0x1, 0x2):
                if not fin:
                    self._sfrag_op = opcode
                    self._sfrag += payload
                    continue
            else:
                logger.warning(
                    "RFB filter: unknown server WS opcode %d — closing",
                    opcode)
                self._dead = True
                return None
            if self._srv_parser is None:
                self._srv.feed(payload)
                if not self._srv.done:
                    # Handshake bytes pass through verbatim.
                    out += _ws_server_frame(payload)
                    continue
                # Handshake just completed inside this payload — the
                # tracker left any trailing message bytes buffered;
                # split the payload: handshake part verbatim, message
                # part to the decoder (never both — no double send).
                self._srv_parser = _ServerMsgParser(
                    self._srv.pix_size, self.allow_clipboard_read)
                leftover = bytes(self._srv.buf)
                self._srv.buf.clear()
                hs_len = len(payload) - len(leftover)
                if hs_len:
                    out += _ws_server_frame(payload[:hs_len])
                payload = payload[hs_len:]
            assert self._srv_parser is not None  # set above or pre-existed
            res = self._srv_parser.feed(payload)
            if res is None:
                self._dead = True
                return None
            if res:
                out += _ws_server_frame(res)
        return bytes(out)

    # ------------------------------------------------------------------
    # Client -> server direction (filtered)
    # ------------------------------------------------------------------
    def client_to_server(self, data: bytes):
        """Filter client->server bytes; returns bytes to forward.

        Returns ``None`` on fatal protocol violation — caller must
        tear down the connection.
        """
        if self._dead:
            return None
        self._ws_cbuf += data
        out = bytearray()
        frames = _parse_ws_frames(self._ws_cbuf)
        if frames is None:
            logger.warning("RFB filter: oversized/invalid WS frame — closing")
            self._dead = True
            return None
        for opcode, payload, raw, fin in frames:
            if opcode in (0x8, 0x9, 0xA):
                # close/ping/pong — forward verbatim
                out += raw
                continue
            if opcode == 0x0:
                if self._frag_op is None:
                    logger.warning("RFB filter: stray continuation frame")
                    self._dead = True
                    return None
                self._frag += payload
                if not fin:
                    continue
                payload = bytes(self._frag)
                self._frag_op = None
                self._frag.clear()
            elif opcode in (0x1, 0x2):
                if not fin:
                    self._frag_op = opcode
                    self._frag += payload
                    continue
            else:
                logger.warning("RFB filter: unknown WS opcode %d", opcode)
                self._dead = True
                return None
            self._rfb += payload
            if len(self._rfb) > _MAX_RFB_BUF:
                logger.warning("RFB filter: RFB buffer overflow — closing")
                self._dead = True
                return None
            res = self._drain_rfb()
            if res is None:
                self._dead = True
                return None
            out += res
        return bytes(out)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _drain_rfb(self):
        """Parse buffered client RFB stream; returns bytes to forward.

        Handshake bytes pass through verbatim. Once the server has
        completed ServerInit the stream is parsed message-by-message
        and input messages are dropped.
        """
        out = bytearray()
        while self._rfb:
            if self._cstate != 'messages':
                consumed = self._client_handshake()
                if consumed < 0:
                    return None
                if consumed == 0:
                    if self._cstate == 'messages':
                        continue  # just transitioned — parse buffered msg
                    break
                out += _ws_frame(bytes(self._rfb[:consumed]))
                del self._rfb[:consumed]
                continue
            parsed = self._parse_message()
            if parsed is None:
                break  # incomplete message — wait for more data
            mtype, mlen = parsed
            if mtype is None:
                logger.warning(
                    "RFB filter: unknown client message type %d — closing",
                    mlen)
                return None
            raw = bytes(self._rfb[:mlen])
            del self._rfb[:mlen]
            if mtype == _TYPE_SET_ENCODINGS:
                # Server-side filtering can only parse encodings whose
                # rect length is decidable — renegotiate to the safe
                # subset so Tight/TRLE never legitimately arrive.
                raw = _rewrite_encodings(raw)
            elif mtype == _TYPE_KEY_EVENT and not self.allow_keyboard:
                continue  # dropped: no desktop:keyboard/control
            elif mtype in (_TYPE_POINTER_EVENT, _TYPE_SET_DESKTOP_SIZE) \
                    and not self.allow_pointer:
                continue  # dropped: no desktop:pointer/control
            if mtype == _TYPE_CUT_TEXT:
                if not self.allow_clipboard_write:
                    continue  # dropped: no desktop:clipboard_write/clipboard
                if mlen > _max_clipboard():
                    # Clipboard size cap: a cut-text is bounded memory
                    # on the server and a potential exfil channel —
                    # drop oversized payloads, keep the stream in sync.
                    logger.warning(
                        "RFB filter: ClientCutText %d bytes exceeds "
                        "cap %d — dropped", mlen, _max_clipboard())
                    continue
                raw = _sanitize_cut_text(raw)
                if len(raw) <= 8:
                    continue  # payload was all control bytes — drop
            out += _ws_frame(raw)
        return bytes(out)

    def _client_handshake(self):
        """Consume handshake bytes; returns count consumed, 0, or -1."""
        if self._cstate == 'version':
            if len(self._rfb) < 12:
                return 0
            self._cstate = 'sectype'
            return 12
        if self._cstate == 'sectype':
            if len(self._rfb) < 1:
                return 0
            sec = self._rfb[0]
            self._srv.sec_type = sec
            # Resume the server tracker — it may be parked at 'secdata'
            # waiting for this type byte.
            self._srv.feed(b'')
            if sec == 2:
                self._cstate = 'secresp'
            elif sec == 1:
                self._cstate = 'clientinit'
            else:
                logger.warning(
                    "RFB filter: unsupported security type %d — closing", sec)
                return -1
            return 1
        if self._cstate == 'secresp':
            if len(self._rfb) < 16:
                return 0
            self._cstate = 'clientinit'
            return 16
        if self._cstate == 'clientinit':
            if len(self._rfb) < 1:
                return 0
            self._cstate = 'wait_serverinit'
            return 1
        if self._cstate == 'wait_serverinit':
            if self._srv.done:
                self._cstate = 'messages'
                return 0
            # Buffer extra client bytes until ServerInit completes —
            # forwarding them unfiltered would let a client smuggle
            # input messages ahead of the handshake end.
            return 0
        return 0

    def _parse_message(self):
        """Parse one RFB client message.

        Returns ``(type, total_len)``, ``None`` when incomplete, or
        ``(None, type_byte)`` when the type is unknown (fail closed).
        """
        b = self._rfb
        t = b[0]
        if t in _FIXED_LEN:
            need = _FIXED_LEN[t]
            return (t, need) if len(b) >= need else None
        if t in _VAR_LEN:
            hdr, tail_fn = _VAR_LEN[t]
            if len(b) < hdr:
                return None
            need = hdr + tail_fn(b)
            return (t, need) if len(b) >= need else None
        return (None, t)
