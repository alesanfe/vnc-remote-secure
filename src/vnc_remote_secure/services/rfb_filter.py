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
  ``desktop:clipboard``.
- Unknown message types close the connection (fail closed) — a message
  whose length cannot be determined would desynchronise the stream and
  could smuggle input messages past the filter.

The handshake phase (protocol version, security negotiation, client/
server init) is passed through verbatim; filtering only starts once
the server finishes ServerInit.
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
}

# Message types whose tail length is computed from a header field.
# Maps type -> (header_len, tail_fn(header_bytes)).
_VAR_LEN = {
    1: (6, lambda h: 6 * int.from_bytes(h[4:6], 'big')),   # FixColourMapEntries
    2: (4, lambda h: 4 * int.from_bytes(h[2:4], 'big')),   # SetEncodings
    6: (8, lambda h: int.from_bytes(h[4:8], 'big')),       # ClientCutText
    150: (8, lambda h: int.from_bytes(h[4:8], 'big')),     # Fence
    251: (8, lambda h: 16 * h[4]),                          # SetDesktopSize
}

# Messages always permitted (display-related, not input).
_ALLOWED_TYPES = set(_FIXED_LEN) | set(_VAR_LEN)

# Input message types gated by session permissions.
_TYPE_KEY_EVENT = 4
_TYPE_POINTER_EVENT = 5
_TYPE_CUT_TEXT = 6

# Bound the reassembly buffers — a peer that never completes a frame
# or an RFB message must not grow memory without limit.
_MAX_WS_PAYLOAD = 8 * 1024 * 1024
_MAX_RFB_BUF = 8 * 1024 * 1024


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

    def __init__(self, allow_clipboard: bool = False):
        self.allow_clipboard = allow_clipboard
        self._ws_cbuf = bytearray()   # raw client WS bytes
        self._ws_sbuf = bytearray()   # raw server WS bytes
        self._rfb = bytearray()       # client RFB stream (payloads)
        self._srv = _ServerHandshake()
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
    # Server -> client direction (tracking only, forwarded verbatim)
    # ------------------------------------------------------------------
    def track_server(self, data: bytes):
        """Feed raw server->client bytes (WS frames) to the tracker."""
        self._ws_sbuf += data
        frames = _parse_ws_frames(self._ws_sbuf)
        if frames is None:
            return
        for opcode, payload, _raw, fin in frames:
            if opcode == 0x0 and self._sfrag_op is not None:
                self._sfrag += payload
                if fin:
                    self._srv.feed(bytes(self._sfrag))
                    self._sfrag_op = None
                    self._sfrag.clear()
            elif opcode in (0x1, 0x2):
                if fin:
                    self._srv.feed(payload)
                else:
                    self._sfrag_op = opcode
                    self._sfrag += payload

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
            if mtype in (_TYPE_KEY_EVENT, _TYPE_POINTER_EVENT):
                continue  # dropped: no desktop:control
            if mtype == _TYPE_CUT_TEXT and not self.allow_clipboard:
                continue  # dropped: no desktop:clipboard
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
