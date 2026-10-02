"""Minimal RFB 3.8 capture client — host screenshot + session recording.

MeshCentral/RustDesk parity: an operator can snapshot the host desktop
on demand or record it to a ``.vrsrec`` rect stream. The client opens
its own *shared* RFB connection to the loopback VNC server (other
viewers stay connected), forces a fixed pixel format

    32bpp depth24 true-colour, little-endian, shifts R16 G8 B0

and restricts encodings to the subset it can decode:

    Raw(0) CopyRect(1) DesktopSize(-223) ExtendedDesktopSize(-308)

That keeps the wire format deterministic for both the screenshot
(one full non-incremental update) and the recorder (incremental
request/response loop).

Wire pixels arrive as 4-byte little-endian BGRX. The framebuffer
accumulator stores them verbatim; channel reordering to RGBA happens
once at export (PNG) or at playback (the .vrsrec header declares
``channels: bgrx``).

Recording file layout::

    'VRSREC01'                          (8 bytes magic)
    u32be header_len + header JSON      (id/created/w/h/name/operator)
    repeated blocks: u32be len + payload
      'R' u32be t_ms u16 x u16 y u16 w u16 h + zlib(bgrx w*h*4)
      'Z' u32be t_ms u16 w u16 h        (framebuffer resize)
      'E' u32be t_ms                    (clean end)

Security: the client only ever dials ``127.0.0.1:<vnc_port>`` — the VNC
password never leaves the host and recordings land in
``<run_dir>/recordings`` with owner-only permissions.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_MAGIC = b"VRSREC01"
_REC_DIRNAME = "recordings"
_LIVE_SUFFIX = ".live"


# Bounds — a forgotten recorder must not eat the disk or run forever.
def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def _max_seconds() -> int:
    return _env_int("VRS_RECORD_MAX_SECONDS", 7200, 60, 86400)


def _max_bytes() -> int:
    return _env_int("VRS_RECORD_MAX_BYTES", 256 * 1024 * 1024, 1024 * 1024, 4 * 1024 * 1024 * 1024)


class RfbError(Exception):
    """Handshake, auth or protocol failure talking to the VNC server."""


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise."""
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RfbError("VNC server closed the connection")
        out += chunk
    return bytes(out)


def _vnc_auth_response(password: str, challenge: bytes) -> bytes:
    """DES-encrypt the 16-byte challenge — password-as-key, each key
    byte bit-reversed (the RFB convention, applied inside ``deskey``)."""
    from vnc_remote_secure.vendor.d3des import desfunc, deskey

    key = password.encode("latin-1", "replace")[:8].ljust(8, b"\x00")
    subkeys = deskey(key, False)
    return desfunc(challenge[:8], subkeys) + desfunc(challenge[8:], subkeys)


class _Framebuffer:
    """BGRX pixel accumulator for Raw/CopyRect/DesktopSize updates."""

    def __init__(self, w: int, h: int):
        self.w = w
        self.h = h
        self.px = bytearray(w * h * 4)

    def resize(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        self.px = bytearray(w * h * 4)

    def blit(self, x: int, y: int, w: int, h: int, data: bytes) -> None:
        """Copy a row-major BGRX rect into the framebuffer."""
        row = w * 4
        for i in range(h):
            dst = ((y + i) * self.w + x) * 4
            self.px[dst : dst + row] = data[i * row : (i + 1) * row]

    def copy_rect(self, x: int, y: int, w: int, h: int, sx: int, sy: int) -> None:
        """RFB CopyRect — move a region already in the framebuffer."""
        row = w * 4
        # Copy line-by-line into a temp so overlapping regions are safe.
        src = bytearray()
        for i in range(h):
            s = ((sy + i) * self.w + sx) * 4
            src += self.px[s : s + row]
        self.blit(x, y, w, h, bytes(src))

    def rect_pixels(self, x: int, y: int, w: int, h: int) -> bytes:
        """Read back a region (post-update state for recording)."""
        row = w * 4
        out = bytearray()
        for i in range(h):
            s = ((y + i) * self.w + x) * 4
            out += self.px[s : s + row]
        return bytes(out)


def _png_encode(fb: _Framebuffer) -> bytes:
    """Encode the framebuffer as PNG (8-bit RGBA, filter 0 rows).

    Stdlib only: zlib + CRC framing. ``bytes`` slicing does the
    BGRX→RGBA channel swap at C speed.
    """
    import binascii

    n = fb.w * fb.h
    rgba = bytearray(n * 4)
    rgba[0::4] = fb.px[2::4]
    rgba[1::4] = fb.px[1::4]
    rgba[2::4] = fb.px[0::4]
    rgba[3::4] = b"\xff" * n

    # One filter-0 byte per scanline, then zlib the whole raster.
    stride = fb.w * 4
    raw = bytearray((stride + 1) * fb.h)
    for i in range(fb.h):
        raw[i * (stride + 1) + 1 : (i + 1) * (stride + 1)] = rgba[i * stride : (i + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            len(data).to_bytes(4, "big")
            + tag
            + data
            + binascii.crc32(tag + data).to_bytes(4, "big")
        )

    ihdr = struct.pack(">IIBBBBB", fb.w, fb.h, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )


class RfbConnection:
    """One RFB session against the loopback VNC server.

    ``connect_fn`` is injectable so tests can feed a scripted socket.
    Rect application callbacks: ``on_rect(x, y, w, h, pixels)`` fires
    for every rect with its post-update pixels (CopyRect resolves to
    pixels too), ``on_resize(w, h)`` on desktop size changes.
    """

    # Encodings the recorder advertises: Raw + CopyRect + the two
    # desktop-size pseudo-encodings (a resolution change resizes fb).
    _ENCODINGS = (0, 1, -223, -308)

    def __init__(self, host: str, port: int, password: str, connect_fn=None, timeout: float = 15.0):
        self._host, self._port = host, port
        self._password = password
        self._connect_fn = connect_fn or (lambda: socket.create_connection((host, port), timeout))
        self._timeout = timeout
        # Set by connect() — None until the handshake completes.
        self.sock: socket.socket | None = None
        self.fb: _Framebuffer | None = None
        self.name = ""
        self.on_rect: Callable[[int, int, int, int, bytes], None] | None = None
        self.on_resize: Callable[[int, int], None] | None = None

    # -- handshake ------------------------------------------------------

    def connect(self) -> tuple[int, int, str]:
        """Run the RFB handshake; returns (width, height, name)."""
        sock = self._connect_fn()
        sock.settimeout(self._timeout)
        self.sock = sock
        banner = _recvn(sock, 12)
        if not banner.startswith(b"RFB "):
            raise RfbError(f"not an RFB server: {banner!r}")
        sock.sendall(b"RFB 003.008\n")
        nsec = _recvn(sock, 1)[0]
        if nsec == 0:
            reason_len = int.from_bytes(_recvn(sock, 4), "big")
            reason = _recvn(sock, reason_len).decode("utf-8", "replace")
            raise RfbError(f"server refused connection: {reason}")
        sectypes = set(_recvn(sock, nsec))
        if 2 in sectypes and self._password:
            sock.sendall(b"\x02")
            sock.sendall(_vnc_auth_response(self._password, _recvn(sock, 16)))
        elif 1 in sectypes:
            sock.sendall(b"\x01")  # no auth
        else:
            raise RfbError(f"no usable security type in {sectypes}")
        if int.from_bytes(_recvn(sock, 4), "big") != 0:
            raise RfbError("VNC authentication failed")
        # ClientInit shared=1 — capture must never evict a live viewer.
        sock.sendall(b"\x01")
        si = _recvn(sock, 24)
        w, h = int.from_bytes(si[0:2], "big"), int.from_bytes(si[2:4], "big")
        name_len = int.from_bytes(si[20:24], "big")
        self.name = _recvn(sock, name_len).decode("utf-8", "replace")
        self.fb = _Framebuffer(w, h)
        self._set_pixel_format()
        self._set_encodings()
        return w, h, self.name

    def _set_pixel_format(self) -> None:
        assert self.sock is not None  # called from connect() only
        pf = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        self.sock.sendall(b"\x00" + b"\x00" * 3 + pf)

    def _set_encodings(self) -> None:
        assert self.sock is not None  # called from connect() only
        self.sock.sendall(
            b"\x02\x00"
            + len(self._ENCODINGS).to_bytes(2, "big")
            + b"".join(e.to_bytes(4, "big", signed=True) for e in self._ENCODINGS)
        )

    def request_update(self, incremental: bool) -> None:
        assert self.sock is not None and self.fb is not None
        fb = self.fb
        self.sock.sendall(
            b"\x03" + bytes([1 if incremental else 0]) + struct.pack(">HHHH", 0, 0, fb.w, fb.h)
        )

    # -- server message pump --------------------------------------------

    def pump(self) -> int:
        """Process ONE complete server message.

        Returns the number of framebuffer rects applied (0 for
        non-update messages like Bell/ServerCutText).
        """
        sock = self.sock
        fb = self.fb
        assert sock is not None and fb is not None  # connect() first
        mtype = _recvn(sock, 1)[0]
        if mtype == 0:  # FramebufferUpdate
            nrects = int.from_bytes(_recvn(sock, 3)[1:3], "big")
            applied = 0
            for _ in range(nrects):
                hdr = _recvn(sock, 12)
                x, y, w, h = struct.unpack(">HHHH", hdr[:8])
                enc = int.from_bytes(hdr[8:12], "big", signed=True)
                if enc == 0:  # Raw
                    data = _recvn(sock, w * h * 4)
                    fb.blit(x, y, w, h, data)
                    applied += 1
                    if self.on_rect:
                        self.on_rect(x, y, w, h, data)
                elif enc == 1:  # CopyRect
                    sx, sy = struct.unpack(">HH", _recvn(sock, 4))
                    fb.copy_rect(x, y, w, h, sx, sy)
                    applied += 1
                    if self.on_rect:
                        # Store post-copy pixels so playback needs no
                        # framebuffer history.
                        self.on_rect(x, y, w, h, fb.rect_pixels(x, y, w, h))
                elif enc in (-223, -308):  # DesktopSize / Extended
                    if enc == -308:
                        nscreens = _recvn(sock, 4)[0]
                        _recvn(sock, 16 * nscreens)
                    fb.resize(w, h)
                    if self.on_resize:
                        self.on_resize(w, h)
                else:
                    raise RfbError(f"un-negotiated encoding {enc}")
            return applied
        if mtype == 1:  # SetColourMapEntries
            hdr = _recvn(sock, 5)
            _recvn(sock, 6 * int.from_bytes(hdr[3:5], "big"))
        elif mtype == 2:  # Bell — no body
            pass
        elif mtype == 3:  # ServerCutText: pad(3) + u32 len + payload
            _recvn(sock, 3)
            _recvn(sock, int.from_bytes(_recvn(sock, 4), "big"))
        else:
            raise RfbError(f"unknown server message type {mtype}")
        return 0

    def pump_frame(self) -> int:
        """Process messages until one FramebufferUpdate completes."""
        applied = 0
        while applied == 0:
            applied += self.pump()
        return applied

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def _vnc_target() -> tuple[str, int, str]:
    """(host, port, password) for the local VNC server."""
    from vnc_remote_secure.core.portal import vnc_effective_port

    return "127.0.0.1", vnc_effective_port(), os.environ.get("VNC_PASSWORD", "")


def capture_screenshot(timeout: float = 15.0) -> bytes:
    """One full non-incremental framebuffer → PNG bytes."""
    host, port, password = _vnc_target()
    conn = RfbConnection(host, port, password, timeout=timeout)
    try:
        conn.connect()
        conn.request_update(incremental=False)
        conn.pump_frame()
        assert conn.fb is not None  # connect() already ran
        return _png_encode(conn.fb)
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Session recording
# ---------------------------------------------------------------------


def recordings_dir() -> str:
    """``<run_dir>/recordings`` — owner-only, created lazily."""
    from vnc_remote_secure.core.paths import _restrict_dir, get_run_dir

    path = os.path.join(get_run_dir(), _REC_DIRNAME)
    os.makedirs(path, exist_ok=True)
    _restrict_dir(path)
    return path


@dataclass
class RecordingMeta:
    id: str
    created: float
    operator: str
    width: int = 0
    height: int = 0
    name: str = ""
    size: int = 0
    running: bool = False
    ended: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created": self.created,
            "operator": self.operator,
            "width": self.width,
            "height": self.height,
            "name": self.name,
            "size": self.size,
            "running": self.running,
            "ended": self.ended,
        }


_LIVE: dict[str, "_Recorder"] = {}
_LIVE_LOCK = threading.Lock()


def _rec_path(rec_id: str) -> str:
    return os.path.join(recordings_dir(), rec_id + ".vrsrec")


def _parse_header(path: str) -> dict | None:
    try:
        with open(path, "rb") as fh:
            if fh.read(8) != _MAGIC:
                return None
            hlen = int.from_bytes(fh.read(4), "big")
            return json.loads(fh.read(hlen))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _file_has_end(path: str) -> bool:
    """True when the file carries a clean 'E' terminator block
    (u32 len=5 + 'E' + u32 t_ms → 9 bytes at the tail)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 9))
            tail = fh.read()
        return len(tail) >= 9 and int.from_bytes(tail[-9:-5], "big") == 5 and tail[-5] == ord("E")
    except OSError:
        return False


def list_recordings() -> list[dict]:
    """Every .vrsrec on disk, newest first."""
    out = []
    live_marker = os.path.join(recordings_dir(), "")
    with _LIVE_LOCK:
        live = set(_LIVE)
    try:
        names = os.listdir(recordings_dir())
    except OSError:
        return []
    for name in names:
        if not name.endswith(".vrsrec"):
            continue
        path = os.path.join(recordings_dir(), name)
        hdr = _parse_header(path)
        if hdr is None:
            continue
        rec_id = name[: -len(".vrsrec")]
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        running = rec_id in live or os.path.exists(live_marker + rec_id + _LIVE_SUFFIX)
        out.append(
            RecordingMeta(
                id=rec_id,
                created=float(hdr.get("created", 0)),
                operator=str(hdr.get("operator", "")),
                width=int(hdr.get("width", 0)),
                height=int(hdr.get("height", 0)),
                name=str(hdr.get("name", "")),
                size=size,
                running=running,
                ended=_file_has_end(path),
            ).to_dict()
        )
    out.sort(key=lambda r: r["created"], reverse=True)
    return out


class _Recorder(threading.Thread):
    """Background RFB capture → .vrsrec rect stream."""

    def __init__(self, rec_id: str, path: str, actor: str):
        super().__init__(daemon=True, name=f"rfb-rec-{rec_id}")
        self.rec_id = rec_id
        self.path = path
        self.actor = actor
        self._stop = threading.Event()
        self.error = ""

    def run(self) -> None:
        started = time.time()
        fh = None
        conn = None
        written = 0
        try:
            host, port, password = _vnc_target()
            conn = RfbConnection(host, port, password, timeout=10.0)
            w, h, name = conn.connect()
            header = {
                "id": self.rec_id,
                "created": started,
                "operator": self.actor,
                "width": w,
                "height": h,
                "name": name,
                "channels": "bgrx",
            }
            fh = open(self.path, "wb")
            fh.write(_MAGIC)
            hblob = json.dumps(header).encode()
            fh.write(len(hblob).to_bytes(4, "big") + hblob)
            fh.flush()
            marker = self.path + _LIVE_SUFFIX
            open(marker, "w").write(str(os.getpid()))

            def _rect(x, y, rw, rh, pixels):
                nonlocal written
                t = int((time.time() - started) * 1000)
                blob = (
                    b"R"
                    + t.to_bytes(4, "big")
                    + struct.pack(">HHHH", x, y, rw, rh)
                    + zlib.compress(pixels, 1)
                )
                fh.write(len(blob).to_bytes(4, "big") + blob)
                written += len(blob)

            def _resize(nw, nh):
                blob = (
                    b"Z"
                    + int((time.time() - started) * 1000).to_bytes(4, "big")
                    + struct.pack(">HH", nw, nh)
                )
                fh.write(len(blob).to_bytes(4, "big") + blob)

            conn.on_rect = _rect
            conn.on_resize = _resize
            conn.request_update(incremental=False)  # keyframe state
            conn.pump_frame()
            while (
                not self._stop.is_set()
                and time.time() - started < _max_seconds()
                and written < _max_bytes()
            ):
                conn.request_update(incremental=True)
                conn.pump_frame()
                fh.flush()
                time.sleep(0.05)
            # Clean terminator: 'E' + u32 t_ms = 5-byte payload.
            t = int((time.time() - started) * 1000)
            fh.write((5).to_bytes(4, "big") + b"E" + t.to_bytes(4, "big"))
            fh.flush()
            os.fsync(fh.fileno())
        except Exception as exc:  # noqa: BLE001 - thread boundary
            self.error = str(exc)
            logger.warning("recording %s ended with error: %s", self.rec_id, exc)
        finally:
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
            if conn is not None:
                conn.close()
            try:
                os.unlink(self.path + _LIVE_SUFFIX)
            except OSError:
                pass
            with _LIVE_LOCK:
                _LIVE.pop(self.rec_id, None)

    def stop(self) -> None:
        self._stop.set()


def start_recording(actor: str) -> dict:
    """Spawn a recorder thread; returns its metadata."""
    import secrets as _secrets

    rec_id = f"rec_{int(time.time())}_{_secrets.token_hex(4)}"
    path = os.path.join(recordings_dir(), rec_id + ".vrsrec")
    rec = _Recorder(rec_id, path, actor)
    with _LIVE_LOCK:
        _LIVE[rec_id] = rec
    rec.start()
    return {"id": rec_id, "running": True}


def stop_recording(rec_id: str) -> bool:
    """Signal a live recorder to finish; False when unknown/dead."""
    with _LIVE_LOCK:
        rec = _LIVE.get(rec_id)
    if rec is None:
        return False
    rec.stop()
    rec.join(timeout=15)
    return True


def recording_file(rec_id: str) -> tuple[bytes, str]:
    """Read back a .vrsrec blob; returns (bytes, download filename)."""
    if not rec_id or not all(c.isalnum() or c in "_-" for c in rec_id):
        raise ValueError("bad recording id")
    path = _rec_path(rec_id)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        raise FileNotFoundError(rec_id) from None
    return data, f"{rec_id}.vrsrec"


def delete_recording(rec_id: str) -> bool:
    """Remove a finished recording; live ones refuse."""
    if not rec_id or not all(c.isalnum() or c in "_-" for c in rec_id):
        raise ValueError("bad recording id")
    with _LIVE_LOCK:
        if rec_id in _LIVE:
            raise RuntimeError("recording still running")
    path = _rec_path(rec_id)
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    return True
