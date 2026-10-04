"""Generate a minimal synthetic .vrsrec for the docs screenshot of
the in-app player. Layout mirrors core/rfb_capture.py:

  'VRSREC01' + u32be header_len + JSON header
  blocks: u32be len + payload
    'R' u32be t_ms u16be x y w h + zlib(bgrx)
    'E' u32be t_ms
"""
import json
import struct
import zlib
import pathlib

W, H = 320, 240


def rect(t: int, x: int, y: int, w: int, h: int, bgrx_px: bytes) -> bytes:
    payload = (
        b"R" + struct.pack(">I", t)
        + struct.pack(">HHHH", x, y, w, h)
        + zlib.compress(bgrx_px * (w * h))
    )
    return struct.pack(">I", len(payload)) + payload


def end(t: int) -> bytes:
    payload = b"E" + struct.pack(">I", t)
    return struct.pack(">I", len(payload)) + payload


header = json.dumps(
    {"width": W, "height": H, "name": "demo-capture"}
).encode()
out = b"VRSREC01" + struct.pack(">I", len(header)) + header

# desktop-like scene: dark bg + windows-ish rects at staggered times
out += rect(0, 0, 0, W, H, bytes([30, 30, 46, 255]))               # bg
out += rect(120, 16, 16, 200, 110, bytes([52, 52, 70, 255]))       # window 1
out += rect(120, 16, 16, 200, 14, bytes([200, 160, 60, 255]))      # title bar
out += rect(480, 60, 150, 150, 70, bytes([60, 45, 45, 255]))       # window 2
out += rect(900, 30, 40, 40, 24, bytes([60, 200, 80, 255]))        # notif
out += rect(1500, 250, 216, 56, 14, bytes([90, 90, 110, 255]))     # taskbar
out += end(1800)

dest = pathlib.Path(__file__).with_name("demo.vrsrec")
dest.write_bytes(out)
print(dest, len(out), "bytes")
