# `.vrsrec` Recording Format (v1)

Session recordings are written to `<run_dir>/recordings/<id>.vrsrec`
by the background RFB capture (`core/rfb_capture.py`). This page is
the external spec — enough to write a player or validator without
reading the implementation.

## Layout

```
'VRSREC01'                          8-byte magic
u32be header_len + header JSON      {id, created, w, h, name, operator, channels:"bgrx"}
repeated blocks:  u32be len + payload
  'R'  u32be t_ms u16 x u16 y u16 w u16 h + zlib(w*h*4 BGRX)   rect update
  'Z'  u32be t_ms u16 w u16 h                                 framebuffer resize
  'E'  u32be t_ms                                             clean end marker
```

- Pixels are 4-byte little-endian **BGRX** (channel reorder to RGBA
  happens at playback/export).
- `t_ms` is milliseconds since recording start.
- Blocks are length-prefixed, so unknown tags can be skipped and a
  truncated tail is detectable (`_file_has_end` checks for `E`).
- A live capture writes a `<id>.vrsrec.live` placeholder until the
  `E` block lands — a file without `E` is either live or interrupted.

## Player

The admin SPA renders recordings on a `<canvas>` by accumulating
`R` rects over a framebuffer and honouring `Z` resizes
(`frontend/` Recordings page). `vnc-remote recording` CLI verbs:
`list`, `play`, `export-png`, `delete`.

## Bounds & integrity

- Env caps: `VRSREC_MAX_SECONDS`, `VRSREC_MAX_BYTES` (a forgotten
  recorder cannot eat the disk).
- Files land owner-only under `recordings/`; listing requires a valid
  magic + parseable header.

## Stability policy

`VRSREC01` is the format version. A breaking layout change bumps the
magic (`VRSREC02`); readers must refuse unknown magics rather than
guess.
