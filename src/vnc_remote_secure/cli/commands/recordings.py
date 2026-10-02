"""``vnc-remote desktop`` / ``vnc-remote recording`` — desktop capture.

Thin transport over ``engine.application.recordings`` — the same use
cases behind ``/api/v1/desktop/screenshot`` and ``/api/v1/recordings*``.
The local shell is the authentication boundary, so no ``auth_ctx`` is
passed and bound step-up grants are skipped (``transport='cli'``).
"""

import json
import sys

from vnc_remote_secure.cli._common import _cli_actor


def _desktop_screenshot(args) -> int:
    """``desktop screenshot`` — one PNG of the live framebuffer."""
    from vnc_remote_secure.engine.application import recordings

    try:
        png = recordings.screenshot(_cli_actor())
    except Exception as e:  # noqa: BLE001 - capture errors vary per OS
        print(f"Error: screenshot failed: {e}", file=sys.stderr)
        return 1
    out = getattr(args, "output", None) or "screenshot.png"
    try:
        with open(out, "wb") as fh:
            fh.write(png)
    except OSError as e:
        print(f"Error: cannot write {out}: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps({"file": out, "bytes": len(png)}, indent=2))
    else:
        print(f"Screenshot saved: {out} ({len(png)} bytes)")
    return 0


def cmd_desktop(args) -> int:
    """Desktop capture actions (screenshot)."""
    action = getattr(args, "desktop_action", None)
    if action == "screenshot":
        return _desktop_screenshot(args)
    print(f"Unknown desktop action: {action}")
    return 1


def _rec_list(args) -> int:
    from vnc_remote_secure.engine.application import recordings

    recs = recordings.list_recordings()
    if getattr(args, "json", False):
        print(json.dumps({"recordings": recs}, indent=2))
        return 0
    if not recs:
        print("No recordings.")
        return 0
    print(f"{'ID':<28} {'SIZE':>10} {'RES':<11} {'STATE':<10} OPERATOR")
    for r in recs:
        state = "running" if r.get("running") else "ended" if r.get("ended") else "open"
        res = f"{r.get('width', 0)}x{r.get('height', 0)}"
        print(
            f"{r['id']:<28} {r.get('size', 0):>10} {res:<11} "
            f"{state:<10} {r.get('operator', '')}"
        )
    return 0


def _rec_download(args) -> int:
    """``recording download <id>`` — write the .vrsrec blob to disk."""
    from vnc_remote_secure.engine.application import recordings

    try:
        data, name = recordings.read(args.recording_id, _cli_actor())
    except FileNotFoundError:
        print(f"Error: recording '{args.recording_id}' not found.", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    out = getattr(args, "output", None) or name
    try:
        with open(out, "wb") as fh:
            fh.write(data)
    except OSError as e:
        print(f"Error: cannot write {out}: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps({"file": out, "bytes": len(data)}, indent=2))
    else:
        print(f"Recording saved: {out} ({len(data)} bytes)")
    return 0


def _rec_start(args) -> int:
    from vnc_remote_secure.engine.application import recordings

    if getattr(args, "dry_run", False):
        print("[DRY RUN] Would start a desktop recording")
        return 0
    try:
        meta = recordings.start(_cli_actor())
    except Exception as e:  # noqa: BLE001
        print(f"Error: recording start failed: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(meta, indent=2))
    else:
        print(f"Recording started: {meta['id']}")
    return 0


def _rec_stop(args) -> int:
    from vnc_remote_secure.engine.application import recordings

    if getattr(args, "dry_run", False):
        print(f"[DRY RUN] Would stop recording '{args.recording_id}'")
        return 0
    try:
        meta = recordings.stop(args.recording_id, _cli_actor())
    except FileNotFoundError:
        print(f"Error: recording '{args.recording_id}' not running.", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(meta, indent=2))
    else:
        print(f"Recording '{args.recording_id}' stopped.")
    return 0


def _rec_delete(args) -> int:
    from vnc_remote_secure.engine.application import recordings

    if getattr(args, "dry_run", False):
        print(f"[DRY RUN] Would delete recording '{args.recording_id}'")
        return 0
    try:
        recordings.delete(args.recording_id, _cli_actor())
    except FileNotFoundError:
        print(f"Error: recording '{args.recording_id}' not found.", file=sys.stderr)
        return 1
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(f"Recording '{args.recording_id}' deleted.")
    return 0


def cmd_recording(args) -> int:
    """Manage desktop recordings (.vrsrec)."""
    action = getattr(args, "recording_action", None)
    handlers = {
        "list": _rec_list,
        "download": _rec_download,
        "start": _rec_start,
        "stop": _rec_stop,
        "delete": _rec_delete,
    }
    handler = handlers.get(action) if isinstance(action, str) else None
    if handler is None:
        print(f"Unknown recording action: {action}")
        return 1
    return handler(args)
