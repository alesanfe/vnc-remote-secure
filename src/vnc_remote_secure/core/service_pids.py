"""PID tracking and process-ownership helpers for the service manager.

This module owns everything related to *recording and terminating*
service processes:

- Per-service PID files under ``run/pids/<service>.pid`` (atomic
  writes, sidecar ``.meta`` identity files for PID-reuse detection).
- Process liveness probes (``tasklist`` on Windows, ``kill(pid, 0)``
  plus a ``/proc`` zombie check on POSIX).
- Ownership verification (cmdline needles + boot-relative start
  tokens) so ``stop`` never kills a foreign process that recycled a
  recorded PID.
- ``_kill_pid``: the only sanctioned way to terminate a managed
  process — fail-closed when identity cannot be verified.
- ``_GlobalLock``: the cross-process file lock (filelock → flock on
  POSIX, msvcrt on Windows) that prevents duplicate instances.

``service_manager`` re-exports every name here; nothing outside this
module should write PID files or signal service processes directly.
"""

import contextlib
import logging
import os
import signal
import subprocess
import time
from contextlib import suppress

from vnc_remote_secure.core.paths import get_run_dir
from vnc_remote_secure.core.processes import run_cmd
from vnc_remote_secure.platform.detection import is_windows

logger = logging.getLogger(__name__)

_LOCK_FILE_NAME = "vnc-remote.lock"
_PID_DIR_NAME = "pids"


def _pid_dir() -> str:
    """Return the directory where per-service PID files live."""
    d = os.path.join(get_run_dir(), _PID_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def _lock_path() -> str:
    return os.path.join(get_run_dir(), _LOCK_FILE_NAME)


def _pid_file(service: str) -> str:
    return os.path.join(_pid_dir(), f"{service}.pid")


def _proc_start_token(pid: int) -> str | None:
    """Boot-relative process start token for PID-reuse detection.

    A PID alone is ambiguous after reuse: the cmdline needles in
    ``_pid_is_ours`` catch *foreign* processes, but a recycled PID
    running the SAME binary would pass them. The start token (process
    creation time) distinguishes the process we spawned from a
    lookalike that took its PID later.
    """
    try:
        import psutil

        return f"psutil:{psutil.Process(pid).create_time()}"
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 - process may have exited
        return None
    if not is_windows():
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                data = f.read().decode("utf-8", errors="replace")
            # Field 22 (starttime) — comm may contain ')' so split
            # after the LAST ')'; post-paren index 19 == field 22.
            return "proc:" + data.rsplit(")", 1)[1].split()[19]
        except (OSError, IndexError):
            return None
    return None


def _pid_meta_file(service: str) -> str:
    return _pid_file(service) + ".meta"


def _write_pid(service: str, pid: int) -> None:
    # Atomic write: a torn pid file would make a healthy service look
    # dead and trigger a duplicate watchdog restart.
    import tempfile

    path = _pid_file(service)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(str(pid))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    # Sidecar identity metadata — the .pid file stays a bare int for
    # compatibility; the meta file strengthens PID-reuse detection.
    token = _proc_start_token(pid)
    if token:
        import json as _json

        try:
            with open(_pid_meta_file(service), "w", encoding="utf-8") as f:
                _json.dump({"pid": pid, "start_token": token, "service": service}, f)
        except OSError:
            pass


def _read_pid_meta(service: str) -> dict | None:
    try:
        import json as _json

        with open(_pid_meta_file(service), encoding="utf-8") as f:
            return _json.load(f)
    except (OSError, ValueError):
        return None


def _read_pid(service: str) -> int | None:
    path = _pid_file(service)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except (ValueError, OSError):
        return None


def _clear_pid(service: str) -> None:
    for path in (_pid_file(service), _pid_meta_file(service)):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError as exc:
                logger.debug("Could not remove PID file %s: %s", path, exc, exc_info=True)


def _pid_alive(pid: int) -> bool:
    """Return True if a process with ``pid`` is currently running."""
    if not pid or pid <= 0:
        return False
    if is_windows():
        try:
            # tasklist with /FI filter is the reliable cross-shell check.
            # The CSV rows are quoted — match the exact field
            # ,"<pid>", rather than a bare substring: pid 12 would
            # otherwise match a row containing pid 12345.
            res = run_cmd(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # res.stdout is None when tasklist output cannot be
            # decoded (non-UTF-8 console locale) — treat as "unknown",
            # not a crash.
            return f',"{pid}",' in (res.stdout or "")
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        os.kill(pid, 0)
    except OSError:  # ProcessLookupError subclasses OSError
        return False
    # os.kill(pid, 0) succeeds on zombies, and our spawned children can
    # sit as zombies until the next Popen triggers subprocess._cleanup —
    # during that window a dead service would be reported as running and
    # the watchdog would never restart it. Check /proc state directly.
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            # comm may contain spaces/parens; state follows the last ')'.
            stat = fh.read()
            state = stat[stat.rfind(")") + 2]
            if state == "Z":
                return False
    except OSError:
        # /proc unavailable (non-Linux POSIX) — fall back to kill result.
        pass
    return True


def _kill_descendants(pid: int, depth: int = 0) -> None:
    """Best-effort SIGTERM to all descendants of ``pid`` (POSIX).

    ``pgrep -P`` lists direct children; recursion covers grandchildren.
    Depth-capped to avoid pathological process graphs.
    """
    if depth > 4:
        return
    try:
        res = run_cmd(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line.isdigit():
            continue
        child = int(line)
        _kill_descendants(child, depth + 1)
        with suppress(OSError):  # ProcessLookupError subclasses OSError
            os.kill(child, signal.SIGTERM)


# Process-name needles per service: most services are python modules
# under ``vnc_remote_secure``, but external binaries (websockify, nginx,
# Xvnc/winvnc, ttyd, ffmpeg) carry their own names. Used to verify a
# recorded PID still belongs to the service before killing it.
_SERVICE_PROC_NEEDLES = {
    # 'tigervnc' covers both the tigervncserver wrapper (the -fg parent
    # we track) and its Xtigervnc child; 'vncserver' is the fallback
    # wrapper the adapter launches when tigervncserver is absent.
    "vnc": ("vnc_remote_secure", "Xvnc", "x11vnc", "winvnc", "tigervnc", "vncserver"),
    "terminal": ("vnc_remote_secure", "ttyd"),
    "websockify": ("websockify",),
    "nginx": ("nginx",),
    "audio": ("vnc_remote_secure", "ffmpeg"),
}


def _pid_is_ours(pid: int, service: str | None = None) -> bool | None:
    """Decide whether ``pid`` belongs to one of our service processes.

    Returns ``True`` (cmdline matches the service's needles), ``False``
    (cmdline read OK and does NOT match), or ``None`` when the identity
    cannot be determined (wmic absent, /proc unavailable, permission
    denied). ``None`` lets the caller keep the previous kill behaviour —
    we only skip the kill when we are CONFIDENT the PID is not ours.
    """
    if not pid or pid <= 0:
        return None
    # PID-reuse guard: when we recorded the process start token at
    # spawn time, a live process with a DIFFERENT token is a lookalike
    # that took the PID — confidently not ours regardless of cmdline.
    if service:
        meta = _read_pid_meta(service)
        if meta and meta.get("pid") == pid and meta.get("start_token"):
            live_token = _proc_start_token(pid)
            if live_token and live_token != meta["start_token"]:
                return False
    needles = _SERVICE_PROC_NEEDLES.get(service or "") or ("vnc_remote_secure", "websockify")

    def _matches(cmdline: str) -> bool:
        return any(n in cmdline for n in needles)

    if is_windows():
        try:
            res = run_cmd(
                [
                    "wmic",
                    "process",
                    "where",
                    f"ProcessId={pid}",
                    "get",
                    "CommandLine",
                    "/FORMAT:LIST",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                return _matches(res.stdout)
            # wmic missing on newer Windows — fall back to PowerShell.
            res = run_cmd(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_Process -Filter " f"'ProcessId={pid}').CommandLine",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            out = res.stdout.strip()
            if out:
                return _matches(out)
            return None  # could not read cmdline
        except (OSError, subprocess.SubprocessError):
            return None
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().decode("utf-8", errors="replace")
        return _matches(cmdline)
    except OSError:
        return None


def _kill_pid(
    pid: int, timeout: float = 5.0, service: str | None = None, force: bool = False
) -> bool:
    """Terminate a process by PID. Returns True if it stopped."""
    if not pid or pid <= 0:
        return True
    if not _pid_alive(pid):
        _clear_pid_by_value(pid)
        return True
    identity = _pid_is_ours(pid, service)
    if identity is False:
        # Stale pid file: the PID exists but belongs to an unrelated
        # process (PID reuse). Do not kill it — just drop the record.
        logger.warning(
            "PID %d exists but is not a vnc_remote_secure process — "
            "removing stale pid file instead of killing",
            pid,
        )
        _clear_pid_by_value(pid)
        return True
    if identity is None and not force:
        # The cmdline could not be read (wmic/PowerShell blocked on
        # Windows, /proc unavailable or denied on POSIX). Killing a PID
        # whose ownership is UNKNOWN can destroy an unrelated process
        # that recycled the number — refuse; the operator can pass
        # --force to override. Callers that spawned the PID themselves
        # (failed-start cleanup) pass force=True since ownership is
        # certain.
        logger.error(
            "Cannot verify that PID %d belongs to %s — refusing to "
            "kill an unidentified process (use --force to override)",
            pid,
            service or "vnc_remote_secure",
        )
        return False
    if is_windows():
        try:
            # /T kills the whole tree: services that spawn children
            # (audio -> ffmpeg, vnc -> winvnc helpers) would otherwise
            # orphan them on stop.
            run_cmd(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        # taskkill returns before the process fully exits — without a
        # settle wait a subsequent start can hit EADDRINUSE on the port
        # the dying process still holds.
        deadline = time.time() + timeout
        while time.time() < deadline and _pid_alive(pid):
            time.sleep(0.1)
    else:
        # Process-group kill first: services spawn with
        # start_new_session so the whole tree (including
        # grandchildren that escaped the pgrep recursion via a
        # double-fork) shares pgid == service pid. killpg is
        # POSIX-only — absent on Windows even when tests simulate
        # the POSIX branch.
        _killpg = getattr(os, "killpg", None)
        if _killpg is not None:
            with suppress(OSError):
                _killpg(pid, signal.SIGTERM)
        # Terminate children first — a dead parent (e.g. the audio
        # supervisor) would orphan grandchildren like ffmpeg, which
        # keep the capture running after `stop`. pgrep covers
        # processes that created their own session.
        _kill_descendants(pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:  # ProcessLookupError subclasses OSError
            _clear_pid_by_value(pid)
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
        if _pid_alive(pid):
            # ProcessLookupError subclasses OSError; POSIX-only branch
            with suppress(OSError):
                os.kill(pid, signal.SIGKILL)  # type: ignore[attr-defined]  # pylint: disable=no-member
    stopped = not _pid_alive(pid)
    if stopped:
        _clear_pid_by_value(pid)
    return stopped


def _clear_pid_by_value(pid: int) -> None:
    """Remove any PID file that points to ``pid``."""
    if not os.path.isdir(_pid_dir()):
        return
    for fname in os.listdir(_pid_dir()):
        if not fname.endswith(".pid"):
            continue
        path = os.path.join(_pid_dir(), fname)
        try:
            with open(path, encoding="utf-8") as f:
                matches = f.read().strip() == str(pid)
            # Close the file before removing it: on Windows an open
            # file cannot be deleted (WinError 32).
            if matches:
                os.remove(path)
        except (OSError, ValueError):
            pass


class _GlobalLock:
    """Cross-process lock — filelock (flock on POSIX, msvcrt on
    Windows) under a non-blocking ``acquire(timeout=0)``.

    filelock owns the platform mechanics (it locks byte 0 via
    ``msvcrt.locking`` / ``fcntl.flock`` — the same primitives the
    hand-rolled version used); this class only keeps the "did we
    get it" contract the callers use.
    """

    def __init__(self):
        self._lock = None
        self._locked = False

    def __enter__(self):
        import filelock

        path = _lock_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = filelock.FileLock(path)
        try:
            # timeout=0 → a single non-blocking attempt; Timeout means
            # another instance holds the lock.
            self._lock.acquire(timeout=0)
            self._locked = True
        except filelock.Timeout:
            self._lock = None
            self._locked = False
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        if self._lock is not None:
            if self._locked:
                with contextlib.suppress(OSError):
                    self._lock.release()
            self._lock = None
            self._locked = False

    @property
    def acquired(self) -> bool:
        return self._locked
