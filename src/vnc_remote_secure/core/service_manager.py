"""Unified service manager for VNC Remote Secure.

This is the single canonical orchestrator for all services. It replaces
the fragmented Bash/PowerShell lifecycle with a Python-native manager
that:

- Acquires a cross-process lock before start/stop/restart to prevent
  duplicate instances (INT-006).
- Tracks every child process PID in ``run/pids/<service>.pid`` so
  ``stop`` kills the exact process started by ``start`` (no
  ``pkill -f`` / ``taskkill /IM`` that can kill unrelated processes).
- Starts exactly the services enabled by the effective configuration
  (INT-001, INT-008, INT-009).
- Reports status from real PIDs, not from port probes that can be
  fooled by unrelated processes (INT-002).
- Cleans up all resources on stop/restart, including the temporary
  user unless ``KEEP_TEMP_USER=true``.

The manager is platform-aware: on Linux it uses ``flock`` for the
global lock and ``kill`` by PID; on Windows it uses a ``msvcrt.locking``
lock and ``taskkill /PID``.
"""
import contextlib
import logging
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from typing import Any

from vnc_remote_secure.core.config import env_flag, get_config, load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_WS_PORT,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.core.paths import find_project_root, get_run_dir
from vnc_remote_secure.core.processes import run_cmd
from vnc_remote_secure.platform.detection import is_windows

logger = logging.getLogger(__name__)

_LOCK_FILE_NAME = 'vnc-remote.lock'
_PID_DIR_NAME = 'pids'


def _pid_dir() -> str:
    """Return the directory where per-service PID files live."""
    d = os.path.join(get_run_dir(), _PID_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def _lock_path() -> str:
    return os.path.join(get_run_dir(), _LOCK_FILE_NAME)


def _pid_file(service: str) -> str:
    return os.path.join(_pid_dir(), f'{service}.pid')


def _write_pid(service: str, pid: int) -> None:
    # Atomic write: a torn pid file would make a healthy service look
    # dead and trigger a duplicate watchdog restart.
    import tempfile
    path = _pid_file(service)
    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(str(pid))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_pid(service: str) -> int | None:
    path = _pid_file(service)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return int(f.read().strip())
    except (ValueError, OSError):
        return None


def _clear_pid(service: str) -> None:
    path = _pid_file(service)
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
                ['tasklist', '/FI', f'PID eq {pid}', '/NH', '/FO', 'CSV'],
                capture_output=True, text=True, timeout=5,
            )
            return f',"{pid}",' in res.stdout
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
        with open(f'/proc/{pid}/stat', encoding='ascii') as fh:
            # comm may contain spaces/parens; state follows the last ')'.
            stat = fh.read()
            state = stat[stat.rfind(')') + 2]
            if state == 'Z':
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
            ['pgrep', '-P', str(pid)],
            capture_output=True, text=True, timeout=5,
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
    'vnc': ('vnc_remote_secure', 'Xvnc', 'x11vnc', 'winvnc',
            'tigervnc', 'vncserver'),
    'terminal': ('vnc_remote_secure', 'ttyd'),
    'websockify': ('websockify',),
    'nginx': ('nginx',),
    'audio': ('vnc_remote_secure', 'ffmpeg'),
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
    needles = _SERVICE_PROC_NEEDLES.get(service or '') or (
        'vnc_remote_secure', 'websockify')

    def _matches(cmdline: str) -> bool:
        return any(n in cmdline for n in needles)

    if is_windows():
        try:
            res = run_cmd(
                ['wmic', 'process', 'where', f'ProcessId={pid}',
                 'get', 'CommandLine', '/FORMAT:LIST'],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                return _matches(res.stdout)
            # wmic missing on newer Windows — fall back to PowerShell.
            res = run_cmd(
                ['powershell', '-NoProfile', '-Command',
                 "(Get-CimInstance Win32_Process -Filter "
                 f"'ProcessId={pid}').CommandLine"],
                capture_output=True, text=True, timeout=10,
            )
            out = res.stdout.strip()
            if out:
                return _matches(out)
            return None  # could not read cmdline
        except (OSError, subprocess.SubprocessError):
            return None
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmdline = f.read().decode('utf-8', errors='replace')
        return _matches(cmdline)
    except OSError:
        return None


def _kill_pid(pid: int, timeout: float = 5.0,
              service: str | None = None, force: bool = False) -> bool:
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
            "removing stale pid file instead of killing", pid)
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
            pid, service or 'vnc_remote_secure')
        return False
    if is_windows():
        try:
            # /T kills the whole tree: services that spawn children
            # (audio -> ffmpeg, vnc -> winvnc helpers) would otherwise
            # orphan them on stop.
            run_cmd(
                ['taskkill', '/F', '/T', '/PID', str(pid)],
                capture_output=True, timeout=10,
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
        _killpg = getattr(os, 'killpg', None)
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
        if not fname.endswith('.pid'):
            continue
        path = os.path.join(_pid_dir(), fname)
        try:
            with open(path, encoding='utf-8') as f:
                matches = f.read().strip() == str(pid)
            # Close the file before removing it: on Windows an open
            # file cannot be deleted (WinError 32).
            if matches:
                os.remove(path)
        except (OSError, ValueError):
            pass


class _GlobalLock:
    """Cross-process lock using flock (Linux) or msvcrt (Windows)."""

    def __init__(self):
        self._fh = None
        self._locked = False

    def __enter__(self):
        path = _lock_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._fh = open(path, 'a+', encoding='utf-8')
        if is_windows():
            import msvcrt
            try:
                # 'a+' opens positioned at EOF — msvcrt locks the byte
                # at the CURRENT position, so a file that ever grew
                # would let two processes lock different bytes and
                # both "win". Seek to 0 so every process locks byte 0.
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                self._locked = True
            except OSError:
                # Could not acquire — another instance holds it.
                self._fh.close()
                self._fh = None
                self._locked = False
        else:
            import fcntl  # pylint: disable=import-error
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._locked = True
            except OSError:
                self._fh.close()
                self._fh = None
                self._locked = False
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._fh is not None:
            if self._locked:
                if is_windows():
                    import msvcrt
                    try:
                        self._fh.seek(0)
                        msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl  # pylint: disable=import-error
                    with contextlib.suppress(OSError):
                        fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
            self._locked = False

    @property
    def acquired(self) -> bool:
        return self._locked


def _port_in_use(port: int, host: str = '127.0.0.1') -> bool:
    """Return True if ``host:port`` is held by another socket.

    Uses a bind probe, not connect_ex: connecting consumes a backlog
    slot on the listener and a listener with a full backlog returns
    WSAEWOULDBLOCK/ECONNREFUSED — falsely reporting the port free.
    Binding fails with EADDRINUSE for any holder regardless of backlog.

    Caveat: a port in TIME_WAIT also fails bind. To avoid a stale
    TIME_WAIT blocking a legitimate restart, when bind fails we
    additionally probe connect_ex — a successful connect confirms a
    live listener. bind-fail + connect-fail means TIME_WAIT (or a
    full backlog — in that case the child will fail to bind anyway
    and the post-start check reports the real failure).
    """
    import socket
    try:
        with socket.socket() as s:
            s.bind((host, port))
        return False
    except OSError:
        pass
    try:
        with socket.socket() as s:
            s.settimeout(1.0)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def _port_accepting(port: int, host: str = '127.0.0.1') -> bool:
    """Return True if a live listener accepts TCP connections on ``port``.

    Used by the post-start verification: the child must not only hold
    the port but actually accept — this distinguishes a bound service
    from a lingering TIME_WAIT socket.
    """
    import socket
    try:
        with socket.socket() as s:
            s.settimeout(1.0)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def audit_internal_listeners(config: dict) -> list:
    """Verify security-internal ports are not bound publicly.

    The RFB port and the WebSocket→RFB bridge MUST stay on loopback —
    the gateway/noVNC proxy is the only legitimate public path to the
    desktop, and a legacy VNC DES credential is not a defence. Other
    backend services are checked too but only flagged when the
    deployment runs nginx (they are meant to be fronted then).

    Reuses doctor's listener enumeration (psutil, then netstat/ss
    fallback) so the post-start audit and ``doctor`` see the same
    socket table.

    Returns:
        A list of human-readable findings (empty = clean).
    """
    try:
        from vnc_remote_secure.core.doctor import _is_loopback_addr, _list_listeners
    except ImportError:
        return []
    listeners = _list_listeners()
    if not listeners:
        return []
    findings = []
    # _service_port_map resolves the EFFECTIVE VNC port (Linux derives
    # it from the display number, not VNC_PORT) — the audit must probe
    # the port TigerVNC actually bound.
    ports = _service_port_map(config)
    strict = {'vnc': ports.get('vnc'),
              'websockify': ports.get('websockify')}
    backend_ports = {p for s, p in ports.items()
                     if s not in strict and p}
    for addr, port in listeners:
        if _is_loopback_addr(addr):
            continue
        for service, expected in strict.items():
            if expected and port == int(expected):
                findings.append(
                    f'{service} port {port} listening on {addr} — '
                    'MUST be loopback-only (public RFB exposure)')
        # Backend services: only flagged when nginx fronts them —
        # without a reverse proxy they ARE the public entry points
        # by design.
        if config.get('nginx_enabled') and port in backend_ports:
            findings.append(
                f'backend port {port} listening on {addr} — '
                'nginx deployment expects loopback backends')
    return findings


def _reap_stale_service(module: str, service_name: str, port: int):
    """Best-effort kill of an orphaned service process holding ``port``.

    A crashed/aborted run can leave a service process alive without a
    PID file — it then occupies the port forever and every subsequent
    start fails with EADDRINUSE. When psutil is available, look for a
    listener on ``port`` whose command line references this service's
    module and kill it. Foreign processes are never touched.
    """
    try:
        import psutil
    except ImportError:
        return
    marker = module
    own_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Never match ourselves — a caller that embeds the module
            # name in its own command line (tests, wrappers) must not
            # be reaped.
            if proc.info['pid'] == own_pid:
                continue
            cmdline = ' '.join(proc.info.get('cmdline') or [])
            if marker not in cmdline:
                continue
            for conn in proc.net_connections('tcp'):
                if (conn.laddr and conn.laddr.port == port
                        and conn.status == 'LISTEN'):
                    logger.warning(
                        "Killing orphaned %s (PID %s) holding port %s",
                        service_name, proc.info['pid'], port)
                    proc.kill()
                    proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue


def _start_python_service(module: str, service_name: str,
                          extra_args: list | None = None,
                          port: int | None = None) -> int | None:
    """Start a Python service module as a subprocess and record its PID.

    Returns the PID on success, None on failure.
    """
    existing = _read_pid(service_name)
    if existing and _pid_alive(existing):
        if _pid_is_ours(existing, service_name) is False:
            # Stale pid file pointing at a reused foreign PID — drop the
            # record instead of reporting "already running" forever.
            logger.warning(
                "Service %s pid file points at foreign PID %d — "
                "clearing stale record", service_name, existing)
            _clear_pid(service_name)
        else:
            logger.info("Service %s already running (PID %s)",
                        service_name, existing)
            return existing
    # Pre-check: if the service port is already occupied, either an
    # orphaned copy of ours survived a crash (reap it) or a foreign
    # process owns it (fail loudly — never kill foreign processes).
    if port and _port_in_use(port):
        _reap_stale_service(module, service_name, port)
        if _port_in_use(port):
            logger.error(
                "%s port %s is already in use by another process — "
                "not starting %s", service_name, port, service_name)
            return None
    cmd = [sys.executable, '-m', module] + list(extra_args or [])
    # websockify is an external binary that performs no auth and needs
    # none of our credentials — strip secret env vars so a compromise
    # of the bridge cannot read VNC_PASSWORD/AUTH_SECRET/etc. from its
    # environment. Our own service modules keep the full env (they
    # read .env themselves anyway).
    child_env = None
    if module == 'websockify':
        # sanitized_child_env never returns None — an env=None fallback
        # would leak every secret to an unauthenticated helper.
        try:
            from vnc_remote_secure.security.redaction import (
                sanitized_child_env,
            )
            child_env = sanitized_child_env()
        except Exception:  # noqa: BLE001 - import broken entirely
            child_env = {'PATH': os.environ.get('PATH', '')}
    # Route service stdout/stderr to a per-service log file under the
    # canonical log dir — DEVNULL would silently discard every error
    # (import failures, bind errors, tracebacks) making a dead service
    # impossible to diagnose.
    from vnc_remote_secure.core.paths import get_log_dir
    log_fh: Any
    try:
        os.makedirs(get_log_dir(), exist_ok=True)
        log_fh = open(  # noqa: SIM115 - fd lives with the child process
            os.path.join(get_log_dir(), f'{service_name}.log'),
            'a', buffering=1, encoding='utf-8', errors='replace')
    except OSError:
        log_fh = subprocess.DEVNULL
    # Own process group/session: services must outlive the terminal
    # that ran `vnc-remote start` (no SIGHUP/CTRL+C propagation), and
    # a group lets _kill_pid reach descendants that escaped the
    # pgrep recursion (double-forked grandchildren share the group).
    _popen_kw: dict = {}
    if is_windows():
        # New process group — console CTRL+C must not propagate to
        # services spawned from an interactive shell.
        _popen_kw['creationflags'] = getattr(
            subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    else:
        _popen_kw['start_new_session'] = True
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=child_env,
            **_popen_kw,
        )
    except OSError:
        logger.exception("Failed to start %s:", service_name)
        return None
    # Post-start verification: a process that is alive but never bound
    # its port (EADDRINUSE inside, import error that caught itself)
    # must not be reported as "started" — status would show "running"
    # for a functionally dead service.
    if port:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if proc.poll() is not None:
                logger.error(
                    "%s exited during startup (code %s) — see %s.log",
                    service_name, proc.returncode, service_name)
                return None
            if _port_accepting(port):
                break
            time.sleep(0.15)
        else:
            logger.error(
                "%s did not bind port %s within 5s — terminating",
                service_name, port)
            _kill_pid(proc.pid, service=service_name, force=True)
            return None
    _write_pid(service_name, proc.pid)
    logger.info("Started %s (PID %s)", service_name, proc.pid)
    return proc.pid


def _enabled_services(config: dict) -> list:
    """Return the list of service names to start, based on config."""
    services = ['vnc', 'terminal', 'novnc', 'landing']
    # The standalone health server is optional — HEALTH_WEB_ENABLED
    # gates it (the Flask UI exposes the same endpoints on
    # USER_UI_PORT when the standalone server is off).
    if config.get('health_web_enabled', True):
        services.append('health')
    # The WebSocket→RFB bridge runs alongside noVNC so the browser
    # client can actually reach the VNC server. It only listens on
    # loopback; the authenticated noVNC static server proxies WS
    # upgrades to it after the auth-gateway check.
    services.append('websockify')
    if config.get('user_ui_enabled'):
        services.append('user_ui')
    if config.get('audio_stream_enabled'):
        services.append('audio')
    if config.get('gamepad_enabled'):
        services.append('gamepad')
    # nginx is Linux-only — on Windows the landing portal is the public
    # entry point and there is no nginx binary to supervise. Listing it
    # here would report a bogus "Failed to start: nginx" (and fire the
    # failure alert) on every Windows start.
    if config.get('nginx_enabled') and not is_windows():
        services.append('nginx')
    # Prometheus and Grafana are external binaries managed by the
    # platform adapter (systemd/Windows Service), not Python services.
    # They are not started here; configure them via the platform adapter.
    return services


def start_all(config: dict | None = None) -> dict:
    """Start all enabled services.

    Returns a dict mapping service name to PID (or None on failure).
    Acquires the global lock; if another instance is already running,
    returns the existing PIDs without starting duplicates.
    """
    if config is None:
        config = get_config()
    load_env_file()

    # Ensure the auth signing secret exists before starting services so
    # that ephemeral session tokens created by the CLI are valid in the
    # service processes (they all read the same secret file).
    from vnc_remote_secure.security.authentication import _get_secret
    _get_secret()

    with _GlobalLock() as lock:
        if not lock.acquired:
            logger.warning("Another instance is already managing services; "
                           "returning existing PIDs")
            return status_all()

        # A crashed run (SIGKILL/power loss) never ran stop, so the
        # temp user may still exist — sweep it before services spawn.
        _sweep_stale_temp_user()

        results = {}
        for service in _enabled_services(config):
            results[service] = _start_service(service, config)

        # Service lifecycle belongs in the audit trail — a stopped or
        # respawned service is a security-relevant event, not just an
        # operational one.
        for service, pid in results.items():
            _audit_lifecycle(
                'service_start' if pid else 'service_start_failed',
                service, pid)

        # Alert on start failures (replaces the legacy Bash alerts).
        failed = [s for s, pid in results.items() if not pid]
        if failed:
            try:
                from vnc_remote_secure.monitoring.alerts import notify
                notify('Service start failure',
                       f"Failed to start: {', '.join(failed)}",
                       severity='error')
            except Exception:  # noqa: BLE001 - alerting is best-effort
                pass

        # Listener audit: a service that bound publicly when it must be
        # loopback-only (RFB, websockify) is a perimeter breach even if
        # every service started "successfully".
        findings = audit_internal_listeners(config)
        for f in findings:
            logger.error("LISTENER AUDIT: %s", f)
        if findings:
            from vnc_remote_secure.security.audit import audit_event
            audit_event('listener_audit_failure',
                      detail='; '.join(findings))
            if config.get('security_profile') in (
                    'public-hardened', 'private-overlay'):
                try:
                    from vnc_remote_secure.monitoring.alerts import notify
                    notify('Public listener detected',
                           '; '.join(findings), severity='critical')
                except Exception:  # noqa: BLE001
                    pass
        return results


# Service name → config key holding the TCP port it binds. Used by
# the pre-start port check and the post-start bind verification.
_SERVICE_PORT_KEYS = {
    'terminal': 'ttyd_port',
    'novnc': 'novnc_port',
    'websockify': 'novnc_ws_port',
    'health': 'health_port',
    'landing': 'landing_port',
    'user_ui': 'user_ui_port',
    'audio': 'audio_stream_port',
    'gamepad': 'gamepad_port',
}


def _metric(name: str, labels: str = '') -> None:
    """Emit a Prometheus counter (best-effort — metrics never break lifecycle)."""
    from vnc_remote_secure.monitoring.prometheus import inc_counter
    inc_counter(name, labels)


def _audit_lifecycle(event: str, service: str, pid) -> None:
    """Record a service lifecycle transition in the audit log."""
    from vnc_remote_secure.security.audit import audit_event
    audit_event(event, detail=f'service={service} pid={pid}')


def _start_service(service: str, config: dict) -> int | None:
    """Start a single service by name. Returns PID or None."""
    port_key = _SERVICE_PORT_KEYS.get(service)
    port = config.get(port_key) if port_key else None
    if service == 'vnc':
        return _start_vnc(config)
    if service == 'terminal':
        return _start_terminal(config)
    if service == 'novnc':
        return _start_novnc(config)
    if service == 'websockify':
        return _start_websockify(config)
    if service == 'health':
        return _start_python_service('vnc_remote_secure.services.health', 'health',
                                     port=port)
    if service == 'landing':
        return _start_python_service('vnc_remote_secure.services.landing', 'landing',
                                     port=port)
    if service == 'user_ui':
        return _start_python_service('vnc_remote_secure.web.application', 'user_ui',
                                     port=port)
    if service == 'audio':
        return _start_python_service('vnc_remote_secure.services.audio', 'audio',
                                     port=port)
    if service == 'gamepad':
        return _start_python_service('vnc_remote_secure.services.gamepad', 'gamepad',
                                     port=port)
    if service == 'nginx':
        return _start_nginx(config)
    logger.warning("Unknown service: %s", service)
    return None


def _start_vnc(config: dict) -> int | None:
    """Start the VNC server via the platform adapter."""
    from vnc_remote_secure.services.vnc import start_vnc
    display = config.get('vnc_display', ':1')
    geometry = config.get('vnc_geometry', '1280x720')
    depth = config.get('vnc_depth', 24)
    password = config.get('vnc_password')
    try:
        result = start_vnc(display, geometry, depth, password)
        pid = result if isinstance(result, int) else getattr(result, 'pid', None)
        if pid:
            try:
                _write_pid('vnc', pid)
            except OSError as e:
                # An unrecorded PID orphans the process — stop() would
                # never find it. Kill the spawn we just made so the
                # reported failure matches reality.
                logger.exception(
                    "VNC started (PID %s) but pid-file write failed "
                    "(%s) — terminating the orphan", pid, e)
                _kill_pid(pid, service='vnc', force=True)
                return None
        return pid
    except Exception:
        logger.exception("Failed to start VNC:")
        return None


def _start_terminal(config: dict) -> int | None:
    """Start the web terminal.

    On Linux, prefer the Python Tornado terminal (services.terminal) so
    that auth_gateway and WebSocket registry are connected. On Windows,
    the same module is used (it was designed for ConPTY issues).
    """
    return _start_python_service(
        'vnc_remote_secure.services.terminal', 'terminal',
        port=config.get('ttyd_port'))


def _resolve_novnc_dir() -> str | None:
    """Locate the noVNC static assets directory.

    Resolution order: ``NOVNC_DIR`` env var, then ``<project_root>/novnc``
    (where ``make setup-novnc`` clones noVNC). Returns ``None`` when no
    directory exists — the caller must not start the static server
    without one, or it would serve the process CWD (which may expose
    ``.env`` and the source tree).
    """
    candidate = os.environ.get('NOVNC_DIR', '').strip()
    if candidate and os.path.isdir(candidate):
        return candidate
    project_root = find_project_root()
    candidate = os.path.join(project_root, 'novnc')
    if os.path.isdir(candidate):
        return candidate
    return None


def _start_novnc(config: dict) -> int | None:
    """Start the noVNC static server.

    The Python services.novnc serves static files; websockify is started
    separately by the platform adapter when needed. We start the Python
    static server so auth can be enforced.
    """
    novnc_dir = _resolve_novnc_dir()
    if not novnc_dir:
        logger.error(
            "noVNC assets directory not found. Run 'make setup-novnc' to "
            "clone noVNC into <project>/novnc, or set NOVNC_DIR in .env. "
            "Refusing to start the static server without a web root.")
        return None
    return _start_python_service(
        'vnc_remote_secure.services.novnc', 'novnc', [novnc_dir],
        port=config.get('novnc_port'))


def _start_websockify(config: dict) -> int | None:
    """Start the WebSocket→RFB bridge on loopback.

    ``websockify`` listens on ``NOVNC_WS_PORT`` (default 5700, loopback
    only) and forwards to the VNC server. Clients never reach it
    directly: the authenticated noVNC static server proxies
    ``/websockify`` upgrades to it after the auth-gateway check.
    """
    ws_port = config.get('novnc_ws_port', DEFAULT_NOVNC_WS_PORT)
    vnc_port = config.get('vnc_port', DEFAULT_VNC_PORT)
    if not is_windows():
        # TigerVNC binds 5900+N for display :N regardless of an
        # explicit VNC_PORT (the adapter never passes -rfbport). The
        # bridge must target the port the server actually binds —
        # services/vnc._vnc_port() performs the same derivation for
        # its liveness probe; config['vnc_port'] may hold an explicit
        # value that points at a dead port.
        try:
            from vnc_remote_secure.services.vnc import _vnc_port
            vnc_port = _vnc_port(config.get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config value
            pass
    bind = os.environ.get('BIND_HOST', '127.0.0.1')
    if bind != '127.0.0.1':
        # The bridge must never be publicly reachable — it performs no
        # auth of its own; authentication happens at the noVNC static
        # server which proxies to it.
        logger.warning(
            "BIND_HOST=%s but websockify has no auth — forcing loopback",
            bind)
    return _start_python_service(
        'websockify', 'websockify',
        [f'127.0.0.1:{ws_port}', f'127.0.0.1:{vnc_port}'],
        port=ws_port,
    )


def _start_nginx(config: dict) -> int | None:
    """Start nginx via systemctl (Linux) or the platform adapter."""
    if is_windows():
        logger.info("nginx not supported on Windows via service manager; skipping")
        return None
    try:
        res = run_cmd(
            ['systemctl', 'start', 'nginx'],
            capture_output=True, timeout=15,
        )
        if res.returncode == 0:
            # Ask systemd for the unit's MainPID instead of pgrep —
            # pgrep order is arbitrary and can adopt a worker or a
            # foreign nginx for later SIGKILL.
            try:
                show = run_cmd(
                    ['systemctl', 'show', '-p', 'MainPID', '--value', 'nginx'],
                    capture_output=True, text=True, timeout=5,
                )
                mpid = int(show.stdout.strip())
                if mpid > 0:
                    _write_pid('nginx', mpid)
                    return mpid
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            return None
        # Fallback: try direct nginx binary
        res = run_cmd(
            ['nginx'], capture_output=True, timeout=10,
        )
        if res.returncode == 0:
            # Find the nginx master PID — ppid==1 distinguishes the
            # daemonized master from its workers (ppid=master). pgrep
            # order is arbitrary, so picking pids[0] could adopt a
            # worker (or a foreign nginx) for later SIGKILL.
            try:
                res = run_cmd(
                    ['pgrep', '-x', 'nginx'], capture_output=True, text=True, timeout=5,
                )
                pids = [int(p) for p in res.stdout.split() if p.strip().isdigit()]
                for pid in pids:
                    try:
                        with open(f'/proc/{pid}/stat', encoding='ascii') as fh:
                            stat = fh.read()
                        if int(stat[stat.rfind(')') + 2:].split()[1]) == 1:
                            _write_pid('nginx', pid)
                            return pid
                    except (OSError, ValueError, IndexError):
                        continue
            except (OSError, ValueError):
                pass
        return None
    except (OSError, subprocess.SubprocessError):
        logger.exception("Failed to start nginx:")
        return None


def stop_all(force: bool = False) -> dict:
    """Stop all managed services by PID. Returns a dict of service -> stopped_bool."""
    with _GlobalLock() as lock:
        if not lock.acquired:
            # Proceeding without the lock can kill services a concurrent
            # start_all is mid-spawn on (PID written, port still binding)
            # leaving a half-dead deployment — refuse instead.
            logger.error("Another instance holds the lock; refusing to "
                         "stop without it")
            return {'error': 'lock held by another instance'}
        results = {}
        # Stop in reverse order of start.
        services = ['nginx', 'gamepad', 'audio',
                    'user_ui', 'websockify', 'health', 'landing', 'novnc',
                    'terminal', 'vnc']
        for service in services:
            pid = _read_pid(service)
            if pid:
                results[service] = _kill_pid(pid, service=service,
                                             force=force)
                _audit_lifecycle(
                    'service_stop' if results[service]
                    else 'service_stop_failed', service, pid)
                if results[service]:
                    _clear_pid(service)
                # else: keep the pid file so a --force retry (or a
                # later stop once identity is readable) can still
                # find the process.
            else:
                results[service] = True
        # Clean up the temporary user unless KEEP_TEMP_USER is set.
        _cleanup_temp_user()
        return results


def restart_all(config: dict | None = None) -> dict:
    """Stop all services, clean up, then start them again.

    Holds the cross-process lock across both phases so a concurrent
    ``start``/``stop`` cannot race in the gap between stop and start.
    """
    from vnc_remote_secure.security.authentication import _get_secret
    _get_secret()
    if config is None:
        config = get_config()

    with _GlobalLock() as lock:
        if not lock.acquired:
            logger.warning("Another instance is already managing services; "
                           "skipping restart")
            return status_all()
        # Stop in reverse order of start (same list as stop_all).
        stop_order = ['nginx', 'gamepad', 'audio',
                      'user_ui', 'websockify', 'health', 'landing', 'novnc',
                      'terminal', 'vnc']
        for service in stop_order:
            pid = _read_pid(service)
            if pid:
                _kill_pid(pid, service=service)
                _clear_pid(service)
        _cleanup_temp_user()
        # Brief pause to let sockets release; bounded and inside the lock.
        time.sleep(0.5)
        # Start all services with the requested config.
        results = {}
        for service in _enabled_services(config):
            results[service] = _start_service(service, config)
        return results


def _service_port_map(config: dict) -> dict:
    """Return the service -> expected port map for status/watchdog probes."""
    # On Linux TigerVNC binds 5900+display regardless of an explicit
    # VNC_PORT — report the effective port so status agrees with the
    # doctor probe and the landing portal (same derivation as
    # services/vnc._vnc_port and _start_websockify).
    vnc_port = config.get('vnc_port')
    if not is_windows():
        try:
            from vnc_remote_secure.services.vnc import _vnc_port
            vnc_port = _vnc_port(config.get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config value
            pass
    return {
        'vnc': vnc_port,
        'terminal': config.get('ttyd_port'),
        'novnc': config.get('novnc_port'),
        'health': config.get('health_port'),
        'landing': config.get('landing_port'),
        'user_ui': config.get('user_ui_port'),
        'audio': config.get('audio_stream_port'),
        'websockify': config.get('novnc_ws_port'),
        'gamepad': config.get('gamepad_port'),
        'nginx': (int(os.environ.get(
            'NGINX_HTTPS_PORT', str(DEFAULT_NGINX_HTTPS_PORT)))
            if config.get('nginx_enabled') else None),
    }


def status_all() -> dict:
    """Return real status of every managed service from PIDs.

    Each entry includes ``running``, ``pid``, and ``port`` (when known)
    so the health endpoints can report the documented schema.
    """
    config = get_config()
    # On Linux TigerVNC binds 5900+display regardless of an explicit
    # VNC_PORT — report the effective port so status agrees with the
    # doctor probe and the landing portal (same derivation as
    # services/vnc._vnc_port and _start_websockify).
    port_map = _service_port_map(config)
    services = list(port_map.keys())
    enabled = set(_enabled_services(config))
    result = {}
    for service in services:
        pid = _read_pid(service)
        alive = _pid_alive(pid) if pid else False
        # PID reuse check: a stale pid file pointing at a foreign,
        # still-living process must not report the service as running.
        if alive and pid is not None and _pid_is_ours(pid, service) is False:
            alive = False
        port = port_map.get(service)
        # A live PID is not enough: a hung service (deadlocked event
        # loop, crashed acceptor) keeps the process alive while the
        # listener is gone. Probe the port when known — but only for
        # services this manager spawned; nginx may be system-managed.
        if alive and port and service != 'nginx':
            # probe is best-effort
            with suppress(Exception):
                alive = _port_accepting(port)
        entry = {
            'pid': pid,
            'running': alive,
        }
        if service not in enabled:
            # Intentionally disabled — report as such instead of
            # looking like a crashed service.
            entry['enabled'] = False
        if port:
            entry['port'] = port
        result[service] = entry
        if not alive and pid:
            _clear_pid(service)
    return result


# Services found dead on the previous watchdog iteration. Module-level
# so alerts fire only on state transitions (a service that stays down
# is not re-alerted every interval).
_last_watchdog_dead: set = set()

# Restart throttling: timestamps of recent auto-restarts per service.
# Without a cap, a permanently broken service would be respawned every
# watchdog tick forever (~2880 restarts/day at the 30s default).
_RESTART_WINDOW_S = 600
_RESTART_MAX = 5
_restart_history: dict = {}

# Services currently in the restart-suppressed state (alert once on
# entry, not every tick).
_last_throttled: set = set()


def _restart_allowed(service: str, now: float) -> bool:
    """Return True if ``service`` may be auto-restarted (rate-limited)."""
    hist = [t for t in _restart_history.get(service, [])
            if now - t < _RESTART_WINDOW_S]
    _restart_history[service] = hist
    return len(hist) < _RESTART_MAX


def _record_restart(service: str, now: float) -> None:
    _restart_history.setdefault(service, []).append(now)


def watchdog_tick(config: dict | None = None) -> dict:
    """One watchdog iteration over all enabled services.

    Checks every enabled service's recorded PID. When ``auto_restart``
    is enabled, dead services are restarted in place. An alert is
    dispatched (subject to ALERTS_ENABLED) on state transitions only.

    Args:
        config: Effective config dict (``healthcheck_enabled``,
            ``auto_restart``).

    Returns:
        Dict of service -> new PID (or None) for services found dead;
        empty dict when everything is healthy or the watchdog is
        disabled.
    """
    if config is None:
        config = get_config()
    if not config.get('healthcheck_enabled', True):
        return {}

    dead = _find_dead_services(config)
    global _last_watchdog_dead
    dead_set = set(dead)
    auto = config.get('auto_restart', False)
    # The dedup early-return must not apply while auto-restart is on:
    # a service whose restart attempt failed stays in dead_set, and
    # skipping the tick would mean never retrying it.
    if dead_set == _last_watchdog_dead and not auto:
        return {}
    newly_dead = dead_set - _last_watchdog_dead
    _last_watchdog_dead = dead_set
    if not dead_set:
        return {}

    results = _auto_restart_dead(dead, config) if auto else {}
    _alert_watchdog_transitions(newly_dead, dead, results, auto)
    return results


def _find_dead_services(config: dict) -> list:
    """Return enabled services whose PID is dead or port is hung."""
    dead = []
    port_map = _service_port_map(config)
    for service in _enabled_services(config):
        pid = _read_pid(service)
        if not pid or not _pid_alive(pid):
            dead.append(service)
            continue
        # A hung process (alive PID, dead listener) is as dead as a
        # crashed one — the watchdog exists to catch exactly this.
        port = port_map.get(service)
        if port and service != 'nginx':
            try:
                if not _port_accepting(port):
                    dead.append(service)
            except Exception:  # noqa: BLE001 - probe is best-effort
                pass
    return dead


def _auto_restart_dead(dead: list, config: dict) -> dict:
    """Restart dead services, honouring the per-service rate limit."""
    results = {}
    now = time.monotonic()
    throttled = []
    for service in dead:
        if not _restart_allowed(service, now):
            throttled.append(service)
            _metric('vnc_remote_service_restart_throttled_total',
                    f'service={service}')
            continue
        _record_restart(service, now)
        _metric('vnc_remote_service_restarts_total',
                f'service={service}')
        # A hung-but-alive service (dead listener, live PID) must be
        # killed before respawn — otherwise it orphans and the next
        # watchdog cycle finds it again.
        pid = _read_pid(service)
        if pid and _pid_alive(pid):
            _kill_pid(pid, service=service)
        _clear_pid(service)
        results[service] = _start_service(service, config)
        _audit_lifecycle(
            'service_restart' if results[service]
            else 'service_restart_failed', service, results[service])
    if throttled:
        _alert_throttled(throttled)
    return results


def _alert_throttled(throttled: list):
    """Log and alert once on the transition into the throttled state."""
    # Not on every tick while the service stays down.
    newly_throttled = [s for s in throttled
                       if s not in _last_throttled]
    _last_throttled.update(throttled)
    for s in set(_last_throttled) - set(throttled):
        _last_throttled.discard(s)
    logger.error(
        "Auto-restart suppressed (>%d restarts in %ds): %s — "
        "the service is kept down; fix the cause and run "
        "'vnc-remote start' manually",
        _RESTART_MAX, _RESTART_WINDOW_S, ', '.join(throttled))
    if newly_throttled:
        try:
            from vnc_remote_secure.monitoring.alerts import notify
            notify('Auto-restart suppressed',
                   'Restart limit reached for: '
                   + ', '.join(newly_throttled),
                   severity='error')
        except Exception:  # noqa: BLE001 - alerting is best-effort
            pass


def _alert_watchdog_transitions(newly_dead, dead, results, auto):
    """Fire service-down/restarted alerts on state transitions only.

    Restarting every tick is correct, but re-alerting every tick would
    be notification spam.
    """
    if not newly_dead:
        return
    try:
        from vnc_remote_secure.monitoring.alerts import notify
        still_dead = [s for s in dead if not results.get(s)]
        if still_dead:
            notify('Services down',
                   'Dead services: ' + ', '.join(still_dead)
                   + ('' if auto else ' (AUTO_RESTART disabled)'),
                   severity='error')
        elif auto:
            notify('Services restarted',
                   'Watchdog restarted: ' + ', '.join(results),
                   severity='warning')
    except Exception:  # noqa: BLE001 - alerting is best-effort
        pass


def _sweep_stale_temp_user() -> None:
    """Remove a temp user left behind by a crashed run.

    ``stop`` removes the temp user, but SIGKILL/power loss never ran
    stop — on the next start the account would linger indefinitely.
    Removal is guarded: if the account still OWNS processes, an
    active (orphaned) session may be using it and deleting the user
    under live processes orphans their files/IPC — warn instead.
    """
    if is_windows():
        return
    if env_flag('KEEP_TEMP_USER', 'false'):
        return
    temp_user = os.environ.get('TEMP_USER', 'remote')
    if not temp_user:
        return
    try:
        import pwd
        pwd.getpwnam(temp_user)  # type: ignore[attr-defined]
    except KeyError:
        return  # not present — nothing stale
    except ImportError:
        return
    try:
        r = subprocess.run(
            ['pgrep', '-u', temp_user],
            capture_output=True, timeout=10, check=False)
        if r.returncode == 0 and r.stdout.strip():
            logger.warning(
                "Temp user %s still owns processes (orphaned session?) "
                "— left in place; clean it up manually or via stop",
                temp_user)
            return
    except Exception:  # noqa: BLE001 - can't prove it's safe
        logger.debug(
            "Could not enumerate %s processes — skipping temp-user "
            "sweep", temp_user)
        return
    try:
        from vnc_remote_secure.platform.base import get_adapter
        if get_adapter().remove_runtime_user(temp_user):
            logger.info(
                "Swept stale temp user %s left by a crashed run",
                temp_user)
    except Exception as e:  # noqa: BLE001
        logger.debug("Stale temp-user sweep failed for %s: %s",
                     temp_user, e)


def _cleanup_temp_user() -> None:
    """Remove the temporary user unless KEEP_TEMP_USER=true."""
    if env_flag('KEEP_TEMP_USER', 'false'):
        return
    temp_user = os.environ.get('TEMP_USER', 'remote')
    if not temp_user:
        return
    try:
        from vnc_remote_secure.platform.base import get_adapter
        adapter = get_adapter()
        if adapter.remove_runtime_user(temp_user):
            logger.info("Removed temporary user %s", temp_user)
        else:
            logger.debug("Temporary user %s was not present or could not be removed", temp_user)
    except Exception as e:  # noqa: BLE001 - cleanup must never crash shutdown
        logger.debug("Could not remove temp user %s: %s", temp_user, e, exc_info=True)


def save_state() -> dict:
    """Persist current service state for backup/restore."""
    return {
        'pids': {svc: _read_pid(svc) for svc in
                 ['vnc', 'terminal', 'novnc', 'websockify', 'health',
                  'landing', 'user_ui', 'audio', 'gamepad', 'nginx']},
        'timestamp': time.time(),
    }


def restore_state(state: dict) -> None:
    """Restore service state (best-effort: re-reads PIDs).

    Only records a PID when it still belongs to this deployment —
    PID reuse between backup and restore would otherwise adopt a
    foreign process into status output.
    """
    pids = state.get('pids', {})
    for svc, pid in pids.items():
        if pid and _pid_alive(pid) and _pid_is_ours(pid, svc) is not False:
            _write_pid(svc, pid)
