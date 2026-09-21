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
import logging
import os
import signal
import subprocess
import sys
import time
from typing import Optional

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_WS_PORT,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.core.paths import find_project_root, get_run_dir
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
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_pid(service: str) -> Optional[int]:
    path = _pid_file(service)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
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
            res = subprocess.run(
                ['tasklist', '/FI', f'PID eq {pid}', '/NH', '/FO', 'CSV'],
                capture_output=True, text=True, timeout=5,
            )
            return f',"{pid}",' in res.stdout
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _kill_descendants(pid: int, depth: int = 0) -> None:
    """Best-effort SIGTERM to all descendants of ``pid`` (POSIX).

    ``pgrep -P`` lists direct children; recursion covers grandchildren.
    Depth-capped to avoid pathological process graphs.
    """
    if depth > 4:
        return
    try:
        res = subprocess.run(
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
        try:
            os.kill(child, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass


# Process-name needles per service: most services are python modules
# under ``vnc_remote_secure``, but external binaries (websockify, nginx,
# Xvnc/winvnc, ttyd, ffmpeg) carry their own names. Used to verify a
# recorded PID still belongs to the service before killing it.
_SERVICE_PROC_NEEDLES = {
    'vnc': ('vnc_remote_secure', 'Xvnc', 'x11vnc', 'winvnc', 'Xtigervnc'),
    'terminal': ('vnc_remote_secure', 'ttyd'),
    'websockify': ('websockify',),
    'nginx': ('nginx',),
    'audio': ('vnc_remote_secure', 'ffmpeg'),
}


def _pid_is_ours(pid: int, service: str = None) -> Optional[bool]:
    """Decide whether ``pid`` belongs to one of our service processes.

    Returns ``True`` (cmdline matches the service's needles), ``False``
    (cmdline read OK and does NOT match), or ``None`` when the identity
    cannot be determined (wmic absent, /proc unavailable, permission
    denied). ``None`` lets the caller keep the previous kill behaviour —
    we only skip the kill when we are CONFIDENT the PID is not ours.
    """
    if not pid or pid <= 0:
        return None
    needles = _SERVICE_PROC_NEEDLES.get(service) or (
        'vnc_remote_secure', 'websockify')

    def _matches(cmdline: str) -> bool:
        return any(n in cmdline for n in needles)

    if is_windows():
        try:
            res = subprocess.run(
                ['wmic', 'process', 'where', f'ProcessId={pid}',
                 'get', 'CommandLine', '/FORMAT:LIST'],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                return _matches(res.stdout)
            # wmic missing on newer Windows — fall back to PowerShell.
            res = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f"(Get-CimInstance Win32_Process -Filter "
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
              service: str = None) -> bool:
    """Terminate a process by PID. Returns True if it stopped."""
    if not pid or pid <= 0:
        return True
    if not _pid_alive(pid):
        _clear_pid_by_value(pid)
        return True
    if _pid_is_ours(pid, service) is False:
        # Stale pid file: the PID exists but belongs to an unrelated
        # process (PID reuse). Do not kill it — just drop the record.
        logger.warning(
            "PID %d exists but is not a vnc_remote_secure process — "
            "removing stale pid file instead of killing", pid)
        _clear_pid_by_value(pid)
        return True
    if is_windows():
        try:
            # /T kills the whole tree: services that spawn children
            # (audio -> ffmpeg, vnc -> winvnc helpers) would otherwise
            # orphan them on stop.
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(pid)],
                capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
    else:
        # Terminate children first — a dead parent (e.g. the audio
        # supervisor) would orphan grandchildren like ffmpeg, which
        # keep the capture running after `stop`.
        _kill_descendants(pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            _clear_pid_by_value(pid)
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
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
            with open(path, 'r', encoding='utf-8') as f:
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
            except (OSError, IOError):
                # Could not acquire — another instance holds it.
                self._fh.close()
                self._fh = None
                self._locked = False
        else:
            import fcntl
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._locked = True
            except (OSError, IOError):
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
                    except (OSError, IOError):
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                    except (OSError, IOError):
                        pass
            self._fh.close()
            self._fh = None
            self._locked = False

    @property
    def acquired(self) -> bool:
        return self._locked


def _start_python_service(module: str, service_name: str,
                          extra_args: Optional[list] = None) -> Optional[int]:
    """Start a Python service module as a subprocess and record its PID.

    Returns the PID on success, None on failure.
    """
    if _read_pid(service_name) and _pid_alive(_read_pid(service_name)):
        logger.info("Service %s already running (PID %s)", service_name, _read_pid(service_name))
        return _read_pid(service_name)
    cmd = [sys.executable, '-m', module] + list(extra_args or [])
    # websockify is an external binary that performs no auth and needs
    # none of our credentials — strip secret env vars so a compromise
    # of the bridge cannot read VNC_PASSWORD/AUTH_SECRET/etc. from its
    # environment. Our own service modules keep the full env (they
    # read .env themselves anyway).
    child_env = None
    if module == 'websockify':
        try:
            from vnc_remote_secure.security.redaction import SECRET_VARS
            child_env = {k: v for k, v in os.environ.items()
                         if k not in SECRET_VARS}
        except Exception:  # noqa: BLE001 - env filtering is best-effort
            child_env = None
    # Route service stdout/stderr to a per-service log file under the
    # canonical log dir — DEVNULL would silently discard every error
    # (import failures, bind errors, tracebacks) making a dead service
    # impossible to diagnose.
    from vnc_remote_secure.core.paths import get_log_dir
    try:
        os.makedirs(get_log_dir(), exist_ok=True)
        log_fh = open(  # noqa: SIM115 - fd lives with the child process
            os.path.join(get_log_dir(), f'{service_name}.log'),
            'a', buffering=1, encoding='utf-8', errors='replace')
    except OSError:
        log_fh = subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=child_env,
        )
    except OSError as e:
        logger.error("Failed to start %s: %s", service_name, e)
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


def start_all(config: dict = None) -> dict:
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

        results = {}
        for service in _enabled_services(config):
            results[service] = _start_service(service, config)

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
        return results


def _start_service(service: str, config: dict) -> Optional[int]:
    """Start a single service by name. Returns PID or None."""
    if service == 'vnc':
        return _start_vnc(config)
    if service == 'terminal':
        return _start_terminal(config)
    if service == 'novnc':
        return _start_novnc(config)
    if service == 'websockify':
        return _start_websockify(config)
    if service == 'health':
        return _start_python_service('vnc_remote_secure.services.health', 'health')
    if service == 'landing':
        return _start_python_service('vnc_remote_secure.services.landing', 'landing')
    if service == 'user_ui':
        return _start_python_service('vnc_remote_secure.web.application', 'user_ui')
    if service == 'audio':
        return _start_python_service('vnc_remote_secure.services.audio', 'audio')
    if service == 'gamepad':
        return _start_python_service('vnc_remote_secure.services.gamepad', 'gamepad')
    if service == 'nginx':
        return _start_nginx(config)
    logger.warning("Unknown service: %s", service)
    return None


def _start_vnc(config: dict) -> Optional[int]:
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
                logger.error(
                    "VNC started (PID %s) but pid-file write failed "
                    "(%s) — terminating the orphan", pid, e)
                _kill_pid(pid, service='vnc')
                return None
        return pid
    except Exception as e:
        logger.error("Failed to start VNC: %s", e, exc_info=True)
        return None


def _start_terminal(config: dict) -> Optional[int]:
    """Start the web terminal.

    On Linux, prefer the Python Tornado terminal (services.terminal) so
    that auth_gateway and WebSocket registry are connected. On Windows,
    the same module is used (it was designed for ConPTY issues).
    """
    return _start_python_service('vnc_remote_secure.services.terminal', 'terminal')


def _resolve_novnc_dir() -> Optional[str]:
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


def _start_novnc(config: dict) -> Optional[int]:
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
        'vnc_remote_secure.services.novnc', 'novnc', [novnc_dir])


def _start_websockify(config: dict) -> Optional[int]:
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
    )


def _start_nginx(config: dict) -> Optional[int]:
    """Start nginx via systemctl (Linux) or the platform adapter."""
    if is_windows():
        logger.info("nginx not supported on Windows via service manager; skipping")
        return None
    try:
        res = subprocess.run(
            ['systemctl', 'start', 'nginx'],
            capture_output=True, timeout=15,
        )
        if res.returncode != 0:
            # Fallback: try direct nginx binary
            res = subprocess.run(
                ['nginx'], capture_output=True, timeout=10,
            )
        if res.returncode == 0:
            # Find the nginx master PID
            try:
                res = subprocess.run(
                    ['pgrep', '-x', 'nginx'], capture_output=True, text=True, timeout=5,
                )
                pids = [int(p) for p in res.stdout.split() if p.strip().isdigit()]
                if pids:
                    _write_pid('nginx', pids[0])
                    return pids[0]
            except (OSError, ValueError):
                pass
        return None
    except (OSError, subprocess.SubprocessError) as e:
        logger.error("Failed to start nginx: %s", e, exc_info=True)
        return None


def stop_all() -> dict:
    """Stop all managed services by PID. Returns a dict of service -> stopped_bool."""
    with _GlobalLock() as lock:
        if not lock.acquired:
            logger.warning("Another instance holds the lock; cannot stop cleanly")
        results = {}
        # Stop in reverse order of start.
        services = ['nginx', 'gamepad', 'audio',
                    'user_ui', 'websockify', 'health', 'landing', 'novnc',
                    'terminal', 'vnc']
        for service in services:
            pid = _read_pid(service)
            if pid:
                results[service] = _kill_pid(pid, service=service)
                _clear_pid(service)
            else:
                results[service] = True
        # Clean up the temporary user unless KEEP_TEMP_USER is set.
        _cleanup_temp_user()
        return results


def restart_all(config: dict = None) -> dict:
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


def status_all() -> dict:
    """Return real status of every managed service from PIDs.

    Each entry includes ``running``, ``pid``, and ``port`` (when known)
    so the health endpoints can report the documented schema.
    """
    from vnc_remote_secure.core.config import get_config

    config = get_config()
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
    port_map = {
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
    services = list(port_map.keys())
    enabled = set(_enabled_services(config))
    result = {}
    for service in services:
        pid = _read_pid(service)
        alive = _pid_alive(pid) if pid else False
        entry = {
            'pid': pid,
            'running': alive,
        }
        if service not in enabled:
            # Intentionally disabled — report as such instead of
            # looking like a crashed service.
            entry['enabled'] = False
        port = port_map.get(service)
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
    """True if ``service`` may be auto-restarted (rate-limited)."""
    hist = [t for t in _restart_history.get(service, [])
            if now - t < _RESTART_WINDOW_S]
    _restart_history[service] = hist
    return len(hist) < _RESTART_MAX


def _record_restart(service: str, now: float) -> None:
    _restart_history.setdefault(service, []).append(now)


def watchdog_tick(config: dict = None) -> dict:
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

    dead = []
    for service in _enabled_services(config):
        pid = _read_pid(service)
        if not pid or not _pid_alive(pid):
            dead.append(service)

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

    results = {}
    if auto:
        import time as _time
        now = _time.monotonic()
        throttled = []
        for service in dead:
            if not _restart_allowed(service, now):
                throttled.append(service)
                continue
            _record_restart(service, now)
            _clear_pid(service)
            results[service] = _start_service(service, config)
        if throttled:
            # Alert once on the transition into the throttled state —
            # not on every tick while the service stays down.
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

    # Alerts fire on state transitions only — restarting every tick is
    # correct, but re-alerting every tick would be notification spam.
    if newly_dead:
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
    return results


def _cleanup_temp_user() -> None:
    """Remove the temporary user unless KEEP_TEMP_USER=true."""
    if os.environ.get('KEEP_TEMP_USER', 'false').lower() in ('true', '1', 'yes'):
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
    """Restore service state (best-effort: re-reads PIDs)."""
    pids = state.get('pids', {})
    for svc, pid in pids.items():
        if pid and _pid_alive(pid):
            _write_pid(svc, pid)
