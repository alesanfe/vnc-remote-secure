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

The manager is platform-aware: the global lock goes through
``filelock`` (flock on POSIX, msvcrt on Windows); process termination
uses ``kill`` by PID on Linux and ``taskkill /PID`` on Windows.

PID bookkeeping/process termination live in ``core.service_pids`` and
port probes/listener auditing in ``core.service_ports``; all their
names are re-exported here so ``service_manager.<name>`` keeps
resolving for existing callers and tests.
"""

import logging
import os
import subprocess
import sys
import time
from contextlib import suppress
from typing import Any

from vnc_remote_secure.core.config import env_flag, get_config, load_env_file
from vnc_remote_secure.core.constants import DEFAULT_NOVNC_WS_PORT, DEFAULT_VNC_PORT
from vnc_remote_secure.core.paths import find_project_root
from vnc_remote_secure.core.processes import run_cmd

# PID tracking and process termination live in ``core.service_pids``;
# port probes and the listener audit live in ``core.service_ports``.
# Everything is re-exported here so existing callers and tests keep
# resolving these names as ``service_manager.<name>``.
from vnc_remote_secure.core.service_pids import (
    _LOCK_FILE_NAME,  # noqa: F401
    _PID_DIR_NAME,  # noqa: F401
    _SERVICE_PROC_NEEDLES,  # noqa: F401
    _clear_pid,
    _clear_pid_by_value,  # noqa: F401
    _GlobalLock,
    _kill_descendants,  # noqa: F401
    _kill_pid,
    _lock_path,  # noqa: F401
    _pid_alive,
    _pid_dir,  # noqa: F401
    _pid_file,  # noqa: F401
    _pid_is_ours,
    _pid_meta_file,  # noqa: F401
    _proc_start_token,  # noqa: F401
    _read_pid,
    _read_pid_meta,  # noqa: F401
    _write_pid,
)
from vnc_remote_secure.core.service_ports import (
    _port_accepting,
    _port_in_use,
    _service_port_map,
    audit_internal_listeners,
)
from vnc_remote_secure.platform.detection import is_windows

logger = logging.getLogger(__name__)


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
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            # Never match ourselves — a caller that embeds the module
            # name in its own command line (tests, wrappers) must not
            # be reaped.
            if proc.info["pid"] == own_pid:
                continue
            cmdline = " ".join(proc.info.get("cmdline") or [])
            if marker not in cmdline:
                continue
            for conn in proc.net_connections("tcp"):
                if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN":
                    logger.warning(
                        "Killing orphaned %s (PID %s) holding port %s",
                        service_name,
                        proc.info["pid"],
                        port,
                    )
                    proc.kill()
                    proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue


def _start_python_service(
    module: str, service_name: str, extra_args: list | None = None, port: int | None = None
) -> int | None:
    """Start a Python service module as a subprocess and record its PID.

    Returns the PID on success, None on failure.
    """
    existing = _read_pid(service_name)
    if existing and _pid_alive(existing):
        if _pid_is_ours(existing, service_name) is False:
            # Stale pid file pointing at a reused foreign PID — drop the
            # record instead of reporting "already running" forever.
            logger.warning(
                "Service %s pid file points at foreign PID %d — " "clearing stale record",
                service_name,
                existing,
            )
            _clear_pid(service_name)
        else:
            logger.info("Service %s already running (PID %s)", service_name, existing)
            return existing
    # Pre-check: if the service port is already occupied, either an
    # orphaned copy of ours survived a crash (reap it) or a foreign
    # process owns it (fail loudly — never kill foreign processes).
    if port and _port_in_use(port):
        _reap_stale_service(module, service_name, port)
        if _port_in_use(port):
            logger.error(
                "%s port %s is already in use by another process — " "not starting %s",
                service_name,
                port,
                service_name,
            )
            return None
    cmd = [sys.executable, "-m", module] + list(extra_args or [])
    # websockify is an external binary that performs no auth and needs
    # none of our credentials — strip secret env vars so a compromise
    # of the bridge cannot read VNC_PASSWORD/AUTH_SECRET/etc. from its
    # environment. Our own service modules keep the full env (they
    # read .env themselves anyway).
    child_env = None
    if module == "websockify":
        # sanitized_child_env never returns None — an env=None fallback
        # would leak every secret to an unauthenticated helper.
        try:
            from vnc_remote_secure.security.redaction import (
                sanitized_child_env,
            )

            child_env = sanitized_child_env()
        except Exception:  # noqa: BLE001 - import broken entirely
            child_env = {"PATH": os.environ.get("PATH", "")}
    # Route service stdout/stderr to a per-service log file under the
    # canonical log dir — DEVNULL would silently discard every error
    # (import failures, bind errors, tracebacks) making a dead service
    # impossible to diagnose.
    from vnc_remote_secure.core.paths import get_log_dir

    log_fh: Any
    try:
        os.makedirs(get_log_dir(), exist_ok=True)
        log_fh = open(  # noqa: SIM115 - fd lives with the child process
            os.path.join(get_log_dir(), f"{service_name}.log"),
            "a",
            buffering=1,
            encoding="utf-8",
            errors="replace",
        )
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
        _popen_kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        _popen_kw["start_new_session"] = True
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
                    service_name,
                    proc.returncode,
                    service_name,
                )
                return None
            if _port_accepting(port):
                break
            time.sleep(0.15)
        else:
            logger.error("%s did not bind port %s within 5s — terminating", service_name, port)
            _kill_pid(proc.pid, service=service_name, force=True)
            return None
    _write_pid(service_name, proc.pid)
    logger.info("Started %s (PID %s)", service_name, proc.pid)
    return proc.pid


def _enabled_services(config: dict) -> list:
    """Return the list of service names to start, based on config.

    Core services are unconditional; optional services come from the
    plugin registry (``core.plugins``) which declares each one's
    config gate, required capability and platform constraint.
    """
    services = ["vnc", "terminal", "novnc", "landing"]
    from vnc_remote_secure.core.plugins import iter_plugins, plugin_enabled

    windows = is_windows()
    # 'health' precedes websockify: the standalone health server is
    # optional (HEALTH_WEB_ENABLED gates it — the user-ui app exposes
    # the same endpoints on USER_UI_PORT when it is off), and
    # preserving the historical start order keeps supervision
    # deterministic.
    for plugin in iter_plugins():
        if plugin.name == "health":
            if plugin_enabled(plugin, config, windows):
                services.append("health")
            # The WebSocket→RFB bridge runs alongside noVNC so the
            # browser client can actually reach the VNC server. It
            # only listens on loopback; the authenticated noVNC
            # static server proxies WS upgrades to it after the
            # auth-gateway check.
            services.append("websockify")
        elif plugin_enabled(plugin, config, windows):
            services.append(plugin.name)
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
            logger.warning(
                "Another instance is already managing services; " "returning existing PIDs"
            )
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
            _audit_lifecycle("service_start" if pid else "service_start_failed", service, pid)

        # Alert on start failures (replaces the legacy Bash alerts).
        failed = [s for s, pid in results.items() if not pid]
        if failed:
            try:
                from vnc_remote_secure.monitoring.alerts import notify

                notify(
                    "Service start failure",
                    f"Failed to start: {', '.join(failed)}",
                    severity="error",
                )
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

            audit_event("listener_audit_failure", detail="; ".join(findings))
            if config.get("security_profile") in ("public-hardened", "private-overlay"):
                try:
                    from vnc_remote_secure.monitoring.alerts import notify

                    notify("Public listener detected", "; ".join(findings), severity="critical")
                except Exception:  # noqa: BLE001
                    pass
        return results


# Service name → config key holding the TCP port it binds. Used by
# the pre-start port check and the post-start bind verification.
_SERVICE_PORT_KEYS = {
    "terminal": "ttyd_port",
    "novnc": "novnc_port",
    "websockify": "novnc_ws_port",
    "health": "health_port",
    "landing": "landing_port",
    "user_ui": "user_ui_port",
    "audio": "audio_stream_port",
    "gamepad": "gamepad_port",
}


def _metric(name: str, labels: str = "") -> None:
    """Emit a Prometheus counter (best-effort — metrics never break lifecycle)."""
    from vnc_remote_secure.monitoring.prometheus import inc_counter

    inc_counter(name, labels)


def _audit_lifecycle(event: str, service: str, pid) -> None:
    """Record a service lifecycle transition in the audit log."""
    from vnc_remote_secure.security.audit import audit_event

    audit_event(event, detail=f"service={service} pid={pid}")


def _start_service(service: str, config: dict) -> int | None:
    """Start a single service by name. Returns PID or None."""
    port_key = _SERVICE_PORT_KEYS.get(service)
    port = config.get(port_key) if port_key else None
    if service == "vnc":
        return _start_vnc(config)
    if service == "terminal":
        return _start_terminal(config)
    if service == "novnc":
        return _start_novnc(config)
    if service == "websockify":
        return _start_websockify(config)
    if service == "health":
        return _start_python_service("vnc_remote_secure.services.health", "health", port=port)
    if service == "landing":
        return _start_python_service("vnc_remote_secure.services.landing", "landing", port=port)
    if service == "user_ui":
        return _start_python_service("vnc_remote_secure.web.application", "user_ui", port=port)
    if service == "audio":
        return _start_python_service("vnc_remote_secure.services.audio", "audio", port=port)
    if service == "gamepad":
        return _start_python_service("vnc_remote_secure.services.gamepad", "gamepad", port=port)
    if service == "nginx":
        return _start_nginx(config)
    logger.warning("Unknown service: %s", service)
    return None


def _start_vnc(config: dict) -> int | None:
    """Start the VNC server via the platform adapter."""
    from vnc_remote_secure.services.vnc import start_vnc

    display = config.get("vnc_display", ":1")
    geometry = config.get("vnc_geometry", "1280x720")
    depth = config.get("vnc_depth", 24)
    password = config.get("vnc_password")
    try:
        result = start_vnc(display, geometry, depth, password)
        pid = result if isinstance(result, int) else getattr(result, "pid", None)
        if pid:
            try:
                _write_pid("vnc", pid)
            except OSError as e:
                # An unrecorded PID orphans the process — stop() would
                # never find it. Kill the spawn we just made so the
                # reported failure matches reality.
                logger.exception(
                    "VNC started (PID %s) but pid-file write failed "
                    "(%s) — terminating the orphan",
                    pid,
                    e,
                )
                _kill_pid(pid, service="vnc", force=True)
                return None
        return pid
    except Exception:
        logger.exception("Failed to start VNC:")
        return None


def _start_terminal(config: dict) -> int | None:
    """Start the web terminal.

    The Python FastAPI terminal (services.terminal) runs on both
    platforms so that auth_gateway and WebSocket registry are
    connected (it was designed for ConPTY issues).
    """
    return _start_python_service(
        "vnc_remote_secure.services.terminal", "terminal", port=config.get("ttyd_port")
    )


def _resolve_novnc_dir() -> str | None:
    """Locate the noVNC static assets directory.

    Resolution order: ``NOVNC_DIR`` env var, then ``<project_root>/novnc``
    (where ``make setup-novnc`` clones noVNC). Returns ``None`` when no
    directory exists — the caller must not start the static server
    without one, or it would serve the process CWD (which may expose
    ``.env`` and the source tree).
    """
    candidate = os.environ.get("NOVNC_DIR", "").strip()
    if candidate and os.path.isdir(candidate):
        return candidate
    project_root = find_project_root()
    candidate = os.path.join(project_root, "novnc")
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
            "Refusing to start the static server without a web root."
        )
        return None
    return _start_python_service(
        "vnc_remote_secure.services.novnc", "novnc", [novnc_dir], port=config.get("novnc_port")
    )


def _start_websockify(config: dict) -> int | None:
    """Start the WebSocket→RFB bridge on loopback.

    ``websockify`` listens on ``NOVNC_WS_PORT`` (default 5700, loopback
    only) and forwards to the VNC server. Clients never reach it
    directly: the authenticated noVNC static server proxies
    ``/websockify`` upgrades to it after the auth-gateway check.
    """
    ws_port = config.get("novnc_ws_port", DEFAULT_NOVNC_WS_PORT)
    vnc_port = config.get("vnc_port", DEFAULT_VNC_PORT)
    if not is_windows():
        # TigerVNC binds 5900+N for display :N regardless of an
        # explicit VNC_PORT (the adapter never passes -rfbport). The
        # bridge must target the port the server actually binds —
        # services/vnc._vnc_port() performs the same derivation for
        # its liveness probe; config['vnc_port'] may hold an explicit
        # value that points at a dead port.
        try:
            from vnc_remote_secure.services.vnc import _vnc_port

            vnc_port = _vnc_port(config.get("vnc_display", ":1"))
        except Exception:  # noqa: BLE001 - fall back to config value
            pass
    bind = os.environ.get("BIND_HOST", "127.0.0.1")
    if bind != "127.0.0.1":
        # The bridge must never be publicly reachable — it performs no
        # auth of its own; authentication happens at the noVNC static
        # server which proxies to it.
        logger.warning("BIND_HOST=%s but websockify has no auth — forcing loopback", bind)
    return _start_python_service(
        "websockify",
        "websockify",
        [f"127.0.0.1:{ws_port}", f"127.0.0.1:{vnc_port}"],
        port=ws_port,
    )


def _start_nginx(config: dict) -> int | None:
    """Start nginx via systemctl (Linux) or the platform adapter."""
    if is_windows():
        logger.info("nginx not supported on Windows via service manager; skipping")
        return None
    try:
        res = run_cmd(
            ["systemctl", "start", "nginx"],
            capture_output=True,
            timeout=15,
        )
        if res.returncode == 0:
            # Ask systemd for the unit's MainPID instead of pgrep —
            # pgrep order is arbitrary and can adopt a worker or a
            # foreign nginx for later SIGKILL.
            try:
                show = run_cmd(
                    ["systemctl", "show", "-p", "MainPID", "--value", "nginx"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                mpid = int(show.stdout.strip())
                if mpid > 0:
                    _write_pid("nginx", mpid)
                    return mpid
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            return None
        # Fallback: try direct nginx binary
        res = run_cmd(
            ["nginx"],
            capture_output=True,
            timeout=10,
        )
        if res.returncode == 0:
            # Find the nginx master PID — ppid==1 distinguishes the
            # daemonized master from its workers (ppid=master). pgrep
            # order is arbitrary, so picking pids[0] could adopt a
            # worker (or a foreign nginx) for later SIGKILL.
            try:
                res = run_cmd(
                    ["pgrep", "-x", "nginx"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                pids = [int(p) for p in res.stdout.split() if p.strip().isdigit()]
                for pid in pids:
                    try:
                        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
                            stat = fh.read()
                        if int(stat[stat.rfind(")") + 2 :].split()[1]) == 1:
                            _write_pid("nginx", pid)
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
            logger.error("Another instance holds the lock; refusing to " "stop without it")
            return {"error": "lock held by another instance"}
        results = {}
        # Stop in reverse order of start.
        services = [
            "nginx",
            "gamepad",
            "audio",
            "user_ui",
            "websockify",
            "health",
            "landing",
            "novnc",
            "terminal",
            "vnc",
        ]
        for service in services:
            pid = _read_pid(service)
            if pid:
                results[service] = _kill_pid(pid, service=service, force=force)
                _audit_lifecycle(
                    "service_stop" if results[service] else "service_stop_failed", service, pid
                )
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
            logger.warning("Another instance is already managing services; " "skipping restart")
            return status_all()
        # Stop in reverse order of start (same list as stop_all).
        stop_order = [
            "nginx",
            "gamepad",
            "audio",
            "user_ui",
            "websockify",
            "health",
            "landing",
            "novnc",
            "terminal",
            "vnc",
        ]
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
        if alive and port and service != "nginx":
            # probe is best-effort
            with suppress(Exception):
                alive = _port_accepting(port)
        entry = {
            "pid": pid,
            "running": alive,
        }
        if service not in enabled:
            # Intentionally disabled — report as such instead of
            # looking like a crashed service.
            entry["enabled"] = False
        if port:
            entry["port"] = port
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

# Blocking posture findings seen on the last tick — transitions only:
# a finding that stays active is not re-alerted every interval.
_last_blocking: frozenset = frozenset()


def _alert_new_blocking_findings() -> None:
    """Page the operator when a NEW blocking security finding appears.

    Posture is recomputed on every watchdog tick already; what was
    missing is the push side — a degraded-config regression found at
    3am should reach the configured channels instead of waiting for
    someone to open /admin/security."""
    global _last_blocking
    try:
        from vnc_remote_secure.security.profiles import (
            get_blocking_findings,
        )

        findings = frozenset(
            str(f.get("code") or f.get("message", "?")) for f in get_blocking_findings()
        )
    except Exception:  # noqa: BLE001 - never break the watchdog
        return
    if findings == _last_blocking:
        return
    new = sorted(findings - _last_blocking)
    _last_blocking = findings
    if not new:
        return
    logger.error("Blocking security finding(s) appeared: %s", new)
    try:
        from vnc_remote_secure.monitoring.alerts import notify

        notify(
            "Blocking security finding",
            "New blocking finding(s): " + ", ".join(new) + " — see /admin/security",
            severity="critical",
        )
    except Exception:  # noqa: BLE001 - alerting is best-effort
        pass


def _restart_allowed(service: str, now: float) -> bool:
    """Return True if ``service`` may be auto-restarted (rate-limited)."""
    hist = [t for t in _restart_history.get(service, []) if now - t < _RESTART_WINDOW_S]
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
    if not config.get("healthcheck_enabled", True):
        return {}

    # A scheduled maintenance drain must not wait for the next user
    # request to fire — the watchdog ticks periodically anyway.
    try:
        from vnc_remote_secure.security.maintenance import enforce_drain_deadline

        enforce_drain_deadline()
    except Exception:  # noqa: BLE001 - never break the watchdog
        logger.debug("Drain check failed", exc_info=True)

    # Posture edge detection belongs to the tick, not to the service
    # check below — it must run even when every service is healthy.
    _alert_new_blocking_findings()

    dead = _find_dead_services(config)
    global _last_watchdog_dead
    dead_set = set(dead)
    auto = config.get("auto_restart", False)
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
        if port and service != "nginx":
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
            _metric("vnc_remote_service_restart_throttled_total", f"service={service}")
            continue
        _record_restart(service, now)
        _metric("vnc_remote_service_restarts_total", f"service={service}")
        # A hung-but-alive service (dead listener, live PID) must be
        # killed before respawn — otherwise it orphans and the next
        # watchdog cycle finds it again.
        pid = _read_pid(service)
        if pid and _pid_alive(pid):
            _kill_pid(pid, service=service)
        _clear_pid(service)
        results[service] = _start_service(service, config)
        _audit_lifecycle(
            "service_restart" if results[service] else "service_restart_failed",
            service,
            results[service],
        )
    if throttled:
        _alert_throttled(throttled)
    return results


def _alert_throttled(throttled: list):
    """Log and alert once on the transition into the throttled state."""
    # Not on every tick while the service stays down.
    newly_throttled = [s for s in throttled if s not in _last_throttled]
    _last_throttled.update(throttled)
    for s in set(_last_throttled) - set(throttled):
        _last_throttled.discard(s)
    logger.error(
        "Auto-restart suppressed (>%d restarts in %ds): %s — "
        "the service is kept down; fix the cause and run "
        "'vnc-remote start' manually",
        _RESTART_MAX,
        _RESTART_WINDOW_S,
        ", ".join(throttled),
    )
    if newly_throttled:
        try:
            from vnc_remote_secure.monitoring.alerts import notify

            notify(
                "Auto-restart suppressed",
                "Restart limit reached for: " + ", ".join(newly_throttled),
                severity="error",
            )
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
            notify(
                "Services down",
                "Dead services: "
                + ", ".join(still_dead)
                + ("" if auto else " (AUTO_RESTART disabled)"),
                severity="error",
            )
        elif auto:
            notify(
                "Services restarted",
                "Watchdog restarted: " + ", ".join(results),
                severity="warning",
            )
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
    if env_flag("KEEP_TEMP_USER", "false"):
        return
    temp_user = os.environ.get("TEMP_USER", "remote")
    if not temp_user:
        return
    try:
        import pwd

        pwd.getpwnam(temp_user)  # type: ignore[attr-defined, unused-ignore]
    except KeyError:
        return  # not present — nothing stale
    except ImportError:
        return
    try:
        r = subprocess.run(["pgrep", "-u", temp_user], capture_output=True, timeout=10, check=False)
        if r.returncode == 0 and r.stdout.strip():
            logger.warning(
                "Temp user %s still owns processes (orphaned session?) "
                "— left in place; clean it up manually or via stop",
                temp_user,
            )
            return
    except Exception:  # noqa: BLE001 - can't prove it's safe
        logger.debug("Could not enumerate %s processes — skipping temp-user " "sweep", temp_user)
        return
    try:
        from vnc_remote_secure.platform.base import get_adapter

        if get_adapter().remove_runtime_user(temp_user):
            logger.info("Swept stale temp user %s left by a crashed run", temp_user)
    except Exception as e:  # noqa: BLE001
        logger.debug("Stale temp-user sweep failed for %s: %s", temp_user, e)


def _cleanup_temp_user() -> None:
    """Remove the temporary user unless KEEP_TEMP_USER=true."""
    if env_flag("KEEP_TEMP_USER", "false"):
        return
    temp_user = os.environ.get("TEMP_USER", "remote")
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
        "pids": {
            svc: _read_pid(svc)
            for svc in [
                "vnc",
                "terminal",
                "novnc",
                "websockify",
                "health",
                "landing",
                "user_ui",
                "audio",
                "gamepad",
                "nginx",
            ]
        },
        "timestamp": time.time(),
    }


def restore_state(state: dict) -> None:
    """Restore service state (best-effort: re-reads PIDs).

    Only records a PID when it still belongs to this deployment —
    PID reuse between backup and restore would otherwise adopt a
    foreign process into status output.
    """
    pids = state.get("pids", {})
    for svc, pid in pids.items():
        if pid and _pid_alive(pid) and _pid_is_ours(pid, svc) is not False:
            _write_pid(svc, pid)
