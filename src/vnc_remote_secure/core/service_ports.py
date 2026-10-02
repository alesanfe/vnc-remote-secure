"""Port probes and listener auditing for the service manager.

This module owns everything related to *ports*, distinct from the
PID tracking in ``service_pids``:

- ``_port_in_use`` / ``_port_accepting``: the pre-start occupancy
  probe (bind, with a connect fallback to distinguish TIME_WAIT) and
  the post-start verification that a child actually bound.
- ``_service_port_map``: the service -> effective port map used by
  ``status_all`` and the watchdog; resolves the TigerVNC display
  derivation so the reported RFB port agrees with what the server
  really bound.
- ``audit_internal_listeners``: the post-start perimeter check that
  flags security-internal ports (RFB, websockify bridge) bound on
  non-loopback addresses, reusing doctor's socket enumeration.

``service_manager`` re-exports every name here so existing callers
and tests keep resolving them at the old path.
"""

import os

from vnc_remote_secure.core.constants import DEFAULT_NGINX_HTTPS_PORT
from vnc_remote_secure.platform.detection import is_windows


def _port_in_use(port: int, host: str = "127.0.0.1") -> bool:
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


def _port_accepting(port: int, host: str = "127.0.0.1") -> bool:
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


def _service_port_map(config: dict) -> dict:
    """Return the service -> expected port map for status/watchdog probes."""
    # On Linux TigerVNC binds 5900+display regardless of an explicit
    # VNC_PORT — report the effective port so status agrees with the
    # doctor probe and the landing portal (same derivation as
    # services/vnc._vnc_port and _start_websockify).
    vnc_port = config.get("vnc_port")
    if not is_windows():
        try:
            from vnc_remote_secure.services.vnc import _vnc_port

            vnc_port = _vnc_port(config.get("vnc_display", ":1"))
        except Exception:  # noqa: BLE001 - fall back to config value
            pass
    return {
        "vnc": vnc_port,
        "terminal": config.get("ttyd_port"),
        "novnc": config.get("novnc_port"),
        "health": config.get("health_port"),
        "landing": config.get("landing_port"),
        "user_ui": config.get("user_ui_port"),
        "audio": config.get("audio_stream_port"),
        "websockify": config.get("novnc_ws_port"),
        "gamepad": config.get("gamepad_port"),
        "nginx": (
            int(os.environ.get("NGINX_HTTPS_PORT", str(DEFAULT_NGINX_HTTPS_PORT)))
            if config.get("nginx_enabled")
            else None
        ),
    }


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
    strict = {"vnc": ports.get("vnc"), "websockify": ports.get("websockify")}
    backend_ports = {p for s, p in ports.items() if s not in strict and p}
    for addr, port in listeners:
        if _is_loopback_addr(addr):
            continue
        for service, expected in strict.items():
            if expected and port == int(expected):
                findings.append(
                    f"{service} port {port} listening on {addr} — "
                    "MUST be loopback-only (public RFB exposure)"
                )
        # Backend services: only flagged when nginx fronts them —
        # without a reverse proxy they ARE the public entry points
        # by design.
        if config.get("nginx_enabled") and port in backend_ports:
            findings.append(
                f"backend port {port} listening on {addr} — "
                "nginx deployment expects loopback backends"
            )
    return findings
