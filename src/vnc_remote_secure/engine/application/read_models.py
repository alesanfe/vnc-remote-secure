"""Read models for the admin views — shaped data the transport
serializes. Queries are pure: no mutation, no audit side effects.

Keeping these behind ``engine/application`` means ``services/api_v1``
handlers never reach into ``security/*`` or ``core/*`` for reads —
the persistence or telemetry backend can move without touching the
API surface.
"""

from __future__ import annotations

from vnc_remote_secure.engine.infrastructure import stores


def operators_index() -> list:
    """Store records with their effective permission set attached."""
    store = stores.operator_load_store()
    users = []
    for username, rec in sorted(store.items()):
        users.append(
            {
                "username": username,
                "role": rec.get("role"),
                "disabled": bool(rec.get("disabled")),
                "created_at": rec.get("created_at"),
                "permissions": sorted(stores.operator_permissions(username)),
            }
        )
    return users


def operator_detail(username: str) -> dict | None:
    """Operator record + display metadata the admin UI shows.

    ``deletion_allowed``/``blocking_reasons`` are display metadata —
    the use case layer still enforces deletion at apply time.
    """
    from vnc_remote_secure.engine.application.operators import viable_admin_count

    rec = stores.operator_load_store().get(username)
    if rec is None:
        return None
    blocking = []
    if rec.get("role") == "admin" and viable_admin_count(excluding=username) == 0:
        blocking.append("last_viable_administrator")
    return {
        "username": username,
        "role": rec.get("role"),
        "disabled": bool(rec.get("disabled")),
        "created_at": rec.get("created_at"),
        "permissions": sorted(stores.operator_permissions(username)),
        "passkey_count": len(stores.credential_list(username)),
        "deletion_allowed": not blocking,
        "blocking_reasons": blocking,
    }


def audit_page(
    limit: int,
    event: str | None = None,
    before_seq: int | None = None,
    user: str | None = None,
    result: str | None = None,
) -> dict:
    """One cursor page of audit entries.

    ``before_seq`` is the opaque cursor (seq of the previous page's
    last entry); ``next_cursor`` repeats it only when more pages
    exist, so the client can stop cleanly.
    """
    entries = stores.audit_read(
        limit=limit + 1, event=event, before_seq=before_seq, user=user, result=result
    )
    has_more = len(entries) > limit
    entries = entries[:limit]
    return {
        "entries": entries,
        "next_cursor": (entries[-1].get("seq") if has_more and entries else None),
        "has_more": has_more,
    }


def audit_integrity() -> dict:
    intact, message = stores.audit_verify_chain()
    return {"intact": intact, "message": message}


def config_vars() -> list:
    """Effective configuration entries (already secret-redacted)."""
    return stores.config_effective()


def backup_paths() -> list:
    """Backup file paths — the transport stats/serializes them."""
    return stores.backups_paths()


def posture() -> dict:
    return stores.posture_report()


def security_overview() -> dict:
    """Security-center rollup — one read for the dashboard the
    operator checks first: posture score, recent auth/deny signals,
    live sessions and running destructive jobs.

    Composes existing reads — no new authority is created here.
    """
    import time

    report = stores.posture_report()
    entries = stores.audit_read(limit=500)
    cutoff = time.time() - 86400
    signals = _failure_signals(entries, cutoff)
    try:
        from vnc_remote_secure.engine.application.sessions import (
            list_share_links,
        )

        active_sessions = len(list_share_links("active"))
    except Exception:  # noqa: BLE001 - rollup is best-effort
        active_sessions = None
    running_jobs = sum(1 for j in stores.jobs_list(50) if j.get("state") not in ("done", "failed"))
    maint = stores.maintenance_info()
    return {
        "posture": {
            "score": report.get("score"),
            "summary": report.get("summary"),
            "summary_key": report.get("summary_key"),
            "blocking_findings": report.get("blocking_findings", []),
        },
        "signals": {
            "failed_auth_24h": signals["failed_auth"],
            "denied_24h": signals["denied"],
            "actors_with_failures": sorted(signals["locked_actors"])[:20],
        },
        "recent_failures": signals["recent_events"],
        "active_sessions": active_sessions,
        "running_jobs": running_jobs,
        "maintenance": maint is not None,
    }


def _failure_signals(entries: list, cutoff: float) -> dict:
    """Scan recent audit entries for auth-failure/deny signals —
    counts, offending actors and a short tail of recent events."""
    failed_auth = 0
    denied = 0
    locked_actors: set = set()
    recent_events: list = []
    for e in entries:
        ts = _entry_timestamp(e)
        res = e.get("result")
        ev = str(e.get("event") or "")
        if res not in ("failure", "denied") or ts < cutoff:
            continue
        if any(k in ev for k in ("login", "auth", "step_up")):
            failed_auth += 1
            user = str(e.get("user") or "")
            if user and user != "anonymous":
                locked_actors.add(user)
        else:
            denied += 1
        if len(recent_events) < 10:
            recent_events.append(
                {
                    "event": ev,
                    "user": e.get("user"),
                    "result": res,
                    "timestamp": e.get("timestamp") or "",
                }
            )
    return {
        "failed_auth": failed_auth,
        "denied": denied,
        "locked_actors": locked_actors,
        "recent_events": recent_events,
    }


def _entry_timestamp(entry: dict) -> float:
    """Parse the audit ``timestamp`` (ISO-Z); unparsable → 0 so the
    entry sorts as 'old' and never counts against a cutoff window."""
    import datetime

    raw = entry.get("timestamp") or ""
    try:
        return (
            datetime.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=datetime.timezone.utc)
            .timestamp()
        )
    except (ValueError, TypeError):
        return 0.0


def doctor() -> dict:
    return stores.doctor_report()


def health() -> dict:
    return stores.health_report()


def jobs(limit: int = 100) -> list:
    """Recent destructive-operation jobs, newest first."""
    limit = max(1, min(int(limit), 500))
    return stores.jobs_list(limit)


def deleted_operators() -> list:
    """Operator tombstones — the restore candidates."""
    from vnc_remote_secure.engine.application.operators import (
        deleted_operators as _deleted,
    )

    return _deleted()


def status(is_operator: bool) -> dict:
    """Service-status payload shared by /status.json and
    /api/v1/status — service liveness map plus the mic indicator.

    Internal topology + LAN IPs + resource usage are operator-grade
    telemetry: an ephemeral view-only link holder gets service states
    only — enough for the portal cards, not enough to map the host.
    """
    from vnc_remote_secure.core.constants import DEFAULT_NOVNC_WS_PORT

    cfg = stores.portal_config()
    is_win = stores.is_windows()
    data = {
        "services": {
            "vnc_desktop_novnc": stores.port_listening(
                cfg["novnc_port"], cfg.get("novnc_host", "127.0.0.1")
            ),
            # websockify always binds loopback (_start_websockify
            # forces 127.0.0.1 regardless of BIND_HOST).
            "vnc_ws_bridge": stores.port_listening(cfg.get("novnc_ws_port", DEFAULT_NOVNC_WS_PORT)),
            "terminal": stores.port_listening(cfg["ttyd_port"], cfg.get("ttyd_host", "127.0.0.1")),
            "health_dashboard": stores.port_listening(
                cfg["health_port"], cfg.get("health_host", "127.0.0.1")
            ),
            "vnc_rfb_direct": stores.port_listening(stores.vnc_effective_port()),
            "landing_page": True,
        }
        | (
            # UltraVNC's built-in HTTP dir is Windows-only — on Linux
            # nothing ever listens there and the card would
            # permanently show a spurious "down" state.
            {"ultravnc_http": stores.port_listening(cfg["vnc_http_port"])}
            if is_win
            else {}
        ),
        "audio_capture": stores.audio_capture_active(),
        # Credentials are NOT exposed in JSON for security
    }
    if is_operator:
        data["lan_ips"] = stores.lan_ips()
        data["system"] = stores.system_metrics()
    return data


def portal(
    *,
    is_operator: bool,
    host: str = "",
    forwarded_host: str = "",
    forwarded_proto: str = "",
    is_tls: bool = False,
    trusted_proxy: bool = False,
) -> dict:
    """Portal read-model — the data the React portal page renders.

    ``is_operator`` distinguishes a credentialed operator from an
    ephemeral share-link session: the session inventory and the
    gamepad kill-switch are operator information — a view-only share
    recipient gets the page without them.

    The forwarded Host/Proto values land inside links the portal
    renders: reject anything outside a strict hostname set or a
    crafted X-Forwarded-Host becomes a phishing redirect.
    """
    import re as _re

    cfg = stores.portal_config()
    use_ssl = stores.tls_available(cfg)
    protocol = "https" if use_ssl else "http"

    external_base = _external_base(trusted_proxy, forwarded_host, forwarded_proto)

    services = stores.service_list(protocol, external_base)
    lan_ips = stores.lan_ips()
    metrics = stores.system_metrics()

    # Effective RFB port and address — loopback-only behind nginx.
    vnc_port = stores.vnc_effective_port()
    nginx = bool(cfg.get("nginx_enabled"))
    vnc_direct = {
        "addr": (
            f"127.0.0.1:{vnc_port}"
            if nginx
            else f'{lan_ips[0] if lan_ips else "127.0.0.1"}:' f"{vnc_port}"
        ),
        "port": vnc_port,
        "running": stores.port_listening(vnc_port),
        "loopback_only": nginx,
    }

    # WebSocket endpoints for the audio/gamepad client pages — behind
    # a trusted nginx the raw service ports are loopback-only, so the
    # pages connect through the proxied /audio//gamepad/ paths. The
    # ws/wss scheme follows the page transport so browsers never get
    # mixed-content ws:// from an https:// page.
    safe_host = _re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", host or "")
    audio_ws, gamepad_ws, terminal_ws = _ws_endpoints(
        cfg,
        host if safe_host else "127.0.0.1",
        external_base,
        is_tls,
    )

    portal = {
        "is_operator": is_operator,
        "metrics": metrics,
        "services": services,
        "lan_ips": lan_ips,
        "nginx_enabled": nginx,
        "nginx_https_port": cfg.get("nginx_https_port"),
        "protocol": protocol,
        "external_base": external_base,
        "use_ssl": use_ssl,
        "platform": "windows" if stores.is_windows() else "linux",
        "vnc_direct": vnc_direct,
        "audio_ws": audio_ws if cfg.get("audio_stream_enabled") else None,
        "gamepad_ws": (gamepad_ws if cfg.get("gamepad_enabled") else None),
        "terminal_ws": terminal_ws,
        "maintenance": stores.maintenance_info(),
        "ports": {
            "landing": cfg["landing_port"],
            "novnc": cfg["novnc_port"],
            "ttyd": cfg["ttyd_port"],
            "health": cfg["health_port"],
        },
    }
    if is_operator:
        # Session inventory + gamepad kill-switch are operator
        # information — a view-only share recipient must not see who
        # else holds links nor control input injection.
        portal["sessions"] = _active_sessions()
        portal["gamepad_stopped"] = stores.gamepad_stopped()
    return portal


def _external_base(trusted_proxy: bool, forwarded_host: str, forwarded_proto: str) -> str | None:
    """Validated ``proto://host`` from the forwarded headers — only a
    strict hostname set is accepted or a crafted X-Forwarded-Host
    becomes a phishing redirect inside the links the portal renders."""
    import re as _re

    if not (trusted_proxy and forwarded_host):
        return None
    proto = (forwarded_proto or "https").split(",")[0].strip()
    fh = forwarded_host.split(",")[0].strip()
    if _re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", fh) and proto in ("http", "https"):
        return f"{proto}://{fh}"
    return None


def _ws_endpoints(
    cfg: dict,
    host: str,
    external_base: str | None,
    is_tls: bool,
) -> tuple[str, str, str]:
    """audio/gamepad/terminal WebSocket URLs — proxied paths behind a
    trusted proxy, raw service ports otherwise."""
    if external_base:
        ws_scheme = "wss" if external_base.startswith("https") else "ws"
        eb = external_base.split("://", 1)[1]
        return (
            f"{ws_scheme}://{eb}/audio/",
            f"{ws_scheme}://{eb}/gamepad/",
            f"{ws_scheme}://{eb}/terminal/ws",
        )
    ws_scheme = "wss" if is_tls else "ws"
    # `host` comes from the request Host header and may carry the
    # landing port (e.g. "127.0.0.1:47715"); the raw services listen
    # on their own ports, so strip any incoming port first.
    if host.startswith("["):
        bare_host = host.split("]", 1)[0] + "]"
    elif host.count(":") == 1:
        bare_host = host.split(":", 1)[0]
    else:
        bare_host = host
    return (
        f'{ws_scheme}://{bare_host}:{cfg["audio_stream_port"]}/',
        f'{ws_scheme}://{bare_host}:{cfg["gamepad_port"]}/',
        f'{ws_scheme}://{bare_host}:{cfg["ttyd_port"]}/ws',
    )


def _active_sessions() -> list:
    """Live share-session inventory — best-effort; a store hiccup
    must not blank the whole portal payload."""
    try:
        store = stores.session_store()
        stores.session_refresh(store)
        return [s.to_dict() for s in store.list_active()]
    except Exception:  # noqa: BLE001 - inventory is best-effort
        return []


def session_grant_preview(signed: str) -> dict | None:
    """Share-link grant summary — the React interstitial renders it
    before activation. Deliberately omits infrastructure detail."""
    return stores.session_preview(signed)


def activate_share_link(signed: str, client_ip: str | None = None):
    """Consume a share-link token on explicit user consent; returns
    the internal session token for cookie issuance."""
    return stores.activate_share_session(signed, client_ip=client_ip)
