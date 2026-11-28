"""Prometheus metrics export for VNC Remote Secure.

Exposes a ``/metrics`` endpoint in Prometheus text exposition format.
Metrics include:

- ``vnc_remote_up``: Service status (1=up, 0=down)
- ``vnc_remote_session_active``: Active ephemeral sessions
- ``vnc_remote_auth_attempts_total``: Login attempts (by result)
- ``vnc_remote_tls_enabled``: TLS status (1=enabled, 0=disabled)
- ``vnc_remote_posture_score``: Security posture score
- ``vnc_remote_health_check_total``: Health check results
"""

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# In-memory metrics store (simple counters and gauges).
_counters: dict[str, dict[str, int]] = {}
_gauges: dict[str, dict[str, float]] = {}

# --- Write buffer ---------------------------------------------------------
# Metric writes used to hit the shared-state SQLite backend SYNCHRONOUSLY
# on every inc/set — on the Pi that meant every WS register/unregister,
# health check and auth event queued on the same DB lock as security
# state. Deltas now accumulate in memory and flush in ONE batched
# transaction per interval; at most one flush interval of telemetry is
# lost on crash (accepted — metrics are not audit records).
_flush_lock = threading.Lock()
_flush_thread = None
# (name, key) -> pending delta not yet persisted.
_pending_counters: dict[tuple, int] = {}
# (name, key) -> (value, seq) — seq orders same-key writes so a failed
# flush never overwrites a newer pending value with an older snapshot.
_pending_gauges: dict[tuple, tuple] = {}
_gauge_seq = 0
_last_flush_mono = 0.0
_FLUSH_INTERVAL = 5.0  # seconds; env-tunable 1..60


def _flush_interval() -> float:
    try:
        return min(60.0, max(1.0, float(os.environ.get("METRICS_FLUSH_SECONDS", "5"))))
    except (TypeError, ValueError):
        return _FLUSH_INTERVAL


def _ensure_flush_worker():
    """Start the single per-process flush thread (lazy, daemon)."""
    global _flush_thread
    if _flush_thread is not None and _flush_thread.is_alive():
        return
    with _flush_lock:
        if _flush_thread is not None and _flush_thread.is_alive():
            return
        import threading as _th

        t = _th.Thread(target=_flush_loop, name="metrics-flush", daemon=True)
        t.start()
        _flush_thread = t


def _flush_loop():
    """Periodic batched flush — jittered so the ~7 service processes do
    not all write the shared DB on the same tick."""
    import random

    # Stagger first flush across the interval.
    time.sleep(random.uniform(0.5, _flush_interval()))
    while True:
        try:
            _do_flush()
        except Exception:  # noqa: BLE001 - flush must never kill the worker
            logger.debug("metrics flush failed", exc_info=True)
        # If a flush ran long, skip beats rather than pile up work.
        time.sleep(_flush_interval() * random.uniform(0.8, 1.2))


def _swap_pending():
    """Atomically detach the pending maps and return fresh ones."""
    global _pending_counters, _pending_gauges
    with _flush_lock:
        old_c, old_g = _pending_counters, _pending_gauges
        _pending_counters, _pending_gauges = {}, {}
        return old_c, old_g


def _requeue(c_snapshot: dict, g_snapshot: dict):
    """Return a failed snapshot to the pending maps without losing or
    duplicating newer writes."""
    global _gauge_seq
    with _flush_lock:
        for k, v in c_snapshot.items():
            _pending_counters[k] = _pending_counters.get(k, 0) + v
        for k, (v, seq) in g_snapshot.items():
            cur = _pending_gauges.get(k)
            if cur is None or seq > cur[1]:
                _pending_gauges[k] = (v, seq)


def _do_flush() -> bool:
    """One flush attempt — returns True on success (or nothing to do)."""
    global _last_flush_mono
    c_snap, g_snap = _swap_pending()
    if not c_snap and not g_snap:
        return True
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        backend = get_backend()
        if c_snap:
            # Compound keys are 'name|labelkey' — split back per metric.
            by_ns: dict = {}
            for (name, key), delta in c_snap.items():
                compound = f"{name}|{key}"
                by_ns.setdefault(_NS_COUNTERS, {})[compound] = delta
            for ns, deltas in by_ns.items():
                backend.increment_many(ns, deltas)
        if g_snap:
            by_ns = {}
            for (name, key), (value, _seq) in g_snap.items():
                compound = f"{name}|{key}"
                by_ns.setdefault(_NS_GAUGES, {})[compound] = value
            for ns, values in by_ns.items():
                backend.set_many(ns, values)
        _last_flush_mono = time.monotonic()
        return True
    except Exception:  # noqa: BLE001 - caller decides; requeue below
        _requeue(c_snap, g_snap)
        raise


# Process start time — recorded at module import (≈ service boot) so the
# vnc_remote_process_start_time gauge reports the actual start, not the
# scrape time. Emitting time.time() at render would make the metric
# useless for uptime derivation (time() - process_start == ~0 always).
_PROCESS_START = time.time()

# Counters are ALSO mirrored into the shared-state backend so auth
# attempts recorded in other service processes (novnc, terminal,
# landing…) are visible to the health process serving /metrics — but
# only via the batched flush above, never synchronously on the hot path.
_NS_COUNTERS = "prometheus_counters"
_NS_GAUGES = "prometheus_gauges"


def inc_counter(name: str, labels: str = "", value: int = 1):
    """Increment a counter metric — memory only, no I/O."""
    global _gauge_seq
    key = labels or "default"
    if name not in _counters:
        _counters[name] = {}
    _counters[name][key] = _counters[name].get(key, 0) + value
    with _flush_lock:
        nk = (name, key)
        _pending_counters[nk] = _pending_counters.get(nk, 0) + value
    _ensure_flush_worker()


def set_gauge(name: str, value: float, labels: str = ""):
    """Set a gauge metric — memory only, dirty-checked."""
    global _gauge_seq
    key = labels or "default"
    if name not in _gauges:
        _gauges[name] = {}
    if _gauges[name].get(key) == value:
        return  # unchanged — no dirty mark, no flush work
    _gauges[name][key] = value
    with _flush_lock:
        _gauge_seq += 1
        _pending_gauges[(name, key)] = (value, _gauge_seq)
    _ensure_flush_worker()


def flush_metrics_now() -> bool:
    """Synchronous flush for shutdown/tests — bounded, best-effort."""
    try:
        return _do_flush()
    except Exception:  # noqa: BLE001
        logger.debug("metrics flush failed", exc_info=True)
        return False


def metrics_pending() -> int:
    """Number of unflushed series — observability + tests."""
    with _flush_lock:
        return len(_pending_counters) + len(_pending_gauges)


def _shared_counters() -> dict[str, dict[str, int]]:
    """Counters = persisted cross-process totals + this process's
    unflushed deltas — ONE ``items`` query per namespace, no N+1."""
    merged: dict[str, dict[str, int]] = {}
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        for compound, val in get_backend().items(_NS_COUNTERS):
            if not isinstance(val, int):
                continue
            name, _, key = compound.partition("|")
            merged.setdefault(name, {})[key] = val
        # Add this process's pending (unflushed) deltas on top.
        with _flush_lock:
            pending = dict(_pending_counters)
        for (name, key), delta in pending.items():
            merged.setdefault(name, {})[key] = merged.setdefault(name, {}).get(key, 0) + delta
        return merged
    except Exception:  # noqa: BLE001 - degraded: local totals only
        for name, entries in _counters.items():
            for key, val in entries.items():
                merged.setdefault(name, {})[key] = val
        return merged


def _shared_gauges() -> dict[str, dict[str, float]]:
    """Gauges merged from persisted state + pending local writes.

    A pending (unflushed) local value is always newer than anything
    persisted — it wins. Otherwise the persisted cross-process value
    is authoritative (last-writer-wins across processes, same as the
    old synchronous mirror).
    """
    merged: dict[str, dict[str, float]] = {}
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        for compound, val in get_backend().items(_NS_GAUGES):
            if not isinstance(val, (int, float)):
                continue
            name, _, key = compound.partition("|")
            merged.setdefault(name, {})[key] = val
        with _flush_lock:
            pending = dict(_pending_gauges)
        for (name, key), (value, _seq) in pending.items():
            merged.setdefault(name, {})[key] = value
        return merged
    except Exception:  # noqa: BLE001
        for name, entries in _gauges.items():
            for key, val in entries.items():
                merged.setdefault(name, {}).setdefault(key, val)
        return merged


def _label_dict(label_str: str) -> dict:
    """``'k=v,k=v'`` → ``{'k': 'v'}`` — the in-memory store keeps
    labels as a flat string; prometheus_client wants a dict."""
    if not label_str or label_str == "default":
        return {}
    out = {}
    for pair in label_str.split(","):
        k, _, v = pair.partition("=")
        if k:
            out[k.strip()] = v.strip()
    return out


def _series(families: list, name: str, help_text: str, mtype: str, series: dict):
    """Append one metric family to ``families`` (prometheus_client
    owns HELP/TYPE headers and label escaping)."""
    from prometheus_client.core import (
        CounterMetricFamily,
        GaugeMetricFamily,
    )

    fam_cls = {"counter": CounterMetricFamily, "gauge": GaugeMetricFamily}[mtype]
    label_names = sorted({lk for ls in series for lk in _label_dict(ls)})
    metric = fam_cls(name, help_text, labels=label_names or None)
    for labels, value in series.items():
        ld = _label_dict(labels)
        v = float(value)
        # Integers render as '5', not '5.0' — keeps scrapes diffable.
        if v == int(v):
            v = int(v)
        metric.add_metric([ld.get(k, "") for k in label_names], v)
    families.append(metric)


def _emit_cert_days(families: list):
    """Certificate expiry gauge (scrape-time, best-effort)."""
    try:
        from vnc_remote_secure.security.tls_validation import cert_days_remaining

        days = cert_days_remaining()
        if days is not None:
            _series(
                families,
                "vnc_remote_cert_days_remaining",
                "Days until TLS certificate expiry",
                "gauge",
                {"default": days},
            )
    except Exception:  # noqa: BLE001
        pass


def _emit_sqlite_stats(families: list):
    """Shared-state backend health + op stats (best-effort)."""
    try:
        from vnc_remote_secure.security.shared_state import backend_degraded, sqlite_stats

        # Degraded-backend flag: 1 means sqlite init failed and the
        # process is running on per-process in-memory state —
        # cross-process revocation/single-use guarantees are OFF.
        _series(
            families,
            "vnc_remote_shared_state_degraded",
            "Shared-state backend fell back to in-memory " "(1=degraded)",
            "gauge",
            {"default": 1 if backend_degraded() else 0},
        )
        st = sqlite_stats()
        if st.get("ops"):
            _series(
                families,
                "vnc_remote_sqlite_ops_total",
                "Shared-state DB operations",
                "counter",
                {"default": st["ops"]},
            )
            _series(
                families,
                "vnc_remote_sqlite_lock_errors_total",
                '"database is locked" errors',
                "counter",
                {"default": st["lock_errors"]},
            )
            _series(
                families,
                "vnc_remote_sqlite_avg_op_ms",
                "Average DB op latency (ms)",
                "gauge",
                {"default": st["total_ms"] / st["ops"]},
            )
    except Exception:  # noqa: BLE001
        pass


def _emit_db_size(families: list):
    """Shared-state DB file size (scrape-time, best-effort)."""
    try:
        import os as _os

        from vnc_remote_secure.security.shared_state import get_backend

        db_path = getattr(get_backend(), "_db_path", None)
        if db_path and _os.path.isfile(db_path):
            _series(
                families,
                "vnc_remote_shared_state_bytes",
                "Shared-state DB size",
                "gauge",
                {"default": _os.path.getsize(db_path)},
            )
    except Exception:  # noqa: BLE001 - metric must not break /metrics
        pass


# Scrape-side caches: /metrics used to run the full posture calc +
# health probe + N+1 DB reads on EVERY request. Render output is now
# cached for ~1s (single-flight via the lock) and the expensive
# collect step for ~10s — gauges still update in memory continuously,
# the cache only bounds how often we pay for the expensive reads.
_render_lock = threading.Lock()
_render_cache: dict = {"text": "", "mono": 0.0}
_render_ttl = 1.0
_collect_lock = threading.Lock()
_collect_cache: dict = {"mono": 0.0}
_collect_ttl = 10.0


def render_metrics() -> str:
    """Render all metrics in Prometheus text exposition format.

    Values are merged from the shared-state backend (cross-process,
    one ``items`` query per namespace) plus this process's pending
    buffer; prometheus_client owns the wire format.
    """
    now = time.monotonic()
    with _render_lock:
        if _render_cache["text"] and now - _render_cache["mono"] < _render_ttl:
            return _render_cache["text"]
        text = _render_metrics_uncached()
        _render_cache["text"] = text
        _render_cache["mono"] = now
        return text


def _render_metrics_uncached() -> str:
    from prometheus_client import generate_latest
    from prometheus_client.core import CollectorRegistry

    families: list = []
    gauges = _shared_gauges()
    counters = _shared_counters()

    _series(
        families,
        "vnc_remote_up",
        "Service status (1=up, 0=down)",
        "gauge",
        gauges.get("vnc_remote_up", {"default": 1}),
    )
    _series(
        families,
        "vnc_remote_session_active",
        "Active ephemeral sessions",
        "gauge",
        gauges.get("vnc_remote_session_active", {"default": 0}),
    )
    _series(
        families,
        "vnc_remote_auth_attempts_total",
        "Login attempts",
        "counter",
        counters.get("vnc_remote_auth_attempts_total", {}),
    )
    _series(
        families,
        "vnc_remote_tls_enabled",
        "TLS status (1=enabled, 0=disabled)",
        "gauge",
        gauges.get("vnc_remote_tls_enabled", {"default": 1}),
    )
    _series(
        families,
        "vnc_remote_posture_score",
        "Security posture score (0-100)",
        "gauge",
        gauges.get("vnc_remote_posture_score", {"default": 0}),
    )
    # health_check_total merged cross-process like auth above —
    # get_health_status runs in every service process.
    _series(
        families,
        "vnc_remote_health_check_total",
        "Health check results",
        "counter",
        counters.get("vnc_remote_health_check_total", {}),
    )

    _emit_cert_days(families)
    _emit_sqlite_stats(families)
    _emit_db_size(families)

    # --- Generic security counters/gauges not covered above ---
    # Any component may inc_counter/set_gauge a security-relevant
    # metric (revocations, expiry closes, rate-limit rejections) and
    # have it exported here without a per-metric render block.
    _emitted = {"vnc_remote_auth_attempts_total", "vnc_remote_health_check_total"}
    for name, entries in sorted(counters.items()):
        if name in _emitted:
            continue
        _series(families, name, name, "counter", entries)
    _emitted_g = {
        "vnc_remote_up",
        "vnc_remote_session_active",
        "vnc_remote_tls_enabled",
        "vnc_remote_posture_score",
    }
    for name, gauge_entries in sorted(gauges.items()):
        if name in _emitted_g:
            continue
        _series(families, name, name, "gauge", gauge_entries)

    # --- Process info ---
    _series(
        families,
        "vnc_remote_process_start_time",
        "Process start time (Unix epoch)",
        "gauge",
        {"default": _PROCESS_START},
    )

    class _Families:
        def collect(self):
            return list(families)

    registry = CollectorRegistry()
    registry.register(_Families())
    return generate_latest(registry).decode("utf-8")


def collect_system_metrics():
    """Collect current system metrics and update gauges.

    Cached for ``_collect_ttl`` seconds — posture calc + health probe +
    session listing are too expensive to run per scrape. Gauges set
    here are memory-only writes; staleness is bounded by the TTL.
    """
    now = time.monotonic()
    if now - _collect_cache["mono"] < _collect_ttl:
        return
    # Single-flight: a second scraper reuses the in-flight result
    # window rather than piling up duplicate probes.
    if not _collect_lock.acquire(blocking=False):
        return
    try:
        if time.monotonic() - _collect_cache["mono"] < _collect_ttl:
            return
        _collect_system_metrics_uncached()
        _collect_cache["mono"] = time.monotonic()
    finally:
        _collect_lock.release()


def _collect_system_metrics_uncached():
    # TLS status.
    from vnc_remote_secure.security.profiles import _is_tls_enabled

    set_gauge("vnc_remote_tls_enabled", 1.0 if _is_tls_enabled() else 0.0)

    # Posture score.
    try:
        from vnc_remote_secure.security.posture import calculate_posture

        posture = calculate_posture()
        set_gauge("vnc_remote_posture_score", float(posture.get("score", 0)))
    except (ImportError, ValueError):
        logger.debug("Failed to collect posture score", exc_info=True)

    # Active sessions.
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store

        sessions = get_session_store().list_active()
        set_gauge("vnc_remote_session_active", float(len(sessions)))
    except (ImportError, OSError, ValueError):
        set_gauge("vnc_remote_session_active", 0.0)

    # Service status.
    try:
        from vnc_remote_secure.services.health import get_health_status

        status = get_health_status()
        up = 1.0 if status.get("status") == "healthy" else 0.0
        set_gauge("vnc_remote_up", up)
    except (ImportError, OSError, RuntimeError):
        set_gauge("vnc_remote_up", 0.0)


def metrics_handler():
    """Return a (body, status_code) tuple for the /metrics endpoint."""
    collect_system_metrics()
    return render_metrics(), 200
