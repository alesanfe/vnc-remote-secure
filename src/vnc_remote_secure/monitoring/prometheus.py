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
import time

logger = logging.getLogger(__name__)

# In-memory metrics store (simple counters and gauges).
_counters: dict[str, dict[str, int]] = {}
_gauges: dict[str, dict[str, float]] = {}

# Process start time — recorded at module import (≈ service boot) so the
# vnc_remote_process_start_time gauge reports the actual start, not the
# scrape time. Emitting time.time() at render would make the metric
# useless for uptime derivation (time() - process_start == ~0 always).
_PROCESS_START = time.time()

# Counters are ALSO mirrored into the shared-state backend so auth
# attempts recorded in other service processes (novnc, terminal,
# landing…) are visible to the health process serving /metrics. With
# the default memory backend this degrades to process-local behaviour.
_NS_COUNTERS = 'prometheus_counters'
_NS_GAUGES = 'prometheus_gauges'


def inc_counter(name: str, labels: str = '', value: int = 1):
    """Increment a counter metric."""
    key = labels or 'default'
    if name not in _counters:
        _counters[name] = {}
    _counters[name][key] = _counters[name].get(key, 0) + value
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().increment(
            _NS_COUNTERS, f'{name}|{key}', amount=value)
    except Exception:  # noqa: BLE001 - metrics must never break auth
        pass


def set_gauge(name: str, value: float, labels: str = ''):
    """Set a gauge metric."""
    key = labels or 'default'
    if name not in _gauges:
        _gauges[name] = {}
    _gauges[name][key] = value
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().set(_NS_GAUGES, f'{name}|{key}', value)
    except Exception:  # noqa: BLE001
        pass


def _shared_counters() -> dict[str, dict[str, int]]:
    """Counters merged from the shared backend (cross-process)."""
    merged: dict[str, dict[str, int]] = {}
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        backend = get_backend()
        for compound in backend.list_keys(_NS_COUNTERS):
            name, _, key = compound.partition('|')
            val = backend.get(_NS_COUNTERS, compound)
            if not isinstance(val, int):
                continue
            merged.setdefault(name, {})[key] = val
    except Exception:  # noqa: BLE001
        pass
    # Merge process-local values only where the shared backend has no
    # entry — the shared value is the cross-process truth (it accumulates
    # every process's increments), while the local dict only reflects
    # this process's own increments and would undercount.
    for name, entries in _counters.items():
        for key, val in entries.items():
            merged.setdefault(name, {}).setdefault(key, val)
    return merged


def _shared_gauges() -> dict[str, dict[str, float]]:
    """Gauges merged from the shared backend (cross-process).

    ``set_gauge`` mirrors every write into the shared store — reading
    only ``_gauges`` here would silently drop gauges set by other
    service processes, the same class of bug the counters had.
    """
    merged: dict[str, dict[str, float]] = {}
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        backend = get_backend()
        for compound in backend.list_keys(_NS_GAUGES):
            name, _, key = compound.partition('|')
            val = backend.get(_NS_GAUGES, compound)
            if not isinstance(val, (int, float)):
                continue
            merged.setdefault(name, {})[key] = val
    except Exception:  # noqa: BLE001
        pass
    for name, entries in _gauges.items():
        for key, val in entries.items():
            merged.setdefault(name, {}).setdefault(key, val)
    return merged


def _format_labels(label_str: str) -> str:
    r"""Format a label string for Prometheus exposition format.

    Escapes the three characters that would corrupt the exposition
    format (``\\``, ``"``, ``\\n``) — label values come from internal
    callers today, but a future dynamic label must not be able to
    inject lines into ``/metrics``.
    """
    if not label_str:
        return ''
    safe = (label_str.replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', '\\n'))
    return '{' + safe + '}'


def _emit_series(lines: list[str], name: str, help_text: str,
                 mtype: str, series: dict):
    """Append HELP/TYPE headers + one sample per label set."""
    lines.append(f'# HELP {name} {help_text}')
    lines.append(f'# TYPE {name} {mtype}')
    for labels, value in series.items():
        suffix = '' if labels == 'default' else _format_labels(labels)
        lines.append(f'{name}{suffix} {value}')


def _emit_cert_days(lines: list[str]):
    """Certificate expiry gauge (scrape-time, best-effort)."""
    try:
        from vnc_remote_secure.security.tls_validation import cert_days_remaining
        days = cert_days_remaining()
        if days is not None:
            _emit_series(lines, 'vnc_remote_cert_days_remaining',
                         'Days until TLS certificate expiry', 'gauge',
                         {'default': days})
    except Exception:  # noqa: BLE001
        pass


def _emit_sqlite_stats(lines: list[str]):
    """Shared-state backend health + op stats (best-effort)."""
    try:
        from vnc_remote_secure.security.shared_state import backend_degraded, sqlite_stats
        # Degraded-backend flag: 1 means sqlite init failed and the
        # process is running on per-process in-memory state —
        # cross-process revocation/single-use guarantees are OFF.
        _emit_series(lines, 'vnc_remote_shared_state_degraded',
                     'Shared-state backend fell back to in-memory '
                     '(1=degraded)', 'gauge',
                     {'default': 1 if backend_degraded() else 0})
        st = sqlite_stats()
        if st.get('ops'):
            _emit_series(lines, 'vnc_remote_sqlite_ops_total',
                         'Shared-state DB operations', 'counter',
                         {'default': st['ops']})
            _emit_series(lines, 'vnc_remote_sqlite_lock_errors_total',
                         '"database is locked" errors', 'counter',
                         {'default': st['lock_errors']})
            _emit_series(lines, 'vnc_remote_sqlite_avg_op_ms',
                         'Average DB op latency (ms)', 'gauge',
                         {'default': f"{st['total_ms'] / st['ops']:.3f}"})
    except Exception:  # noqa: BLE001
        pass


def _emit_db_size(lines: list[str]):
    """Shared-state DB file size (scrape-time, best-effort)."""
    try:
        import os as _os

        from vnc_remote_secure.security.shared_state import get_backend
        db_path = getattr(get_backend(), '_db_path', None)
        if db_path and _os.path.isfile(db_path):
            _emit_series(lines, 'vnc_remote_shared_state_bytes',
                         'Shared-state DB size', 'gauge',
                         {'default': _os.path.getsize(db_path)})
    except Exception:  # noqa: BLE001 - metric must not break /metrics
        pass


def render_metrics() -> str:
    """Render all metrics in Prometheus text exposition format.

    Returns:
        A string suitable for the ``/metrics`` endpoint response body.
    """
    lines: list[str] = []
    gauges = _shared_gauges()
    counters = _shared_counters()

    _emit_series(lines, 'vnc_remote_up',
                 'Service status (1=up, 0=down)', 'gauge',
                 gauges.get('vnc_remote_up', {'default': 1}))
    _emit_series(lines, 'vnc_remote_session_active',
                 'Active ephemeral sessions', 'gauge',
                 gauges.get('vnc_remote_session_active', {'default': 0}))
    _emit_series(lines, 'vnc_remote_auth_attempts_total',
                 'Login attempts', 'counter',
                 counters.get('vnc_remote_auth_attempts_total', {}))
    _emit_series(lines, 'vnc_remote_tls_enabled',
                 'TLS status (1=enabled, 0=disabled)', 'gauge',
                 gauges.get('vnc_remote_tls_enabled', {'default': 1}))
    _emit_series(lines, 'vnc_remote_posture_score',
                 'Security posture score (0-100)', 'gauge',
                 gauges.get('vnc_remote_posture_score', {'default': 0}))
    # health_check_total merged cross-process like auth above —
    # get_health_status runs in every service process.
    _emit_series(lines, 'vnc_remote_health_check_total',
                 'Health check results', 'counter',
                 counters.get('vnc_remote_health_check_total', {}))

    _emit_cert_days(lines)
    _emit_sqlite_stats(lines)
    _emit_db_size(lines)

    # --- Generic security counters/gauges not covered above ---
    # Any component may inc_counter/set_gauge a security-relevant
    # metric (revocations, expiry closes, rate-limit rejections) and
    # have it exported here without a per-metric render block.
    _emitted = {'vnc_remote_auth_attempts_total',
                'vnc_remote_health_check_total'}
    for name, entries in sorted(_shared_counters().items()):
        if name in _emitted:
            continue
        lines.append(f'# TYPE {name} counter')
        for labels, value in entries.items():
            if labels == 'default':
                lines.append(f'{name} {value}')
            else:
                lines.append(
                    f'{name}{_format_labels(labels)} {value}')
    _emitted_g = {'vnc_remote_up', 'vnc_remote_session_active',
                  'vnc_remote_tls_enabled', 'vnc_remote_posture_score'}
    for name, gauge_entries in sorted(gauges.items()):
        if name in _emitted_g:
            continue
        lines.append(f'# TYPE {name} gauge')
        for labels, gval in gauge_entries.items():
            if labels == 'default':
                lines.append(f'{name} {gval}')
            else:
                lines.append(
                    f'{name}{_format_labels(labels)} {gval}')

    # --- Process info ---
    lines.append('# HELP vnc_remote_process_start_time Process start time (Unix epoch)')
    lines.append('# TYPE vnc_remote_process_start_time gauge')
    lines.append(f'vnc_remote_process_start_time {_PROCESS_START:.0f}')

    return '\n'.join(lines) + '\n'


def collect_system_metrics():
    """Collect current system metrics and update gauges."""
    # TLS status.
    from vnc_remote_secure.security.profiles import _is_tls_enabled
    set_gauge('vnc_remote_tls_enabled', 1.0 if _is_tls_enabled() else 0.0)

    # Posture score.
    try:
        from vnc_remote_secure.security.posture import calculate_posture
        posture = calculate_posture()
        set_gauge('vnc_remote_posture_score', float(posture.get('score', 0)))
    except (ImportError, ValueError):
        logger.debug("Failed to collect posture score", exc_info=True)

    # Active sessions.
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        sessions = get_session_store().list_active()
        set_gauge('vnc_remote_session_active', float(len(sessions)))
    except (ImportError, OSError, ValueError):
        set_gauge('vnc_remote_session_active', 0.0)

    # Service status.
    try:
        from vnc_remote_secure.services.health import get_health_status
        status = get_health_status()
        up = 1.0 if status.get('status') == 'healthy' else 0.0
        set_gauge('vnc_remote_up', up)
    except (ImportError, OSError, RuntimeError):
        set_gauge('vnc_remote_up', 0.0)


def metrics_handler():
    """Return a (body, status_code) tuple for the /metrics endpoint."""
    collect_system_metrics()
    return render_metrics(), 200
