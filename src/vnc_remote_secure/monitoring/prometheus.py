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


def render_metrics() -> str:
    """Render all metrics in Prometheus text exposition format.

    Returns:
        A string suitable for the ``/metrics`` endpoint response body.
    """
    lines: list[str] = []
    gauges = _shared_gauges()

    # --- Service status gauge ---
    lines.append('# HELP vnc_remote_up Service status (1=up, 0=down)')
    lines.append('# TYPE vnc_remote_up gauge')
    for labels, value in gauges.get('vnc_remote_up', {'default': 1}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_up {value}')
        else:
            lines.append(f'vnc_remote_up{_format_labels(labels)} {value}')

    # --- Active sessions gauge ---
    lines.append('# HELP vnc_remote_session_active Active ephemeral sessions')
    lines.append('# TYPE vnc_remote_session_active gauge')
    for labels, value in gauges.get('vnc_remote_session_active', {'default': 0}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_session_active {value}')
        else:
            lines.append(f'vnc_remote_session_active{_format_labels(labels)} {value}')

    # --- Auth attempts counter (merged across processes) ---
    lines.append('# HELP vnc_remote_auth_attempts_total Login attempts')
    lines.append('# TYPE vnc_remote_auth_attempts_total counter')
    for labels, value in _shared_counters().get(
            'vnc_remote_auth_attempts_total', {}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_auth_attempts_total {value}')
        else:
            lines.append(f'vnc_remote_auth_attempts_total{_format_labels(labels)} {value}')

    # --- TLS enabled gauge ---
    lines.append('# HELP vnc_remote_tls_enabled TLS status (1=enabled, 0=disabled)')
    lines.append('# TYPE vnc_remote_tls_enabled gauge')
    for labels, value in gauges.get('vnc_remote_tls_enabled', {'default': 1}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_tls_enabled {value}')
        else:
            lines.append(f'vnc_remote_tls_enabled{_format_labels(labels)} {value}')

    # --- Posture score gauge ---
    lines.append('# HELP vnc_remote_posture_score Security posture score (0-100)')
    lines.append('# TYPE vnc_remote_posture_score gauge')
    for labels, value in gauges.get('vnc_remote_posture_score', {'default': 0}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_posture_score {value}')
        else:
            lines.append(f'vnc_remote_posture_score{_format_labels(labels)} {value}')

    # --- Health check counter (merged across processes — like the
    # auth counter above; get_health_status runs in every service
    # process, not only the health server) ---
    lines.append('# HELP vnc_remote_health_check_total Health check results')
    lines.append('# TYPE vnc_remote_health_check_total counter')
    for labels, value in _shared_counters().get(
            'vnc_remote_health_check_total', {}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_health_check_total {value}')
        else:
            lines.append(f'vnc_remote_health_check_total{_format_labels(labels)} {value}')

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
