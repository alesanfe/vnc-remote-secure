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
from typing import Dict, List

logger = logging.getLogger(__name__)

# In-memory metrics store (simple counters and gauges).
_counters: Dict[str, Dict[str, int]] = {}
_gauges: Dict[str, Dict[str, float]] = {}


def inc_counter(name: str, labels: str = '', value: int = 1):
    """Increment a counter metric."""
    key = labels or 'default'
    if name not in _counters:
        _counters[name] = {}
    _counters[name][key] = _counters[name].get(key, 0) + value


def set_gauge(name: str, value: float, labels: str = ''):
    """Set a gauge metric."""
    key = labels or 'default'
    if name not in _gauges:
        _gauges[name] = {}
    _gauges[name][key] = value


def _format_labels(label_str: str) -> str:
    """Format a label string for Prometheus exposition format."""
    if not label_str:
        return ''
    return '{' + label_str + '}'


def render_metrics() -> str:
    """Render all metrics in Prometheus text exposition format.

    Returns:
        A string suitable for the ``/metrics`` endpoint response body.
    """
    lines: List[str] = []

    # --- Service status gauge ---
    lines.append('# HELP vnc_remote_up Service status (1=up, 0=down)')
    lines.append('# TYPE vnc_remote_up gauge')
    for labels, value in _gauges.get('vnc_remote_up', {'default': 1}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_up {value}')
        else:
            lines.append(f'vnc_remote_up{{{_format_labels(labels)}}} {value}')

    # --- Active sessions gauge ---
    lines.append('# HELP vnc_remote_session_active Active ephemeral sessions')
    lines.append('# TYPE vnc_remote_session_active gauge')
    for labels, value in _gauges.get('vnc_remote_session_active', {'default': 0}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_session_active {value}')
        else:
            lines.append(f'vnc_remote_session_active{{{_format_labels(labels)}}} {value}')

    # --- Auth attempts counter ---
    lines.append('# HELP vnc_remote_auth_attempts_total Login attempts')
    lines.append('# TYPE vnc_remote_auth_attempts_total counter')
    for labels, value in _counters.get('vnc_remote_auth_attempts_total', {}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_auth_attempts_total {value}')
        else:
            lines.append(f'vnc_remote_auth_attempts_total{{{_format_labels(labels)}}} {value}')

    # --- TLS enabled gauge ---
    lines.append('# HELP vnc_remote_tls_enabled TLS status (1=enabled, 0=disabled)')
    lines.append('# TYPE vnc_remote_tls_enabled gauge')
    for labels, value in _gauges.get('vnc_remote_tls_enabled', {'default': 1}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_tls_enabled {value}')
        else:
            lines.append(f'vnc_remote_tls_enabled{{{_format_labels(labels)}}} {value}')

    # --- Posture score gauge ---
    lines.append('# HELP vnc_remote_posture_score Security posture score (0-100)')
    lines.append('# TYPE vnc_remote_posture_score gauge')
    for labels, value in _gauges.get('vnc_remote_posture_score', {'default': 0}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_posture_score {value}')
        else:
            lines.append(f'vnc_remote_posture_score{{{_format_labels(labels)}}} {value}')

    # --- Health check counter ---
    lines.append('# HELP vnc_remote_health_check_total Health check results')
    lines.append('# TYPE vnc_remote_health_check_total counter')
    for labels, value in _counters.get('vnc_remote_health_check_total', {}).items():
        if labels == 'default':
            lines.append(f'vnc_remote_health_check_total {value}')
        else:
            lines.append(f'vnc_remote_health_check_total{{{_format_labels(labels)}}} {value}')

    # --- Process info ---
    lines.append('# HELP vnc_remote_process_start_time Process start time (Unix epoch)')
    lines.append('# TYPE vnc_remote_process_start_time gauge')
    lines.append(f'vnc_remote_process_start_time {time.time():.0f}')

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
    except Exception:
        pass

    # Active sessions.
    try:
        from vnc_remote_secure.security.ephemeral_sessions import list_sessions
        sessions = list_sessions()
        set_gauge('vnc_remote_session_active', float(len(sessions)))
    except Exception:
        set_gauge('vnc_remote_session_active', 0.0)

    # Service status.
    try:
        from vnc_remote_secure.services.health import get_health_status
        status = get_health_status()
        up = 1.0 if status.get('status') == 'healthy' else 0.0
        set_gauge('vnc_remote_up', up)
    except Exception:
        set_gauge('vnc_remote_up', 0.0)


def metrics_handler():
    """Return a (body, status_code) tuple for the /metrics endpoint."""
    collect_system_metrics()
    return render_metrics(), 200
