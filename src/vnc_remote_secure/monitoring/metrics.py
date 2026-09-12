"""Metrics collection for VNC Remote Secure.

Collects system and service metrics into a single dictionary and
formats them for human or machine consumption (text, JSON).
"""
import json
import time

from vnc_remote_secure.monitoring.health import get_all_health

# In-memory snapshot of the last collected metrics.
_last_metrics = None


def collect_metrics():
    """Collect a fresh metrics snapshot and cache it.

    Returns:
        A dict containing timestamp, system, and service metrics.
    """
    global _last_metrics
    snapshot = {
        'timestamp': time.time(),
        'system': get_all_health()['system'],
        'services': get_all_health()['services'],
    }
    _last_metrics = snapshot
    return snapshot


def get_metrics():
    """Return the most recently collected metrics.

    Collects a fresh snapshot if none has been collected yet.
    """
    if _last_metrics is None:
        return collect_metrics()
    return _last_metrics


def format_metrics(format='text'):
    """Format metrics for output.

    Args:
        format: One of ``'text'``, ``'json'``.

    Returns:
        A string representation of the metrics.
    """
    metrics = get_metrics()
    fmt = str(format).lower()
    if fmt == 'json':
        return json.dumps(metrics, indent=2)
    # Default: human-readable text.
    lines = [f"VNC Remote Secure Metrics ({time.ctime(metrics['timestamp'])})"]
    lines.append("")
    lines.append("System:")
    for key, value in metrics['system'].items():
        lines.append(f"  {key:>10}: {value}")
    lines.append("")
    lines.append("Services:")
    for name, listening in metrics['services'].items():
        state = 'ONLINE' if listening else 'OFFLINE'
        lines.append(f"  {name:>10}: {state}")
    return "\n".join(lines)
