"""Status reporting for VNC Remote Secure.

Produces a unified status report combining application lifecycle state,
service health, and recent alerts. Output can be formatted as text or
JSON for CLI or API consumption.
"""
import json
import platform

from vnc_remote_secure.core.lifecycle import health_check, is_running
from vnc_remote_secure.monitoring.alerts import get_alerts
from vnc_remote_secure.monitoring.health import get_system_health


def get_status():
    """Return a status dict combining lifecycle, services, and alerts."""
    return {
        'app_name': 'VNC Remote Secure',
        'platform': platform.system(),
        'running': is_running(),
        'health': health_check(),
        'system': get_system_health(),
        'recent_alerts': get_alerts(limit=10),
    }


def format_status(format='text'):
    """Format the status report for output.

    Args:
        format: One of ``'text'``, ``'json'``.

    Returns:
        A string representation of the status.
    """
    status = get_status()
    fmt = str(format).lower()
    if fmt == 'json':
        return json.dumps(status, indent=2, default=str)
    # Default: human-readable text.
    lines = ["VNC Remote Secure - Status Report", "=" * 40]
    lines.append(f"Platform:  {status['platform']}")
    lines.append(f"Running:   {status['running']}")
    lines.append(f"Overall:   {status['health']['status']}")
    lines.append("")
    lines.append("Services:")
    for name, info in status['health']['services'].items():
        state = 'ONLINE' if info['listening'] else 'OFFLINE'
        lines.append(f"  {name:>10} (port {info['port']}): {state}")
    lines.append("")
    lines.append("System:")
    for key, value in status['system'].items():
        lines.append(f"  {key:>10}: {value}")
    if status['recent_alerts']:
        lines.append("")
        lines.append("Recent Alerts:")
        for alert in status['recent_alerts']:
            lines.append(f"  [{alert['level'].upper()}] {alert['message']}")
    return "\n".join(lines)
