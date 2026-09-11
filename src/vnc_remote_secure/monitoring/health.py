"""Health monitoring for VNC Remote Secure.

Aggregates system-level and per-service health into a unified view.
System health covers CPU, memory, disk, and uptime; service health
delegates to the health-check service.
"""
import platform
import subprocess

from vnc_remote_secure.services.health import check_health


def get_system_health():
    """Return a dict with system resource health metrics.

    Values are best-effort strings; ``'N/A'`` is used when a metric
    cannot be collected on the current platform.
    """
    metrics = {
        'cpu': 'N/A',
        'memory': 'N/A',
        'disk': 'N/A',
        'uptime': 'N/A',
        'hostname': platform.node(),
        'os': f'{platform.system()} {platform.release()}',
    }

    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'loadpercentage', '/value'],
                capture_output=True, text=True, timeout=5,
            )
            import re
            match = re.search(r'LoadPercentage=(\d+)', result.stdout)
            if match:
                metrics['cpu'] = f"{match.group(1)}%"
        except Exception:
            pass
    else:
        try:
            with open('/proc/loadavg', 'r') as f:
                metrics['cpu'] = f"Load: {f.readline().split()[0]}"
        except Exception:
            pass

    return metrics


def get_service_health(name=None):
    """Return health for a single service or all services.

    Args:
        name: Optional service name. When ``None`` all services are
            returned.

    Returns:
        A dict (single service) or dict of dicts (all services).
    """
    services = check_health()
    if name:
        return {name: services.get(name, False)}
    return services


def get_all_health():
    """Return a combined system + service health snapshot."""
    return {
        'system': get_system_health(),
        'services': get_service_health(),
    }
