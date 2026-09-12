"""Health monitoring for VNC Remote Secure.

Aggregates system-level and per-service health into a unified view.
System health covers CPU, memory, disk, and uptime; service health
delegates to the health-check service.
"""
import logging
import platform

from vnc_remote_secure.services.health import get_health_status

logger = logging.getLogger(__name__)


def _get_platform_metrics():
    """Delegate system metrics collection to the platform adapter."""
    if platform.system() == 'Windows':
        try:
            from vnc_remote_secure.platform.windows.metrics import get_system_metrics
        except ImportError:
            return {}
        return get_system_metrics()
    else:
        try:
            from vnc_remote_secure.platform.linux.metrics import get_system_metrics
        except ImportError:
            return {}
        return get_system_metrics()


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
    metrics.update(_get_platform_metrics())
    return metrics


def get_service_health(name=None):
    """Return health for a single service or all services.

    Args:
        name: Optional service name. When ``None`` all services are
            returned.

    Returns:
        A dict (single service) or dict of dicts (all services).
    """
    services = get_health_status()['services']
    if name:
        return {name: services.get(name, False)}
    return services


def get_all_health():
    """Return a combined system + service health snapshot.

    The ``services`` key contains the aggregated status dict produced
    by :func:`get_health_status` (with ``status``, ``services_up``,
    ``services_total`` and per-service booleans).
    """
    return {
        'system': get_system_health(),
        'services': get_health_status(),
    }
