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
    """Delegate system metrics collection to the platform adapter.

    Best-effort: a metrics collection failure (WMI query failed,
    /proc unreadable) must degrade to empty metrics — never crash the
    health endpoint that exists to report problems.
    """
    try:
        if platform.system() == 'Windows':
            from vnc_remote_secure.platform.windows.metrics import (
                get_system_metrics)
        else:
            from vnc_remote_secure.platform.linux.metrics import (
                get_system_metrics)
        return get_system_metrics()
    except Exception:  # noqa: BLE001 - health checks are best-effort
        logger.debug("Platform metrics unavailable", exc_info=True)
        return {}


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
    """Return a combined system + service + posture health snapshot.

    The ``services`` key contains the aggregated status dict produced
    by :func:`get_health_status` (with ``status``, ``services_up``,
    ``services_total`` and per-service booleans). The ``posture`` key
    carries the security-posture report documented in the monitoring
    runbook; posture calculation is best-effort so a posture failure
    never breaks the health endpoint.
    """
    posture = {}
    try:
        from vnc_remote_secure.security.posture import calculate_posture
        posture = calculate_posture()
    except Exception:  # noqa: BLE001 - posture is informational
        logger.debug("Posture calculation failed", exc_info=True)
    return {
        'system': get_system_health(),
        'services': get_health_status(),
        'posture': posture,
    }
