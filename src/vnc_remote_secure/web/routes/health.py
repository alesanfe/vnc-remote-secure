"""Health route handler for the web UI.

Exposes JSON endpoints reporting service and system health.
Also exposes Prometheus metrics and audit log access.
"""
import logging

from flask import Blueprint, Response, jsonify, request

from vnc_remote_secure.core.errors import json_error
from vnc_remote_secure.monitoring.health import get_all_health
from vnc_remote_secure.security.http_auth import check_health_auth, require_auth
from vnc_remote_secure.security.rate_limit import check_rate_limit
from vnc_remote_secure.services.health import get_health_status

health_bp = Blueprint('health', __name__)
logger = logging.getLogger(__name__)


def _check_metrics_auth(auth_header, client_ip=None, peer_ip=None):
    """Metrics scope: METRICS_AUTH_TOKEN when set, else the general token."""
    return check_health_auth(auth_header, client_ip=client_ip,
                             peer_ip=peer_ip, scope='metrics')


def _check_audit_auth(auth_header, client_ip=None, peer_ip=None):
    """Audit scope: AUDIT_AUTH_TOKEN when set, else the general token."""
    return check_health_auth(auth_header, client_ip=client_ip,
                             peer_ip=peer_ip, scope='audit')


@health_bp.route('/health')
@health_bp.route('/health_status')
@health_bp.route('/health_status.json')
@require_auth(check_health_auth, scheme='Bearer', realm='Health')
def health():
    """Return aggregated service health as JSON.

    Returns 503 when the aggregate status is ``down``/``unknown`` so a
    monitor polling the user-UI port sees the same failure signal the
    standalone health server emits (200 for healthy/degraded).
    """
    status = get_health_status()
    code = 200 if status.get('status') in ('healthy', 'degraded') else 503
    return jsonify(status), code


@health_bp.route('/health/live')
def health_live():
    """Liveness probe — always 200 when the process is running.

    Rate-limited per IP to prevent trivial DoS / reconnaissance.
    """
    # Behind a trusted proxy the peer is always 127.0.0.1 — key the
    # limiter on the forwarded client IP like every other route, or one
    # abuser rate-limits the liveness probe for everyone.
    # Liveness probes poll frequently (k8s: every 10s by default), so
    # this endpoint gets a generous budget: 60 req / 60s per IP.
    from vnc_remote_secure.security.http_auth import client_ip_from
    ip = client_ip_from(request.headers, request.remote_addr) or 'unknown'
    if not check_rate_limit(ip, max_requests=60, window_seconds=60):
        return json_error('Too many requests', 429)
    return jsonify({'status': 'alive'})


@health_bp.route('/health/ready')
@require_auth(check_health_auth, scheme='Bearer', realm='Health')
def health_ready():
    """Readiness probe — 200 when all enabled services are listening."""
    status = get_health_status()
    services = status.get('services', {}) if isinstance(status, dict) else {}
    all_ready = all(services.values()) if services else False
    if all_ready:
        return jsonify({'status': 'ready'})
    return jsonify({'status': 'not ready'}), 503


@health_bp.route('/health/services')
@require_auth(check_health_auth, scheme='Bearer', realm='Health')
def health_services():
    """Per-service status with PID and port details."""
    from vnc_remote_secure.core.service_manager import status_all

    return jsonify(status_all())


@health_bp.route('/health/all')
@require_auth(check_health_auth, scheme='Bearer', realm='Health')
def health_all():
    """Return combined system + service health as JSON."""
    try:
        return jsonify(get_all_health())
    except Exception:
        logger.exception("Health status generation failed")
        return json_error('Health status generation failed', 500)


@health_bp.route('/metrics')
@require_auth(_check_metrics_auth, scheme='Bearer', realm='Metrics')
def metrics():
    """Return Prometheus-format metrics."""
    from vnc_remote_secure.monitoring.prometheus import metrics_handler
    body, status = metrics_handler()
    return Response(body, status=status, mimetype='text/plain')


@health_bp.route('/audit')
@require_auth(_check_audit_auth, scheme='Bearer', realm='Audit')
def audit():
    """Return recent audit log entries."""
    from vnc_remote_secure.security.audit import get_audit_entries
    limit = request.args.get('limit', 100, type=int)
    event = request.args.get('event', None)
    limit = max(1, min(limit, 1000))
    entries = get_audit_entries(limit=limit, event=event)
    return jsonify(entries)


@health_bp.route('/audit/verify')
@require_auth(_check_audit_auth, scheme='Bearer', realm='Audit')
def audit_verify():
    """Verify audit log chain integrity."""
    from vnc_remote_secure.security.audit import verify_chain
    intact, message = verify_chain()
    return jsonify({'intact': intact, 'message': message})
