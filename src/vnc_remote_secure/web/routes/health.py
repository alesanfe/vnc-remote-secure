"""Health route handler for the web UI.

Exposes JSON endpoints reporting service and system health.
Also exposes Prometheus metrics and audit log access.
"""
import logging

from flask import Blueprint, Response, jsonify, request

from vnc_remote_secure.core.errors import json_error
from vnc_remote_secure.monitoring.health import get_all_health
from vnc_remote_secure.security.http_auth import check_health_auth, require_auth
from vnc_remote_secure.services.health import get_health_status

health_bp = Blueprint('health', __name__)
logger = logging.getLogger(__name__)


@health_bp.route('/health')
@health_bp.route('/health_status')
@health_bp.route('/health_status.json')
@require_auth(check_health_auth, scheme='Bearer', realm='Health')
def health():
    """Return aggregated service health as JSON."""
    return jsonify(get_health_status())


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
@require_auth(check_health_auth, scheme='Bearer', realm='Metrics')
def metrics():
    """Return Prometheus-format metrics."""
    from vnc_remote_secure.monitoring.prometheus import metrics_handler
    body, status = metrics_handler()
    return Response(body, status=status, mimetype='text/plain')


@health_bp.route('/audit')
@require_auth(check_health_auth, scheme='Bearer', realm='Audit')
def audit():
    """Return recent audit log entries."""
    from vnc_remote_secure.security.audit import get_audit_entries
    limit = request.args.get('limit', 100, type=int)
    event = request.args.get('event', None)
    limit = max(1, min(limit, 1000))
    entries = get_audit_entries(limit=limit, event=event)
    return jsonify(entries)


@health_bp.route('/audit/verify')
@require_auth(check_health_auth, scheme='Bearer', realm='Audit')
def audit_verify():
    """Verify audit log chain integrity."""
    from vnc_remote_secure.security.audit import verify_chain
    intact, message = verify_chain()
    return jsonify({'intact': intact, 'message': message})
