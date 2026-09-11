"""Health route handler for the web UI.

Exposes JSON endpoints reporting service and system health.
"""
from flask import Blueprint, jsonify

from vnc_remote_secure.monitoring.health import get_all_health
from vnc_remote_secure.services.health import get_health_status

health_bp = Blueprint('health', __name__)


@health_bp.route('/health')
@health_bp.route('/health_status')
@health_bp.route('/health_status.json')
def health():
    """Return aggregated service health as JSON."""
    return jsonify(get_health_status())


@health_bp.route('/health/all')
def health_all():
    """Return combined system + service health as JSON."""
    return jsonify(get_all_health())
