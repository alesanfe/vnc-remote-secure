"""Health route handler for the web UI.

Exposes JSON endpoints reporting service and system health.
"""
import logging

from flask import Blueprint, jsonify

from vnc_remote_secure.core.errors import json_error
from vnc_remote_secure.monitoring.health import get_all_health
from vnc_remote_secure.services.health import get_health_status
from vnc_remote_secure.security.http_auth import require_auth, check_health_auth

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
