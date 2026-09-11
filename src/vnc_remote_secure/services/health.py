"""Health check service for VNC Remote Secure.

Provides a lightweight HTTP health endpoint and helper functions to
query the status of all managed services. The HTTP server uses only the
standard library so it has no external dependencies.
"""
import json
import socket
import threading

from vnc_remote_secure.core.constants import (
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.core.processes import is_port_available

import http.server


_SERVICE_PORTS = {
    'vnc': DEFAULT_VNC_PORT,
    'novnc': DEFAULT_NOVNC_PORT,
    'ttyd': DEFAULT_TTYD_PORT,
    'health': DEFAULT_HEALTH_PORT,
    'landing': DEFAULT_LANDING_PORT,
}


def _check_port(port):
    """Return True if ``port`` is listening (i.e. not available)."""
    return not is_port_available(port)


def check_health():
    """Return a dict mapping service names to listening booleans."""
    return {name: _check_port(port) for name, port in _SERVICE_PORTS.items()}


def get_health_status():
    """Return an aggregated health status dict.

    The ``status`` field is ``healthy`` when every service is listening,
    ``degraded`` when some are down, and ``unknown`` when no data is
    available.
    """
    services = check_health()
    up = sum(1 for v in services.values() if v)
    total = len(services)
    if total == 0:
        status = 'unknown'
    elif up == total:
        status = 'healthy'
    elif up == 0:
        status = 'down'
    else:
        status = 'degraded'
    return {
        'status': status,
        'services_up': up,
        'services_total': total,
        'services': services,
    }


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the health endpoint."""

    def do_GET(self):  # noqa: N802 - stdlib API
        if self.path in ('/health', '/health_status', '/health_status.json'):
            status = get_health_status()
            body = json.dumps(status, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):  # noqa: D401 - silence stdlib logs
        pass


def start_health_server(port=DEFAULT_HEALTH_PORT, host='0.0.0.0'):
    """Start the health HTTP server in a background thread.

    Returns the :class:`http.server.HTTPServer` instance. The caller is
    responsible for calling ``shutdown()`` when finished.
    """
    server = http.server.HTTPServer((host, port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
