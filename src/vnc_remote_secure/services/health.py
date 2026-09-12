"""Health check service for VNC Remote Secure.

Provides a lightweight HTTP health endpoint and helper functions to
query the status of all managed services. The HTTP server uses only the
standard library so it has no external dependencies.
"""
import json
import logging
import os
import threading

from vnc_remote_secure.core.constants import (
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
    DEFAULT_BIND_HOST,
)
from vnc_remote_secure.core.errors import log_exception, error_json
from vnc_remote_secure.core.processes import is_port_available

import http.server

logger = logging.getLogger(__name__)


def _service_ports():
    """Return the service-to-port mapping, honoring .env overrides.

    Reads ``VNC_PORT``, ``NOVNC_PORT``, ``TTYD_PORT``, ``HEALTH_WEB_PORT``
    and ``LANDING_PORT`` from the environment (falling back to the
    platform-aware ``DEFAULT_*`` constants) so the health check probes
    the ports the operator actually configured.
    """
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    return {
        'vnc': int(os.environ.get('VNC_PORT', str(DEFAULT_VNC_PORT))),
        'novnc': int(os.environ.get('NOVNC_PORT', str(DEFAULT_NOVNC_PORT))),
        'ttyd': int(os.environ.get('TTYD_PORT', str(DEFAULT_TTYD_PORT))),
        'health': int(os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT))),
        'landing': int(os.environ.get('LANDING_PORT', str(DEFAULT_LANDING_PORT))),
    }


def _check_port(port):
    """Return True if ``port`` is listening (i.e. not available)."""
    return not is_port_available(port)


def check_health():
    """Return a dict mapping service names to listening booleans."""
    return {name: _check_port(port) for name, port in _service_ports().items()}


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
    """HTTP request handler for the health endpoint.

    Auth is controlled by ``HEALTH_AUTH_TOKEN`` via the shared
    :func:`check_health_auth` helper. When the token is unset, access
    is open (intended for localhost-only binding via ``DEFAULT_BIND_HOST``).
    """

    def do_GET(self):  # noqa: N802 - stdlib API
        from vnc_remote_secure.security.http_auth import check_health_auth
        if self.path in ('/health', '/health_status', '/health_status.json'):
            if not check_health_auth(self.headers.get('Authorization', '')):
                body, _ = error_json('Unauthorized', 401)
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('WWW-Authenticate', 'Bearer realm="Health"')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
            status = get_health_status()
            body = json.dumps(status, indent=2).encode('utf-8')
            # Return 503 when unhealthy, 200 when healthy/degraded
            code = 200 if status['status'] in ('healthy', 'degraded') else 503
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/health/live':
            # Liveness: process responds (always 200 if server is running)
            body = json.dumps({'status': 'alive'}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/health/ready':
            # Readiness: can fulfill requests (depends on services)
            if not check_health_auth(self.headers.get('Authorization', '')):
                body, _ = error_json('Unauthorized', 401)
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('WWW-Authenticate', 'Bearer realm="Health"')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
            status = get_health_status()
            body = json.dumps(status, indent=2).encode('utf-8')
            code = 200 if status['status'] in ('healthy', 'degraded') else 503
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/health/services':
            # Per-service status
            if not check_health_auth(self.headers.get('Authorization', '')):
                body, _ = error_json('Unauthorized', 401)
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('WWW-Authenticate', 'Bearer realm="Health"')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
            services = check_health()
            body = json.dumps({'services': services}, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/health/all':
            if not check_health_auth(self.headers.get('Authorization', '')):
                body, _ = error_json('Unauthorized', 401)
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('WWW-Authenticate', 'Bearer realm="Health"')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
            from vnc_remote_secure.monitoring.health import get_all_health
            try:
                status = get_all_health()
                body = json.dumps(status, indent=2).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                logger.exception("Health status generation failed")
                body, _ = error_json('Health status generation failed', 500)
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
        else:
            body, _ = error_json('Not found', 404)
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))

    def log_message(self, fmt, *args):  # noqa: D401 - route stdlib logs to logger
        logger.info("%s - %s", self.client_address[0], fmt % args)


def start_health_server(port=DEFAULT_HEALTH_PORT, host=DEFAULT_BIND_HOST, ssl_context=None):
    """Start the health HTTP server in a background thread.

    Args:
        port: Port to listen on.
        host: Bind address.
        ssl_context: Optional :class:`ssl.SSLContext` to enable HTTPS.

    Returns the :class:`http.server.HTTPServer` instance. The caller is
    responsible for calling ``shutdown()`` when finished.
    """
    server = http.server.HTTPServer((host, port), _HealthHandler)
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == '__main__':
    import time

    _port = int(os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT)))
    _host = os.environ.get('HEALTH_WEB_HOST', DEFAULT_BIND_HOST)
    from vnc_remote_secure.security.certificates import create_ssl_context
    _ssl = create_ssl_context()
    logger.info("Health server starting on %s:%s (%s)", _host, _port, 'https' if _ssl else 'http')
    srv = start_health_server(port=_port, host=_host, ssl_context=_ssl)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        logger.info("Health server stopped")
