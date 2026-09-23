"""Health check service for VNC Remote Secure.

Provides a lightweight HTTP health endpoint and helper functions to
query the status of all managed services. The HTTP server uses only the
standard library so it has no external dependencies.
"""
import http.server
import json
import logging
import os
import threading

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_NOVNC_WS_PORT,
    DEFAULT_TTYD_PORT,
)
from vnc_remote_secure.core.errors import error_json
from vnc_remote_secure.core.processes import is_port_available
from vnc_remote_secure.services.bounded_server import SecuredHandlerMixin

logger = logging.getLogger(__name__)


def _service_ports():
    """Return the service-to-port mapping, honoring .env overrides.

    Reads ``NOVNC_PORT``, ``TTYD_PORT``, ``HEALTH_WEB_PORT`` and
    ``LANDING_PORT`` from the environment (falling back to the
    platform-aware ``DEFAULT_*`` constants); the VNC port comes from
    ``get_config()`` so the display-derived RFB port (5900+N) is
    probed on Linux.
    """
    from vnc_remote_secure.core.config import get_config, load_env_file
    from vnc_remote_secure.core.constants import (
        DEFAULT_AUDIO_STREAM_PORT,
        DEFAULT_GAMEPAD_PORT,
        DEFAULT_USER_UI_PORT,
    )
    load_env_file()
    # Use get_config() for the VNC port: on Linux the effective RFB
    # port is display-derived (5900+N), which the raw env read misses.
    # An explicit non-default VNC_PORT is still honoured by
    # get_config(), but TigerVNC binds 5900+N regardless — derive the
    # real port like services/vnc._vnc_port() does so the probe checks
    # where the server actually listens.
    _vnc_probe = get_config()['vnc_port']
    try:
        if os.name != 'nt':
            from vnc_remote_secure.services.vnc import _vnc_port
            _vnc_probe = _vnc_port(
                os.environ.get('VNC_DISPLAY', ':1'))
    except Exception:  # noqa: BLE001 - fall back to config value
        pass
    # Each entry is (host, port): services bind their own <SVC>_HOST,
    # so probing everything on loopback reports a LAN-bound service as
    # down forever (aggregate 'degraded'). Wildcard binds are probed on
    # loopback — connecting to '0.0.0.0' is unreliable on Windows.

    def _h(env, default='127.0.0.1'):
        host = (os.environ.get(env, '') or default).strip()
        # justification: detection, not a bind
        return '127.0.0.1' if host in ('0.0.0.0', '::', '') else host  # nosec B104

    def _p(env, default):
        # A malformed port env var must not crash every health request —
        # fall back to the same default get_config() would use.
        try:
            return int(os.environ.get(env, str(default)))
        except (ValueError, TypeError):
            return default

    ports = {
        'vnc': ('127.0.0.1', _vnc_probe),
        'novnc': (_h('NOVNC_HOST'), _p('NOVNC_PORT', DEFAULT_NOVNC_PORT)),
        'terminal': (_h('TTYD_HOST'), _p('TTYD_PORT', DEFAULT_TTYD_PORT)),
        'landing': (_h('LANDING_HOST'), _p('LANDING_PORT', DEFAULT_LANDING_PORT)),
        # Internal WebSocket->RFB bridge (loopback only, always runs
        # alongside noVNC — _start_websockify binds 127.0.0.1).
        'websockify': ('127.0.0.1', _p('NOVNC_WS_PORT', DEFAULT_NOVNC_WS_PORT)),
    }
    # Optional services are probed only when enabled, so a disabled
    # feature does not drag the aggregated status to 'degraded'.
    if env_flag('HEALTH_WEB_ENABLED', 'true'):
        ports['health'] = (_h('HEALTH_WEB_HOST'),
                           _p('HEALTH_WEB_PORT', DEFAULT_HEALTH_PORT))
    if env_flag('USER_UI_ENABLED', 'false'):
        ports['user_ui'] = (_h('USER_UI_HOST'),
                            _p('USER_UI_PORT', DEFAULT_USER_UI_PORT))
    if env_flag('AUDIO_STREAM_ENABLED', 'false'):
        ports['audio'] = (_h('AUDIO_STREAM_HOST'),
                          _p('AUDIO_STREAM_PORT', DEFAULT_AUDIO_STREAM_PORT))
    if env_flag('GAMEPAD_ENABLED', 'false'):
        ports['gamepad'] = (_h('GAMEPAD_HOST'),
                            _p('GAMEPAD_PORT', DEFAULT_GAMEPAD_PORT))
    return ports


def _check_port(port, host='127.0.0.1'):
    """Return True if ``port`` is listening on ``host``."""
    return not is_port_available(port, host=host)


def check_health():
    """Return a dict mapping service names to listening booleans."""
    return {name: _check_port(port, host)
            for name, (host, port) in _service_ports().items()}


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
    # Increment the Prometheus health-check counter (best-effort).
    from vnc_remote_secure.monitoring.prometheus import inc_counter
    inc_counter('vnc_remote_health_check_total', labels=status)
    return {
        'status': status,
        'services_up': up,
        'services_total': total,
        'services': services,
    }


class _HealthHandler(SecuredHandlerMixin, http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the health endpoint.

    Auth is controlled by ``HEALTH_AUTH_TOKEN`` via the shared
    :func:`check_health_auth` helper. When the token is unset, access
    is open only while every health-serving bind is loopback; a public
    bind without a token fails closed with 401. The mixin installs the
    Slowloris read timeout and security headers.
    """

    def _send_json(self, status, body, content_type='application/json'):
        """Write a JSON (or text) response body."""
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, message, realm=None):
        """Write a JSON error body, optionally with WWW-Authenticate."""
        body, _ = error_json(message, status)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        if realm:
            self.send_header('WWW-Authenticate',
                             f'Bearer realm="{realm}"')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def _require_health_auth(self, realm='Health'):
        """Check the health auth token; send 401 and return False on failure."""
        from vnc_remote_secure.security.http_auth import check_health_auth
        if check_health_auth(self.headers.get('Authorization', ''),
                             peer_ip=self.client_address[0]
                             if self.client_address else None):
            return True
        self._send_error(401, 'Unauthorized', realm=realm)
        return False

    def _serve_health(self, ready_only=False):
        """Serve the aggregated health status."""
        if not self._require_health_auth():
            return
        status = get_health_status()
        body = json.dumps(status, indent=2).encode('utf-8')
        # Readiness is stricter than /health: a 'degraded' aggregate
        # means an enabled service is down, so the deployment cannot
        # serve all traffic (matches the Flask blueprint, which
        # requires all services listening).
        ok_states = ('healthy',) if ready_only else ('healthy', 'degraded')
        code = 200 if status['status'] in ok_states else 503
        self._send_json(code, body)

    def _serve_live(self):
        """Serve the liveness probe (unauthenticated, rate-limited)."""
        # Rate-limited per IP like the Flask blueprint — the probe is
        # unauthenticated so it must not be a cheap DoS/recon vector.
        # 60 req / 60s — liveness probes poll frequently (k8s: every
        # 10s by default); the generic 5/5min budget would break real
        # monitoring.
        from vnc_remote_secure.security.http_auth import client_ip_from
        from vnc_remote_secure.security.rate_limit import (
            check_rate_limit,
        )
        if not check_rate_limit(
                client_ip_from(
                    self.headers, self.client_address[0]),
                max_requests=60, window_seconds=60):
            self._send_error(429, 'Too many requests')
            return
        self._send_json(200, json.dumps({'status': 'alive'}))

    def _serve_services(self):
        """Per-service status with PID and port details."""
        if not self._require_health_auth():
            return
        from vnc_remote_secure.core.service_manager import status_all
        self._send_json(200, json.dumps(status_all(), indent=2))

    def _serve_all_health(self):
        """Serve the monitoring aggregate (all health checks)."""
        if not self._require_health_auth():
            return
        from vnc_remote_secure.monitoring.health import get_all_health
        try:
            status = get_all_health()
            self._send_json(200, json.dumps(status, indent=2))
        except Exception:
            logger.exception("Health status generation failed")
            self._send_error(500, 'Health status generation failed')

    def _serve_metrics(self):
        """Prometheus scrape endpoint on the health port."""
        if not self._require_health_auth(realm='Metrics'):
            return
        from vnc_remote_secure.monitoring.prometheus import metrics_handler
        body, status = metrics_handler()
        self._send_json(status, body, content_type='text/plain; version=0.0.4')

    def _serve_audit(self):
        """Serve recent audit entries (bounded by ?limit=)."""
        if not self._require_health_auth(realm='Audit'):
            return
        from urllib.parse import parse_qs, urlparse

        from vnc_remote_secure.security.audit import get_audit_entries
        qs = parse_qs(urlparse(self.path).query)
        try:
            limit = max(1, min(int(qs.get('limit', ['100'])[0]), 1000))
        except (ValueError, TypeError):
            self._send_error(400, 'Invalid limit parameter')
            return
        event = qs.get('event', [None])[0]
        entries = get_audit_entries(limit=limit, event=event)
        self._send_json(200, json.dumps(entries, indent=2))

    def _serve_audit_verify(self):
        """Serve the audit chain integrity check."""
        if not self._require_health_auth(realm='Audit'):
            return
        from vnc_remote_secure.security.audit import verify_chain
        intact, message = verify_chain()
        self._send_json(200, json.dumps(
            {'intact': intact, 'message': message}))

    def do_GET(self):  # noqa: N802 - stdlib API
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(self.headers):
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(
                error_json('Ambiguous request framing', 400)[0]
                .encode('utf-8'))
            return
        # Strip the query string once: Flask routes match path-only and
        # nginx forwards the request URI verbatim, so /health?x=1 must
        # not 404 here while succeeding through the proxy. (The /audit
        # branch still reads the query via urlparse(self.path).)
        path = self.path.split('?', 1)[0]
        if path in ('/health', '/health_status', '/health_status.json'):
            self._serve_health()
        elif path == '/health/live':
            self._serve_live()
        elif path == '/health/ready':
            self._serve_health(ready_only=True)
        elif path == '/health/services':
            self._serve_services()
        elif path == '/health/all':
            self._serve_all_health()
        elif path == '/metrics':
            self._serve_metrics()
        elif path == '/audit':
            self._serve_audit()
        elif path == '/audit/verify':
            self._serve_audit_verify()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(error_json('Not found', 404)[0].encode('utf-8'))


def start_health_server(port=DEFAULT_HEALTH_PORT, host=DEFAULT_BIND_HOST, ssl_context=None):
    """Start the health HTTP server in a background thread.

    Args:
        port: Port to listen on.
        host: Bind address.
        ssl_context: Optional :class:`ssl.SSLContext` to enable HTTPS.

    Returns the :class:`http.server.HTTPServer` instance. The caller is
    responsible for calling ``shutdown()`` when finished.
    """
    # Bounded threading server: a single slow/hung health probe must
    # not block every other probe behind it (HTTP/1.1 keep-alive),
    # and a pre-auth connection flood cannot exhaust threads.
    from vnc_remote_secure.services.bounded_server import (
        BoundedThreadingHTTPServer,
    )
    server = BoundedThreadingHTTPServer((host, port), _HealthHandler)
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == '__main__':
    import time

    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    _port = int(os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT)))
    # Same resolution chain as config._env_host: HEALTH_WEB_HOST →
    # BIND_HOST → loopback — so the documented BIND_HOST knob actually
    # controls this backend's binding.
    _host = (os.environ.get('HEALTH_WEB_HOST', '').strip()
             or os.environ.get('BIND_HOST', '').strip()
             or DEFAULT_BIND_HOST)
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
