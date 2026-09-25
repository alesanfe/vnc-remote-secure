"""FastAPI health/metrics/audit application.

Replaces both the Flask blueprint (``web.routes.health``) and the
stdlib ``_HealthHandler`` (``services.health``): one ASGI app serving
the machine-facing surface on either the ``health`` or ``user_ui``
service process.

Endpoints (all JSON except ``/metrics``):

- ``GET /health`` | ``/health_status`` | ``/health_status.json`` —
  aggregate status; 503 when ``down``/``unknown``.
- ``GET /health/live`` — liveness probe, unauthenticated but
  rate-limited (60 req / 60s per IP).
- ``GET /health/ready`` — readiness: 200 only when every enabled
  service listens.
- ``GET /health/services`` — per-service PID/port detail.
- ``GET /health/all`` — full system + service health.
- ``GET /metrics`` — Prometheus exposition (metrics auth scope).
- ``GET /audit`` / ``GET /audit/verify`` — audit log tail + chain
  verification (audit auth scope).

Auth: ``HEALTH_AUTH_TOKEN`` Bearer (scope-specific overrides
``METRICS_AUTH_TOKEN``/``AUDIT_AUTH_TOKEN``) via
``check_health_auth`` — open only while every health-serving bind is
loopback; a public bind without a token fails closed with 401.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

logger = logging.getLogger(__name__)


def _unauthorized(realm: str) -> JSONResponse:
    from vnc_remote_secure.core.errors import error_json
    body, status = error_json('Unauthorized', 401)
    return JSONResponse(
        __import__('json').loads(body), status_code=status,
        headers={'WWW-Authenticate': f'Bearer realm="{realm}"'})


def _authed(request: Request, realm: str = 'Health',
            scope: str | None = None) -> Response | None:
    """Bearer-gate a request; returns the 401 response or None."""
    from vnc_remote_secure.security.http_auth import check_health_auth
    peer = request.client.host if request.client else ''
    if check_health_auth(request.headers.get('Authorization', ''),
                         peer_ip=peer, scope=scope):
        return None
    return _unauthorized(realm)


def create_health_app():
    """Build the FastAPI health application."""
    from fastapi import FastAPI
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware('http')
    async def _security_headers(request: Request, call_next):
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(request.headers):
            import json as _json

            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Ambiguous request framing', 400)
            resp = JSONResponse(_json.loads(body), status_code=status)
        else:
            resp = await call_next(request)
        from vnc_remote_secure.security.http_headers import get_security_headers
        emitted = {k.lower() for k in resp.headers.keys()}
        for name, value in get_security_headers(
                tls_enabled=request.url.scheme == 'https').items():
            if name.lower() not in emitted:
                resp.headers[name] = value
        return resp

    # Non-route responses (404/405) keep the canonical error_json
    # envelope — FastAPI's default {'detail': ...} would diverge from
    # the documented error contract.
    from starlette.exceptions import HTTPException as _HTTPExc

    @app.exception_handler(_HTTPExc)
    async def _http_exc(request: Request, exc):
        import json as _json

        from vnc_remote_secure.core.errors import error_json
        body, status = error_json('Not found' if exc.status_code == 404
                                  else 'Error', exc.status_code)
        resp = JSONResponse(_json.loads(body), status_code=status)
        from vnc_remote_secure.security.http_headers import get_security_headers
        emitted = {k.lower() for k in resp.headers.keys()}
        for name, value in get_security_headers(
                tls_enabled=request.url.scheme == 'https').items():
            if name.lower() not in emitted:
                resp.headers[name] = value
        return resp

    @app.get('/health')
    @app.get('/health_status')
    @app.get('/health_status.json')
    def health(request: Request):
        if (r := _authed(request)) is not None:
            return r
        from vnc_remote_secure.services.health import get_health_status
        status = get_health_status()
        code = 200 if status.get('status') in ('healthy', 'degraded') \
            else 503
        return JSONResponse(status, status_code=code)

    @app.get('/health/live')
    def health_live(request: Request):
        # Rate-limited per IP — the probe is unauthenticated so it
        # must not be a cheap DoS/recon vector. 60 req / 60s (k8s
        # probes poll every ~10s).
        from vnc_remote_secure.security.http_auth import client_ip_from
        from vnc_remote_secure.security.rate_limit import check_rate_limit
        ip = client_ip_from(
            request.headers,
            request.client.host if request.client else '') or 'unknown'
        if not check_rate_limit(ip, max_requests=60, window_seconds=60):
            import json as _json

            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Too many requests', 429)
            return JSONResponse(_json.loads(body), status_code=status)
        return {'status': 'alive'}

    @app.get('/health/ready')
    def health_ready(request: Request):
        # Readiness is stricter than /health: 200 only when the
        # aggregate is 'healthy' (every enabled service listening);
        # the full status payload travels in the body either way.
        if (r := _authed(request)) is not None:
            return r
        from vnc_remote_secure.services.health import get_health_status
        status = get_health_status()
        code = 200 if status.get('status') == 'healthy' else 503
        return JSONResponse(status, status_code=code)

    @app.get('/health/services')
    def health_services(request: Request):
        if (r := _authed(request)) is not None:
            return r
        from vnc_remote_secure.core.service_manager import status_all
        return status_all()

    @app.get('/health/all')
    def health_all(request: Request):
        if (r := _authed(request)) is not None:
            return r
        from vnc_remote_secure.monitoring.health import get_all_health
        try:
            return get_all_health()
        except Exception:
            logger.exception("Health status generation failed")
            import json as _json

            from vnc_remote_secure.core.errors import error_json
            body, status = error_json(
                'Health status generation failed', 500)
            return JSONResponse(_json.loads(body), status_code=status)

    @app.get('/metrics')
    def metrics(request: Request):
        if (r := _authed(request, realm='Metrics',
                         scope='metrics')) is not None:
            return r
        from vnc_remote_secure.monitoring.prometheus import metrics_handler
        body, status = metrics_handler()
        return PlainTextResponse(body, status_code=status)

    @app.get('/audit')
    def audit(request: Request, limit: str = '100',
              event: str | None = None):
        if (r := _authed(request, realm='Audit',
                         scope='audit')) is not None:
            return r
        # Manual parse — a malformed limit is a 400 client error, not
        # a framework 422.
        try:
            limit_i = max(1, min(int(limit), 1000))
        except (ValueError, TypeError):
            import json as _json

            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Invalid limit parameter', 400)
            return JSONResponse(_json.loads(body), status_code=status)
        from vnc_remote_secure.security.audit import get_audit_entries
        return get_audit_entries(limit=limit_i, event=event)

    @app.get('/audit/verify')
    def audit_verify(request: Request):
        if (r := _authed(request, realm='Audit',
                         scope='audit')) is not None:
            return r
        from vnc_remote_secure.security.audit import verify_chain
        intact, message = verify_chain()
        return {'intact': intact, 'message': message}

    return app


class UvicornServerHandle:
    """Handle mimicking the stdlib server API around uvicorn — keeps
    callers/tests (``server_address``, ``shutdown()``,
    ``server_close()``) unchanged."""

    def __init__(self, server, thread, port: int):
        self._server = server
        self._thread = thread
        host = server.config.host
        self.server_address = (host, port)

    def shutdown(self):
        self._server.should_exit = True
        self._thread.join(timeout=5)

    def server_close(self):
        pass


def start_health_server(port, host, ssl_context=None,
                        ssl_certfile=None, ssl_keyfile=None) -> UvicornServerHandle:
    """Start the health server (uvicorn) in a background thread."""
    import threading
    import time

    import uvicorn
    kwargs = {}
    if ssl_certfile:
        kwargs = {'ssl_certfile': ssl_certfile}
        if ssl_keyfile:
            kwargs['ssl_keyfile'] = ssl_keyfile
    config = uvicorn.Config(
        create_health_app(), host=host, port=port,
        log_level='warning', access_log=False,
        proxy_headers=False, **kwargs)
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError('health server did not start')
        time.sleep(0.01)
    actual = server.servers[0].sockets[0].getsockname()[1]
    return UvicornServerHandle(server, t, actual)


def main() -> None:
    """``python -m`` entry — health/metrics surface on USER_UI_PORT."""
    import os

    from vnc_remote_secure.core.config import load_env_file
    from vnc_remote_secure.core.constants import DEFAULT_HEALTH_PORT, DEFAULT_USER_UI_PORT
    load_env_file()
    import uvicorn

    from vnc_remote_secure.security.certificates import create_ssl_context
    port = int(os.environ.get(
        'USER_UI_PORT',
        os.environ.get('HEALTH_WEB_PORT',
                       str(DEFAULT_USER_UI_PORT or DEFAULT_HEALTH_PORT))))
    host = (os.environ.get('USER_UI_HOST', '').strip()
            or os.environ.get('HEALTH_WEB_HOST', '').strip()
            or os.environ.get('BIND_HOST', '').strip()
            or '127.0.0.1')
    ssl_ctx = create_ssl_context()
    kwargs = {}
    if ssl_ctx:
        kwargs = {'ssl_certfile': os.environ.get('SSL_CERT'),
                  'ssl_keyfile': os.environ.get('SSL_KEY')}
    logger.info("Health app starting on %s:%s (%s)",
                host, port, 'https' if ssl_ctx else 'http')
    uvicorn.run(create_health_app(), host=host, port=port,
                log_level='warning', access_log=False,
                proxy_headers=False, **kwargs)
