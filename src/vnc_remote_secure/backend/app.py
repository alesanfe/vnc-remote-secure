"""FastAPI application for the landing portal + versioned JSON API.

Replaces the stdlib ``LandingHandler`` transport: the SPA bundle,
``/status.json``, ``/sessions.json`` and every ``/api/v1/*`` endpoint
run through the same gate/dispatch logic, now on an ASGI server
(uvicorn) instead of ``http.server``.

The security surface is unchanged — it lives in
``backend.context.PortalContext`` (shared with the legacy stdlib
handler until that is removed): operator/ephemeral identity
resolution, CSRF (vnc_op + vnc_csrf + X-CSRF-Token), Origin and
Sec-Fetch-Site checks, request-framing rejection, rate limiting, and
the SPA/static rules are all exercised by the same code paths as
before. Only the HTTP transport changed.
"""
from __future__ import annotations

import logging
import re as _re

from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Paths that serve the React SPA shell without authentication — the
# bundle is a public static asset (it carries no data; every API call
# the SPA makes is independently authenticated).
_SPA_PATHS = (
    '/', '/index.html', '/share', '/share/',
    '/audio_receiver.html', '/gamepad.html',
    '/audio', '/audio/', '/gamepad', '/gamepad/',
    '/terminal', '/terminal/', '/terminal.html',
)


def _new_context(request: Request, body: bytes = b''):
    """Build a PortalContext over a Starlette request."""
    from vnc_remote_secure.backend.context import AsgiPortalContext
    client = request.client.host if request.client else ''
    return AsgiPortalContext(
        headers=request.headers,
        client_ip=client,
        is_tls=request.url.scheme == 'https',
        body=body,
        path=request.url.path + (
            f'?{request.url.query}' if request.url.query else ''),
        method=request.method,
    )


def _access_log(request: Request, status: int) -> None:
    """Access log with the share-link token redacted — the request
    line carries ``?session=<signed>`` which must never sit
    replayable in logs (same rule the stdlib handler enforced)."""
    line = _re.sub(r'session=[^&\s"]+', 'session=<redacted>',
                   f'{request.method} {request.url.path}'
                   + (f'?{request.url.query}' if request.url.query
                      else ''))
    ip = request.client.host if request.client else '-'
    logger.info('%s - "%s" %s', ip, line, status)


def create_app():
    """Build the FastAPI app for the landing portal."""
    from fastapi import FastAPI
    app = FastAPI(
        title='vnc-remote-secure portal',
        # No public docs — the OpenAPI spec is maintained manually in
        # docs/api/openapi.v1.yaml; exposing /docs would fingerprint
        # the deployment.
        docs_url=None, redoc_url=None, openapi_url=None,
    )

    @app.middleware('http')
    async def _framing_and_logging(request: Request, call_next):
        """Reject ambiguous request framing before any route runs —
        the stdlib handler did this in do_*; the middleware covers
        every method uniformly (plus an access log with token
        redaction)."""
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(request.headers):
            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Ambiguous request framing', 400)
            resp = Response(content=body, status_code=status,
                            media_type='application/json')
            _apply_security_headers(resp, request)
            _access_log(request, status)
            return resp
        resp = await call_next(request)
        _access_log(request, resp.status_code)
        return resp

    def _ctx_response(request: Request, ctx) -> Response:
        return ctx.to_response()

    # -- public SPA surface -------------------------------------------
    # NOTE: these handlers are deliberately SYNC (``def``, not
    # ``async def``) — Starlette runs sync endpoints in a threadpool.
    # The portal work they call (port probes, metrics collection,
    # session-store IO) is blocking; an ``async def`` route would run
    # it on the event loop and stall EVERY concurrent request —
    # including logout — until the probe finishes.
    @app.api_route('/{path:path}', methods=['GET', 'HEAD'])
    def _get(request: Request, path: str):
        ctx = _new_context(request)
        p = request.url.path
        # Public SPA bundle + public API routes precede the gate.
        if p in _SPA_PATHS:
            ctx._serve_admin('/index.html')
            return _ctx_response(request, ctx)
        from vnc_remote_secure.backend.api import is_public_route
        if is_public_route('GET', p):
            ctx._serve_api_get(p)
            return _ctx_response(request, ctx)
        if p == '/admin' or p.startswith('/admin/'):
            ctx._serve_admin(p)
            return _ctx_response(request, ctx)
        # HEAD runs the same gate — otherwise it would leak file
        # metadata without authentication.
        authed, operator = ctx._portal_identity()
        if not authed:
            ctx.send_json_error('Unauthorized', 401,
                                www_authenticate='Basic realm="VNC Portal"')
            return _ctx_response(request, ctx)
        ctx._portal_operator = operator
        from vnc_remote_secure.backend.api import is_api_path
        if p == '/status.json':
            ctx._serve_status_json()
        elif is_api_path(p):
            ctx._serve_api_get(p)
        else:
            ctx.send_json_error('Not found', 404)
        resp = _ctx_response(request, ctx)
        if request.method == 'HEAD':
            # HEAD mirrors GET headers but carries no body — h11
            # rejects body bytes on a HEAD response.
            resp.body = b''
            return resp
        # A live vnc_session may earn an idle-timeout refresh — queue
        # the renewed cookie on authenticated GETs (the stdlib
        # handler did this in do_GET for every authed response).
        if request.method == 'GET':
            refresh = ctx._session_refresh_header()
            if refresh:
                resp.headers.append('Set-Cookie', refresh)
        return resp

    # -- mutations ----------------------------------------------------
    def _mutate_sync(request: Request, body: bytes) -> Response:
        """Sync mirror of the stdlib ``_serve_api_mutation``/``do_POST``:
        POST goes through ``handle_post``; PATCH/DELETE/PUT through the
        generic dispatcher. Public API routes (share-link preview/
        activate) are decided inside the dispatcher itself.

        On a dispatch exception the response buffers are reset before
        writing the 500 — a handler may have already committed a
        partial body when it raised."""
        ctx = _new_context(request, body=body)
        p = request.url.path
        from vnc_remote_secure.backend.api import _dispatch, handle_post
        from vnc_remote_secure.core.errors import log_exception
        try:
            if request.method == 'POST':
                if not handle_post(ctx, p):
                    ctx.send_json_error('Not found', 404)
            else:
                if not _dispatch(ctx, request.method, p, {}):
                    ctx.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001 - never take the portal down
            log_exception(e, f'api {request.method}')
            ctx._resp_status = 500
            ctx._resp_headers = []
            ctx._headers_buffer = []
            ctx.wfile.seek(0)
            ctx.wfile.truncate(0)
            ctx.send_json_error('Internal error', 500)
        return _ctx_response(request, ctx)

    @app.api_route('/api/v1/{path:path}',
                   methods=['POST', 'PATCH', 'DELETE', 'PUT'])
    async def _mutate(request: Request, path: str):
        body = await request.body()
        # Dispatch is synchronous portal work — run it off the event
        # loop (same threadpool reason as _get).
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(_mutate_sync, request, body)

    @app.api_route('/{path:path}', methods=['POST', 'PATCH', 'DELETE', 'PUT'])
    async def _mutate_other(request: Request, path: str):
        """Every mutation lives under /api/v1/ — anything else is 404."""
        await request.body()  # drain so the connection stays sane
        ctx = _new_context(request)
        ctx.send_json_error('Not found', 404)
        return _ctx_response(request, ctx)

    return app


def _apply_security_headers(resp: Response, request: Request) -> None:
    """Apply the standard security headers to a response that bypassed
    the context collector (middleware-level rejections)."""
    from vnc_remote_secure.security.http_headers import get_security_headers
    emitted = {k.lower() for k in resp.headers.keys()}
    for name, value in get_security_headers(
            tls_enabled=request.url.scheme == 'https').items():
        if name.lower() not in emitted:
            resp.headers[name] = value


def main() -> None:
    """Start the portal server (uvicorn, TLS when configured)."""
    from vnc_remote_secure.services.landing import _config
    cfg = _config()
    import uvicorn

    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_ctx = create_ssl_context(cfg['ssl_cert'], cfg['ssl_key'])
    kwargs = {}
    if ssl_ctx:
        # uvicorn wants cert/key paths or an SSLContext via
        # `ssl_context` is not supported — pass cert/key files
        # directly (create_ssl_context validated them already).
        kwargs = {'ssl_certfile': cfg['ssl_cert'],
                  'ssl_keyfile': cfg['ssl_key']}
    logger.info("Landing portal running on %s:%s",
                cfg['landing_host'], cfg['landing_port'])
    logger.info("URL: %s://127.0.0.1:%s", 'https' if ssl_ctx else 'http',
                cfg['landing_port'])
    uvicorn.run(
        'vnc_remote_secure.backend.app:create_app',
        factory=True,
        host=cfg['landing_host'],
        port=cfg['landing_port'],
        # The access log would write the request line verbatim —
        # including share-link tokens. Access logging lives in the
        # middleware, which redacts them.
        access_log=False,
        log_level='warning',
        # CRITICAL: uvicorn honours X-Forwarded-Proto/For from trusted
        # peers by default. Our own gate (TRUSTED_PROXY + client_ip_from)
        # is the only authority on forwarded headers — an untrusted
        # client must never be able to spoof https or a remote IP.
        proxy_headers=False,
        **kwargs,
    )


if __name__ == '__main__':  # pragma: no cover
    main()
