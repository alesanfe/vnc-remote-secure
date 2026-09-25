#!/usr/bin/env python3
"""noVNC static file server with session validation (FastAPI).

Serves the noVNC web client and enforces authentication before any
request is served. Authentication uses the central auth gateway so
that:

- Session cookies / bearer tokens are validated centrally.
- Ephemeral session tokens with ``desktop:view`` / ``desktop:control``
  permissions are honored.
- Revoked sessions are rejected immediately.

RFB input filtering — ``view_only`` enforcement:
    The ``/websockify`` relay is byte-transparent by default, but when
    the client authenticates with an ephemeral session that lacks
    ``desktop:control`` (or either clipboard direction) the relay
    activates ``services.rfb_filter.RfbInputFilter``: a protocol-aware
    filter that parses the RFB message streams inside the WebSocket
    payloads both ways — dropping KeyEvent (4), PointerEvent (5) and
    ClientCutText (6) client->server, and ServerCutText (3)
    server->client unless ``desktop:clipboard_read`` is held. Unknown
    message types or unparseable streams close the connection (fail
    closed). Regular (non-ephemeral) sessions are
    not filtered — they are full-control admin sessions.

    The filter operates on raw WebSocket frames; the ASGI transport
    demuxes frames into messages, so the relay re-wraps each message
    payload in a synthetic frame before feeding the filter and unwraps
    the filter's framed output back into messages. Frame payloads are
    byte-identical either way — the RFB tracker sees the same stream.

Security model:
    This server binds to 127.0.0.1 by default. Even with the bind,
    authentication is enforced so that a misconfigured reverse proxy
    cannot bypass the gateway. Setting SERVE_NOVNC_HOST=0.0.0.0 is
    discouraged and logged as a warning.
"""
import contextlib
import logging
import os
import sys

logger = logging.getLogger(__name__)

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_NOVNC_PORT,
    DEFAULT_NOVNC_WS_PORT,
)

# Idle budget for the WebSocket relay: no traffic in either direction
# for this long closes the tunnel. VNC sessions are chatty in practice;
# a dead peer is reaped instead of pinning a task + upstream socket.
_RELAY_IDLE_TIMEOUT = 300


class _RfbFilterError(Exception):
    """A restricted ephemeral session's RFB filter could not be built."""


def _check_novnc_auth(headers, client_ip=None):
    """Validate a request against the central auth gateway.

    Accepts either a session cookie, a Bearer session token, or an
    ephemeral session token with ``desktop:view`` permission.
    ``client_ip`` enforces the session's ``allowed_ip`` binding.
    Returns (allowed: bool, reason: str).

    The credential→session→permission→rate-limit tree lives in
    ``auth_gateway.authorize_request`` — this function only extracts
    credentials from the headers.
    """
    from vnc_remote_secure.security.auth_gateway import authorize_request
    from vnc_remote_secure.security.http_auth import (
        cookie_value,
        extract_bearer_token,
        header_get,
    )
    cookie = header_get(headers, 'Cookie')
    session_cookie = cookie_value(cookie, 'vnc_session')
    eph = cookie_value(cookie, 'vnc_ephemeral')
    bearer = extract_bearer_token(header_get(headers, 'Authorization'))
    allowed, reason, _ = authorize_request(
        cookie_value=session_cookie,
        bearer_token=bearer,
        ephemeral_cookie=eph,
        resource='desktop',
        required_permission='desktop:view',
        client_ip=client_ip or '',
    )
    return allowed, reason


def _parse_cookies(cookie_header):
    """Parse the Cookie header into a ``name -> value`` dict."""
    cookies = {}
    if cookie_header:
        for part in cookie_header.split(';'):
            part = part.strip()
            if '=' in part:
                k, _, v = part.partition('=')
                cookies[k.strip()] = v.strip()
    return cookies


def _ephemeral_token(cookies, bearer):
    """Return the ephemeral session token, from cookie or Bearer.

    The ephemeral credential may arrive as the ``vnc_ephemeral``
    cookie OR as a Bearer token — a Bearer-only path would bypass
    view-only enforcement entirely.
    """
    eph_tok = cookies.get('vnc_ephemeral') or ''
    if not eph_tok and bearer:
        try:
            from vnc_remote_secure.security.ephemeral_sessions import (
                verify_ephemeral_token,
            )
            payload = verify_ephemeral_token(bearer)
            if payload:
                eph_tok = payload['session_token']
        except Exception:  # noqa: BLE001 - not an ephemeral bearer
            pass
    return eph_tok


def _build_rfb_filter(eph_tok):
    """Return an RfbInputFilter when the ephemeral session is restricted.

    An ephemeral session without ``desktop:control`` gets
    protocol-level view-only — the filter drops
    KeyEvent/PointerEvent/ClientCutText inside the WebSocket stream
    so a modified client cannot send input even though the UI hides
    the controls.
    """
    if not eph_tok:
        return None
    try:
        from vnc_remote_secure.security.ephemeral_sessions import (
            get_session_store,
        )
        store = get_session_store()
        store._load_if_changed()
        sess = store.get(eph_tok)
        if sess is None:
            return None
        keyboard = sess.has_permission('desktop:keyboard', 'desktop')
        pointer = sess.has_permission('desktop:pointer', 'desktop')
        clip_w = sess.has_permission(
            'desktop:clipboard_write', 'desktop')
        clip_r = sess.has_permission(
            'desktop:clipboard_read', 'desktop')
        if keyboard and pointer and clip_w and clip_r:
            return None
        from vnc_remote_secure.services.rfb_filter import (
            RfbInputFilter,
        )
        logger.info(
            "RFB input filter active (keyboard=%s pointer=%s "
            "clipboard_write=%s clipboard_read=%s)",
            keyboard, pointer, clip_w, clip_r)
        return RfbInputFilter(
            allow_keyboard=keyboard, allow_pointer=pointer,
            allow_clipboard_write=clip_w,
            allow_clipboard_read=clip_r)
    except _RfbFilterError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail CLOSED
        # A restricted session whose filter cannot be built must
        # not fall back to byte-transparent proxying — that would
        # silently grant full RFB input to a view-only session.
        logger.exception(
            "RFB filter construction failed for ephemeral "
            "session — denying upgrade")
        raise _RfbFilterError(
            "cannot enforce restricted-session input policy") from exc


def _record_ws_origin_failure(headers, peer_ip):
    """Record a rate-limit failure for a rejected WS origin."""
    try:
        from vnc_remote_secure.security.http_auth import client_ip_from
        from vnc_remote_secure.security.rate_limit import get_auth_limiter
        ip = client_ip_from(headers, peer_ip)
        get_auth_limiter().record_failure(f'ws:{ip}')
    except Exception:  # noqa: BLE001 - rate limiting is best-effort
        pass


def _ws_payloads(data: bytes):
    """Extract message payloads from raw WebSocket frames.

    Returns a list of payloads for data opcodes, or ``None`` on a
    protocol violation. The RFB filter emits complete frames; anything
    unparseable means the filter's own output is broken — the caller
    must tear the connection down (fail closed).
    """
    from vnc_remote_secure.services.rfb_filter import _parse_ws_frames
    buf = bytearray(data)
    frames = _parse_ws_frames(buf)
    if frames is None:
        return None
    out = []
    for opcode, payload, _raw, _fin in frames:
        if opcode in (0, 1, 2):  # continuation/text/binary
            out.append(payload)
        elif opcode == 8:  # close — relay ends
            return out if out else []
    return out


async def _relay_ws(websocket, upstream, rfb_filter):
    """Pump messages between the client WebSocket and the upstream
    websockify bridge, applying ``rfb_filter`` when present.

    ``websocket`` is a Starlette WebSocket (message-level) and
    ``upstream`` a ``websockets`` client connection. With a filter,
    each message payload is wrapped in a synthetic frame — the filter
    tracks WS framing internally — and its framed output is unwrapped
    back to message payloads. ``None`` from the filter is a protocol
    violation: fail closed by tearing down both ends.

    The idle deadline mirrors the old select-loop budget: a receive
    that blocks longer than ``_RELAY_IDLE_TIMEOUT`` reaps the tunnel.

    Returns when either side closes, errors, or the idle deadline is
    exceeded. Caller owns endpoint cleanup.
    """
    import asyncio

    from vnc_remote_secure.services.rfb_filter import (
        _ws_frame,
        _ws_server_frame,
    )

    async def client_to_upstream():
        while True:
            data = await asyncio.wait_for(
                websocket.receive_bytes(), timeout=_RELAY_IDLE_TIMEOUT)
            if rfb_filter is None:
                await upstream.send(data)
                continue
            out = rfb_filter.client_to_server(_ws_frame(data))
            if out is None:
                return
            payloads = _ws_payloads(out)
            if payloads is None:
                return
            for payload in payloads:
                await upstream.send(payload)

    async def upstream_to_client():
        while True:
            msg = await asyncio.wait_for(
                upstream.recv(), timeout=_RELAY_IDLE_TIMEOUT)
            data = msg if isinstance(msg, bytes) else msg.encode()
            if rfb_filter is None:
                await websocket.send_bytes(data)
                continue
            out = rfb_filter.track_server(_ws_server_frame(data))
            if out is None:
                return
            payloads = _ws_payloads(out)
            if payloads is None:
                return
            for payload in payloads:
                await websocket.send_bytes(payload)

    tasks = [asyncio.ensure_future(client_to_upstream()),
             asyncio.ensure_future(upstream_to_client())]
    done, _pending = await asyncio.wait(
        tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    # Surface a pump failure to the caller for logging/teardown.
    for t in done:
        with contextlib.suppress(Exception):
            t.result()


def _resolve_static(root: str, path: str):
    """Resolve ``path`` inside ``root``; None when outside/missing.

    Returns (kind, absolute_path) where kind is 'file' or 'dir'.
    """
    root_real = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root_real, path))
    if target != root_real and not target.startswith(root_real + os.sep):
        return None
    if os.path.isfile(target):
        return ('file', target)
    if os.path.isdir(target):
        return ('dir', target)
    return None


def make_app(novnc_dir: str | None = None):
    """Build the FastAPI noVNC application.

    ``GET /<path>`` serves the vendored noVNC static bundle behind the
    auth gateway; ``/websockify`` upgrades to the authenticated
    RFB-over-WebSocket relay toward the loopback websockify bridge.
    """
    from fastapi import FastAPI
    from starlette.requests import Request
    from starlette.responses import (
        FileResponse,
        JSONResponse,
        RedirectResponse,
    )
    from starlette.websockets import WebSocket, WebSocketDisconnect

    from vnc_remote_secure.security.http_headers import get_security_headers

    root = os.path.realpath(novnc_dir or os.environ.get('NOVNC_DIR', '.'))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def _unauthorized(reason: str) -> JSONResponse:
        return JSONResponse(
            {'error': 'unauthorized', 'reason': reason},
            status_code=401,
            headers={'WWW-Authenticate': 'Bearer realm="noVNC"'})

    def _client_ip(headers, client) -> str:
        from vnc_remote_secure.security.http_auth import client_ip_from
        return client_ip_from(
            headers, client.host if client else '')

    @app.middleware('http')
    async def _security_headers(request, call_next):
        resp = await call_next(request)
        emitted = {k.lower() for k in resp.headers.keys()}
        for name, value in get_security_headers(
                tls_enabled=request.url.scheme == 'https').items():
            if name.lower() not in emitted:
                resp.headers[name] = value
        return resp

    @app.websocket('/websockify')
    async def websockify(websocket: WebSocket):
        """Authenticated RFB-over-WebSocket relay to the loopback
        websockify bridge (``NOVNC_WS_PORT``, default 5700).

        The bridge does the RFB-over-WebSocket translation to the VNC
        server. Clients reach it only through this authenticated
        endpoint, so the auth-gateway check below is the single
        enforcement point. The connection is registered so revoking
        the session kills the stream immediately.
        """
        import asyncio

        headers = websocket.headers
        client_ip = _client_ip(headers, websocket.client)

        # Auth gate first — a rejected upgrade answers HTTP 401/403,
        # not an accepted socket.
        allowed, reason = _check_novnc_auth(headers, client_ip)
        if not allowed:
            await websocket.send_denial_response(
                _unauthorized(reason))
            return

        # CSWSH protection: the upgrade carries ambient credentials
        # (cookies), so the Origin header must be on the allowlist.
        from vnc_remote_secure.security.auth_gateway import (
            check_origin,
            get_allowed_origins,
        )
        if not check_origin(
                headers.get('origin', ''), get_allowed_origins()):
            _record_ws_origin_failure(
                headers, websocket.client.host if websocket.client
                else '')
            await websocket.send_denial_response(JSONResponse(
                {'error': 'invalid origin'}, status_code=403))
            return

        # Credential extraction + RFB filter BEFORE the upstream dial
        # — a denied restricted session never reaches the bridge.
        bearer = ''
        cookies = {}
        try:
            from vnc_remote_secure.security.http_auth import (
                extract_bearer_token,
            )
            bearer = extract_bearer_token(
                headers.get('authorization', ''))
            cookies = _parse_cookies(headers.get('cookie', ''))
        except Exception:  # noqa: BLE001 - header parse is best-effort
            pass
        try:
            rfb_filter = _build_rfb_filter(
                _ephemeral_token(cookies, bearer))
        except _RfbFilterError:
            # Restricted session, filter unavailable: deny rather than
            # proxy unfiltered (fail-closed, see _build_rfb_filter).
            await websocket.send_denial_response(JSONResponse(
                {'error': 'restricted session'}, status_code=403))
            return

        ws_port = int(os.environ.get(
            'NOVNC_WS_PORT', str(DEFAULT_NOVNC_WS_PORT)))
        try:
            import websockets
            upstream = await websockets.connect(
                f'ws://127.0.0.1:{ws_port}{websocket.url.path}',
                subprotocols=[
                    s for s in websocket.scope.get('subprotocols', [])
                ] or None,
                open_timeout=10,
                # No pings — the old byte-level TCP relay added none;
                # keep the wire behavior identical.
                ping_interval=None,
                max_size=None,
            )
        except Exception:  # noqa: BLE001 - any dial/handshake failure
            await websocket.send_denial_response(JSONResponse(
                {'error': 'vnc bridge unavailable'}, status_code=502))
            return

        # Register for live revocation. The registry's close callback
        # fires on a watcher THREAD — hop back onto the loop.
        loop = asyncio.get_running_loop()
        token = (cookies.get('vnc_ephemeral') or bearer
                 or cookies.get('vnc_session') or '')
        conn_id = None
        if token:
            def _close_cb():
                async def _tear():
                    with contextlib.suppress(Exception):
                        await upstream.close()
                    with contextlib.suppress(Exception):
                        await websocket.close(code=1000)
                asyncio.run_coroutine_threadsafe(_tear(), loop)
            try:
                from vnc_remote_secure.security.websocket_registry import (
                    register_connection,
                    start_revocation_watcher_thread,
                )
                conn_id = register_connection(
                    token, _close_cb, resource='desktop',
                    client_ip=client_ip)
                if conn_id is not None:
                    start_revocation_watcher_thread(token)
                else:
                    # Session revoked between validation and
                    # registration (TOCTOU guard in the registry).
                    await websocket.send_denial_response(JSONResponse(
                        {'error': 'Session revoked'}, status_code=403))
                    with contextlib.suppress(Exception):
                        await upstream.close()
                    return
            except Exception:  # noqa: BLE001 - registration best-effort
                conn_id = None

        # Negotiate the 'binary' subprotocol the upstream picked — the
        # noVNC client offers it and expects it echoed back.
        await websocket.accept(subprotocol=upstream.subprotocol)
        try:
            await _relay_ws(websocket, upstream, rfb_filter)
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001 - pump ended abnormally
            pass
        finally:
            with contextlib.suppress(Exception):
                await upstream.close()
            if conn_id:
                try:
                    from vnc_remote_secure.security.websocket_registry import (
                        unregister_connection,
                    )
                    unregister_connection(conn_id)
                except Exception:  # noqa: BLE001
                    pass

    @app.api_route('/{path:path}', methods=['GET', 'HEAD'])
    async def static_files(request: Request, path: str = ''):
        """Serve the noVNC bundle behind the auth gate.

        Directory requests serve ``index.html`` when present; the
        bare root falls back to ``vnc.html`` (the noVNC bundle has no
        index). No directory listings — path containment is enforced
        with realpath.
        """
        from vnc_remote_secure.security.http_auth import (
            request_headers_safe,
        )
        if not request_headers_safe(request.headers):
            return JSONResponse({'error': 'bad request'},
                                status_code=400)
        client_ip = _client_ip(request.headers, request.client)
        allowed, reason = _check_novnc_auth(request.headers, client_ip)
        if not allowed:
            return _unauthorized(reason)
        resolved = _resolve_static(root, path)
        if resolved is None:
            return JSONResponse({'error': 'not found'},
                                status_code=404)
        kind, target = resolved
        if kind == 'dir':
            for cand in ('index.html', 'vnc.html', 'vnc_lite.html'):
                hit = _resolve_static(root, f'{path.rstrip("/")}/{cand}'
                                      .lstrip('/'))
                if hit and hit[0] == 'file':
                    if path == '':
                        return RedirectResponse(f'/{cand}')
                    return FileResponse(hit[1])
            return JSONResponse({'error': 'not found'},
                                status_code=404)
        return FileResponse(target)

    return app


def main():
    """Run the authenticated noVNC server (uvicorn)."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s')

    novnc_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        'NOVNC_DIR')
    if not novnc_dir:
        logger.error(
            "noVNC directory not provided (argv[1] or NOVNC_DIR). "
            "Run the dependency downloader first.")
        sys.exit(1)
    if not os.path.isdir(novnc_dir):
        logger.error("Directory '%s' does not exist", novnc_dir)
        sys.exit(1)

    try:
        port = int(os.environ.get('NOVNC_PORT', str(DEFAULT_NOVNC_PORT)))
    except (TypeError, ValueError):
        port = DEFAULT_NOVNC_PORT
    # Same resolution chain as config._env_host: SERVE_NOVNC_HOST →
    # NOVNC_HOST → BIND_HOST → loopback — so the documented BIND_HOST
    # knob actually controls this backend's binding.
    host = (os.environ.get('SERVE_NOVNC_HOST', '').strip()
            or os.environ.get('NOVNC_HOST', '').strip()
            or os.environ.get('BIND_HOST', '').strip()
            or DEFAULT_BIND_HOST)
    # justification: detection, not a bind
    if host == '0.0.0.0':  # nosec B104
        logger.warning("SERVE_NOVNC_HOST=0.0.0.0 exposes noVNC directly; "
                       "use a reverse proxy instead")

    ssl_kwargs = {}
    from vnc_remote_secure.security.certificates import create_ssl_context
    if create_ssl_context():
        ssl_kwargs = {
            'ssl_certfile': os.environ.get('SSL_CERT'),
            'ssl_keyfile': os.environ.get('SSL_KEY')}
        scheme = 'https'
    else:
        scheme = 'http'
    logger.info("noVNC web server running on %s://%s:%s (auth: enabled)",
                scheme, host, port)
    uvicorn.run(make_app(novnc_dir), host=host, port=port,
                log_level='warning', access_log=False,
                proxy_headers=False, **ssl_kwargs)


if __name__ == '__main__':
    main()
