#!/usr/bin/env python3
"""noVNC static file server with session validation.

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
    ``desktop:control`` (or ``desktop:clipboard``) the relay activates
    ``services.rfb_filter.RfbInputFilter``: a protocol-aware filter
    that parses the client RFB message stream inside the WebSocket
    frames and drops KeyEvent (4), PointerEvent (5) and ClientCutText
    (6) messages. Unknown message types or unparseable streams close
    the connection (fail closed). Regular (non-ephemeral) sessions are
    not filtered — they are full-control admin sessions.

Security model:
    This server binds to 127.0.0.1 by default. Even with the bind,
    authentication is enforced so that a misconfigured reverse proxy
    cannot bypass the gateway. Setting SERVE_NOVNC_HOST=0.0.0.0 is
    discouraged and logged as a warning.
"""
import http.server
import logging
import os
import select
import signal
import sys
import time

logger = logging.getLogger(__name__)

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_NOVNC_PORT,
    DEFAULT_NOVNC_WS_PORT,
)

# Idle budget for the WebSocket relay: no traffic in either direction
# for this long closes the tunnel. VNC sessions are chatty in practice;
# a dead peer is reaped instead of pinning a thread + upstream socket.
_RELAY_IDLE_TIMEOUT = 300


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
    cookie = headers.get('Cookie', '') if hasattr(headers, 'get') else ''
    cookie_value = ''
    eph = ''
    if cookie:
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_session='):
                cookie_value = part.split('=', 1)[1].strip()
            elif part.startswith('vnc_ephemeral='):
                eph = part.split('=', 1)[1].strip()
    bearer = ''
    auth = headers.get('Authorization', '') if hasattr(headers, 'get') else ''
    if auth and auth.lower().startswith('bearer '):
        bearer = auth[7:].strip()
    allowed, reason, _ = authorize_request(
        cookie_value=cookie_value,
        bearer_token=bearer,
        ephemeral_cookie=eph,
        resource='desktop',
        required_permission='desktop:view',
        client_ip=client_ip or '',
    )
    return allowed, reason


def relay_rfb_stream(client_sock, upstream, rfb_filter=None):
    """Pump bytes between the client WS connection and the upstream
    websockify bridge, applying ``rfb_filter`` when present.

    Extracted from the request handler so the relay is unit-testable
    over ``socket.socketpair()`` without spawning the service.

    Details preserved from the handler implementation:
    - The upstream bridge answers the relayed upgrade with its own
      ``HTTP/1.1 101`` header block before WebSocket traffic begins.
      Those bytes reach the client verbatim but must NOT enter the
      RFB tracker's WS-frame parser — parsing HTTP as frames would
      desynchronise the handshake state machine permanently.
    - Idle cap: a half-open TCP connection (client vanished without
      RST) must not pin this handler thread and the upstream socket
      forever — select's 60s tick is the probe, but only an absolute
      budget actually reaps zombies.
    - ``rfb_filter.client_to_server`` returning ``None`` is a protocol
      violation: fail closed by tearing down both sockets.

    Returns when either side closes, errors, or the idle deadline is
    exceeded. Caller owns socket cleanup.
    """
    upstream_hdr_pending = rfb_filter is not None
    idle_deadline = time.monotonic() + _RELAY_IDLE_TIMEOUT
    while True:
        readable, _, _ = select.select(
            [client_sock, upstream], [], [], 60)
        if not readable:
            if time.monotonic() > idle_deadline:
                logger.debug("novnc relay idle timeout — closing")
                return
            continue
        idle_deadline = time.monotonic() + _RELAY_IDLE_TIMEOUT
        for sock in readable:
            data = sock.recv(65536)
            if not data:
                return
            if rfb_filter is not None:
                if sock is client_sock:
                    out = rfb_filter.client_to_server(data)
                    if out is None:
                        # Protocol violation / fail-closed:
                        # tear the connection down rather than
                        # relay unparseable input.
                        return
                    if out:
                        upstream.sendall(out)
                else:
                    if upstream_hdr_pending:
                        end = data.find(b'\r\n\r\n')
                        if end >= 0:
                            # Header block complete; only the
                            # remainder is WebSocket traffic.
                            rfb_filter.track_server(data[end + 4:])
                            upstream_hdr_pending = False
                        # else: still inside the 101 headers —
                        # nothing reaches the tracker yet.
                    else:
                        rfb_filter.track_server(data)
                    client_sock.sendall(data)
                continue
            peer = upstream if sock is client_sock else client_sock
            peer.sendall(data)


class _AuthedSimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler that enforces auth before serving files."""

    def setup(self):
        super().setup()
        # Slowloris guard: bound the pre-auth header-read window. The
        # websocket path clears this before relaying — the RFB relay
        # owns its own idle timeout for long-lived sessions.
        from vnc_remote_secure.services.bounded_server import (
            install_read_timeout,
        )
        install_read_timeout(self)

    def end_headers(self):
        from vnc_remote_secure.security.http_headers import send_security_headers
        send_security_headers(self)
        super().end_headers()

    def _require_auth(self) -> bool:
        """Run the auth gate; sends 401 and returns False on failure."""
        from vnc_remote_secure.security.http_auth import client_ip_from
        client_ip = client_ip_from(
            self.headers,
            self.client_address[0] if self.client_address else None)
        allowed, reason = _check_novnc_auth(
            self.headers, client_ip=client_ip)
        if not allowed:
            body = b'{"error":"unauthorized","reason":"' + reason.encode() + b'"}'
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.send_header('WWW-Authenticate', 'Bearer realm="noVNC"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def do_GET(self):  # noqa: N802 - stdlib API
        if not self._require_auth():
            return
        if self.path.split('?', 1)[0] == '/websockify' and \
                'websocket' in self.headers.get('Upgrade', '').lower():
            self._proxy_websocket()
            return
        super().do_GET()

    def do_HEAD(self):  # noqa: N802 - stdlib API
        # HEAD must go through the same gate — otherwise directory
        # listings and file metadata leak without authentication.
        if not self._require_auth():
            return
        super().do_HEAD()

    def _proxy_websocket(self):
        """Relay the WebSocket upgrade to the loopback websockify bridge.

        The bridge (``NOVNC_WS_PORT``, default 5700, loopback only) does
        the RFB-over-WebSocket translation to the VNC server. Clients
        reach it only through this authenticated endpoint, so the
        auth-gateway check above is the single enforcement point. The
        connection is registered so revoking the session kills the
        stream immediately.
        """
        import socket

        # CSWSH protection: the upgrade carries ambient credentials
        # (cookies), so the Origin header must be on the allowlist —
        # same rule the other WebSocket services enforce via
        # check_websocket_upgrade.
        from vnc_remote_secure.security.auth_gateway import check_origin, get_allowed_origins
        if not check_origin(
                self.headers.get('Origin', ''), get_allowed_origins()):
            try:
                from vnc_remote_secure.security.http_auth import client_ip_from
                from vnc_remote_secure.security.rate_limit import get_auth_limiter
                ip = client_ip_from(
                    self.headers,
                    self.client_address[0]
                    if self.client_address else None)
                get_auth_limiter().record_failure(f'ws:{ip}')
            except Exception:  # noqa: BLE001 - rate limiting is best-effort
                pass
            body = b'{"error":"invalid origin"}'
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        ws_port = int(os.environ.get(
            'NOVNC_WS_PORT', str(DEFAULT_NOVNC_WS_PORT)))
        try:
            upstream = socket.create_connection(('127.0.0.1', ws_port), timeout=10)
        except OSError:
            body = b'{"error":"vnc bridge unavailable"}'
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Re-register for live revocation (best-effort).
        conn_id = None
        rfb_filter = None
        try:
            auth = self.headers.get('Authorization', '')
            bearer = auth[7:].strip() if auth.lower().startswith('bearer ') else ''
            cookie = self.headers.get('Cookie', '')
            # Pick the credential in the same priority order the auth
            # check uses (vnc_ephemeral > bearer > vnc_session) so the
            # revocation registration binds to the identity that
            # actually authenticated — revoking the "other" cookie
            # must not leave this socket alive.
            cookies = {}
            if cookie:
                for part in cookie.split(';'):
                    part = part.strip()
                    if '=' in part:
                        k, _, v = part.partition('=')
                        cookies[k.strip()] = v.strip()
            token = (cookies.get('vnc_ephemeral') or bearer
                     or cookies.get('vnc_session') or '')
            # RFB input filter: an ephemeral session without
            # desktop:control gets protocol-level view-only — the
            # filter drops KeyEvent/PointerEvent/ClientCutText inside
            # the WebSocket stream so a modified client cannot send
            # input even though the UI hides the controls.
            # The ephemeral credential may arrive as the vnc_ephemeral
            # cookie OR as a Bearer token — a Bearer-only path would
            # bypass view-only enforcement entirely.
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
            if eph_tok:
                try:
                    from vnc_remote_secure.security.ephemeral_sessions import (
                        get_session_store,
                    )
                    store = get_session_store()
                    store._load_if_changed()
                    sess = store.get(eph_tok)
                    if sess is not None:
                        control = sess.has_permission(
                            'desktop:control', 'desktop')
                        clip = sess.has_permission(
                            'desktop:clipboard', 'desktop')
                        if not (control and clip):
                            from vnc_remote_secure.services.rfb_filter import (
                                RfbInputFilter,
                            )
                            rfb_filter = RfbInputFilter(
                                allow_clipboard=clip)
                            logger.info(
                                "RFB input filter active "
                                "(control=%s clipboard=%s)", control, clip)
                except Exception:  # noqa: BLE001 - filter is best-effort
                    rfb_filter = None
            if token:
                from vnc_remote_secure.security.websocket_registry import register_connection
                def _close():
                    for s in (self.connection, upstream):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        try:
                            s.close()
                        except OSError:
                            pass
                conn_id = register_connection(
                    token, _close, resource='desktop')
                if conn_id is not None:
                    # Cross-process revocation: a CLI revoke marks the
                    # shared namespace — this handler runs on a worker
                    # thread, so the watcher is a thread too.
                    from vnc_remote_secure.security.websocket_registry import (
                        start_revocation_watcher_thread,
                    )
                    start_revocation_watcher_thread(token)
                if conn_id is None:
                    # Session revoked between validation and
                    # registration (TOCTOU guard in the registry) —
                    # do not forward the upgrade.
                    self.send_response(403)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(
                        b'{"error":"Session revoked","status":403}')
                    try:
                        upstream.close()
                    except OSError:
                        pass
                    return
        except Exception:  # noqa: BLE001 - registration is best-effort
            conn_id = None

        # Rebuild and forward the original upgrade request verbatim.
        request = f"{self.command} {self.path} HTTP/1.1\r\n"
        for key, val in self.headers.items():
            request += f"{key}: {val}\r\n"
        request += "\r\n"
        # The upstream bridge's own ``HTTP/1.1 101`` header block is
        # forwarded verbatim but skipped for the RFB tracker — handled
        # inside relay_rfb_stream.
        try:
            # latin-1 can raise UnicodeEncodeError on exotic header
            # values — encode failures are not OSError, so encode here
            # first and let the except below catch both.
            request_bytes = request.encode('latin-1')
        except (UnicodeEncodeError, ValueError):
            logger.debug("Unencodable upstream request; dropping relay")
            try:
                upstream.close()
            except OSError:
                pass
            if conn_id:
                try:
                    from vnc_remote_secure.security.websocket_registry import unregister_connection
                    unregister_connection(conn_id)
                except Exception:  # noqa: BLE001
                    pass
            return
        try:
            upstream.sendall(request_bytes)
            self.close_connection = True
            # The header-read timeout from setup() must not fire inside
            # the relay — an idle VNC session is legitimate, and the
            # relay applies its own (longer) idle timeout via select.
            self.connection.settimeout(None)
            relay_rfb_stream(self.connection, upstream, rfb_filter)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass
            if conn_id:
                try:
                    from vnc_remote_secure.security.websocket_registry import unregister_connection
                    unregister_connection(conn_id)
                except Exception:  # noqa: BLE001
                    pass

    def log_message(self, fmt, *args):  # noqa: D401
        logger.info("%s - %s", self.client_address[0], fmt % args)


def main():
    """Start the noVNC static file server.

    Reads the noVNC directory and port from argv (or NOVNC_PORT env).
    """
    load_env_file()

    novnc_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('NOVNC_DIR', '')
    if not novnc_dir:
        # Never default to '.' — serving the process CWD would expose the
        # source tree and .env through the authenticated endpoint.
        logger.error(
            "noVNC directory not provided (argv[1] or NOVNC_DIR). "
            "Run 'make setup-novnc' or set NOVNC_DIR in .env.")
        sys.exit(1)
    try:
        port = int(sys.argv[2]) if len(sys.argv) > 2 else int(
            os.environ.get('NOVNC_PORT', str(DEFAULT_NOVNC_PORT)))
    except ValueError:
        logger.error("Invalid port '%s'", sys.argv[2])
        sys.exit(1)

    if not os.path.isdir(novnc_dir):
        logger.error("Directory '%s' does not exist", novnc_dir)
        sys.exit(1)

    os.chdir(novnc_dir)

    from vnc_remote_secure.services.bounded_server import (
        BoundedThreadingTCPServer,
    )

    # Same resolution chain as config._env_host: SERVE_NOVNC_HOST →
    # NOVNC_HOST → BIND_HOST → loopback — so the documented BIND_HOST
    # knob actually controls this backend's binding.
    host = (os.environ.get('SERVE_NOVNC_HOST', '').strip()
            or os.environ.get('NOVNC_HOST', '').strip()
            or os.environ.get('BIND_HOST', '').strip()
            or DEFAULT_BIND_HOST)
    if host == '0.0.0.0':
        logger.warning("SERVE_NOVNC_HOST=0.0.0.0 exposes noVNC directly; "
                       "use a reverse proxy instead")

    def signal_handler(sig, frame):
        logger.info("Shutting down...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    with BoundedThreadingTCPServer((host, port), _AuthedSimpleHTTPRequestHandler) as httpd:
        from vnc_remote_secure.security.certificates import create_ssl_context
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = 'https' if ssl_ctx else 'http'
        logger.info("noVNC web server running on %s://%s:%s (auth: enabled)",
                    scheme, host, port)
        httpd.serve_forever()


if __name__ == '__main__':
    main()
