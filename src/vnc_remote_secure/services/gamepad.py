#!/usr/bin/env python3
"""
Gamepad Forwarding Server for VNC Remote Secure.

Receives gamepad events from the browser client (via WebSocket) and
injects them as keyboard/mouse events on the server using platform-native tools.

Browser side: HTML5 Gamepad API → WebSocket → This server
Server side:
    - Linux:   uinput (virtual input device) via evdev
    - Windows: SendInput via ctypes (virtual keyboard/mouse)

This allows using a Bluetooth gamepad connected to the client device
to control the remote server.

Usage:
    python3 -m vnc_remote_secure.services.gamepad [--port 7788] [--host 127.0.0.1]

Environment variables:
    GAMEPAD_PORT  - WebSocket port (default: 7788)
    GAMEPAD_HOST  - Bind address (default: 127.0.0.1)
"""

import argparse
import asyncio
import json
import logging
import os
import platform

import websockets

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_GAMEPAD_PORT,
    DEFAULT_PING_INTERVAL,
    DEFAULT_PING_TIMEOUT,
)

logger = logging.getLogger(__name__)

DEFAULT_PORT = DEFAULT_GAMEPAD_PORT
DEFAULT_HOST = DEFAULT_BIND_HOST


# ============================================================================
# WebSocket Server
# ============================================================================

def _extract_upgrade_headers(websocket):
    """Return the HTTP upgrade request headers from a websockets connection.

    ``websockets``>=13 exposes the handshake on ``connection.request``;
    the deprecated legacy protocol used ``connection.request_headers``
    and very old versions ``connection.handler.request``. Trying the
    modern attribute first keeps auth working on current releases —
    an empty header dict would make every origin check reject the
    upgrade.
    """
    try:
        return websocket.request.headers
    except (AttributeError, OSError):
        pass
    try:
        return websocket.request_headers
    except (AttributeError, OSError):
        pass
    try:
        return websocket.handler.request.headers
    except (AttributeError, OSError):
        return {}


def _authenticate_gamepad_connection(headers, websocket):
    """Extract and validate auth from the WebSocket upgrade headers.

    Performs the auth-gateway upgrade check and registers the
    connection so it can be revoked later.

    Returns:
        (allowed, token, conn_id, error_msg) — when *allowed* is
        ``False`` the remaining values are ``None`` and *error_msg*
        carries the rejection reason.
    """
    from vnc_remote_secure.security.auth_gateway import (
        check_websocket_upgrade,
        register_websocket_connection,
    )
    origin = headers.get('Origin', '') if hasattr(headers, 'get') else ''
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
    from vnc_remote_secure.security.http_auth import client_ip_from
    peer_ip = client_ip_from(
        headers,
        websocket.remote_address[0]
        if getattr(websocket, 'remote_address', None) else None)
    # Unified auth: session cookie, bearer, or activated ephemeral
    # cookie — resolved by the gateway's single enforcement tree.
    allowed, reason = check_websocket_upgrade(
        origin=origin,
        cookie_value=cookie_value,
        bearer_token=bearer,
        resource='gamepad',
        required_permission='desktop:control',
        client_ip=peer_ip,
        ephemeral_cookie=eph,
    )
    if not allowed:
        return False, None, None, reason
    token = eph or bearer or cookie_value
    conn_id = register_websocket_connection(token, websocket.close, resource='gamepad')
    if conn_id is None:
        # Session revoked between validation and registration
        # (TOCTOU guard in the registry).
        return False, None, None, 'Session revoked'
    # Cross-process revocation: the CLI's revoke marks shared state;
    # this watcher runs the local close path when the mark appears.
    from vnc_remote_secure.security.websocket_registry import (
        start_revocation_watcher,
    )
    start_revocation_watcher(token)
    return True, token, conn_id, None


def _process_gamepad_message(server, msg_data, websocket):
    """Process a single gamepad message (button, axis, ping).

    Returns a response dict to send back to the client, or ``None``
    when no response is required.
    """
    event_type = msg_data.get("type")

    if event_type == "button":
        button = msg_data.get("button")
        value = msg_data.get("value", 0)
        server.injector.inject_button(button, value)
        return None

    if event_type == "axis":
        axis = msg_data.get("axis")
        value = msg_data.get("value", 0.0)
        server.injector.inject_axis(axis, value)
        return None

    if event_type == "ping":
        return {"type": "pong"}

    return None


class GamepadServer:
    """Gamepad Server."""

    def __init__(self, host, port):
        """Init."""
        self.host = host
        self.port = port
        self.injector = None
        self.clients = set()

        # Create platform-appropriate injector via the platform adapter
        try:
            from vnc_remote_secure.platform.base import get_adapter
            self.injector = get_adapter().create_gamepad_injector()
        except Exception as e:
            logger.warning("Gamepad injector creation failed: %s", e)
            self.injector = None
        # Normalize an unavailable injector to None for consistent handling
        if self.injector is not None and not getattr(self.injector, 'available', False):
            self.injector = None
        if self.injector is None:
            logger.warning("Gamepad forwarding not supported on %s", platform.system())

    async def handle_client(self, websocket, _path=None):
        """Handle a new gamepad WebSocket client with auth gateway enforcement.

        Gamepad input is a control action: it requires the
        ``desktop:control`` permission. View-only sessions are rejected.
        """
        from vnc_remote_secure.security.auth_gateway import (
            unregister_websocket_connection,
        )
        headers = _extract_upgrade_headers(websocket)

        allowed, _token, conn_id, error_msg = _authenticate_gamepad_connection(
            headers, websocket)
        if not allowed:
            logger.warning("Gamepad WebSocket rejected: %s", error_msg)
            await websocket.close(code=1008, reason=error_msg)
            return

        self.clients.add(websocket)
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        logger.info("Gamepad client connected: %s", client_ip)

        if not self.injector or not self.injector.available:
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Gamepad injection not available on this server"
            }))
            await websocket.close()
            self.clients.discard(websocket)
            try:
                unregister_websocket_connection(conn_id)
            except (KeyError, ImportError):
                logger.debug("Failed to unregister gamepad connection", exc_info=True)
            return

        # Create virtual device if the injector supports it (Linux uinput)
        if hasattr(self.injector, 'create_device') and not self.injector.create_device():
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Failed to create virtual input device"
            }))
            await websocket.close()
            self.clients.discard(websocket)
            # Unregister like the unavailable-injector branch above —
            # otherwise the registry keeps a stale entry whose close
            # callback points at a dead websocket until revocation.
            try:
                unregister_websocket_connection(conn_id)
            except (KeyError, ImportError):
                logger.debug("Failed to unregister gamepad connection",
                             exc_info=True)
            return

        await websocket.send(json.dumps({
            "type": "connected",
            "message": "Gamepad forwarding active"
        }))

        try:
            async for message in websocket:
                try:
                    event = json.loads(message)
                    response = _process_gamepad_message(self, event, websocket)
                    if response is not None:
                        await websocket.send(json.dumps(response))

                except json.JSONDecodeError as exc:
                    logger.debug("Ignoring malformed gamepad message: %s", exc)

        except websockets.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            logger.info("Gamepad client disconnected")
            try:
                unregister_websocket_connection(conn_id)
            except (KeyError, ImportError):
                logger.debug("Failed to unregister gamepad connection", exc_info=True)

            if not self.clients and self.injector:
                self.injector.close()
                if hasattr(self.injector, 'uinput'):
                    # Reset for next client
                    self.injector.uinput = None

    async def run(self):
        """Run."""
        # Optional TLS via shared SSL context builder.
        from vnc_remote_secure.security.certificates import create_ssl_context
        ssl_ctx = create_ssl_context()
        scheme = 'wss' if ssl_ctx else 'ws'

        logger.info("Gamepad Forwarding Server")
        logger.info("  Host:   %s", self.host)
        logger.info("  Port:   %s", self.port)
        logger.info("  Platform: %s", platform.system())
        logger.info("  Injector: %s", 'available' if self.injector and self.injector.available else 'not available')
        logger.info("  URL:    %s://%s:%s", scheme, self.host, self.port)

        async with websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_ctx,
            ping_interval=DEFAULT_PING_INTERVAL,
            ping_timeout=DEFAULT_PING_TIMEOUT,
            # Gamepad events are small JSON objects — the 1 MiB default
            # only served a memory-exhaustion vector.
            max_size=8192,
        ):
            logger.info("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()


def main():
    """Start the gamepad forwarding server."""
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    parser = argparse.ArgumentParser(description="Gamepad Forwarding Server")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", type=str, default=None)
    args = parser.parse_args()

    # Same resolution chain as config._env_host: GAMEPAD_HOST →
    # BIND_HOST → loopback.
    host = (args.host
            or os.environ.get("GAMEPAD_HOST", '').strip()
            or os.environ.get('BIND_HOST', '').strip()
            or DEFAULT_HOST)
    port = args.port or int(os.environ.get("GAMEPAD_PORT", DEFAULT_PORT))

    server = GamepadServer(host, port)

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Shutting down...")
        if server.injector:
            server.injector.close()


if __name__ == "__main__":
    main()
