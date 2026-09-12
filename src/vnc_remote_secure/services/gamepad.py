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

class GamepadServer:
    def __init__(self, host, port):
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

    async def handle_client(self, websocket, path=None):
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
            return

        # Create virtual device if the injector supports it (Linux uinput)
        if hasattr(self.injector, 'create_device'):
            if not self.injector.create_device():
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Failed to create virtual input device"
                }))
                await websocket.close()
                self.clients.discard(websocket)
                return

        await websocket.send(json.dumps({
            "type": "connected",
            "message": "Gamepad forwarding active"
        }))

        try:
            async for message in websocket:
                try:
                    event = json.loads(message)
                    event_type = event.get("type")

                    if event_type == "button":
                        button = event.get("button")
                        value = event.get("value", 0)
                        self.injector.inject_button(button, value)

                    elif event_type == "axis":
                        axis = event.get("axis")
                        value = event.get("value", 0.0)
                        self.injector.inject_axis(axis, value)

                    elif event_type == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))

                except json.JSONDecodeError as exc:
                    logger.debug("Ignoring malformed gamepad message: %s", exc)

        except websockets.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            logger.info("Gamepad client disconnected")

            if not self.clients and self.injector:
                self.injector.close()
                if hasattr(self.injector, 'uinput'):
                    # Reset for next client
                    self.injector.uinput = None

    async def run(self):
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
            ping_timeout=DEFAULT_PING_TIMEOUT
        ):
            logger.info("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(description="Gamepad Forwarding Server")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", type=str, default=None)
    args = parser.parse_args()

    host = args.host or os.environ.get("GAMEPAD_HOST", DEFAULT_HOST)
    port = args.port or int(os.environ.get("GAMEPAD_PORT", DEFAULT_PORT))

    server = GamepadServer(host, port)

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("\nShutting down...")
        if server.injector:
            server.injector.close()


if __name__ == "__main__":
    main()
