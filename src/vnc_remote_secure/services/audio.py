#!/usr/bin/env python3
"""
Audio Stream Server for VNC Remote Secure.

Captures system audio from the server and streams it via WebSocket
to the browser client. The client plays it through its local audio
output (including Bluetooth headphones/speakers).

Architecture:
    System audio → ffmpeg (capture) → WebSocket → Browser <audio>

Works on:
    - Linux: PulseAudio (pactl/pacmd) or ALSA (arecord)
    - Windows: dshow (DirectShow) or WASAPI

Usage:
    python3 -m vnc_remote_secure.services.audio [--port 7777] [--host 127.0.0.1]
    python3 -m vnc_remote_secure.services.audio --list-devices   # List available audio devices

Environment variables:
    AUDIO_STREAM_PORT  - WebSocket port (default: 7777)
    AUDIO_STREAM_HOST  - Bind address (default: 127.0.0.1)
    AUDIO_DEVICE       - Audio device name (auto-detect if not set)
    AUDIO_BITRATE      - Bitrate in kbps (default: 128)
"""

import argparse
import asyncio
import contextlib
import json
import logging
import os
import subprocess

import websockets

from vnc_remote_secure.core.constants import (
    DEFAULT_AUDIO_STREAM_PORT,
    DEFAULT_BIND_HOST,
    DEFAULT_PING_INTERVAL,
    DEFAULT_PING_TIMEOUT,
)

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_PORT = DEFAULT_AUDIO_STREAM_PORT
DEFAULT_HOST = DEFAULT_BIND_HOST
DEFAULT_BITRATE = 128


def find_ffmpeg():
    """Find ffmpeg binary."""
    try:
        from vnc_remote_secure.core.processes import run_cmd
        result = run_cmd(["ffmpeg", "-version"], capture_output=True,
                         timeout=5)
        # run_cmd maps a timeout to returncode=-1 — a hung ffmpeg is
        # not a usable ffmpeg, so the rc matters here.
        return "ffmpeg" if result.returncode == 0 else None
    except FileNotFoundError:
        return None


def list_audio_devices():
    """List available audio capture devices."""
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        logger.error("ffmpeg not found. Install it to use audio streaming.")
        logger.error("  Linux:   sudo apt-get install ffmpeg")
        logger.error("  Windows: choco install ffmpeg  or  download from https://ffmpeg.org/")
        return

    logger.info("Available audio capture devices:\n")

    try:
        from vnc_remote_secure.platform.base import get_adapter
        get_adapter().list_audio_devices(ffmpeg)
    except Exception:
        logger.exception("Error listing devices:")

    logger.info("\nSet AUDIO_DEVICE=<name> in .env to use a specific device.")


def get_ffmpeg_capture_cmd(device=None, bitrate=DEFAULT_BITRATE):
    """Build ffmpeg command to capture system audio as MP3 stream."""
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        return None

    try:
        from vnc_remote_secure.platform.base import get_adapter
        input_args = get_adapter().get_audio_capture_cmd(ffmpeg, device, bitrate)
    except Exception as e:
        logger.debug("Platform audio capture cmd failed: %s", e)
        # Fallback: macOS avfoundation
        if not device:
            device = ":0"
        input_args = ["-f", "avfoundation", "-i", device]

    return [
        ffmpeg,
        "-loglevel", "error",  # Suppress verbose output
        *input_args,
        "-codec:a", "libmp3lame",
        "-b:a", f"{bitrate}k",
        "-f", "mp3",
        "pipe:1"  # Output to stdout
    ]


class AudioStreamServer:
    """WebSocket server that streams audio to connected clients."""

    def __init__(self, host, port, device, bitrate):
        """Init."""
        self.host = host
        self.port = port
        self.device = device
        self.bitrate = bitrate
        self.ffmpeg_process = None
        self.clients = set()
        self._ffmpeg_lock = asyncio.Lock()
        # Set while an ffmpeg process is running so audio_reader knows
        # when there is a stdout pipe to drain. ffmpeg starts lazily on
        # the first client, so the reader cannot just check once.
        self._ffmpeg_running = asyncio.Event()

    async def start_ffmpeg(self):
        """Start ffmpeg process to capture audio."""
        cmd = get_ffmpeg_capture_cmd(self.device, self.bitrate)
        if not cmd:
            logger.error("ffmpeg not found or audio device not available")
            return False

        try:
            # ffmpeg is an external binary that needs none of our
            # credentials — strip secret env vars like the service
            # manager does for websockify.
            try:
                from vnc_remote_secure.security.redaction import (
                    sanitized_child_env,
                )
                child_env = sanitized_child_env()
            except Exception:  # noqa: BLE001 - import broken entirely
                child_env = {'PATH': os.environ.get('PATH', '')}
            self.ffmpeg_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env,
            )
            self._ffmpeg_running.set()
            logger.info("ffmpeg started (PID: %s)", self.ffmpeg_process.pid)
            return True
        except Exception:
            logger.exception("Failed to start ffmpeg:")
            return False

    async def stop_ffmpeg(self):
        """Stop ffmpeg process."""
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            try:
                # A wedged encoder must not hang shutdown forever —
                # escalate to kill after the grace period.
                await asyncio.wait_for(self.ffmpeg_process.wait(), 5)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self.ffmpeg_process.kill()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self.ffmpeg_process.wait(), 5)
            self.ffmpeg_process = None
            self._ffmpeg_running.clear()
            logger.info("ffmpeg stopped")

    async def audio_reader(self):
        """Read audio from ffmpeg stdout and broadcast to clients.

        ffmpeg starts lazily when the first client connects, so this
        task waits on ``_ffmpeg_running`` instead of returning when no
        process exists yet — without that wait the pipe is never
        drained and ffmpeg stalls on a full stdout buffer.
        """
        restarts = 0
        max_restarts = 5
        while True:
            await self._ffmpeg_running.wait()
            proc = self.ffmpeg_process
            if proc is None or proc.stdout is None:
                self._ffmpeg_running.clear()
                continue
            data = await proc.stdout.read(4096)
            if not data:
                if proc is not self.ffmpeg_process:
                    # A different ffmpeg was started (or it was stopped)
                    # since we captured proc — re-wait on the event.
                    continue
                # ffmpeg ended, try to restart — but bound the retries:
                # a permanently broken capture would otherwise respawn
                # ffmpeg every ~2s forever while a client is connected.
                restarts += 1
                if restarts > max_restarts:
                    logger.error(
                        "ffmpeg restarted %d times without producing "
                        "audio; giving up", max_restarts)
                    self._ffmpeg_running.clear()
                    async with self._ffmpeg_lock:
                        await self.stop_ffmpeg()
                    continue
                logger.warning("ffmpeg stream ended, restarting "
                               "(%d/%d)...", restarts, max_restarts)
                await asyncio.sleep(2)
                async with self._ffmpeg_lock:
                    if self.ffmpeg_process is proc:
                        self.ffmpeg_process = None
                        self._ffmpeg_running.clear()
                    if not self.ffmpeg_process:
                        await self.start_ffmpeg()
                continue
            restarts = 0  # healthy stream resets the counter

            # Broadcast to all connected clients
            if self.clients:
                # Remove disconnected clients
                disconnected = set()
                for ws in self.clients:
                    try:
                        await ws.send(data)
                    except websockets.ConnectionClosed:
                        disconnected.add(ws)
                self.clients -= disconnected

    async def handle_client(self, websocket, _path=None):
        """Handle a new WebSocket client connection.

        Authentication is enforced via the central auth gateway before
        any audio data is sent. This prevents unauthorized clients from
        capturing the server's audio output.
        """
        # Validate auth via the central gateway.
        from vnc_remote_secure.security.auth_gateway import (
            check_websocket_upgrade,
            register_websocket_connection,
            unregister_websocket_connection,
        )
        # websockets>=13 exposes the handshake on connection.request;
        # the deprecated legacy protocol used request_headers and very
        # old versions connection.handler.request.
        headers = {}
        with contextlib.suppress(AttributeError, OSError):
            headers = websocket.request.headers
        if not headers:
            with contextlib.suppress(AttributeError, OSError):
                headers = websocket.request_headers
        if not headers:
            try:
                headers = websocket.handler.request.headers
            except (AttributeError, OSError):
                headers = {}
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
        # Unified auth: session cookie, bearer, or activated ephemeral
        # cookie — all resolved by the gateway's single enforcement tree.
        from vnc_remote_secure.security.http_auth import client_ip_from
        allowed, reason = check_websocket_upgrade(
            origin=origin,
            cookie_value=cookie_value,
            bearer_token=bearer,
            resource='audio',
            required_permission='desktop:view',
            client_ip=client_ip_from(
                headers,
                websocket.remote_address[0]
                if websocket.remote_address else None),
            ephemeral_cookie=eph,
        )
        if not allowed:
            logger.warning("Audio WebSocket rejected: %s", reason)
            await websocket.close(code=1008, reason=reason)
            return
        token = eph or bearer or cookie_value
        conn_id = register_websocket_connection(token, websocket.close, resource='audio')
        if conn_id is None:
            # Session revoked between validation and registration
            # (TOCTOU guard in the registry) — the socket must not
            # stay open for a revoked session.
            await websocket.close(code=1008, reason='Session revoked')
            return
        # A revocation issued from another process (e.g. the CLI) only
        # marks the shared namespace — this watcher notices and runs
        # the local close path.
        from vnc_remote_secure.security.websocket_registry import (
            start_revocation_watcher,
        )
        start_revocation_watcher(token)

        self.clients.add(websocket)
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        logger.info("Client connected: %s (total: %s)", client_ip, len(self.clients))

        # Start ffmpeg if not running
        async with self._ffmpeg_lock:
            if not self.ffmpeg_process and not await self.start_ffmpeg():
                await websocket.close(code=1011, reason="Audio capture failed")
                self.clients.discard(websocket)
                # Unregister like the finally block below — this
                # early return happens before the try/finally, so
                # without it the registry keeps a stale entry whose
                # close callback points at a dead websocket.
                try:
                    unregister_websocket_connection(conn_id)
                except (KeyError, ImportError):
                    logger.debug("Failed to unregister audio connection",
                                 exc_info=True)
                return

        try:
            # Keep connection alive; client sends periodic pings
            async for message in websocket:
                # Client can send control messages
                if isinstance(message, str):
                    try:
                        cmd = json.loads(message)
                        if cmd.get("type") == "status":
                            await websocket.send(json.dumps({
                                "type": "status",
                                "clients": len(self.clients),
                                "device": self.device or "auto",
                                "bitrate": f"{self.bitrate}k"
                            }))
                    except json.JSONDecodeError as exc:
                        logger.debug("Ignoring malformed audio message: %s", exc)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            logger.info("Client disconnected (total: %s)", len(self.clients))
            # Unregister from the revocation registry.
            try:
                unregister_websocket_connection(conn_id)
            except (KeyError, ImportError):
                logger.debug("Failed to unregister audio connection", exc_info=True)

            # Stop ffmpeg if no clients
            if not self.clients:
                async with self._ffmpeg_lock:
                    await self.stop_ffmpeg()

    async def run(self):
        """Start the WebSocket server."""
        # Optional TLS via shared SSL context builder.
        from vnc_remote_secure.security.certificates import create_ssl_context
        ssl_ctx = create_ssl_context()
        scheme = 'wss' if ssl_ctx else 'ws'

        logger.info("Audio Stream Server")
        logger.info("  Host:   %s", self.host)
        logger.info("  Port:   %s", self.port)
        logger.info("  Device: %s", self.device or 'auto-detect')
        logger.info("  Format: MP3 %skbps", self.bitrate)
        logger.info("  URL:    %s://%s:%s", scheme, self.host, self.port)

        # Start audio reader task
        asyncio.create_task(self.audio_reader())

        # Start WebSocket server (with optional TLS).
        async with websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_ctx,
            ping_interval=DEFAULT_PING_INTERVAL,
            ping_timeout=DEFAULT_PING_TIMEOUT,
            # Inbound client messages are control-only — the audio
            # flows server->client, so a few KiB is generous (default
            # was 1 MiB).
            max_size=8192,
        ):
            logger.info("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()  # Run forever


def main():
    """Start the audio streaming server."""
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    parser = argparse.ArgumentParser(description="Audio Stream Server")
    parser.add_argument("--port", type=int, default=None, help="WebSocket port")
    parser.add_argument("--host", type=str, default=None, help="Bind address")
    parser.add_argument("--device", type=str, default=None, help="Audio device name")
    parser.add_argument("--bitrate", type=int, default=None, help="Bitrate in kbps")
    parser.add_argument("--list-devices", action="store_true", help="List audio devices")
    args = parser.parse_args()

    if args.list_devices:
        list_audio_devices()
        return

    # Load from environment — same resolution chain as
    # config._env_host: AUDIO_STREAM_HOST → BIND_HOST → loopback.
    host = (args.host
            or os.environ.get("AUDIO_STREAM_HOST", '').strip()
            or os.environ.get('BIND_HOST', '').strip()
            or DEFAULT_HOST)
    port = args.port or int(os.environ.get("AUDIO_STREAM_PORT", DEFAULT_PORT))
    device = args.device or os.environ.get("AUDIO_DEVICE", "")
    bitrate = args.bitrate or int(os.environ.get("AUDIO_BITRATE", DEFAULT_BITRATE))

    server = AudioStreamServer(host, port, device or None, bitrate)

    async def _main():
        try:
            await server.run()
        finally:
            # Stop ffmpeg on the SAME loop that created it — awaiting a
            # subprocess from a fresh loop (asyncio.run after the first
            # one closed) raises RuntimeError or hangs.
            await server.stop_ffmpeg()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
