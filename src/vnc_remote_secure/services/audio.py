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
        subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=5)
        return "ffmpeg"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def list_audio_devices():
    """List available audio capture devices."""
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        logger.error("ffmpeg not found. Install it to use audio streaming.")
        logger.error("  Linux:   sudo apt-get install ffmpeg")
        logger.error("  Windows: choco install ffmpeg  or  download from https://ffmpeg.org/")
        return

    print("Available audio capture devices:\n")

    try:
        from vnc_remote_secure.platform.base import get_adapter
        get_adapter().list_audio_devices(ffmpeg)
    except Exception as e:
        logger.error("Error listing devices: %s", e)

    print("\nSet AUDIO_DEVICE=<name> in .env to use a specific device.")


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

    cmd = [
        ffmpeg,
        "-loglevel", "error",  # Suppress verbose output
        *input_args,
        "-codec:a", "libmp3lame",
        "-b:a", f"{bitrate}k",
        "-f", "mp3",
        "pipe:1"  # Output to stdout
    ]

    return cmd


class AudioStreamServer:
    """WebSocket server that streams audio to connected clients."""

    def __init__(self, host, port, device, bitrate):
        self.host = host
        self.port = port
        self.device = device
        self.bitrate = bitrate
        self.ffmpeg_process = None
        self.clients = set()
        self._ffmpeg_lock = asyncio.Lock()

    async def start_ffmpeg(self):
        """Start ffmpeg process to capture audio."""
        cmd = get_ffmpeg_capture_cmd(self.device, self.bitrate)
        if not cmd:
            logger.error("ffmpeg not found or audio device not available")
            return False

        try:
            self.ffmpeg_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info("ffmpeg started (PID: %s)", self.ffmpeg_process.pid)
            return True
        except Exception as e:
            logger.error("Failed to start ffmpeg: %s", e)
            return False

    async def stop_ffmpeg(self):
        """Stop ffmpeg process."""
        if self.ffmpeg_process:
            self.ffmpeg_process.terminate()
            await self.ffmpeg_process.wait()
            self.ffmpeg_process = None
            logger.info("ffmpeg stopped")

    async def audio_reader(self):
        """Read audio from ffmpeg stdout and broadcast to clients."""
        if not self.ffmpeg_process:
            return

        while True:
            data = await self.ffmpeg_process.stdout.read(4096)
            if not data:
                # ffmpeg ended, try to restart
                logger.warning("ffmpeg stream ended, restarting...")
                await asyncio.sleep(2)
                await self.start_ffmpeg()
                if not self.ffmpeg_process:
                    break
                continue

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

    async def handle_client(self, websocket, path=None):
        """Handle a new WebSocket client connection."""
        self.clients.add(websocket)
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        logger.info("Client connected: %s (total: %s)", client_ip, len(self.clients))

        # Start ffmpeg if not running
        async with self._ffmpeg_lock:
            if not self.ffmpeg_process:
                if not await self.start_ffmpeg():
                    await websocket.close(code=1011, reason="Audio capture failed")
                    self.clients.discard(websocket)
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
            ping_timeout=DEFAULT_PING_TIMEOUT
        ):
            logger.info("Server running. Press Ctrl+C to stop.")
            await asyncio.Future()  # Run forever


def main():
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

    # Load from environment
    host = args.host or os.environ.get("AUDIO_STREAM_HOST", DEFAULT_HOST)
    port = args.port or int(os.environ.get("AUDIO_STREAM_PORT", DEFAULT_PORT))
    device = args.device or os.environ.get("AUDIO_DEVICE", "")
    bitrate = args.bitrate or int(os.environ.get("AUDIO_BITRATE", DEFAULT_BITRATE))

    server = AudioStreamServer(host, port, device or None, bitrate)

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print("\nShutting down...")
        asyncio.run(server.stop_ffmpeg())


if __name__ == "__main__":
    main()
