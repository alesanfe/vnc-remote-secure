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
    python3 gamepad_server.py [--port 7788] [--host 127.0.0.1]

Environment variables:
    GAMEPAD_PORT  - WebSocket port (default: 7788)
    GAMEPAD_HOST  - Bind address (default: 127.0.0.1)
"""

import argparse
import asyncio
import json
import os
import platform
import sys
import websockets
from datetime import datetime

DEFAULT_PORT = 7788
DEFAULT_HOST = "127.0.0.1"


def is_windows():
    return platform.system() == "Windows"


def is_linux():
    return platform.system() == "Linux"


# ============================================================================
# Linux: uinput via evdev (optional dependency)
# ============================================================================

class LinuxInputInjector:
    """Inject input events on Linux using uinput (via evdev)."""

    def __init__(self):
        self.uinput = None
        self.available = False
        try:
            import evdev
            from evdev import UInput, ecodes
            self.ecodes = ecodes
            self.UInput = UInput
            self.evdev = evdev
            self.available = True
        except ImportError:
            print("WARNING: evdev not installed. Gamepad forwarding disabled on Linux.")
            print("  Install with: pip install evdev")
            print("  Also ensure uinput module is loaded: sudo modprobe uinput")

    def create_device(self):
        if not self.available:
            return False
        try:
            self.uinput = self.UInput(
                events={
                    self.ecodes.EV_KEY: [
                        self.ecodes.BTN_GAMEPAD,
                        self.ecodes.BTN_A,
                        self.ecodes.BTN_B,
                        self.ecodes.BTN_X,
                        self.ecodes.BTN_Y,
                        self.ecodes.BTN_TL,
                        self.ecodes.BTN_TR,
                        self.ecodes.BTN_SELECT,
                        self.ecodes.BTN_START,
                        self.ecodes.BTN_THUMBL,
                        self.ecodes.BTN_THUMBR,
                        self.ecodes.KEY_ENTER,
                        self.ecodes.KEY_ESC,
                        self.ecodes.KEY_SPACE,
                        self.ecodes.BTN_LEFT,
                    ],
                    self.ecodes.EV_ABS: [
                        self.ecodes.ABS_X,
                        self.ecodes.ABS_Y,
                        self.ecodes.ABS_RX,
                        self.ecodes.ABS_RY,
                    ],
                },
                name="VNC Remote Virtual Gamepad"
            )
            return True
        except Exception as e:
            print(f"ERROR: Failed to create uinput device: {e}")
            print("  Ensure uinput is accessible: sudo chmod 0666 /dev/uinput")
            return False

    def inject_button(self, button, value):
        if not self.uinput:
            return
        self.uinput.write(self.ecodes.EV_KEY, button, value)
        self.uinput.syn()

    def inject_axis(self, axis, value):
        if not self.uinput:
            return
        # value is -1.0 to 1.0, convert to uinput range (-32768 to 32767)
        uinput_value = int(value * 32767)
        self.uinput.write(self.ecodes.EV_ABS, axis, uinput_value)
        self.uinput.syn()

    def close(self):
        if self.uinput:
            self.uinput.close()
            self.uinput = None


# ============================================================================
# Windows: SendInput via ctypes
# ============================================================================

class WindowsInputInjector:
    """Inject input events on Windows using SendInput (ctypes)."""

    def __init__(self):
        self.available = True
        # Map gamepad buttons to virtual key codes
        self.key_map = {
            "button_0": 0x1D,  # 'A' key (cross button)
            "button_1": 0x1E,  # 'B' key (circle button)
            "button_2": 0x2C,  # 'X' key (square button)
            "button_3": 0x2D,  # 'Y' key (triangle button)
            "button_4": 0x10,  # 'Q' key (L1)
            "button_5": 0x19,  # 'P' key (R1)
            "button_8": 0x3A,  # Escape (Select/Share)
            "button_9": 0x1C,  # Enter (Start)
        }

    def inject_button(self, button_code, value):
        import ctypes
        from ctypes import wintypes

        # SendInput structures
        INPUT_KEYBOARD = 1
        INPUT_MOUSE = 2

        KEYEVENTF_KEYDOWN = 0x0000
        KEYEVENTF_KEYUP = 0x0002

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", wintypes.WORD),
                        ("wScan", wintypes.WORD),
                        ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("ki", KEYBDINPUT)]
            _anonymous_ = ("_input",)
            _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT)]

        vk = self.key_map.get(button_code)
        if vk is None:
            return

        flags = KEYEVENTF_KEYUP if value == 0 else KEYEVENTF_KEYDOWN

        inp = INPUT()
        inp.type = INPUT_KEYBOARD
        inp.ki.wVk = vk
        inp.ki.dwFlags = flags

        ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))

    def inject_axis(self, axis, value):
        # On Windows, map left stick to mouse movement
        import ctypes
        from ctypes import wintypes

        INPUT_MOUSE = 2
        MOUSEEVENTF_MOVE = 0x0001

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", wintypes.LONG),
                        ("dy", wintypes.LONG),
                        ("mouseData", wintypes.DWORD),
                        ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("mi", MOUSEINPUT)]
            _anonymous_ = ("_input",)
            _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT)]

        # Only move on left stick (axis_0 = X, axis_1 = Y)
        dx = dy = 0
        if axis == "axis_0":
            dx = int(value * 20)
        elif axis == "axis_1":
            dy = int(value * 20)
        else:
            return

        if dx == 0 and dy == 0:
            return

        inp = INPUT()
        inp.type = INPUT_MOUSE
        inp.mi.dx = dx
        inp.mi.dy = dy
        inp.mi.dwFlags = MOUSEEVENTF_MOVE

        ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))

    def close(self):
        pass  # Nothing to clean up on Windows


# ============================================================================
# WebSocket Server
# ============================================================================

class GamepadServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.injector = None
        self.clients = set()

        # Create platform-appropriate injector
        if is_linux():
            self.injector = LinuxInputInjector()
        elif is_windows():
            self.injector = WindowsInputInjector()
        else:
            print(f"WARNING: Gamepad forwarding not supported on {platform.system()}")
            self.injector = None

    async def handle_client(self, websocket, path=None):
        self.clients.add(websocket)
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Gamepad client connected: {client_ip}")

        if not self.injector or not self.injector.available:
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Gamepad injection not available on this server"
            }))
            await websocket.close()
            self.clients.discard(websocket)
            return

        # Create virtual device on Linux
        if is_linux() and hasattr(self.injector, 'create_device'):
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

                except json.JSONDecodeError:
                    pass

        except websockets.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Gamepad client disconnected")

            if not self.clients and self.injector:
                self.injector.close()
                if is_linux() and hasattr(self.injector, 'available'):
                    # Reset for next client
                    self.injector.uinput = None

    async def run(self):
        print(f"Gamepad Forwarding Server")
        print(f"  Host:   {self.host}")
        print(f"  Port:   {self.port}")
        print(f"  Platform: {platform.system()}")
        print(f"  Injector: {'available' if self.injector and self.injector.available else 'not available'}")
        print(f"  URL:    ws://{self.host}:{self.port}")
        print()

        async with websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=60
        ):
            print("Server running. Press Ctrl+C to stop.")
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
