# Gamepad Support

## Overview

VNC Remote Secure can optionally forward gamepad input from your browser
to the server, allowing you to play games remotely.

## Enabling Gamepad

Set in `.env`:
```
GAMEPAD_ENABLED=true
```

## How It Works

1. Browser captures gamepad input via the Gamepad API
2. Input is sent via WebSocket to `vnc_remote_secure.services.gamepad`
3. Server creates a virtual gamepad device:
   - **Linux**: via `uinput` (requires `evdev` and `uinput` module)
   - **Windows**: via `SendInput` (ctypes/win32)
4. Games on the server receive the input as if from a local controller

## Requirements

- **Linux**: `uinput` module loaded, `evdev` Python package, `sudo` or uinput permissions
- **Windows**: no special requirements (uses `SendInput` via ctypes)
- Browser with Gamepad API support (Chrome, Firefox, Edge)
- Physical gamepad connected to the client machine

## Limitations

- Latency may affect fast-paced games
