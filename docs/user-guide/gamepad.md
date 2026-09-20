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
3. Server injects the input into the OS:
   - **Linux**: a virtual gamepad device via `uinput` (requires `evdev`
     and the `uinput` kernel module) — games see a real controller
   - **Windows**: keystrokes via `SendInput` (ctypes) — buttons are
     mapped to keyboard keys, not a gamepad device
4. Games on the server receive the input — as a real controller on
   Linux, as keyboard input on Windows

## Requirements

- **Linux**: `uinput` module loaded, `evdev` Python package, `sudo` or uinput permissions
- **Windows**: no special requirements (uses `SendInput` via ctypes)
- Browser with Gamepad API support (Chrome, Firefox, Edge)
- Physical gamepad connected to the client machine

## Limitations

- **Windows**: input is keyboard emulation — games that require a real
  XInput/DirectInput controller will not see it. The Linux path creates
  an actual gamepad device.
- Latency may affect fast-paced games
