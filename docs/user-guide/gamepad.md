# Gamepad Support

## Overview

VNC Remote Secure can optionally forward gamepad input from your browser
to the server, allowing you to play games remotely.

## Enabling Gamepad

Set in `.env`:
```
ENABLE_GAMEPAD=true
```

## How It Works

1. Browser captures gamepad input via the Gamepad API
2. Input is sent via WebSocket to `gamepad_server.py`
3. Server creates a virtual gamepad device (via `uinput` on Linux)
4. Games on the server receive the input as if from a local controller

## Requirements

- Linux server with `uinput` module loaded
- Browser with Gamepad API support (Chrome, Firefox, Edge)
- Physical gamepad connected to the client machine

## Limitations

- Linux only (requires uinput)
- Requires `sudo` or uinput permissions
- Latency may affect fast-paced games
