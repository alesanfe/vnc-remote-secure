# Audio Streaming

## Overview

VNC Remote Secure can optionally stream audio from the server to your browser
via WebSocket.

## Enabling Audio

Set in `.env`:
```
ENABLE_AUDIO=true
```

## How It Works

1. `ffmpeg` captures audio from the server's audio device
2. Audio is encoded as Ogg/Opus
3. Streamed via WebSocket to the browser
4. Played back using the Web Audio API

## Requirements

- `ffmpeg` installed on the server
- `audio_stream_server.py` running (started automatically)
- Browser with WebSocket and Web Audio API support

## Limitations

- Currently mono only
- Latency depends on network conditions
- Not available on Windows (Linux only)
