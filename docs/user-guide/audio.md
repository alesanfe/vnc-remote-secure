# Audio Streaming

## Overview

VNC Remote Secure can optionally stream audio from the server to your browser
via WebSocket.

## Enabling Audio

Set in `.env`:
```
AUDIO_STREAM_ENABLED=true
```

## How It Works

1. `ffmpeg` captures audio from the server's audio device
2. Audio is encoded as MP3 (libmp3lame)
3. Streamed via WebSocket to the browser
4. Played back using the Web Audio API

## Requirements

- `ffmpeg` installed on the server
- `vnc_remote_secure.services.audio` running (started automatically)
- Browser with WebSocket and Web Audio API support

## Platform Support

- **Linux**: captures via ALSA (`arecord`)
- **Windows**: captures via DirectShow/WASAPI (`dshow`)

## Limitations

- Currently mono only
- Latency depends on network conditions
