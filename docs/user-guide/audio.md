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

- **Linux**: PulseAudio (`ffmpeg -f pulse`) is used whenever a source
  can be resolved — `AUDIO_DEVICE` when set, otherwise the PulseAudio
  default source via `pactl get-default-source`. Only when no device
  is configured **and** PulseAudio is unavailable does capture fall
  back to the ALSA default device (`ffmpeg -f alsa`)
- **Windows**: captures via DirectShow/WASAPI (`ffmpeg -f dshow`);
  `AUDIO_DEVICE` overrides the default DirectShow input name, e.g.
  `AUDIO_DEVICE=audio=<device-name>` as listed by
  `ffmpeg -list_devices true -f dshow -i dummy`

## Limitations

- Currently mono only
- Latency depends on network conditions
