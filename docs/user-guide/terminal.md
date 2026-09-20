# Web Terminal

## Accessing the Web Terminal

1. Open your web browser
2. Navigate to `https://your-server:8000` (landing page)
3. Click on the "Web Terminal" link
4. Authenticate with your terminal credentials (TTYD_USERNAME / TTYD_PASSWD)

## Features

- Full terminal access in the browser
- Multiple sessions supported
- SSL-encrypted connection
- Configurable shell (bash on Linux, cmd.exe on Windows)
- Fully self-hosted: xterm.js assets are vendored under
  `static/xterm/` and served at `/xterm/` — no CDN dependency, so the
  terminal works in air-gapped/offline deployments

## Configuration

Set in `.env`:
```
TTYD_USERNAME=admin
TTYD_PASSWD="your-strong-password"
WEBTERM_SHELL=/bin/bash  # or cmd.exe on Windows
TTYD_PORT=5000
```

## Security

- Web Terminal is behind the SSL reverse proxy
- Authentication required (username/password, or an ephemeral Bearer
  token with terminal permission)
- Internal port (5000) is not publicly exposed
- Rate limiting enforced at the application layer (auth lockouts and
  per-IP throttling via `security/rate_limit.py`)
- Step-up re-authentication required before opening a terminal
  (`require_step_up('open_terminal')`)
