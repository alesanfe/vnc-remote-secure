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
- Fully self-hosted: xterm.js is bundled into the React SPA by Vite
  (`@xterm/xterm` npm dependency) — no CDN dependency and no separate
  `/xterm/` static route, so the terminal works in
  air-gapped/offline deployments
- The page at `/terminal` (alias `/terminal.html`) is the React
  `TerminalPage`; it obtains the WebSocket URL from
  `GET /api/v1/portal` and talks a JSON line-editing protocol
  (`command` / `interrupt` / `complete` messages) to the terminal
  service (`services/terminal.py`, Starlette WebSocket at `/ws`)

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
- Authentication required (operator session cookie, or an ephemeral
  Bearer token with terminal permission)
- Permission split: `terminal_view` opens the terminal with read-only
  builtins; spawning commands requires `terminal_write`
- Internal port (5000) is not publicly exposed
- Rate limiting enforced at the application layer (auth lockouts and
  per-IP throttling via `security/rate_limit.py`)
- Step-up re-authentication required before opening a terminal
  (`require_step_up('open_terminal')`)
