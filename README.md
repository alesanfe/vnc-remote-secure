# VNC Remote Secure

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Shell](https://img.shields.io/badge/Shell-Bash%20%2F%20PowerShell-blue.svg)](https://www.gnu.org/software/bash/)
[![Windows](https://img.shields.io/badge/Windows-10%2B-blue.svg)](https://www.microsoft.com/windows)
[![Tests](https://github.com/alesanfe/vnc-remote-secure/actions/workflows/ci.yml/badge.svg)](https://github.com/alesanfe/vnc-remote-secure/actions/workflows/ci.yml)

> Self-hosted, browser-based remote access with VNC, web terminal, health
> monitoring, and TLS security. Cross-platform: Linux and Windows.

---

## Features

- **Desktop access** — Full GUI via noVNC in the browser, no client install
- **Web terminal** — Command-line access from any browser tab
- **TLS security** — Self-signed certs (Windows) or Let's Encrypt (Linux)
- **Health monitoring** — Real-time system status dashboard and JSON API
- **Landing portal** — Single page linking to all running services
- **Audio streaming** — Server audio forwarded to the client browser (optional)
- **Gamepad forwarding** — Client gamepad input injected on the server (optional)
- **User isolation** — Temporary user on Linux (removed on exit); restricted runtime user on Windows (see ADR-0007)
- **Dynamic DNS** — Built-in Duck DNS updater for changing IPs

## Platform Compatibility

| Platform | Status | VNC Server | Web Terminal | TLS | Notes |
|----------|--------|------------|----------|-----|-------|
| Debian 12+ / Ubuntu 22.04+ | Production | TigerVNC | FastAPI | Let's Encrypt | Full stack |
| Raspberry Pi OS 64-bit | Production | TigerVNC | FastAPI | Let's Encrypt | Full stack |
| Windows 10 / 11 | Supported | UltraVNC | FastAPI | Self-signed | No fail2ban (uses Windows Firewall); restricted runtime user |
| Windows Server 2022+ | Experimental | UltraVNC | FastAPI | Self-signed | Less tested |
| Any browser (client) | Supported | — | — | — | No install needed |

## Feature Maturity

| Feature | Status | Notes |
|---------|--------|-------|
| Desktop (noVNC + websockify) | Stable | Primary use case |
| Web terminal (FastAPI + xterm.js) | Stable | `env` sanitized for child processes |
| Auth gateway (sessions, MFA, RBAC) | Stable | Step-up for sensitive actions |
| Ephemeral share sessions | Stable | Revocation closes live WebSockets |
| Health dashboard + `/metrics` | Stable | Loopback-only by default |
| TLS (self-signed / Let's Encrypt) | Stable | Per-profile policy |
| Landing portal | Stable | |
| Encrypted backups | Stable | Fernet/PBKDF2, `verify backup` |
| Audio streaming | Beta | Optional; `AUDIO_STREAM_ENABLED` |
| Gamepad forwarding | Experimental | Optional; `GAMEPAD_ENABLED`; view-only sessions block it |
| DuckDNS updater | Stable | |
| React admin SPA + `/api/v1` | Stable | RBAC, CSRF, step-up on mutations |

## Architecture

```
                 +-------------------+
                 |   vnc-remote CLI  |
                 | (Python, unified) |
                 +---------+---------+
                           |
                  +--------v--------+
                  | Service Manager |
                  |  (Python core)  |
                  | lock + PID track |
                  +----+----+-------+
                       |    |
            +----------+    +----------+
            |                         |
  +---------v---------+         +---------v---------+
  |  Linux adapter    |         |  Windows adapter   |
  | (Python + systemd)|         | (Python + services)|
  | Bash = thin wrap  |         | PowerShell = thin  |
  +---------+---------+         +---------+---------+
            |                             |
            +--------------+--------------+
                           |
                  +--------v--------+
                  | Common services |
                  |  (Python core)  |
                  +----+----+-------+
                       |    |
            +----------+    +----------+
            | noVNC proxy |   | Web Terminal |
            +------+-----+   +------+------+
                   |                |
            +------v------+  +------v------+
            | VNC server  |  | health dash |
            +-------------+  +-------------+
```

The Python CLI/service manager is canonical on every platform. Bash
(`src/rpi-vnc-remote.sh`) and PowerShell (`VncRemote.ps1`) are thin
compatibility wrappers that delegate to the Python CLI.

Platform-specific logic lives in `src/vnc_remote_secure/platform/{linux,windows}/`.
Common business logic in `services/`, `security/`, `monitoring/`, and `web/`
is platform-agnostic and delegates to the adapter when needed.

## Quick Start

### Linux / Raspberry Pi

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure && make setup-env && make setup-deps
make run-ssl   # or: make run (HTTP only)
```

### Windows

```powershell
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure
make setup-env ; make setup-deps ; make win-run
```

> Windows auto-provisions UltraVNC on first `vnc-remote install` if not
> already present. Set `ULTRAVNC_PATH` to use a manually-installed copy,
> or `ULTRAVNC_URL` to override the download source.

After starting, the launcher prints all access URLs. The client only needs
a web browser — open the portal URL printed on screen.

## Configuration

All configuration is via environment variables loaded from `.env` (gitignored).
Run `make setup-env` to copy the template, then edit it.

| Variable | Default | Description |
|----------|---------|-------------|
| `VNC_PASSWORD` | (generated) | VNC desktop password (8 char limit) |
| `TTYD_USERNAME` | OS default | Web terminal username |
| `TTYD_PASSWD` | (generated) | Web terminal password |
| `VNC_PORT` | 5900 / 5901 | VNC server port (Win / Linux) |
| `NOVNC_PORT` | 6080 | noVNC web + authenticated WS proxy port |
| `NOVNC_WS_PORT` | 5700 | Internal websockify bridge (loopback only) |
| `TTYD_PORT` | 5000 | Web terminal port |
| `HEALTH_WEB_PORT` | 8080 / 8090 | Health dashboard port (Linux / Win) |
| `LANDING_PORT` | 8000 | Landing page port |
| `DUCK_DOMAIN` | (empty) | Duck DNS subdomain for Let's Encrypt |
| `DUCKDNS_TOKEN` | (empty) | Duck DNS API token |
| `EMAIL` | (empty) | Email for certificate registration |
| `TLS_ENABLED` | true | Enable HTTPS / WSS |

See `.env.example` for the full list.

## Testing

### Linux

```bash
make test-all          # Full suite (all levels)
make test-static       # Lint, syntax, shellcheck
make test-unit         # Isolated function tests
make test-integration  # Multi-module interaction
make test-e2e          # Entry point and full flow
make test-security     # Password, sanitization, hardening
```

### Windows

```powershell
pwsh -c "Invoke-Pester tests/powershell -Output Detailed"
pytest tests/unit tests/security
```

Test counts vary by platform and installed runners. Run
`bash tests/run_tests.sh -l` to see the exact count for your environment.

## Security

- No hardcoded credentials — secrets come from `.env` or are generated at runtime
- TLS by default — self-signed (Windows) or Let's Encrypt (Linux)
- Constant-time password comparison via `hmac.compare_digest`
- WebSocket origin validation on the web terminal
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` (when TLS enabled)
- Rate limiting on login attempts
- Optional fail2ban intrusion prevention (Linux)
- User isolation: temporary user on Linux (removed on exit); restricted runtime user on Windows (process-level isolation, see ADR-0007)

See [`SECURITY.md`](SECURITY.md) for the full policy and
[`THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the threat model.

## Roadmap

| Version | Focus |
|---------|-------|
| 0.3.0 | Stabilize Windows adapter, unified config migration |
| 0.4.0 | Docker packaging and container deployment (pending) |
| 0.5.0 | Multi-user sessions and role-based access |
| 0.6.0 | Prometheus monitoring stack (Grafana optional) |
| 0.7.0 | Audit log replay and tamper-evident chain verification |
| 0.8.0 | Mobile-friendly client UI |
| 0.9.0 | Hardening pass and external security audit |
| 1.0.0 | Stable API, full docs, production readiness |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, coding
standards, and pull request guidelines. This project uses
[Conventional Commits](https://www.conventionalcommits.org/).

## License

MIT License — see [`LICENSE`](LICENSE).
