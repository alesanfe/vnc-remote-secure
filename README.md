# VNC Remote Secure

Secure remote access via browser using noVNC (desktop) and web terminal with SSL/TLS support.
Supports both Linux/Raspberry Pi (production) and Windows (local/LAN access).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell Script](https://img.shields.io/badge/Shell-Script-blue.svg)](https://www.gnu.org/software/bash/)
[![Python 3](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-ARM64-green.svg)](https://www.raspberrypi.org/)
[![Windows](https://img.shields.io/badge/Windows-10%2B-blue.svg)](https://www.microsoft.com/windows)
[![Tests](https://img.shields.io/badge/Tests-116%20passing-brightgreen.svg)](tests/)
[![Conventional Commits](https://img.shields.io/badge/Commits-Conventional-orange.svg)](https://www.conventionalcommits.org/)

## Overview

VNC Remote Secure provides secure, web-based remote access to your machine. It combines:

- **Desktop Access** — Full GUI via noVNC web interface
- **Terminal Access** — Command-line via web terminal
- **SSL/TLS Security** — Automatic HTTPS with self-signed or Let's Encrypt certificates
- **User Isolation** — Secure temporary user sessions (Linux)
- **Health Monitoring** — Real-time system status dashboard
- **Landing Page** — Portal with links to all services

Perfect for remote administration, development, or accessing your machine from anywhere with just a web browser.

## Table of Contents

- [Platform Support](#platform-support)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Duck DNS](#duck-dns)
- [Bluetooth Device Sharing](#bluetooth-device-sharing)
- [Usage](#usage)
- [Testing](#testing)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Platform Support

### Compatibility Matrix

| Platform | Architecture | Status | Use Case | Limitations |
|----------|-------------|--------|----------|-------------|
| **Raspberry Pi OS 64-bit** | ARM64 | **Supported** (production) | Full server: nginx SSL, fail2ban, monitoring, user isolation | None |
| **Debian 12+** | x64/ARM64 | **Supported** (production) | Full server | None |
| **Ubuntu 22.04+** | x64/ARM64 | **Supported** (production) | Full server | None |
| **Ubuntu 20.04** | x64 | Partial | Server | Older packages may need manual updates |
| **Windows 11** | x64 | **Supported** (local/LAN) | UltraVNC + Python stack | No fail2ban, no Let's Encrypt, no user isolation |
| **Windows 10** | x64 | Limited | Local/LAN | Same as Windows 11, less tested |
| **Windows Server 2022+** | x64 | Experimental | Server | Not fully tested, documented limitations |
| **Windows ARM64** | ARM64 | Experimental | Local | UltraVNC ARM64 availability uncertain |
| **WSL2** | x64 | Development only | Testing | Not a production target, VNC display issues |
| **Client (browser)** | Any | **Supported** | Access | Chrome, Firefox, Safari, Edge — no install needed |

### What "Windows Support" Means

- **Native execution**: PowerShell CLI (`VncRemote.ps1`) + Git Bash launcher (`launch.sh`)
- **VNC server**: UltraVNC (not TigerVNC, which is Linux-only)
- **Web terminal**: Python/Tornado (not ttyd, which has ConPTY issues on Windows 11)
- **noVNC proxy**: websockify (cross-platform Python)
- **SSL**: Self-signed certificates (no Let's Encrypt/certbot on Windows)
- **Firewall**: Windows Firewall rules managed via PowerShell (`scripts/Manage-Firewall.ps1`)
- **No systemd**: Processes managed by script, not system services
- **No fail2ban**: Windows Defender / Windows Firewall instead
- **No user isolation**: Uses current user (no temp user creation)

### CLI Interfaces

| Platform | CLI | Commands |
|----------|-----|----------|
| **Linux** | `vnc-remote` (Bash) | install, start, stop, restart, status, doctor, backup, restore, uninstall |
| **Windows** | `VncRemote.ps1` (PowerShell) | Install, Start, Stop, Restart, Get-Status, Test-Configuration, Backup, Restore, Uninstall |

Both CLIs provide the same functionality using native mechanisms:
- Linux: `--dry-run`, `--json`, `--verbose`, `--quiet`
- Windows: `-WhatIf`, `-Json`, `-Verbose`, `-DryRun` (PowerShell-native)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client (Web Browser)                      │
│              Any OS — no software needed                      │
└──────────┬──────────┬──────────┬──────────┬──────────────────┘
           │          │          │          │
    ┌──────▼──┐ ┌────▼───┐ ┌────▼───┐ ┌────▼────┐
    │ Landing │ │ noVNC  │ │Terminal│ │ Health  │
    │  Page   │ │ Desktop│ │  Web   │ │Dashboard│
    │ :8000   │ │ :6080  │ │ :5000  │ │ :8090   │
    └─────────┘ └───┬────┘ └───┬────┘ └─────────┘
                    │          │
              ┌─────▼────┐  ┌──▼──────────┐
              │websockify│  │web_terminal │
              │ (proxy)  │  │  (Tornado)  │
              └─────┬────┘  └─────────────┘
                    │
              ┌─────▼─────┐
              │  VNC Server│
              │  (UltraVNC │
              │ /TigerVNC) │
              └───────────┘
```

### Project Structure

```
vnc-remote-secure/
├── src/                          # Main application (Linux/RPi)
│   ├── rpi-vnc-remote.sh         # Entry point
│   └── lib/
│       ├── core/                 # Config, logging, utils, validation
│       ├── security/             # SSL, fail2ban, user management
│       ├── web/                  # nginx, Flask user UI
│       ├── monitoring/           # Health checks, dashboard
│       ├── communication/        # Alerts, notifications
│       ├── features/             # Session recording
│       └── platform/             # OS detection, Windows backend
├── launch.sh                     # Windows launcher (with --no-ssl flag)
├── kill_all.sh                   # Windows service cleanup
├── web_terminal.py               # Tornado-based web terminal (Windows)
├── landing_page.py               # Landing page portal
├── health_web_server.py          # (symlink to src/lib/monitoring/)
├── gen_ssl.py                    # Self-signed certificate generator
├── gen_vnc_pass.py               # VNC password hash generator
├── verify_all.py                # End-to-end verification script
├── config_loader.py             # Shared Python config loader
├── tests/                        # Test pyramid (116 tests)
│   ├── static/                   # Level 0: lint, syntax, CRLF
│   ├── unit/                     # Level 1: isolated functions
│   ├── integration/              # Level 3: multi-module
│   ├── e2e/                      # Level 5: entry point
│   └── security/                 # Level 7: hardening
├── scripts/                      # Maintenance scripts
├── docker/                       # Docker integration
├── doc/                          # Documentation
├── Makefile                      # Central command hub
└── .env.example                  # Configuration template
```

## Quick Start

### Prerequisites

- **Linux/RPi**: Bash 4+, Python 3.8+, sudo access
- **Windows**: Git Bash, Python 3.8+, UltraVNC binaries in `bin/ultravnc/`

### Setup (both platforms)

```bash
# Clone
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Configure (copy template and edit)
make setup-env
# Edit .env with your credentials:
#   - VNC_PASSWORD, TTYD_USERNAME, TTYD_PASSWD
#   - DUCK_DOMAIN, EMAIL (for SSL, Linux only)

# Install dependencies
make setup-deps
```

### Run on Linux / Raspberry Pi

```bash
# Full stack with SSL (requires DUCK_DOMAIN and EMAIL in .env)
make run-ssl

# Or without SSL (testing only)
make run

# Stop services
make stop
```

### Run on Windows

```bash
# With SSL (self-signed certificate)
make win-run

# Without SSL (HTTP, for testing)
make win-run-nossl

# Stop all services
make win-stop

# Verify all services are responding
make win-verify
```

### Access from another device (LAN)

After starting, the launcher prints all access URLs. Example:

```
Local access (this machine):
  Portal:        https://localhost:8000
  VNC desktop:   https://localhost:6080/vnc.html
  Terminal:      https://localhost:5000
  Health:        http://localhost:8090/health_status

Remote access (from other devices on the same network):
  --- IP: 192.168.1.100 ---
    Portal:        https://192.168.1.100:8000
    VNC desktop:   https://192.168.1.100:6080/vnc.html
    Terminal:      https://192.168.1.100:5000
    Health:        http://192.168.1.100:8090/health_status
```

**Windows Firewall** (run as Admin to allow remote access):

```powershell
New-NetFirewallRule -DisplayName "VNC Remote" -Direction Inbound `
  -LocalPort 5000,6080,8000,8090,5900 -Protocol TCP -Action Allow
```

## Configuration

All configuration is via environment variables, loaded from `.env` (gitignored).
Copy `.env.example` and edit:

```bash
make setup-env
nano .env
```

Key variables (see `.env.example` for full list):

| Variable | Default | Description |
|----------|---------|-------------|
| `VNC_PASSWORD` | (generated) | VNC desktop password (8 char limit) |
| `TTYD_USERNAME` | `admin` | Web terminal username |
| `TTYD_PASSWD` | (generated) | Web terminal password |
| `VNC_PORT` | `5900` (Win) / `5901` (Linux) | VNC server port |
| `NOVNC_PORT` | `6080` | noVNC/websockify port |
| `TTYD_PORT` | `5000` | Web terminal port |
| `HEALTH_WEB_PORT` | `8090` (Win) / `8080` (Linux) | Health dashboard port |
| `LANDING_PORT` | `8000` | Landing page port |
| `HEALTH_WEB_HOST` | `127.0.0.1` | Health bind (set `0.0.0.0` to expose) |
| `LANDING_HOST` | `127.0.0.1` | Landing bind (set `0.0.0.0` to expose) |
| `DUCK_DOMAIN` | (empty) | Duck DNS subdomain (e.g. `alesanfe` for `alesanfe.duckdns.org`) |
| `DUCKDNS_TOKEN` | (empty) | Duck DNS API token (from https://www.duckdns.org/) |
| `DUCKDNS_UPDATE_INTERVAL` | `5` | Update interval in minutes (daemon mode) |
| `EMAIL` | (empty) | Email for certificate registration |

## Duck DNS

[Duck DNS](https://www.duckdns.org/) provides free dynamic DNS. The project includes
automatic IP update scripts that work on both Linux and Windows.

### Setup

1. Create a free account at [duckdns.org](https://www.duckdns.org/)
2. Create a subdomain (e.g. `alesanfe`)
3. Copy your token from the dashboard
4. Add to `.env`:

```bash
DUCK_DOMAIN=alesanfe
DUCKDNS_TOKEN=your-token-here
DUCKDNS_UPDATE_INTERVAL=5
```

### Commands

```bash
make duckdns-update    # One-shot IP update
make duckdns-check     # Check DNS resolution vs current IP
make duckdns-daemon    # Continuous update (every 5 min, until Ctrl+C)
```

### Automatic updates

- **Windows**: `launch.sh` runs `duckdns_update.sh` automatically on startup
- **Linux**: `src/rpi-vnc-remote.sh` runs it before SSL setup (so certbot can use the domain)
- **Daemon**: Run `make duckdns-daemon` for continuous background updates

### Cross-platform support

Both `scripts/duckdns_update.sh` (Bash, uses `curl` with Python fallback) and
`scripts/duckdns_update.py` (pure Python) are provided. The Bash script is preferred
when `curl` is available; the Python script works anywhere Python 3 is installed.

## Bluetooth Device Sharing

The project supports sharing Bluetooth devices between the client (where you open
the browser) and the server (the remote machine):

### Audio Streaming (Server → Client Bluetooth Headphones)

Stream the server's system audio to the client browser. The audio plays through
whatever audio output the client has — including Bluetooth headphones/speakers.

**Prerequisites**: `ffmpeg` installed on the server
- Linux: `sudo apt-get install ffmpeg`
- Windows: `choco install ffmpeg` or download from https://ffmpeg.org/

**Enable** in `.env`:
```bash
AUDIO_STREAM_ENABLED=true
AUDIO_STREAM_PORT=7777
# AUDIO_DEVICE=  (leave empty for auto-detect)
# AUDIO_BITRATE=128
```

**Use**: After launching, open the Audio Receiver page:
```
https://localhost:8000/audio_receiver.html
```
Click "Connect" — audio from the server will play through your Bluetooth headphones.

### Gamepad Forwarding (Client Bluetooth Gamepad → Server)

Forward Bluetooth gamepad input from the client browser to the server. The gamepad
events are injected as virtual keyboard/mouse on the server.

**Prerequisites**:
- Linux: `pip install evdev` + `sudo modprobe uinput` + `sudo chmod 0666 /dev/uinput`
- Windows: No extra deps (uses ctypes SendInput)

**Enable** in `.env`:
```bash
GAMEPAD_ENABLED=true
GAMEPAD_PORT=7788
```

**Use**: After launching, open the Gamepad page:
```
https://localhost:8000/gamepad.html
```
1. Pair your Bluetooth gamepad with the client device
2. Click "Connect" to connect to the server
3. Click "Scan for Gamepads" — press a button on your gamepad
4. Gamepad input is now forwarded to the server

### Keyboard/Mouse (Already Works)

Bluetooth keyboards and mice connected to the client device work automatically
through the VNC/noVNC session — no configuration needed.

### Limitations

- Audio streaming requires ffmpeg on the server
- Gamepad forwarding on Linux requires evdev and uinput access
- Gamepad buttons are mapped to keyboard keys (see `gamepad_server.py` for mapping)
- Audio is streamed as MP3 (low latency, but not lossless)
- Both features bind to `127.0.0.1` by default; set host to `0.0.0.0` for LAN access

## Usage

### Common commands (via Makefile)

```bash
make help          # Show all available commands
make setup         # Full setup (env + deps + noVNC)
make check         # Run all quality checks (lint + tests)
make test-all      # Run full test suite
make status        # Show service status (Linux)
make clean         # Clean temporary files
```

### Service management (Linux)

```bash
make services-start  # Start VNC + ttyd + noVNC
make services-stop   # Stop all services
make ssl-setup       # Setup SSL certificates
make ssl-check       # Check certificate expiry
make user-create     # Create temp user
make user-remove     # Remove temp user
```

## Testing

The project uses a testing pyramid with 5 levels (116 tests total):

```bash
make test-all          # Run all tests
make test-static       # Level 0: lint, syntax, CRLF, shellcheck
make test-unit         # Level 1: isolated function tests
make test-integration  # Level 3: multi-module interaction
make test-e2e          # Level 5: entry point and full flow
make test-security     # Level 7: password, sanitization, hardening
make test-fast         # Run all except e2e (fast feedback)
```

## Development

### Code quality

```bash
make lint            # Run shellcheck (non-fatal)
make lint-strict     # Run shellcheck (fail on warnings)
make lint-python     # Run Python linters (ruff, black)
make format          # Format Python code with black
make check           # Run all quality checks
```

### Pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

Hooks run shellcheck, Python compile, CRLF check, and trailing whitespace removal.

### Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(security): validate VNC_PASSWORD in validate_config
fix(config): default KEEP_TEMP_USER to false
docs(architecture): correct module paths
test(unit): add password strength tests
```

See `CONTRIBUTING.md` for full guidelines.

## Troubleshooting

See [`doc/troubleshooting.md`](doc/troubleshooting.md) for common issues and solutions.

Quick checks:

```bash
make status          # Service status
make ssl-check       # SSL certificate status
make test-fast       # Run quick tests
./scripts/health-check.sh  # Full health check (Linux)
```

## Security

- **No hardcoded credentials** — All secrets come from `.env` or are generated at runtime
- **SSL/TLS by default** — Self-signed certificates generated automatically (Linux)
- **VNC password hashing** — UltraVNC/TigerVNC password format (8 char limit)
- **WebSocket origin validation** — Web terminal rejects cross-site connections
- **Constant-time auth** — Password comparison uses `hmac.compare_digest`
- **Session cookies** — `HttpOnly`, `SameSite=Lax`, `Secure` (when SSL enabled)
- **Rate limiting** — Login attempts limited per IP
- **Fail2ban** — Optional intrusion prevention (Linux)
- **Temp user isolation** — Removed on exit unless `KEEP_TEMP_USER=true`

See [`SECURITY.md`](SECURITY.md) for full security policy and vulnerability reporting.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, coding standards,
and pull request guidelines.

## License

MIT License — see [`LICENSE`](LICENSE).

## Acknowledgments

- [noVNC](https://github.com/novnc/noVNC) — Browser-based VNC client
- [websockify](https://github.com/novnc/websockify) — WebSocket-to-VNC proxy
- [UltraVNC](https://www.uvnc.com/) — Windows VNC server
- [TigerVNC](https://tigervnc.org/) — Linux VNC server
- [ttyd](https://github.com/tsl0922/ttyd) — Web terminal (Linux)
- [Tornado](https://www.tornadoweb.org/) — Python web framework (Windows terminal)
