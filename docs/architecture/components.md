# Project Structure

## Overview

Complete documentation of the VNC Remote Secure project structure and organization.

The project is **Python-canonical**: `src/vnc_remote_secure/` is the
single runtime on every platform. Bash (`src/rpi-vnc-remote.sh`,
`vnc-remote`, `launch.sh`) and PowerShell (`VncRemote.ps1`,
`native/windows/VncRemote.psm1`) are thin compatibility wrappers that
delegate to `vnc_remote_secure.cli`. See
[ADR-0009](../adr/0009-bash-python-coexistence.md) (superseded) for the
historical dual-implementation rationale.

## Project Organization

```
vnc-remote-secure/
├── src/
│   ├── rpi-vnc-remote.sh          # Legacy Linux Bash entry point (thin wrapper)
│   └── vnc_remote_secure/          # Python package (canonical, cross-platform)
│       ├── cli/                     # Unified CLI entry point (package: commands/, _parser, _app)
│       ├── core/                   # config, constants, paths, processes, service_manager
│       ├── platform/
│       │   ├── linux/               # Linux platform adapter
│       │   └── windows/             # Windows platform adapter
│       ├── services/               # landing, health, terminal, vnc, novnc, audio, gamepad
│       ├── security/               # authentication, certificates, credentials
│       ├── monitoring/             # health, prometheus
│       ├── web/                    # Flask app, routes, templates
│       ├── vendor/
│       │   └── d3des.py            # VNC DES (legacy protocol compat)
│       ├── native/
│       │   ├── linux/
│       │   │   ├── bin/vnc-remote   # Native Linux launcher wrapper
│       │   │   └── systemd/         # systemd unit files
│       │   └── windows/
│       │       ├── VncRemote.psd1   # PowerShell module manifest
│       │       ├── VncRemote.psm1   # PowerShell module
│       │       ├── Firewall.ps1     # Windows Firewall management
│       │       ├── commands/        # Install, Start, Stop, Test, Uninstall
│       │       └── service/
│       │           └── service-config.xml  # Windows Service config
│       ├── config/                  # Config schema, defaults, examples, nginx.conf
│       └── third_party/             # Dependency manifests, licenses, checksums
├── VncRemote.ps1                    # Windows PowerShell entry point
├── vnc-remote                       # Bash CLI wrapper (root)
├── launch.sh                        # Windows Git-Bash launcher (deprecated)
├── tools/
│   ├── download_dependencies.py     # Third-party binary downloader
│   ├── verify_dependencies.py       # Checksum verification
│   └── migrate_configuration.py     # Config migration tool
├── scripts/
│   ├── development/                 # Dev tools
│   ├── maintenance/                 # backup, restore, uninstall, cleanup, update
│   ├── release/                     # Release scripts
│   └── utilities/                   # duckdns, ssl, vnc password, ultravnc config
├── tests/
│   ├── run_tests.sh                 # Test runner (Bash + Python + Pester)
│   ├── unit/                        # Python unit tests
│   ├── integration/                 # Cross-module interaction
│   ├── e2e/                         # Entry-point and full-flow
│   ├── security/                    # Password, sanitization, hardening
│   ├── powershell/                  # Pester tests (Windows module)
│   ├── windows/                     # Pester tests (Windows wrapper)
│   └── fixtures/                    # Static test data
├── packaging/
│   ├── docker/                      # Dockerfile + Compose files
│   ├── linux/                       # Linux packaging
│   └── windows/                     # Windows packaging
├── docs/
│   ├── architecture/                # Architecture docs (this file)
│   ├── adr/                         # Architecture Decision Records
│   ├── installation/                # Installation guides
│   ├── user-guide/                  # User guides
│   └── developer/                   # Developer guides
├── .github/workflows/               # CI/CD pipelines
├── .env.example                     # Environment variable template
├── pyproject.toml                   # Python project config (deps, build, tools)
├── Makefile                         # Build, test, and lint targets
├── AGENTS.md                        # Operational guide for agents/contributors
└── README.md                        # Project README
```

> **Note:** The canonical runtime is the Python package
> `src/vnc_remote_secure/`. The legacy Bash stack under `src/lib/`
> has been removed. `src/rpi-vnc-remote.sh` is a thin wrapper that
> delegates all commands to the Python CLI. All business logic lives
> in `src/vnc_remote_secure/`.

## Core System Modules (Python)

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `src/vnc_remote_secure/core/config.py` | Configuration | .env loading, secure defaults |
| `src/vnc_remote_secure/core/constants.py` | Constants | Platform-aware port/geometry defaults |
| `src/vnc_remote_secure/core/processes.py` | Process management | Port availability, process lifecycle |
| `src/vnc_remote_secure/services/landing.py` | Landing page | Service links, LAN IP discovery |
| `src/vnc_remote_secure/services/health.py` | Health dashboard | HTTP health endpoint, port checks |
| `src/vnc_remote_secure/services/terminal.py` | Web Terminal | Tornado WebSocket, auth, shell exec |
| `src/vnc_remote_secure/services/vnc.py` | VNC management | Start/stop VNC server |
| `src/vnc_remote_secure/services/novnc.py` | noVNC static server | Auth-gated static files + `/websockify` upgrade proxy to the loopback websockify bridge (`NOVNC_WS_PORT`, 5700) |
| `src/vnc_remote_secure/security/authentication.py` | Auth | Token-based, Basic auth |

## Usage Examples

### Maintenance
```bash
# Complete system backup (canonical Python implementation)
vnc-remote backup

# Restore from backup
vnc-remote restore backups/backup_20260428_211300.tar.gz

# System health check
./scripts/maintenance/health-check.sh

# System cleanup
./scripts/maintenance/cleanup.sh
```

### Testing
```bash
# Run all tests (pytest + Pester via run_tests.sh)
make test-all

# Run specific test levels
make test-unit
make test-integration
make test-security

# Lint all shell scripts
make lint
```

### Installation
```bash
# Install Python dependencies
pip install -e ".[dev]"

# Install the CLI
pip install -e .
```
