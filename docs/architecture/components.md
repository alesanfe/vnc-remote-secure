# Project Structure

## Overview

Complete documentation of the VNC Remote Secure project structure and organization.

The project has a dual implementation: a Bash/Linux path and a Python
cross-platform path, with shared Python services. See
[ADR-0008](../adr/0008-bash-python-coexistence.md) for the rationale.

## Project Organization

```
vnc-remote-secure/
├── src/
│   ├── rpi-vnc-remote.sh          # Linux Bash entry point
│   ├── lib/                        # Bash modules (Linux)
│   │   ├── core/                   # Config, logging, validation, utils
│   │   ├── security/               # SSL, user management, fail2ban
│   │   ├── web/                    # nginx, user UI (Flask)
│   │   ├── monitoring/             # Health checks, health web server
│   │   ├── communication/          # Discord, alerts
│   │   └── features/               # Recording
│   ├── config/
│   │   └── nginx.conf              # nginx reverse proxy template
│   └── vnc_remote_secure/          # Python package (cross-platform)
│       ├── cli.py                  # Unified CLI entry point
│       ├── core/                   # config, constants, paths, processes
│       ├── platform/
│       │   ├── linux/               # Linux platform adapter
│       │   └── windows/             # Windows platform adapter
│       ├── services/               # landing, health, terminal, vnc, novnc, audio, gamepad
│       ├── security/               # authentication, certificates, credentials
│       ├── monitoring/             # alerts, health, metrics, status
│       ├── web/                    # Flask app, routes, templates, static
│       └── vendor/
│           └── d3des.py            # VNC DES (legacy protocol compat)
├── native/
│   ├── linux/
│   │   └── bin/vnc-remote           # Native Linux launcher wrapper
│   └── windows/
│       ├── VncRemote.psd1           # PowerShell module manifest
│       ├── VncRemote.psm1           # PowerShell module
│       ├── Firewall.ps1             # Windows Firewall management
│       ├── commands/                # Install, Start, Stop, Test, Uninstall
│       └── service/
│           └── service-config.xml   # Windows Service config
├── VncRemote.ps1                    # Windows PowerShell entry point
├── vnc-remote                       # Bash CLI wrapper (root)
├── launch.sh                        # Windows Git-Bash launcher (deprecated)
├── config/
│   ├── defaults/                    # Platform default .env files
│   ├── schema/                      # JSON config schema
│   └── examples/                    # Profile examples (local, public-https, vpn)
├── third_party/
│   ├── manifests/                   # Download manifests (UltraVNC, ttyd, TightVNC, noVNC)
│   ├── checksums/                   # SHA-256 checksums
│   └── licenses/                    # Third-party license files
├── tools/
│   ├── doctor.py                    # System diagnostics
│   ├── download_dependencies.py     # Third-party binary downloader
│   ├── verify_dependencies.py       # Checksum verification
│   └── migrate_configuration.py     # Config migration tool
├── scripts/
│   ├── development/                 # Dev tools
│   ├── maintenance/                 # backup, restore, uninstall, cleanup, update
│   ├── release/                     # Release scripts
│   └── utilities/                   # duckdns, ssl, vnc password, ultravnc config
├── tests/
│   ├── run_tests.sh                 # Test runner (Bash + Bats + Python + Pester)
│   ├── lib/                         # Bash test framework
│   ├── static/                      # Level 0: lint, syntax, shellcheck
│   ├── unit/                        # Level 1: Python unit tests
│   ├── integration/                 # Level 3: cross-module interaction
│   ├── e2e/                         # Level 5: entry-point and full-flow
│   ├── security/                    # Level 7: password, sanitization, hardening
│   ├── powershell/                  # Pester tests (Windows module)
│   ├── windows/                     # Pester tests (Windows wrapper)
│   ├── shell/                       # Bats-style shell tests
│   └── fixtures/                    # Static test data
├── packaging/
│   ├── linux/                       # Linux packaging
│   ├── windows/                     # Windows packaging
│   └── docker/                      # Docker configuration
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

## Core System Modules (Bash/Linux)

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `core/logging.sh` | Structured logging | Levels (DEBUG/INFO/WARN/ERROR/FATAL), timestamps |
| `core/validation.sh` | Input validation | Password strength, port/domain validation |
| `core/config.sh` | Configuration | Environment variable loading with defaults |
| `core/services.sh` | Service management | VNC, ttyd, nginx lifecycle |
| `security/ssl.sh` | SSL/TLS management | certbot, self-signed cert generation |
| `security/user.sh` | User management | Temp user creation/removal |
| `security/fail2ban.sh` | Fail2ban integration | Intrusion prevention |
| `web/nginx.sh` | nginx reverse proxy | SSL termination, routing |
| `monitoring/healthcheck.sh` | Health monitoring | Service status checks |

## Core System Modules (Python)

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `core/config.py` | Configuration | .env loading, secure defaults |
| `core/constants.py` | Constants | Platform-aware port/geometry defaults |
| `core/processes.py` | Process management | Port availability, process lifecycle |
| `services/landing.py` | Landing page | Service links, LAN IP discovery |
| `services/health.py` | Health dashboard | HTTP health endpoint, port checks |
| `services/terminal.py` | Web terminal | Tornado WebSocket, auth, shell exec |
| `services/vnc.py` | VNC management | Start/stop VNC server |
| `services/novnc.py` | noVNC proxy | websockify integration |
| `security/authentication.py` | Auth | Token-based, Basic auth |

## Usage Examples

### Maintenance Scripts
```bash
# Complete system backup
./scripts/maintenance/backup.sh

# Restore from backup
./scripts/maintenance/restore.sh backup_20260428_211300.tar.gz

# System health check
./scripts/maintenance/health-check.sh

# System cleanup
./scripts/maintenance/cleanup.sh
```

### Testing
```bash
# Run all tests (Bash + Bats + Python + Pester)
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
