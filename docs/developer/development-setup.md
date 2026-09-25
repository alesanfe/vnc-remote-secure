# Development Setup

How to set up a local development environment for VNC Remote Secure.

## Prerequisites

- **Python 3.11+** (required by `pyproject.toml`)
- **Git**
- **pip** (for installing the package in editable mode)
- **Linux**: bash 4.0+, sudo (for system service tests)
- **Windows**: PowerShell 5.1+, Git Bash (for wrapper tests)

## Quick start

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux
# .venv\Scripts\Activate.ps1  # Windows PowerShell

# Install in development mode (includes test and lint tools)
pip install -e ".[dev]"

# Copy the example configuration
cp .env.example .env
# Edit .env and set VNC_PASSWORD, TTYD_PASSWD, etc.

# Verify the installation
vnc-remote version
vnc-remote doctor
```

## Architecture overview

The project uses a **package-based multiplatform architecture**:

```
Unified CLI (vnc-remote) → Python service manager (src/vnc_remote_secure/core/service_manager.py)
        |
        +-- Common services (src/vnc_remote_secure/services/)
        |     audio, gamepad, health, landing, novnc, terminal, vnc
        |
        +-- Platform adapters (src/vnc_remote_secure/platform/)
        |     linux/  — TigerVNC, FastAPI terminal, nginx, systemd, certbot
        |     windows/ — UltraVNC, FastAPI, Windows Services, Firewall, ACLs
        |
        +-- Security (src/vnc_remote_secure/security/)
        |     auth_gateway, authentication, mfa, sessions, rate_limit,
        |     audit, certificates, http_auth, websocket_registry, ...
        |
        +-- Portal transport (src/vnc_remote_secure/backend/app.py)
        |     FastAPI/uvicorn — serves the built React SPA and /api/v1/*
        |
        +-- Frontend (frontend/)
        |     React + TypeScript + Vite SPA; `npm run build` emits the
        |     bundle to src/vnc_remote_secure/web/static/admin/
        |
        +-- Health service (src/vnc_remote_secure/web/application.py)
              entry point for the machine-facing health/metrics/audit
              app (backend/health_app.py) — no UI routes or templates
```

The canonical entry point is `vnc-remote` (a thin Bash wrapper that
delegates to `vnc_remote_secure.cli:main`). The legacy Bash stack under
`src/lib/` has been removed; `src/rpi-vnc-remote.sh` is the only retained
Bash wrapper and delegates all commands to the Python CLI.

## Running tests

```bash
# Python unit and security tests
pytest tests/unit tests/security

# Full Bash test pyramid (static, unit, integration, e2e, security)
bash tests/run_tests.sh

# List available test suites
bash tests/run_tests.sh -l

# Lint
ruff check src/vnc_remote_secure
black --check src/vnc_remote_secure

# PowerShell tests (Windows, requires Pester)
pwsh -c "Invoke-Pester tests/powershell -Output Detailed"
```

### Test structure

```
tests/
├── static/         # Lint, syntax, CRLF, shellcheck
├── unit/           # Python unit tests (core, security, services, web)
├── integration/    # Cross-module integration (common, linux, windows)
├── e2e/            # End-to-end scenarios (linux, windows)
├── security/       # Security tests (permissions, secret exposure, network)
├── powershell/     # Pester tests for Windows PowerShell module
├── windows/        # Pester tests for Windows wrapper (VncRemote.ps1)
└── fixtures/       # Static test data (certificates)
```

## Configuration

Configuration defaults live in `src/vnc_remote_secure/config/defaults/`:

- `common.env` — shared defaults (ports, features)
- `linux.env` — Linux-specific defaults (VNC port 5901, health 8080)
- `windows.env` — Windows-specific defaults (VNC port 5900, health 8090)

The Python runtime loads these as the lowest-priority defaults before
the project `.env` file. Platform-aware fallbacks are in
`src/vnc_remote_secure/core/constants.py`.

```bash
# Show the effective configuration
vnc-remote config show-effective

# Validate the configuration
vnc-remote config validate

# Diff two profiles (both --profile-a and --profile-b are required)
vnc-remote config diff --profile-a development --profile-b public-hardened
```

## Development workflow

1. Create a feature branch: `git checkout -b feat/my-feature`
2. Make changes following the existing code style (Ruff + Black).
3. Add or update tests under `tests/`.
4. Run the full test suite: `pytest tests/unit tests/security && bash tests/run_tests.sh`
5. Run lint: `ruff check src/vnc_remote_secure`
6. Run the architecture + security gates: `make lint-arch lint-semgrep lint-bandit check-secrets`
   (import-linter contracts, project semgrep rules, bandit SAST,
   detect-secrets baseline). With `pre-commit install` the same hooks
   run on every commit.
7. Commit using Conventional Commits (see `CONTRIBUTING.md`).
8. Push and open a pull request.

## Debugging

```bash
# Run the doctor to diagnose system readiness
vnc-remote doctor

# Check service status
vnc-remote status

# View logs (Linux)
journalctl -u vnc-remote -f

# Run a single service in the foreground for debugging
vnc-remote start --verbose
```

## Dependencies

Dependencies are managed in `pyproject.toml` (single source of truth).

```bash
# Install development dependencies (test + lint + security toolchain)
pip install -e ".[dev]"

# Install Linux-specific dependencies
pip install -e ".[linux]"

# Optional extras
pip install -e ".[otel]"            # OTLP trace export (OTEL_ENABLED)
pip install -e ".[windows-gamepad]" # ViGEmBus-backed XInput
pip install -e ".[webauthn]"        # passkey ceremonies
pip install -e ".[ops]"             # psutil orphan reaping
pip install -e ".[e2e]"             # Playwright browser tests

# Build the package
python -m build
```

## Supply-chain and security tooling

```bash
make lint-arch       # import-linter engine-layering contracts
make lint-semgrep    # project rules (.semgrep.yml)
make lint-bandit     # SAST on src/
make check-secrets   # detect-secrets vs .secrets.baseline
make check-deps      # pip-audit (known-vulnerable deps)
make sbom            # CycloneDX SBOM → sbom.cdx.json (gitignored)
```

`detect-secrets` runs in pre-commit against `.secrets.baseline` —
commit any NEW legitimate baseline entry by regenerating with
`detect-secrets scan src/ tests/ tools/ > .secrets.baseline` and
reviewing the diff.
