# Testing Guide

This project uses a **testing pyramid** strategy with multiple levels, from
cheapest to most expensive. Tests are organized by level under `tests/` and
span four runners: Bash, Python (`pytest`), PowerShell (Pester), and
Playwright (browser).

Run `bash tests/run_tests.sh -l` to see the exact count for your environment;
test counts vary by platform and installed runners.

## Directory Layout

```
tests/
├── static/             # Level 0: bash -n, shellcheck, CRLF, shebang
├── unit/
│   ├── core/           # Python unit tests (config, logging, utils, validation)
│   ├── services/       # Python unit tests (audio, gamepad, landing, novnc, vnc)
│   ├── security/       # Python security tests (auth, credentials, sessions)
│   └── web/            # Python web route tests
├── integration/        # Level 3: multi-module interaction (common, linux, windows)
├── e2e/
│   ├── linux/          # Linux end-to-end scenarios
│   ├── windows/        # Windows end-to-end scenarios
│   └── browser/        # Playwright browser tests
├── security/          # Level 7: password, sanitization, hardening
├── powershell/        # Pester tests for the Windows PowerShell module
├── windows/           # Pester tests for the Windows wrapper (VncRemote.ps1)
├── fixtures/          # Static test data (certificates)
└── run_tests.sh       # Runner with auto-discovery by level
```

The legacy Bash/Bats test framework (`tests/lib/`, `tests/shell/`) has been
removed along with the legacy Bash stack; Python (`pytest`) is the canonical
test runner.

## Running Tests

```bash
# Run the full Bash pyramid (all levels in order)
bash tests/run_tests.sh
make test-all

# Run a single level
bash tests/run_tests.sh static/       # Level 0
bash tests/run_tests.sh unit/          # Level 1
bash tests/run_tests.sh integration/  # Level 3
bash tests/run_tests.sh e2e/           # Level 5
bash tests/run_tests.sh security/     # Level 7

# Or via Makefile
make test-static
make test-unit
make test-integration
make test-e2e
make test-security

# Python tests
pytest tests/unit tests/security

# PowerShell tests (Windows)
pwsh -c "Invoke-Pester tests/powershell -Output Detailed"

# List available tests
bash tests/run_tests.sh -l
make test-list
```

## Supported Test Formats

| Format | Runner | Description |
|--------|--------|-------------|
| `test_*.sh` | `bash` | Bash test scripts |
| `test_*.py` | `pytest` | Python unit/integration tests |
| `*.Tests.ps1` | `pwsh` / `powershell` | Pester tests for PowerShell |

`run_tests.sh` auto-discovers the formats above. Tests for unavailable runners
(e.g., `pwsh` on Linux) are skipped with a warning.

Playwright browser tests (`tests/e2e/browser/*.spec.js`) are run
separately via `npx playwright test` (see `.github/workflows/integration.yml`).

## Test Framework

The Bash test framework (`tests/lib/test_framework.sh`) has been
removed along with the legacy Bash stack. The canonical test suite is
now Python-based (`pytest`). Bash tests for the thin wrapper
(`src/rpi-vnc-remote.sh`) are no longer maintained; the wrapper is
verified via the Python CLI tests.

## What Each Level Tests

### Level 0 — Static (`tests/static/`)

Catches errors before execution:
- `bash -n` syntax check on all `.sh` files in `src/` and `scripts/`
- `shellcheck` (errors are blocking, warnings are advisory)
- CRLF line ending detection (`.sh` and `.py`)
- Shebang and `set -e` / `set -o pipefail` verification
- File permission checks
- Python source compilation (`python3 -c compile`)

### Level 1 — Unit (`tests/unit/`)

Isolated function tests (Python/pytest):
- Core: config loading, paths, backup/restore, service manager
- Security: auth gateway, credentials, sessions, ephemeral sessions,
  rate limiting, MFA, file permissions, shared state, token signing
- Services: start/stop helpers, landing page generation, noVNC auth,
  terminal auth, health endpoints
- Web: Flask application, routes, user management

### Level 3 — Integration (`tests/integration/`)

Multi-module interaction:
- Python module loading and cross-module interaction
- Config loading end-to-end (defaults → platform env → .env)
- Platform detection and adapter selection (linux/windows/common)
- Profile application and consistency

### Level 5 — E2E (`tests/e2e/`)

Entry-point and full-flow:
- CLI commands (`python -m vnc_remote_secure version`, doctor, status)
- Help output and argument parsing
- Linux and Windows platform-specific flows
- Browser tests via Playwright (landing page, portal, auth)

### Level 7 — Security (`tests/security/`)

Security-critical behavior:
- Auth integration (login → cookie → session → revocation)
- Password policy: rejects empty, weak patterns, short, and non-complex
- Config hardening: insecure defaults rejected by validate_config
- `KEEP_TEMP_USER=false` by default (temp user removed on exit)
- Optional features (fail2ban, Discord) disabled by default
- Command injection prevention in usernames
- Reserved system usernames rejected
- Directory traversal prevention in paths

## CI/CD Pipeline

The recommended CI pipeline runs levels in order (fastest first):

```
static → unit → integration → e2e → security
```

Each level gates the next: if static fails, don't run unit; if unit fails,
don't run integration; etc. This gives the fastest feedback on errors.

## Adding New Tests

1. Create a test file in the appropriate level directory using the
   `test_*.py` format (Python/pytest is the canonical test framework).
2. For PowerShell module tests, use `*.Tests.ps1` (Pester).
3. The runner auto-discovers test files — no registration needed.
