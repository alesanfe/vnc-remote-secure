# AGENTS.md

Operational guide for agents and contributors working on this repository.

## Project overview

VNC Remote Secure: cross-platform system for secure browser-based remote access
via VNC, noVNC desktop, web terminal, optional audio/gamepad streaming, health
dashboard, and a Flask user-management UI.

The project uses a **Python-canonical architecture**: the unified Python CLI
(``vnc_remote_secure.cli``) is the single authoritative runtime on every
platform. A unified service manager (``core.service_manager``) owns the
lifecycle of all services with cross-process locking, PID tracking, and
auth-gateway enforcement. Bash and PowerShell remain as thin compatibility
wrappers that delegate to the Python CLI.

```
CLI canónico en Python (vnc-remote → vnc_remote_secure.cli:main)
        |
        +-- Service Manager (src/vnc_remote_secure/core/service_manager.py)
        |      +-- lock cross-process (flock / msvcrt)
        |      +-- PID tracking (run/pids/<service>.pid)
        |      +-- start/stop/restart por PID (no pkill -f)
        |
        +-- Servicios comunes (src/vnc_remote_secure/services/)
        |      +-- auth_gateway conectado a todos los handlers
        |      +-- WebSocket registry (revocación en vivo)
        |
        +-- Adaptador Linux (src/vnc_remote_secure/platform/linux/)
        |      +-- Bash (src/rpi-vnc-remote.sh) — wrapper fino
        |      +-- systemd (src/vnc_remote_secure/native/linux/systemd/)
        |      +-- permisos POSIX
        |
        +-- Adaptador Windows (src/vnc_remote_secure/platform/windows/)
               +-- PowerShell (src/vnc_remote_secure/native/windows/, VncRemote.ps1) — wrapper fino
               +-- Windows Services
               +-- ACL
               +-- Windows Firewall
```

### Entry points

- **Canonical CLI**: `vnc-remote` (Bash thin wrapper) → `vnc_remote_secure.cli:main` (Python)
  - Commands: `start`, `stop`, `restart`, `status`, `doctor`, `install`, `uninstall`, `backup`, `restore`, `session`, `secrets`, `config`, `verify`, `service`, `version`, `help`
- **Windows PowerShell**: `VncRemote.ps1` and `src/vnc_remote_secure/native/windows/VncRemote.psm1` (thin
  compatibility wrappers — all commands delegate to the Python CLI via
  `Invoke-PythonCli`; PowerShell verb names map to Python subcommands:
  `Get-Status`→`status`, `Test-Configuration`→`doctor`, `Get-Version`→`version`)
- **Windows launcher**: `launch.sh` (deprecated thin delegator → Python CLI)
- **Linux Bash**: `src/rpi-vnc-remote.sh` (legacy, retained for compatibility)

### Version management

The package version is defined in **`pyproject.toml`** (single source of truth).
All other locations read it dynamically:

- `src/vnc_remote_secure/__init__.py` — `importlib.metadata.version("vnc-remote-secure")`
- `src/vnc_remote_secure/core/constants.py` — imports `__version__` from the package
- `VncRemote.ps1` / `VncRemote.psm1` — invoke Python to read `__version__`
- `scripts/release/build.ps1` — invoke Python to read `__version__`
- `packaging/windows/build-installer.ps1` — invoke Python to read `__version__`
- `src/vnc_remote_secure/native/windows/VncRemote.psd1` — `ModuleVersion`
  is stamped by `scripts/release/build.ps1` at build time (a .psd1
  requires a literal field, so it cannot read the version dynamically)

Never hardcode the version string in more than `pyproject.toml` (the
`.psd1` manifest is the exception — it is regenerated at build time).

### Source layout

- **Python package**: `src/vnc_remote_secure/` (69 modules + `__init__.py`s)
  - `cli/`  unified CLI package (canonical entry point: `commands/` per domain, `_parser.py` argparse wiring, `_app.py` `main()`, `_common.py` shared helpers)
  - `core/` — backup, config, **config_inspector**, constants, **doctor**, errors, exceptions, logging, paths, processes, validation, lifecycle, **service_manager**, uninstall
  - `platform/{linux,windows}/` — platform adapters (adapter, installer, services, users, permissions, metrics, gamepad; Windows also firewall + `_powershell`), plus shared `platform/{base,detection}.py`
  - `services/` — audio, gamepad, health, landing, novnc (static +
    `/websockify` proxy to the loopback websockify bridge), terminal, vnc
  - `security/` — audit, **auth_gateway**, authentication, certificates, credentials, ephemeral_sessions, file_permissions, http_auth, http_headers, mfa, posture, **profiles**, **rate_limit**, redaction, sessions, **shared_state**, step_up_auth, tls_validation, **token_signing**, **websocket_registry**
  - `monitoring/` — health, prometheus, **alerts** (Discord/webhook/email dispatch)
  - `web/` — Flask application, routes, templates
  - `vendor/d3des.py` — VNC DES (legacy protocol compatibility, pycryptodome-backed)
- **Linux Bash**: `src/rpi-vnc-remote.sh` (thin compatibility wrapper → Python CLI)
- **Windows PowerShell**: `src/vnc_remote_secure/native/windows/` (module + commands)
- **Native assets**: `src/vnc_remote_secure/native/` — `linux/{bin,systemd}/` (launcher + unit), `windows/` (`VncRemote.psm1/.psd1`, `commands/*.ps1`, `Firewall.ps1`, `service/service-config.xml`)
- **Configuration**: `src/vnc_remote_secure/config/{schema,defaults,examples}/` (nginx template lives at `src/vnc_remote_secure/config/nginx.conf`)
- **External deps**: `src/vnc_remote_secure/third_party/{manifests,licenses,checksums}/`
- **Tools**: `tools/{download_dependencies,verify_dependencies,migrate_configuration}.py`
- **Scripts**: `scripts/{development,maintenance,release,utilities}/`
- **Packaging**: `packaging/{linux,windows}/`
- **Documentation**: `docs/{architecture,adr,api,installation,user-guide,developer,runbook,migration,reports,archive}/`

## Platform support

**Server-side: Linux and Windows.**

- **Linux**: TigerVNC, Tornado (web terminal), nginx, systemd, certbot, fail2ban, apt-get
  (the ttyd binary is an optional alternative download, not the default backend)
- **Windows**: UltraVNC, Tornado (web terminal), Windows Services, Windows Firewall, ACLs

Platform-specific logic is isolated in `src/vnc_remote_secure/platform/{linux,windows}/`.
The common business logic in `services/`, `security/`, `monitoring/`, and `web/` is
platform-agnostic and delegates to the platform adapter when needed.

**Client-side: any OS.** The client only needs a web browser.

## Verification commands

The test suite follows a **testing pyramid** with multiple levels:

```bash
# Run the full Bash pyramid (all levels in order)
bash tests/run_tests.sh
make test-all

# Run a single level
bash tests/run_tests.sh static/       # Level 0: lint, syntax, CRLF, shellcheck
bash tests/run_tests.sh unit/          # Level 1: isolated function tests
bash tests/run_tests.sh integration/  # Level 3: multi-module interaction
bash tests/run_tests.sh e2e/           # Level 5: entry-point and full-flow
bash tests/run_tests.sh security/     # Level 7: password, sanitization, hardening

# PowerShell tests (Windows)
pwsh -c "Invoke-Pester tests/powershell -Output Detailed"

# Python tests
pytest tests/unit tests/security

# Or via Makefile
make test-static
make test-unit
make test-integration
make test-e2e
make test-security

# List available tests
bash tests/run_tests.sh -l
make test-list
```

### Test structure

```
tests/
├── static/         # Level 0 checks (lint, syntax, CRLF, shellcheck)
├── unit/           # Python unit tests (core, security, services, web)
├── integration/    # Cross-module integration (common, linux, windows)
├── e2e/            # End-to-end scenarios (linux, windows)
├── security/       # Security tests (permissions, secret exposure, network)
├── powershell/     # Pester tests for Windows PowerShell module
├── windows/        # Pester tests for Windows wrapper (VncRemote.ps1)
└── fixtures/       # Static test data (certificates)
```

### Supported test formats

| Format | Runner | Description |
|--------|--------|-------------|
| `test_*.py` | `pytest` | Python unit/integration tests (canonical) |
| `*.Tests.ps1` | `pwsh` / `powershell` | Pester tests for PowerShell |

`run_tests.sh` auto-discovers test files. The legacy Bash/Bats test
framework (`tests/lib/`, `tests/shell/`) has been removed along with the
legacy Bash stack.

**Note: Test counts vary by platform and installed runners. Run
`bash tests/run_tests.sh -l` to see the exact count for your environment.**

Always run `bash tests/run_tests.sh` before committing changes to `src/` or `tests/`.

## Commit conventions

This project uses **Conventional Commits**. Do NOT use generic messages such as
"Subir", "update", or "wip". See `CONTRIBUTING.md` for the full guide.

Format: `type(scope): description`

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `refactor`: code restructuring without behavior change
- `test`: adding or fixing tests
- `chore`: maintenance, deps, tooling
- `style`: formatting / style only

Examples:
```
feat(security): validate VNC_PASSWORD and USER_UI_PASSWORD in validate_config
fix(config): default KEEP_TEMP_USER to false so temp users are cleaned up
docs(architecture): correct module paths to reflect subfolder layout
```

## Security rules

- NEVER commit `.env`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, or any file under
  `data/ssl/`, `ssl/`, or `secrets/`. These are gitignored; keep them out of history.
- Default passwords (`changeme`, `admin123`, `YourStrongPassword123`) are rejected
  by `validate_password()` in `get_config()` for user-set credentials
  (`VNC_PASSWORD`, `TTYD_PASSWD`, `USER_UI_PASSWORD`, `LANDING_PASSWORD`) and by
  `vnc-remote config validate` / `vnc-remote doctor` via `validate_config()`.
  Set real values in `.env` (copied from `.env.example`).
- The temporary user (`TEMP_USER`, default `remote`) is removed on exit unless
  `KEEP_TEMP_USER=true`. Do not change this default without a reason.
- VNC uses legacy DES authentication (fixed key, 8-char password limit). This is
  a protocol limitation, not a security feature. Always place VNC behind HTTPS,
  VPN, or SSH tunnel.

## Module loading order (Linux Bash)

`src/rpi-vnc-remote.sh` is a thin compatibility wrapper that delegates
all commands to the Python CLI (`vnc_remote_secure.cli:main`). It does
not source any Bash library; the legacy `src/lib/` tree has been
removed. All business logic lives in the Python package under
`src/vnc_remote_secure/`.

## Dependencies

Dependencies are managed in `pyproject.toml` (single source of truth).

```bash
# Install in development mode
pip install -e ".[dev]"

# Build the package
python -m build
```

## Known limitations

These are documented architectural limitations, not bugs. They should be
addressed in future work but are tracked here for transparency.

- **F-016 Configuration reads at import time.** Resolved: service
  modules (`services/terminal.py`, `services/landing.py`) now use a
  lazy `_config()` accessor that calls `get_config()` at call time
  rather than reading `os.environ` at import time. Configuration
  changes take effect on the next call without requiring a process
  restart.

- **F-018 Single-process state.** Resolved: `RateLimiter`,
  `WebSocketRegistry` (revocation propagation), the audit chain hash,
  and step-up auth times use the shared-state backend
  (`security.shared_state`). `config/defaults/common.env` sets
  `SHARED_STATE_BACKEND=sqlite` because the service manager spawns
  one process per service — with `memory` each process would see an
  empty copy of rate limits, revocations and auth times (e.g. the
  terminal would always demand step-up re-auth). Close callbacks
  remain process-local (they are Python callables), but revocation
  is propagated via the shared `websocket_revoked_sessions`
  namespace so other processes reject new WebSocket upgrades for
  revoked sessions.

- **F-022 `http.server` fallback.** When Flask is not installed, the
  package falls back to `http.server` handlers. The fallback omits Flask
  sessions, CSRF protection, security headers, `/metrics`, `/audit`, and
  `/audit/verify`. Hardened profiles (`public-hardened`, `private-overlay`,
  `trusted-lan`) now reject startup in fallback mode with a `RuntimeError`
  (implemented in `web/application.py`). The `SimpleWebApp` fallback remains
  available for the `development` profile only. Install Flask in production.

- **F-024 `src/vnc_remote_secure/config/defaults/{common,linux,windows}.env`.** These files are
  loaded by the Python runtime as the lowest-priority defaults (before the
  project `.env`), via `_load_platform_defaults()` in `src/vnc_remote_secure/core/config.py`.
  `src/vnc_remote_secure/core/constants.py` provides the platform-aware fallbacks used when a
  variable is absent from both the defaults files and the environment.

- **F-026 systemd unit files.** `src/vnc_remote_secure/native/linux/systemd/vnc-remote.service`
  is now provided as the canonical systemd unit. Additional per-service
  units (vnc, terminal, novnc, health, landing) may be added in the
  future; the unified `vnc-remote.service` unit runs the Python service
  manager which supervises all of them.

- **F-027 Legacy Bash stack under `src/lib/` (RESOLVED).** The
  deprecated parallel Bash implementation under `src/lib/` has been
  removed. `src/rpi-vnc-remote.sh` is now a thin wrapper that delegates
  directly to the Python CLI. All business logic lives in
  `src/vnc_remote_secure/`.

- **F-028 Auth gateway not applied to Flask routes (RESOLVED).** Flask
  web routes now validate sessions through `auth_gateway.check_authenticated`
  via the `_require_session()` helper in `web/routes/users.py`.

- **F-029 Step-up auth and consent (RESOLVED).**
  `require_step_up()` is now called before sensitive actions
  (create_user, delete_user, open_terminal). The `security/consent.py`
  module was **removed**: it implemented a complete consent state
  machine but had no callers — there is no local approval surface
  (UI/CLI) for a support consent flow to be meaningful. If a
  consent flow is ever built, it needs an approval channel first.

- **F-030 Backups are not encrypted at rest (RESOLVED).** When
  `BACKUP_PASSWORD` is set, backups are encrypted with Fernet
  (AES-128-CBC) and use the `.enc.tar.gz` extension. Restore
  decrypts automatically.

- **F-031 Audit log has no trusted anchor or rotation (RESOLVED).**
  The audit log now writes a genesis anchor entry, verifies the
  chain on startup, rotates at 10 MB (configurable via
  `AUDIT_LOG_MAX_BYTES`), and sets `0o600` permissions.

- **F-032 Linux paths are not XDG-compliant (RESOLVED).**
  `core/paths.py` now uses XDG base directories
  (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`) for
  non-root Linux deployments, falling back to FHS paths for root.

- **F-033 `RECORDING_ENABLED` placeholder (RESOLVED).** The
  `RECORDING_ENABLED` env var has been removed entirely from the
  config, schema, defaults, and `.env.example` since no recording
  service exists.

- **F-034 Legacy Bash parity gaps (RESOLVED).** Three features the
  Bash stack provided were missing from Python and are now
  implemented: (1) Let's Encrypt issuance via certbot
  (`security/certificates.py::request_letsencrypt`, wired into the
  Linux installer when `DUCK_DOMAIN`+`EMAIL` are set — parity with the
  historical `make ssl-setup`); (2) alert dispatch to
  Discord/webhook/email (`monitoring/alerts.py`, wired into
  `service_manager` start failures and the watchdog); (3) the
  per-service watchdog (`service_manager.watchdog_tick`, driven by
  `HEALTHCHECK_ENABLED`/`HEALTHCHECK_INTERVAL`/`AUTO_RESTART` inside
  `vnc-remote service --run` and `start --foreground`). Dead config
  keys consumed by nothing (`MONITORING_ENABLED`, `PROMETHEUS_PORT`,
  `GRAFANA_PORT`, `NODE_EXPORTER_PORT`) were removed.

- **F-035 Windows process isolation (DOCUMENTED LIMITATION).** The
  restricted runtime user is created and ACLs applied to data dirs,
  but VNC/terminal processes run under the current user's context —
  UltraVNC shares the interactive console session, so running it as
  a different user would break screen capture (Session-0 isolation).
  Full impersonation (CreateProcessAsUser via ctypes or the uvnc
  service account) is a tracked enhancement; see ADR-0007 Risks.
