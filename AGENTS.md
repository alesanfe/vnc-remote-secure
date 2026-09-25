# AGENTS.md

Operational guide for agents and contributors working on this repository.

## Project overview

VNC Remote Secure: cross-platform system for secure browser-based remote access
via VNC, noVNC desktop, web terminal, optional audio/gamepad streaming, health
dashboard, and a React admin/user-facing UI (single SPA bundle).

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
  - Commands: `start`, `stop`, `restart`, `status`, `doctor`, `install`, `uninstall`, `backup`, `restore`, `session`, `operator`, `secrets`, `config`, `security`, `upgrade`, `maintenance`, `verify`, `service`, `version`, `help`
- **Windows PowerShell**: `VncRemote.ps1` and `src/vnc_remote_secure/native/windows/VncRemote.psm1` (thin
  compatibility wrappers — all commands delegate to the Python CLI via
  `Invoke-PythonCli`; PowerShell verb names map to Python subcommands:
  `Get-Status`→`status`, `Test-Configuration`→`doctor`, `Get-Version`→`version`,
  `Verify`→`verify`)
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

- **Python package**: `src/vnc_remote_secure/` (three-layer architecture)
  - `engine/` — domain + use cases, transport-free
    - `domain/` — `decision.py` (canonical `UseCaseError` codes); depends
      on stdlib only
    - `application/` — use cases: `operators`, `sessions`, `passkeys`,
      `maintenance`, `system_users`. Never import `security/*`,
      `services/*`, `web/*`, `platform/*` — the boundary test
      (`tests/unit/architecture/test_import_boundaries.py`) enforces it
    - `ports/` — protocol seam documentation
    - `infrastructure/stores.py` — the ONLY engine module allowed to
      touch `security/*`/`platform/*`; narrow delegation functions
  - `backend/` — transport namespace for the versioned JSON API;
    `backend/api.py` is the stable facade consumers import
    (implementation still in `services/api_v1.py` while the migration
    proceeds)
  - `cli/`  unified CLI package (canonical entry point: `commands/` per domain, `_parser.py` argparse wiring, `_app.py` `main()`, `_common.py` shared helpers)
  - `core/` — backup, config, **config_inspector**, constants, **doctor**, errors, exceptions, logging, paths, processes, validation, lifecycle, **service_manager**, uninstall
  - `platform/{linux,windows}/` — platform adapters (adapter, installer, services, users, permissions, metrics, gamepad; Windows also firewall + `_powershell`), plus shared `platform/{base,detection}.py`
  - `services/` — audio, gamepad, health, landing, novnc (static +
    `/websockify` proxy to the loopback websockify bridge), terminal, vnc,
    **api_v1** (versioned JSON API for the admin SPA)
  - `security/` — audit, **auth_gateway**, authentication, certificates, credentials, ephemeral_sessions, file_permissions, http_auth, http_headers, mfa, posture, **profiles**, **rate_limit**, redaction, sessions, **shared_state**, step_up_auth, tls_validation, **token_signing**, **websocket_registry**
  - `monitoring/` — health, prometheus, **alerts** (Discord/webhook/email dispatch)
  - `web/` — health/metrics app entry point (`application.py` →
    `backend/health_app.py`, FastAPI/uvicorn; machine-facing only, no
    UI routes/templates) + `static/admin/` (built SPA assets)
  - `vendor/d3des.py` — VNC DES (legacy protocol compatibility, pycryptodome-backed)
- **Frontend**: `frontend/` — React + TypeScript + Vite SPA
  (`react-router-dom`, `@tanstack/react-query`) serving EVERY
  user-facing surface: portal (`/`), share links (`/share`), audio
  (`/audio`), gamepad (`/gamepad`) and the operator console
  (`/admin/*`). `npm run build` emits the bundle to
  `src/vnc_remote_secure/web/static/admin/`; the landing service
  serves `index.html` for all those routes with SPA fallback.
  The SPA talks to `/api/v1/*` on the landing service
  (`services/api_v1.py`) — Python remains the sole authority on
  security decisions; React only renders and posts actions.
  - `npm run gen:types` regenerates `src/api/generated/types.ts` from
    `docs/api/openapi.v1.yaml` — run it whenever the spec changes.
  - `npm run test:e2e` runs the Playwright suite in `frontend/e2e/`;
    the global setup spawns the real landing service on a random
    loopback port with an isolated run dir (no Node needed at runtime,
    only for development).
- **CLI ↔ UI parity**: every manageable CLI verb is reachable over
  `/api/v1/*` with the same use case behind it
  (`engine/application/ops.py` — backups create/verify/restore,
  secrets status/redact/rotate/rotate-signing/check/recovery-codes,
  config effective/explain/validate/diff/migrate, lifecycle
  status/start/stop/restart, upgrade check/run/rollback, version).
  The shared logic lives in `security/secret_rotation.py` and
  `core/config_migration.py` so CLI and API never diverge.
  - `engine/domain/operations.py` is the canonical **operation
    catalog** — every transport-checkable operation declares its
    permission, authentication policy (`stepup` recency vs
    `stepup-bound` single-use grant), execution mode
    (`sync`/`job`/`deferred`), confirmation type, audit event and
    reversibility there. `tools/parity_matrix.py` regenerates
    `docs/api/parity-matrix.md`; the contract test in
    `tests/unit/engine/` fails when a route drifts from the catalog.
  - Destructive ops persist a QUEUED job on the shared-state backend
    before answering (`security/jobs.py` `job_enqueue`/`job_claim`),
    then `POST /api/v1/lifecycle|backups/restore|upgrade*` returns
    202+`job_id` and a detached runner
    (`core/deferred_lifecycle.py run <job_id>`) claims and executes
    it — a persisted job, not the sleep, is what guarantees the
    operation. A `destructive` op-class lock prevents overlapping
    lifecycle/restore/upgrade.
  - `stepup-bound` operations consume a single-use grant minted by
    `POST /api/v1/step-up {password, operation, resource}` —
    `security/step_up_auth.py` binds the grant to
    operation+resource+session (120 s TTL) so a grant for one
    operation can never unlock another.
  - `core/test_isolation.py` (`VRS_TEST_MODE=1`, set by
    `tests/conftest.py`) aborts writes to repo-root `.env`/backups
    and detached spawns unless an explicit `VRS_*_DIR` override or
    `VRS_TEST_ALLOW_SPAWN=1` applies.
  Host bootstrap stays CLI-only by design: `install`, `uninstall`,
  `service --run`, `help` cannot run from a UI that only exists once
  services are up.
- **Share-link flow**: generated links are fragment URLs —
  `GET /share#t=<token>` serves the React SPA; the token never reaches
  the server — the SPA wipes it from the URL, calls
  `POST /api/v1/session/preview` (non-consuming grant summary →
  consent card) and, on consent, `POST /api/v1/session/activate`,
  which issues the `vnc_ephemeral` cookie on the JSON response.
  Legacy `GET /?session=<token>` links still work through the same
  consent flow but are never generated.
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

- **Linux**: TigerVNC, FastAPI/uvicorn (web terminal + all HTTP/WS surfaces), nginx, systemd, certbot, fail2ban, apt-get
  (the ttyd binary is an optional alternative download, not the default backend)
- **Windows**: UltraVNC, FastAPI/uvicorn (web terminal + all HTTP/WS surfaces), Windows Services, Windows Firewall, ACLs

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
# Install in development mode (runtime + dev/security toolchain)
pip install -e ".[dev]"

# Optional extras
pip install -e ".[otel]"            # OTLP trace export (OTEL_ENABLED)
pip install -e ".[windows-gamepad]" # ViGEmBus-backed XInput on Windows

# Build the package
python -m build
```

### Library policy

Use the declared dependency for its responsibility instead of
reimplementing it:

| Responsibility | Library | Where |
|---|---|---|
| API request/response validation | `pydantic` (strict, `extra='forbid'`) | `backend/schemas.py` |
| Typed env/settings | `pydantic-settings` | `monitoring/settings.py` (complements `config.schema.json`, which stays the declarative contract) |
| Outbound HTTP | `httpx` via `security/http_client.py` (SSRF policy + DNS pinning, no redirects, tenacity retry on transport errors) | alerts, audit-export webhooks, upgrade check |
| Metrics exposition | `prometheus-client` wire format over the shared-state backend | `monitoring/prometheus.py` |
| JSON logging | `structlog` `ProcessorFormatter` (`ts`/`level`/`logger`/`msg`) | `core/logging.py` |
| Password hashing | `argon2-cffi` Argon2id (legacy `pbkdf2:`/`scrypt:` still verify; rehash-on-login) | `security/credentials.py`, `security/operator_users.py` |
| TOTP primitives | `pyotp` (RFC 4226/6238) — replay protection + recovery codes stay project-owned | `security/mfa.py` |
| Retries | `tenacity` (bounded, transport-errors only — never on HTTP status) | `security/http_client.py` |
| Architecture contracts | `import-linter` (`lint-imports`; tests wrap it) | `tests/unit/architecture/` |
| OpenAPI contract | `openapi-spec-validator` + `openapi-core` | `tests/unit/api/test_openapi_contract.py` |
| Property tests | `hypothesis` | `tests/unit/security/test_properties.py` |
| Mock HTTP in tests | `httpx.MockTransport` injection via `secure_client(transport=)` — respx does NOT intercept the custom PinnedTransport, it only patches httpx's built-in transports | `tests/unit/security/test_http_client.py` |
| Frozen time in tests | `time-machine` | `tests/unit/monitoring/test_otel_settings.py` |
| Secrets scanning | `detect-secrets` + `.secrets.baseline` | pre-commit hook |
| SAST | `bandit`, `semgrep` (project rules in `.semgrep.yml`) | `make lint-bandit`, `make lint-semgrep` |
| Config schema validation | `jsonschema` (Draft 2020-12) — the schema document + shipped defaults are contract-tested | `tests/unit/core/test_config_schema.py` |
| Dependency audit / SBOM | `pip-audit`, `cyclonedx-bom` | `make check-deps`, `make sbom` |
| File hygiene | upstream `pre-commit-hooks` (json/yaml/toml, large files, private keys, EOL) | `.pre-commit-config.yaml` |

Do NOT introduce parallel systems: no Django/Flask-Security, no JWT
web sessions (HMAC cookies are canonical), no second rate-limit or
logging system, no mandatory Redis/SQLAlchemy inside the Engine.

Deliberately NOT adopted after evaluation: `platformdirs` —
`core/paths.py` implements elevation-aware semantics it cannot
reproduce (ProgramData for elevated/SYSTEM runs, LocalLow under
MSIX packaging, FHS vs XDG keyed on root). `respx` — it only patches
httpx's built-in transports, so it cannot intercept the custom
`PinnedTransport`; tests inject `httpx.MockTransport` instead.
`freezegun` — `time-machine` covers the same surface.

Audited and intentionally kept manual: `core/config.py`'s
`_parse_env_file` (python-dotenv cannot reproduce the `$(`-skip +
`_DEFAULT_INJECTED` precedence tracking), `core/service_manager.py`
locking (msvcrt/flock semantics `filelock`/`portalocker` don't
guarantee), `core/backup.py` `tarfile w:gz` (zstandard would change
the artifact format — restore compatibility outweighs the gain for
config-sized backups), `security/token_signing.py` (type-tagged
HMAC + revocation/SID semantics — itsdangerous evaluated and
rejected), `monitoring/alerts.py` email (stdlib `smtplib` is the
right call for a synchronous alert path).

### Security & quality tooling

```bash
make lint-arch       # import-linter: engine layering contracts
make lint-semgrep    # project rules (.semgrep.yml)
make lint-bandit     # SAST on src/
make check-secrets   # detect-secrets vs .secrets.baseline
make check-deps      # pip-audit
make sbom            # CycloneDX sbom.cdx.json
```

pre-commit hooks (`pre-commit install`) run: CRLF/whitespace checks,
shellcheck/shfmt, ruff, black, yamllint, bandit, pydocstyle, codespell,
detect-secrets, import-linter and semgrep (the last two skip cleanly
when the tool is not installed).

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

- **F-022 `http.server` fallback (RESOLVED).** The Flask app, the WSGI
  fallback and the `SimpleWebApp`/`http.server` degraded mode were
  removed: `web/application.py` always builds the FastAPI
  health/metrics app (`backend/health_app.py`, served by uvicorn) and
  the portal runs on FastAPI/uvicorn (`backend/app.py`). There is no
  fallback transport that could silently drop sessions, CSRF
  protection, security headers, or `/metrics`/`/audit` endpoints.

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

- **F-028 Auth gateway not applied to Flask routes (RESOLVED).** The
  Flask users blueprint was removed — the user-facing UI is the React
  SPA served by the landing service, and every mutating surface is
  `/api/v1/*`, which resolves operator sessions through the auth
  gateway (`vnc_op` + CSRF) in `services/api_v1.py`. The health/metrics
  surface is the FastAPI app in `backend/health_app.py`.

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

- **F-035 Windows process isolation (MITIGATED).** UltraVNC still
  shares the interactive console session (Session-0 isolation makes a
  different-user capture impossible — inherent platform constraint).
  Terminal commands, however, now spawn inside an **AppContainer**
  (`platform/windows/sandbox.py`, `TERMINAL_WINDOWS_SANDBOX=auto|
  strict|off`): the sandboxed shell cannot read the user profile
  holding `auth_secret.key`, `shared_state.db`, or generated
  credentials. A scratch dir under %TEMP% is ACL-granted to the
  AppContainer SID; extra read paths via
  `TERMINAL_WINDOWS_SANDBOX_DIRS`. See ADR-0007 Risks.
  The same applies to the **web terminal**: `_build_child_env`
  only hides secrets from `env`/`set` — the spawned shell still runs
  as the service account and can read `.env`,
  `<run_dir>/auth_secret.key`, and the session stores. On POSIX,
  `WEBTERM_USER` (requires the service running as root) drops the
  shell to a restricted user; there is no equivalent on Windows.

- **F-036 Pre-audit verification pass (RESOLVED + DOCUMENTED).** An
  evidence-based review of the boundary hypotheses an external audit
  would target closed 18 gaps: RFB filter fail-open, webhook SSRF,
  audit-rotation chain continuity, missing operator-store permission
  checks, stale signing-secret cache, no PBKDF2 rehash-on-login,
  upgrade supply-chain (PIP_* injection / downgrades / sdists),
  CSRF on landing POSTs, status.json disclosure to ephemeral
  sessions, silent revocation/expiry degradation, temp-user process
  leaks, stuck SendInput keys, audio head-of-line blocking, gamepad
  event floods, missing terminal rlimits, view-only path completion,
  request-smuggling framing, and plaintext backups under hardened
  profiles. The full CONFIRMED/COVERED/PARTIAL/LIMITATION matrix —
  including the residuals a third-party auditor will still flag —
  lives in `docs/security/pre-audit-verification.md`.
