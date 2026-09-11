# AGENTS.md

Operational guide for agents and contributors working on this repository.

## Project overview

VNC Remote Secure: cross-platform system for secure browser-based remote access
via VNC, noVNC desktop, web terminal, optional audio/gamepad streaming, health
dashboard, and a Flask user-management UI.

The project uses a **package-based multiplatform architecture**:

```
CLI común en Python (vnc-remote)
        |
        +-- Servicios comunes (src/vnc_remote_secure/services/)
        |
        +-- Adaptador Linux (src/vnc_remote_secure/platform/linux/)
        |      +-- Bash (src/rpi-vnc-remote.sh, src/lib/)
        |      +-- systemd (native/linux/systemd/)
        |      +-- permisos POSIX
        |
        +-- Adaptador Windows (src/vnc_remote_secure/platform/windows/)
               +-- PowerShell (native/windows/, VncRemote.ps1)
               +-- Windows Services
               +-- ACL
               +-- Windows Firewall
```

### Entry points

- **Unified CLI**: `vnc-remote` (Bash wrapper) → `vnc_remote_secure.cli:main` (Python)
  - Commands: `start`, `stop`, `restart`, `status`, `doctor`, `install`, `uninstall`, `backup`, `restore`, `version`, `help`
- **Windows PowerShell**: `VncRemote.ps1` (compatibility wrapper)
- **Windows launcher**: `launch.sh` (deprecated, use `vnc-remote start`)
- **Linux Bash**: `src/rpi-vnc-remote.sh` (internal, called by `vnc-remote`)

### Source layout

- **Python package**: `src/vnc_remote_secure/` (60 modules)
  - `cli.py` — unified CLI
  - `core/` — config, paths, sessions, validation, lifecycle
  - `platform/{linux,windows}/` — platform adapters
  - `services/` — audio, gamepad, health, landing, novnc, terminal, vnc
  - `security/` — authentication, certificates, credentials, encryption
  - `monitoring/` — alerts, health, metrics, status
  - `web/` — Flask application, routes, templates, static
  - `vendor/d3des.py` — VNC DES (legacy protocol compatibility)
- **Linux Bash**: `src/rpi-vnc-remote.sh` + `src/lib/{core,security,web,monitoring,communication,features}/`
- **Windows PowerShell**: `native/windows/` (module + commands)
- **Native assets**: `native/linux/systemd/`, `native/windows/service/`
- **Configuration**: `config/{schema,defaults,nginx,examples}/`
- **External deps**: `third_party/{manifests,licenses,checksums}/`
- **Tools**: `tools/{doctor,download_dependencies,verify_dependencies,migrate_configuration}.py`
- **Scripts**: `scripts/{development,maintenance,release,utilities}/`
- **Packaging**: `packaging/{linux,windows,docker}/`
- **Documentation**: `docs/{architecture,adr,installation,user-guide,developer,archive}/`

## Platform support

**Server-side: Linux and Windows.**

- **Linux**: TigerVNC, ttyd, nginx, systemd, certbot, fail2ban, apt-get
- **Windows**: UltraVNC, ttyd, Windows Services, Windows Firewall, ACLs

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
├── unit/           # Python unit tests (core, security, services, web)
├── integration/    # Cross-module integration (common, linux, windows)
├── e2e/            # End-to-end scenarios (linux, windows)
├── security/       # Security tests (permissions, secret exposure, network)
├── powershell/     # Pester tests for Windows PowerShell module
├── shell/          # Bats-style shell tests
├── fixtures/       # Static test data (config, certificates, responses)
└── lib/            # Bash test framework
```

**Baseline: 140 tests passing (116 Bash + 24 PowerShell).**

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
  by `validate_config` at startup. Set real values in `.env` (copied from
  `.env.example`).
- The temporary user (`TEMP_USER`, default `remote`) is removed on exit unless
  `KEEP_TEMP_USER=true`. Do not change this default without a reason.
- VNC uses legacy DES authentication (fixed key, 8-char password limit). This is
  a protocol limitation, not a security feature. Always place VNC behind HTTPS,
  VPN, or SSH tunnel.

## Module loading order (Linux Bash)

`src/rpi-vnc-remote.sh` sources modules in a specific order. `core/utils.sh`
sources the specialized `core/*_utils.sh` modules and then redefines shared
helpers, so definitions in `utils.sh` take precedence. When adding a utility,
place it in the appropriate `*_utils.sh` module and avoid redefining it in
`utils.sh` unless intentional.

Note: `src/lib/core/utils.sh` only contains functions unique to it (cleanup,
validate_password_strength, check_port_available, validate_config, show_logs,
debug helpers). All other helpers (logging, display, commands, cleanup
primitives, validation, dependency installation) live in their respective
`*_utils.sh` / `logging.sh` / `validation.sh` modules and must not be
duplicated here.

## Dependencies

Dependencies are managed in `pyproject.toml` (single source of truth).

```bash
# Install in development mode
pip install -e ".[dev]"

# Build the package
python -m build
```
