# AGENTS.md

Operational guide for agents and contributors working on this repository.

## Project overview

Raspberry Pi VNC Remote: modular Bash system for secure web-based remote access
to a Raspberry Pi (noVNC desktop + ttyd terminal behind an nginx SSL reverse proxy,
with optional monitoring, recording, fail2ban and a Flask user-management UI).

- Entry point: `src/rpi-vnc-remote.sh` (sources modules from `src/lib/`)
- Modules are organized by category under `src/lib/{core,security,web,monitoring,communication,features}/`
- Two Python components: `src/lib/web/user_ui_app.py` (Flask UI) and
  `src/lib/monitoring/health_web_server.py` (health dashboard)
- Configuration via environment variables; defaults live in `src/lib/core/config.sh`
  and are documented in `.env.example`

## Platform support

**Server-side: Linux only.** The script manages Linux-native services (tigervncserver,
nginx, systemd, apt-get, useradd, fail2ban, certbot) that do not exist on Windows or
macOS. It runs **on the Pi** to provide remote access **to** the Pi. Porting to
Windows/macOS is not feasible without a complete rewrite.

**Client-side: any OS.** The client only needs a web browser. No software installation
on the client machine.

## Verification commands

```bash
# Run the full test suite (auto-discovers all test_*.sh files)
bash tests/run_tests.sh

# Run a specific test category (path prefix filter)
bash tests/run_tests.sh unit/core/
bash tests/run_tests.sh unit/security/

# List available tests
bash tests/run_tests.sh -l

# Lint shell scripts (if shellcheck is installed)
make lint
```

The test suite uses `tests/lib/test_framework.sh` which provides `assert_eq`,
`assert_success`, `assert_failure`, `assert_contains`, `assert_function_exists`,
`begin_suite`, `run_test`, and `end_suite`. Each test file sources the framework
and the module under test, then defines test functions.

Always run `bash tests/run_tests.sh` before committing changes to `src/` or `tests/`.

## Commit conventions

This project uses **Conventional Commits**. Do NOT use generic messages such as
"Subir", "update", or "wip". See `doc/developer/contributing.md` for the full guide.

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

- NEVER commit `.env`, `*.pem`, `*.key`, or any file under `data/ssl/` or `ssl/`.
  These are gitignored; keep them out of history.
- Default passwords (`changeme`, `admin123`, `YourStrongPassword123`) are rejected
  by `validate_config` at startup. Set real values in `.env` (copied from
  `.env.example`).
- The temporary user (`TEMP_USER`, default `remote`) is removed on exit unless
  `KEEP_TEMP_USER=true`. Do not change this default without a reason.

## Module loading order

`src/rpi-vnc-remote.sh` sources modules in a specific order. `core/utils.sh`
sources the specialized `core/*_utils.sh` modules and then redefines shared
helpers, so definitions in `utils.sh` take precedence. When adding a utility,
place it in the appropriate `*_utils.sh` module and avoid redefining it in
`utils.sh` unless intentional.

Note: `src/lib/core/utils_refactored.sh` is NOT loaded by the main script and is
kept only as a reference; do not rely on it at runtime.
