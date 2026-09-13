# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-11

### Added
- Unified HTTP authentication model (`security/http_auth.py`) shared across all services
- Shared SSL/TLS context creation (`security/certificates.py::create_ssl_context()`)
- Unified Flask JSON error envelope (`core/errors.py::json_error()`)
- Optional health endpoint authentication via `HEALTH_AUTH_TOKEN`
- Sanitized environment for terminal subprocesses (no secret leakage)
- Cross-platform test runner with Windows Python fallback from WSL

### Changed
- Migrated landing, terminal, and health services to shared auth helpers
- All 7 HTTP/WebSocket services now support TLS consistently via `create_ssl_context()`
- Flask routes return unified JSON error schema
- `Firewall.ps1` parameter `Action` no longer mandatory (defaults to `List`)
- CRLF-safe `.env` loading in all Bash scripts
- `run_tests.sh` detects and uses Windows Python from WSL
- `shellcheck` test skips gracefully when not functional

### Fixed
- `subprocess.CREATE_NO_WINDOW` now conditional on Windows (was crashing Linux)
- Flask health and landing routes now require authentication
- `VncRemote.ps1` correctly finds `bash.exe` in Git for Windows
- `VncRemote.ps1` uses `vnc-remote` instead of deprecated `launch.sh`
- `launch.sh` respects `KEEP_TEMP_USER` from `.env` (was forced to `true`)
- `config.sh` fallback password no longer generates the prohibited `ChangeMe!` pattern
- `common.env` no longer forces Windows ports on Linux
- Removed unused `pycryptodome` dependency; added `werkzeug`
- Dead variables removed from `landing.py`

## [0.1.0] - 2026-09-11

### First public release

Initial release of VNC Remote Secure — secure, browser-based remote access
to Linux/Raspberry Pi and Windows machines.

### Added
- Modular Bash architecture (`src/lib/` with 7 categories: core, security, web, monitoring, communication, features, platform)
- noVNC desktop access via browser (TigerVNC on Linux, UltraVNC on Windows)
- Web terminal (ttyd on Linux, Tornado-based on Windows)
- SSL/TLS support with self-signed or Let's Encrypt certificates
- Duck DNS dynamic DNS integration (cross-platform: Bash + Python scripts)
- Health monitoring dashboard with real-time system metrics
- Landing page portal with service links and status
- Temporary user isolation on Linux (created on start, removed on exit)
- Rate limiting and Fail2ban support
- Session recording (optional, asciinema format)
- Backup and restore scripts with SSL path consistency
- Docker integration testing environment
- Test pyramid: 116 tests across 5 levels (static, unit, integration, e2e, security)
- CI/CD pipeline: parallel lint, test, security scanning, Docker build, multi-arch
- Pre-commit hooks: shellcheck, shfmt, ruff, black, yamllint, CRLF detection
- Windows local/LAN support (UltraVNC + Python stack with documented limitations)
- Bluetooth audio streaming (server → client headphones via WebSocket + ffmpeg)
- Bluetooth gamepad forwarding (client gamepad → server input via WebSocket)
- Systemd service units with security hardening (NoNewPrivileges, ProtectSystem, etc.)
- Full uninstaller (reversible installation: removes services, nginx config, certs, users)
- Professional documentation: README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ROADMAP
- GitHub issue templates (bug report, feature request, security report)
- Pull request template with checklist
- `.editorconfig` and `.gitattributes` for consistent line endings
- CI security scanning: Gitleaks (secret detection), Trivy (container/filesystem)

### Security
- Removed all hardcoded credentials from Python and Bash files
- Landing page no longer exposes passwords in HTML or JSON
- Fixed Cross-Site WebSocket Hijacking (CSWSH) in `web_terminal.py`
- Fixed timing attack in auth: uses `hmac.compare_digest()`
- VNC server binds to localhost when nginx is enabled (was: all interfaces)
- ttyd credentials read from temp file (not command-line args) to avoid process list exposure
- Flask error messages no longer expose raw exception text
- Rate limiter supports `X-Forwarded-For` only under trusted proxy configuration
- Password validation rejects weak passwords (changeme, admin123, etc.)
- SSL certificate and key files never committed (gitignored)

### Changed
- Consolidated `launch.sh` and `launch_nossl.sh` into single script with `--no-ssl` flag
- Makefile reorganized with categorized help and prerequisite validation
- `.gitignore` expanded to cover all runtime artifacts, logs, caches, and temp files
- Python tooling centralized in `pyproject.toml` (black, ruff configuration)
- `update.sh` respects current git branch (was: hardcoded main/master)
- `cleanup.sh` uses safe nullglob and quoted array expansion
- `health-check.sh` validates non-empty env vars (was: accepted empty values)
- Portable password generation with OpenSSL/urandom/Python fallbacks

### Compatibility
- **Linux/Raspberry Pi**: Raspberry Pi OS (64-bit), Ubuntu 22.04+, Debian 12+
- **Windows**: Windows 10+ with Git Bash, Python 3.11+, UltraVNC binaries
- **Client**: Any modern web browser (Chrome, Firefox, Safari, Edge)

## [Unreleased]

### Added
- `config_loader.py`: shared configuration loader that reads `.env` file and
  provides secure defaults with random password generation.
- `CHANGELOG.md`: this file.
