# Roadmap

This document describes the planned direction for VNC Remote Secure.
Dates are indicative and may change based on priorities and feedback.

## Status Legend

- ✅ Done
- 🔄 In progress
- 📋 Planned
- 💡 Under consideration

---

## v0.1.0 — Foundation

- ✅ Modular Bash architecture (`src/lib/` with 7 categories)
- ✅ noVNC desktop access via browser
- ✅ Web terminal (ttyd on Linux, Tornado on Windows)
- ✅ SSL/TLS with self-signed or Let's Encrypt certificates
- ✅ Duck DNS dynamic DNS integration (cross-platform)
- ✅ Health monitoring dashboard
- ✅ Landing page portal
- ✅ Temporary user isolation (Linux and Windows)
- ✅ Rate limiting and Fail2ban support
- ✅ Session recording (optional)
- ✅ Backup and restore scripts
- ✅ Docker integration testing
- ✅ Test pyramid (251 Python + 39 Bash + 7 Pester + 11 Playwright)
- ✅ CI/CD pipeline (lint, test, build, multi-arch Docker)
- ✅ Pre-commit hooks (shellcheck, shfmt, ruff, black, yamllint)
- ✅ Professional documentation (README, CONTRIBUTING, SECURITY, CHANGELOG)
- ✅ Windows local/LAN support (UltraVNC + Python stack)
- ✅ Bluetooth audio streaming (server → client)
- ✅ Bluetooth gamepad forwarding (client → server)
- ✅ Systemd service units with hardening
- ✅ Full uninstaller (reversible installation)
- ✅ CLI tool (`vnc-remote` command)
- ✅ Architecture Decision Records (ADRs)

## v0.2.0 — Security Hardening (current)

- ✅ Threat model documentation in SECURITY.md
- ✅ Gitleaks secret scanning in CI
- ✅ Trivy container image scanning in CI
- ✅ OpenSSF Scorecard integration
- ✅ Central authentication gateway with MFA/TOTP
- ✅ Per-action WebSocket authorization
- ✅ Ephemeral sessions with revocation
- ✅ Security profiles (Zero Trust naming)
- ✅ Blocking posture controls (not just scoring)
- ✅ Adversarial security tests (14 tests)
- ✅ Backend bind enforcement (127.0.0.1 only)
- ✅ Windows restricted runtime user
- ✅ TLS cipher validation tests
- ✅ HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- ✅ Structured audit logging (JSON, tamper-evident chain)
- ✅ Secret file permissions validation
- ✅ Prometheus metrics export
- ✅ API documentation (OpenAPI 3.0)
- ✅ Monitoring runbook

## v0.3.0 — Reliability

- 📋 Idempotency tests (run setup twice, verify no duplication)
- ✅ Bats testing framework for Bash unit tests
- 📋 CI matrix: Debian 12, Ubuntu 22.04/24.04, Raspberry Pi OS
- 📋 Automated backup verification
- 📋 Automated restore testing
- ✅ Centralized error handling with structured output
- 📋 Service health check integration with systemd

## v0.4.0 — Features

- ✅ Installation profiles (`SECURITY_PROFILE=development|trusted-lan|private-overlay|public-hardened`)
- ✅ Session management with TTL (`session create --ttl 2h`, `session revoke`)
- 📋 Admin dashboard (authenticated, full system status)
- ✅ Prometheus metrics export
- 📋 Alert integration (email, webhook on cert expiry / service failure)
- 📋 DNS provider abstraction (DuckDNS, Cloudflare, manual, self-signed)
- ✅ `make demo` target (Docker-based, self-contained demo)
- ✅ API documentation (OpenAPI) for health endpoints

## v0.5.0 — Distribution

- 💡 .deb package for Debian/Ubuntu
- 💡 Ansible playbook for automated deployment
- 💡 GitHub Releases with checksums and artifacts
- 💡 Compatibility matrix (tested platforms/versions)
- ✅ Migration guide between versions

## v1.0.0 — Production Ready

- 💡 Full security audit (external)
- 💡 Performance benchmarks
- 💡 Load testing
- 💡 Documentation site (MkDocs or Docusaurus)
- ✅ API documentation for health endpoint
- ✅ Monitoring runbook
- 💡 Disaster recovery procedures

---

## Guiding Principles

1. **Security first**: Every feature must be secure by default. Insecure defaults are bugs.
2. **Reversibility**: Every change the project makes must be undoable.
3. **Idempotency**: Running setup twice should produce the same result as running it once.
4. **Minimal privileges**: Services run with the least privileges needed.
5. **Evidence over claims**: Tests and CI prove that features work.
6. **Linux primary, Windows practical**: Linux/RPi is the production target. Windows is local/LAN.
7. **No secrets in code**: Credentials live in `.env` or secret files, never in the repository.
