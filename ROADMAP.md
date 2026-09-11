# Roadmap

This document describes the planned direction for VNC Remote Secure.
Dates are indicative and may change based on priorities and feedback.

## Status Legend

- ✅ Done
- 🔄 In progress
- 📋 Planned
- 💡 Under consideration

---

## v0.1.0 — Foundation (current release)

- ✅ Modular Bash architecture (`src/lib/` with 7 categories)
- ✅ noVNC desktop access via browser
- ✅ Web terminal (ttyd on Linux, Tornado on Windows)
- ✅ SSL/TLS with self-signed or Let's Encrypt certificates
- ✅ Duck DNS dynamic DNS integration (cross-platform)
- ✅ Health monitoring dashboard
- ✅ Landing page portal
- ✅ Temporary user isolation (Linux)
- ✅ Rate limiting and Fail2ban support
- ✅ Session recording (optional)
- ✅ Backup and restore scripts
- ✅ Docker integration testing
- ✅ Test pyramid (116 tests: static, unit, integration, e2e, security)
- ✅ CI/CD pipeline (lint, test, build, multi-arch Docker)
- ✅ Pre-commit hooks (shellcheck, shfmt, ruff, black, yamllint)
- ✅ Professional documentation (README, CONTRIBUTING, SECURITY, CHANGELOG)
- ✅ Windows local/LAN support (UltraVNC + Python stack)
- ✅ Bluetooth audio streaming (server → client)
- ✅ Bluetooth gamepad forwarding (client → server)
- ✅ Systemd service units with hardening
- ✅ Full uninstaller (reversible installation)

## v0.2.0 — Security Hardening

- 📋 Threat model documentation in SECURITY.md
- 📋 Gitleaks secret scanning in CI
- 📋 Trivy container image scanning in CI
- 📋 OpenSSF Scorecard integration
- 📋 TLS cipher validation tests
- 📋 HTTP security headers audit
- 📋 Structured audit logging (JSON format)
- 📋 Password prompt with hidden input (no echo)
- 📋 Secret file permissions validation (reject world-readable)

## v0.3.0 — Reliability

- 📋 Idempotency tests (run setup twice, verify no duplication)
- 📋 Bats testing framework for Bash unit tests
- 📋 CI matrix: Debian 12, Ubuntu 22.04/24.04, Raspberry Pi OS
- 📋 Automated backup verification
- 📋 Automated restore testing
- 📋 Centralized error handling with structured output
- 📋 Service health check integration with systemd

## v0.4.0 — Features

- 📋 Installation profiles (`--profile local|vpn|public-https|development`)
- 📋 Session management with TTL (`session create --ttl 2h`, `session revoke`)
- 📋 Admin dashboard (authenticated, full system status)
- 📋 Prometheus metrics export
- 📋 Alert integration (email, webhook on cert expiry / service failure)
- 📋 DNS provider abstraction (DuckDNS, Cloudflare, manual, self-signed)
- 📋 `make demo` target (Docker-based, self-contained demo)

## v0.5.0 — Distribution

- 💡 .deb package for Debian/Ubuntu
- 💡 Ansible playbook for automated deployment
- 💡 CLI tool (`vnc-remote` command)
- 💡 GitHub Releases with checksums and artifacts
- 💡 Compatibility matrix (tested platforms/versions)
- 💡 Migration guide between versions

## v1.0.0 — Production Ready

- 💡 Full security audit (external)
- 💡 Performance benchmarks
- 💡 Load testing
- 💡 Documentation site (MkDocs or Docusaurus)
- 💡 Architecture Decision Records (ADRs)
- 💡 API documentation for health endpoint
- 💡 Monitoring runbook
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
