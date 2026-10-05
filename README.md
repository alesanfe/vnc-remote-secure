# VNC Remote Secure

**Self-hosted remote access for a machine you own — desktop, terminal,
audio and file share, all through the browser.** One Python CLI installs,
runs, secures and audits the whole stack; the client needs nothing but
a web browser.

[![CI](https://github.com/alesanfe/vnc-remote-secure/actions/workflows/ci.yml/badge.svg)](https://github.com/alesanfe/vnc-remote-secure/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

[Documentation](docs/README.md) ·
[Report a bug](https://github.com/alesanfe/vnc-remote-secure/issues) ·
[Security](SECURITY.md) ·
[Changelog](CHANGELOG.md)

> [!IMPORTANT]
> **Status: 0.x — active development.** The `/api/v1/*` contract and
> `.env` knobs are versioned and stable; internals may still evolve.
> Breaking changes are announced in the changelog (e.g. legacy
> `?session=` share links were removed — use `/share#t=` links).

<p align="center">
  <img src="docs/assets/screenshots/portal.png" alt="Portal del operador: métricas del host en vivo (CPU, RAM, disco, uptime) y tarjetas de servicio con estado online/offline" width="880" />
</p>
<p align="center">
  <sub>Operator portal — live host metrics and per-service status</sub>
</p>

## Who it's for

- You want to reach **your own** desktop/terminal from a browser
  (homelab, headless server, Pi, Windows box) without installing
  anything on the client.
- You want a **guest access link** that expires, can be revoked, and
  can't be shared twice — not a permanent tunnel.
- You want remote access that is **auditable**: every session start,
  revoke, config change and file op lands in a tamper-evident log.

Not for: remote support of other people's machines, multi-tenant
hosting, or anything needing per-user cloud identity — see
`docs/REQUIREMENTS.md` for the scope boundary.

## Features

- **Desktop in the browser** — noVNC + websockify, zero client install
- **Web terminal** — xterm.js, command allowlist, per-connection caps
- **Guest share links** — single-use, TTL'd, revocable mid-session;
  revoking kills live WebSockets, not just future logins
- **Session recording** — `.vrsrec` captures + in-browser player
  ([format spec](docs/RECORDING_FORMAT.md))
- **File share** — scoped, size-capped, traversal-proof
  (`FILE_SHARE_ROOT`, 32 MiB)
- **Audio + gamepad forwarding** — optional channels
- **Auth gateway** — sessions, TOTP MFA, WebAuthn passkeys, step-up
  grants for destructive ops, optional IP-bound operator cookies
- **Health + metrics + audit** — `/health`, Prometheus `/metrics`,
  verifiable audit chain (`/audit/verify`), syslog/webhook export
- **TLS** — Let's Encrypt (Linux) or self-signed (Windows); nginx or
  direct bind
- **Encrypted backups + verified restore** — `vnc-remote backup` /
  `restore` with auto-rollback on failed upgrades

## Quick start

Requires **Python 3.11+** and git. First run generates credentials and
provisions VNC if missing (TigerVNC on Linux, UltraVNC on Windows).

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure
make setup-env        # copies .env.example → .env
```

### Linux / Raspberry Pi

```bash
make setup-deps && make run-ssl   # or `make run` for HTTP-only LAN use
```

### Windows

```powershell
make setup-deps; make win-run
```

### Verify it works

```bash
vnc-remote status     # every service should report running
vnc-remote doctor     # full diagnostic — config, ports, certs, firewall
curl -sk https://localhost:<HEALTH_WEB_PORT>/health/live
```

<img src="docs/assets/screenshots/cmd-status.png" alt="Salida de vnc-remote status: tabla de servicios con PID, estado y puerto" width="760" />

Then open the portal URL printed on screen (`https://<host>:8000`
by default). If `doctor` fails on a fresh box, see
[troubleshooting](docs/user-guide/troubleshooting.md).

## First share link (the core workflow)

```bash
vnc-remote session create --role viewer --ttl 1h
# → https://<host>/share#t=…   (token never reaches the server)
```

The guest opens the link, sees a consent card describing the grant,
accepts, and gets a revocable cookie session — operator-side:
`vnc-remote session list` / `session revoke <id>`.

<img src="docs/assets/screenshots/share-consent.png" alt="Tarjeta de consentimiento del share link: lista de capacidades (ver escritorio, controlar teclado/ratón, terminal, audio, archivos, chat), caducidad automática y botones Aceptar/Cancelar" width="560" />

## Operator console

The admin SPA (at `/admin/`) manages sessions, operators, security,
audit and backups — every CLI verb is reachable through `/api/v1/*`
with the same use case behind it.

<table>
<tr>
  <td><img src="docs/assets/screenshots/admin-overview.png" alt="Consola de administración: resumen con postura de seguridad y acciones rápidas" width="420" /></td>
  <td><img src="docs/assets/screenshots/admin-sessions.png" alt="Inventario de sesiones: estado, permiso, caducidad, revocación" width="420" /></td>
</tr>
</table>
<p><sub>Overview · Access links</sub></p>

<details>
<summary>More CLI captures</summary>

| `vnc-remote --help` | `vnc-remote doctor` |
|---|---|
| <img src="docs/assets/screenshots/cmd-help.png" alt="Salida de vnc-remote --help — comandos y verbos del CLI" width="400" /> | <img src="docs/assets/screenshots/cmd-doctor.png" alt="Diagnóstico del CLI" width="400" /> |

| `vnc-remote config validate` | `vnc-remote session list` |
|---|---|
| <img src="docs/assets/screenshots/cmd-config-validate.png" alt="Validación de configuración" width="400" /> | <img src="docs/assets/screenshots/cmd-session-list.png" alt="Listado de sesiones" width="400" /> |

Captured from the real CLI (see `frontend/e2e/screenshots.spec.ts` —
`VRS_SHOTS=1 npm run test:e2e -- screenshots` regenerates them).

</details>

<details>
<summary>Every console page — the full admin SPA walkthrough</summary>

| Sessions & access | |
|---|---|
| Session inventory: invitations, operators and guests with state and expiry | ![Session inventory: invitations, operators and guests with state and expiry](docs/assets/screenshots/admin-sessions.png) |
| Session detail: permissions, restrictions (single-use, IP-only) and revoke | ![Session detail: permissions, restrictions (single-use, IP-only) and revoke](docs/assets/screenshots/admin-session-detail.png) |
| In-session chat tab | ![In-session chat tab](docs/assets/screenshots/admin-session-chat.png) |
| Session-creation wizard — limits step (expiry, uses, IP restriction) | ![Session-creation wizard — limits step (expiry, uses, IP restriction)](docs/assets/screenshots/admin-wizard-limits.png) |
| Session-creation wizard — review step before minting the link | ![Session-creation wizard — review step before minting the link](docs/assets/screenshots/admin-wizard-review.png) |
| Link created: URL + QR shown exactly once, copy toast | ![Link created: URL + QR shown exactly once, copy toast](docs/assets/screenshots/admin-toast.png) |
| Revocation confirmation dialog | ![Revocation confirmation dialog](docs/assets/screenshots/admin-confirm-revoke.png) |

| Operations | |
|---|---|
| Overview: posture summary, jobs in flight, quick actions | ![Overview: posture summary, jobs in flight, quick actions](docs/assets/screenshots/admin-overview.png) |
| Activity feed | ![Activity feed — recent operations in the admin console](docs/assets/screenshots/admin-activity.png) |
| Diagnostics: config/ports/certs/firewall checks with OK/WARN/FAIL | ![Diagnostics: config/ports/certs/firewall checks with OK/WARN/FAIL](docs/assets/screenshots/admin-doctor.png) |
| Jobs queue | ![Jobs queue — background operations with state](docs/assets/screenshots/admin-jobs.png) |
| Job detail with progress bar and payload | ![Job detail with progress bar and payload](docs/assets/screenshots/admin-job-detail.png) |

| Files & remote work | |
|---|---|
| Session file browser | ![Session file browser](docs/assets/screenshots/admin-files.png) |
| Drag-over state on the dropzone | ![Drag-over state on the dropzone](docs/assets/screenshots/admin-files-drop.png) |
| Real drop → transfer queue "uploading…" | ![Real drop → transfer queue "uploading…"](docs/assets/screenshots/admin-files-drop-upload.png) |
| Immersive remote console (noVNC) | ![Immersive remote console (noVNC)](docs/assets/screenshots/admin-remote.png) |
| Session recordings | ![Session recordings](docs/assets/screenshots/admin-recordings.png) |
| `.vrsrec` recording player with seek and speed controls | ![`.vrsrec` recording player with seek and speed controls](docs/assets/screenshots/admin-recording-player.png) |

| Security & administration | |
|---|---|
| Security posture: findings by severity | ![Security posture: findings by severity](docs/assets/screenshots/admin-security.png) |
| Tamper-evident audit log with integrity chain | ![Tamper-evident audit log with integrity chain](docs/assets/screenshots/admin-audit.png) |
| Audit — load error with retry | ![Audit — load error with retry](docs/assets/screenshots/admin-audit-error.png) |
| Operators & identities | ![Operators & identities](docs/assets/screenshots/admin-identities.png) |
| Operator detail | ![Operator detail](docs/assets/screenshots/admin-user-detail.png) |
| Config editor with validation and effective diff | ![Config editor with validation and effective diff](docs/assets/screenshots/admin-config.png) |
| Backups: create, verify, restore | ![Backups: create, verify, restore](docs/assets/screenshots/admin-backups.png) |
| Step-up reauthentication for destructive operations | ![Step-up reauthentication for destructive operations](docs/assets/screenshots/admin-stepup.png) |

| Shell & access | |
|---|---|
| Console login | ![Admin console login with MFA hint](docs/assets/screenshots/admin-login.png) |
| Login — invalid credentials | ![Login — invalid credentials](docs/assets/screenshots/admin-login-error.png) |
| Command palette (Ctrl+K) | ![Command palette (Ctrl+K)](docs/assets/screenshots/admin-palette.png) |
| Keyboard-shortcut dialog | ![Keyboard-shortcut dialog](docs/assets/screenshots/admin-shortcuts.png) |
| Built-in help | ![Built-in help — routes, shortcuts and glossary](docs/assets/screenshots/admin-help.png) |
| Unknown route → "Page not found" | ![Unknown route → "Page not found"](docs/assets/screenshots/admin-404.png) |

| Guest-facing surfaces | |
|---|---|
| Guest session view | ![Guest session view](docs/assets/screenshots/guest.png) |
| Desktop stream (noVNC) | ![Desktop stream (noVNC)](docs/assets/screenshots/desktop.png) |
| Web terminal | ![Web terminal in a guest session (xterm.js)](docs/assets/screenshots/terminal.png) |
| Audio streaming | ![Audio streaming](docs/assets/screenshots/audio.png) |
| Gamepad streaming | ![Gamepad streaming](docs/assets/screenshots/gamepad.png) |
| Guest file browser | ![Guest file browser](docs/assets/screenshots/files-public.png) |
| Account-recovery surface | ![Account-recovery surface](docs/assets/screenshots/recovery.png) |
| Share-link consent in English | ![Share-link consent in English](docs/assets/screenshots/share-consent-en.png) |
| Portal connection cards (operator portal) | ![Portal connection cards (operator portal)](docs/assets/screenshots/admin-connect.png) |

</details>

<details>
<summary>Theme, density, viewport and locale matrix</summary>

| Variant | Capture |
|---|---|
| Dark — overview | ![Dark — overview](docs/assets/screenshots/dark-overview.png) |
| Dark — sessions | ![Dark — sessions](docs/assets/screenshots/dark-sessions.png) |
| Dark — security | ![Dark — security](docs/assets/screenshots/dark-security.png) |
| Dark — connect | ![Connect page in dark theme — services and links](docs/assets/screenshots/dark-connect.png) |
| Dark — guest | ![Guest session in dark theme](docs/assets/screenshots/dark-guest.png) |
| Dark — share consent | ![Dark — share consent](docs/assets/screenshots/dark-share-consent.png) |
| Compact density — sessions | ![Compact density — sessions](docs/assets/screenshots/admin-sessions-compact.png) |
| English locale — sessions | ![English locale — sessions](docs/assets/screenshots/admin-sessions-en.png) |
| Mobile 390px — sessions | ![Mobile 390px — sessions](docs/assets/screenshots/mobile-sessions.png) |
| Mobile 390px — connect | ![Mobile 390px — connect](docs/assets/screenshots/mobile-connect.png) |
| Mobile 390px — identities | ![Mobile 390px — identities](docs/assets/screenshots/mobile-identities.png) |
| Mobile 390px — guest | ![Mobile 390px — guest](docs/assets/screenshots/mobile-guest.png) |

</details>

## Configuration

Everything is environment-driven via `.env` (copied from
`.env.example`, gitignored). The most-used knobs:

| Variable | Default | Description |
|----------|---------|-------------|
| `VNC_PASSWORD` | generated | VNC desktop password (8-char DES limit) |
| `TTYD_PASSWD` | generated | Web terminal credential |
| `VNC_PORT` | 5900/5901 | VNC server port (Win/Linux) |
| `NOVNC_PORT` | 6080 | noVNC web + authenticated WS proxy |
| `LANDING_PORT` | 8000 | Portal / share links / API |
| `HEALTH_WEB_PORT` | 8080/8090 | Health dashboard |
| `TLS_ENABLED` | true | HTTPS/WSS everywhere |
| `SECURITY_PROFILE` | development | `development`/`trusted-lan`/`private-overlay`/`public-hardened` |
| `DUCK_DOMAIN`/`DUCKDNS_TOKEN` | — | Dynamic DNS + Let's Encrypt |

Every knob is documented in [`.env.example`](.env.example) and
validated by `vnc-remote config validate` (`config.schema.json` is
the machine-checkable contract).

## Architecture

```
                 +-------------------+
                 |   vnc-remote CLI  |
                 | (Python, unified) |
                 +---------+---------+
                           |
                  +--------v--------+
                  | Service Manager |
                  |  lock + PID     |
                  +----+-----+------+
                       |     |
             +---------+     +----------+
             |                          |
   +---------v---------+       +--------v---------+
   |  Linux adapter    |       | Windows adapter   |
   | Python + systemd  |       | Python + services |
   | Bash = thin wrap  |       | PowerShell = thin |
   +---------+---------+       +---------+---------+
             |                          |
             +------------+-------------+
                          |
                +---------v---------+
                |  Common services   |
                |  (Python core)     |
                +----+-----+------+--+
                     |     |      |
              noVNC proxy  |   health/metrics/audit
              web terminal |   landing portal + /api/v1
                     |     |
                VNC server (TigerVNC / UltraVNC)
```

The Python CLI + service manager is canonical on every platform;
Bash/PowerShell are thin delegating wrappers. Detail:
[architecture overview](docs/architecture/overview.md) ·
[component catalog](docs/architecture/catalog.md) ·
[12 ADRs](docs/decisions/README.md) · [failure modes](docs/architecture/failure-modes.md).

## Platform support

| Platform | Status | VNC | Notes |
|----------|--------|-----|-------|
| Debian 12+ / Ubuntu 22.04+ | Production | TigerVNC | systemd, nginx, certbot |
| Raspberry Pi OS 64-bit | Production | TigerVNC | full stack |
| Windows 10/11 | Supported | UltraVNC | services, firewall, AppContainer sandbox |
| Windows Server 2022+ | Experimental | UltraVNC | less coverage |

Client: **any browser** — no install.

## Known limitations

- **VNC DES auth** — the RFB password handshake is a protocol-bound
  legacy cipher (fixed key, 8-char cap). Always serve over HTTPS/WSS
  or a VPN. Documented as accepted risk R-01.
- **Single host** — one deployment = one machine's sessions. No
  clustering or multi-tenant identity (by design).
- **File share** — JSON/base64, 32 MiB cap; for large transfers use
  a real transport.
- **SSO/OIDC** — deliberately delegated to your reverse proxy
  (ADR-0012); the product ships local accounts + passkeys.

## Testing

```bash
make test-all    # static → unit → integration → e2e → security
make test-fast   # skips e2e
make debt-audit  # debt signals: hotspots, dead code, markers, drift
make coverage    # coverage report (indicator, not a gate)
```

Windows/PowerShell: `pwsh -c "Invoke-Pester tests/powershell -Output Detailed"`.
Frontend: `cd frontend && npm run build && npm run test:e2e` (Playwright).
~1758 Python tests + e2e; see [testing guide](docs/developer/testing.md).

## Security

- Zero hardcoded credentials — generated or `.env`-only, gitignored,
  gitleaks+detect-secrets in CI
- Tamper-evident append-only audit log with a chain you can verify:
  `vnc-remote verify` / `GET /audit/verify`
- Rate limits on auth + every surface; fail-closed health on public
  binds; OWASP-hardened headers; CSRF double-submit on mutations
- Release supply chain: SBOM (SPDX + CycloneDX), SHA-256 sums,
  SLSA-compatible provenance attestations, SHA-pinned actions

Full policy: [SECURITY.md](SECURITY.md) —
threat model: [THREAT_MODEL.md](docs/THREAT_MODEL.md) —
risk register: [docs/security/risk-register.md](docs/security/risk-register.md).

## Documentation

Everything lives under [`docs/`](docs/README.md):
install [Linux](docs/installation/linux.md) ·
[Windows](docs/installation/windows.md) ·
[Docker](docs/installation/docker.md) —
user guide ([sessions](docs/user-guide/sessions.md),
[terminal](docs/user-guide/terminal.md),
[production hardening](docs/user-guide/production-hardening.md)) —
ops ([SLO/RPO/RTO](docs/runbook/slo.md),
[incidents](docs/runbook/incident-response.md),
[drills](docs/runbook/drills.md)) —
governance ([requirements](docs/REQUIREMENTS.md),
[maturity](docs/maturity.md), [policies](docs/policies/README.md),
[tech debt](docs/TECH_DEBT.md)) —
[OpenAPI spec](docs/api/openapi.v1.yaml) · [ROADMAP](ROADMAP.md).

## Contributing & support

- Bugs → [issues](https://github.com/alesanfe/vnc-remote-secure/issues)
  (template + reproduction steps)
- Security reports → [SECURITY.md](SECURITY.md) **privately**; every
  deployment also serves `/.well-known/security.txt`
- Contributing → [CONTRIBUTING.md](CONTRIBUTING.md)
  (Conventional Commits, review checklist, DoR/DoD)

## License

MIT — see [`LICENSE`](LICENSE).
