# Service & Component Catalog

Inventory of runtime components: purpose, owner, criticality, state
store, and where its runbook lives. Keep this table current — it is
the "what exists" index for operators and reviewers.

| Component | Purpose | Criticality | Data it manages | Runbook / docs |
|---|---|---|---|---|
| `vnc` (TigerVNC/UltraVNC) | Native RFB desktop | Critical | desktop framebuffer | `user-guide/desktop.md` |
| `websockify` bridge | WS→RFB loopback proxy | Critical | none | `architecture/overview.md` |
| `novnc` | browser desktop surface | High | none | `user-guide/desktop.md` |
| `landing` | portal SPA + auth gateway front | Critical | session cookies | `user-guide/sessions.md` |
| `terminal` | web shell (xterm.js + sandboxed PTY) | High | spawned shells | `user-guide/terminal.md` |
| `audio` | Opus audio stream | Medium | none | `user-guide/audio.md` |
| `gamepad` | gamepad input relay | Medium | none | `user-guide/gamepad.md` |
| `health`/`user_ui` app | `/health*`, `/metrics`, `/audit`, `/.well-known/security.txt` | High | none | `runbook/monitoring.md` |
| `api_v1` | versioned admin JSON API | High | ops/jobs/sessions | `api/openapi.v1.yaml`, `api/parity-matrix.md` |
| `rfb_capture` | screenshot + `.vrsrec` recording | Medium | recordings dir | `user-guide/…` + `recordings` CLI |
| `SessionStore` | persisted ephemeral sessions | High | `data/` session store | `runbook/recovery.md` |
| `shared_state` (sqlite) | cross-process KV: rate limits, jobs, revoke lists | High | `run/shared_state.db` | `adr/0011` |
| `audit` chain | append-only tamper-evident log | High | `data/audit*` | `security/audit-events.md` |
| `auth_gateway` | per-surface auth enforcement | Critical | — | `architecture/security-model.md` |
| `rfb_filter` | protocol-aware RFB proxy filter | Critical | — | `architecture/trust-boundaries.md` |
| `secrets` store | generated creds + rotation | Critical | `generated_credentials.env` | `runbook/recovery.md` |
| `operator store` | accounts, TOTP, WebAuthn | High | operator DB | `adr/0012` |
| Alert dispatch | Discord/webhook/email/syslog | Medium | — | `runbook/monitoring.md` |
| `upgrader` | self-upgrade with auto-rollback | High | backup before install | `developer/releasing.md` |
| `backup`/`restore` | snapshot + verified restore | High | backup archives | `runbook/recovery.md` |

## Lifecycle states (per §40 of the maturity model)

| State | Components |
|---|---|
| stable | everything above except below |
| experimental | `gamepad` on Windows (ViGEmBus extra), OTLP tracing (`[otel]` extra) |
| deprecated → removed | legacy Bash stack (superseded, ADR-0005/0006/0009); legacy `?session=` URLs (compat shim removed — fragment links only) |

## Owners

Single maintainer (@alesanfe) — see `GOVERNANCE.md`. `CODEOWNERS`
routes security-critical paths (`security/`, `rfb_filter.py`,
`backend/`) for review.
