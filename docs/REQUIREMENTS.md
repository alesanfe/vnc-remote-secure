# Requirements — VNC Remote Secure

Traceable requirement set. Each functional requirement has verifiable
acceptance criteria; each non-functional requirement is measurable and
names the mechanism that enforces it. Companion documents:
[THREAT_MODEL.md](THREAT_MODEL.md) (attack surface),
[architecture/overview.md](architecture/overview.md) (design),
[runbook/slo.md](runbook/slo.md) (operational targets),
[api/openapi.v1.yaml](api/openapi.v1.yaml) (API contract).

## 1. Purpose and scope

**Objective.** Provide secure, browser-based remote access (desktop via
noVNC, web terminal, audio, gamepad) to a self-hosted Linux or Windows
host — without exposing the raw VNC port — with operator-grade auth,
audit, shareable ephemeral sessions and upgrade/rollback.

**Users**

- **Operator** — authenticates to the admin console, manages sessions,
  configuration, backups and lifecycle.
- **Guest** — opens a share link (`/share#t=…`), consents, gets
  time-limited, permission-scoped access.
- **Deployer/SRE** — installs, upgrades, monitors, backs up and restores.

**In scope:** desktop (noVNC), terminal, audio, gamepad, ephemeral
sessions, operator accounts + MFA/step-up, audit log, metrics/alerts,
backup/restore, upgrade/rollback, maintenance mode, hardened profiles.

**Out of scope:** NAT traversal relays (a public deployment is behind
the operator's own TLS/proxy), multi-user concurrent desktops on one
session, public internet scale-out, a hosted/SaaS offering.

## 2. Functional requirements (verifiable)

| ID | Requirement | Acceptance criteria | Verified by |
|----|-------------|---------------------|-------------|
| FR-01 | Operator authenticates with username/password (+ optional TOTP) | Wrong credentials → generic 401 (no enumeration); lockout after `AUTH_MAX_ATTEMPTS`; success recorded for step-up recency | `tests/unit/security/test_http_auth.py`, `test_webauthn.py` |
| FR-02 | Share link grants scoped, time-limited access | Preview is non-consuming; activation mints a `vnc_ephemeral` cookie; expired/revoked/budget-exhausted links deny; IP/CIDR binding enforced fail-closed | `tests/unit/security/test_ephemeral*.py` |
| FR-03 | RFB traffic filtered by granted permissions | Unknown/malformed encodings close the stream; keyboard/pointer/clipboard events dropped without the matching permission; only parseable encodings negotiated | `tests/unit/services/test_rfb_filter.py` |
| FR-04 | Destructive ops are durable jobs | `lifecycle|backups/restore|upgrade` return 202 + `job_id`; the job persists on the shared-state backend before the response; `destructive` lock prevents overlap | `tests/unit/security/test_jobs*.py`, ops catalog tests |
| FR-05 | Step-up grants are single-use and bound | `POST /step-up {password, operation, resource}` mints a grant bound to op+resource+session (120 s); a grant for one op never unlocks another | `test_step_up*` |
| FR-06 | Upgrade refuses downgrades and unsafe configs | Pinned `==` older than installed → refused pre-backup; hardened profiles block when `validate_config()` has critical findings; failures roll back | `tests/unit/core/test_upgrader*` |
| FR-07 | Health endpoints never expose on public binds | Scoped tokens (`HEALTH`/`AUDIT`/`METRICS_AUTH_TOKEN`) required unless every bind + peer is loopback; Bearer rate-limited | `test_http_auth.py` health cases |
| FR-08 | Revocation propagates live | Revoking a session/operator disconnects open WebSockets carrying that grant | `test_websocket_registry.py` |
| FR-09 | Sessions/audit survive process restarts | SessionStore persists atomically (`.tmp`+rename); audit entries carry `seq` and are searchable without full scans | `test_audit*`, `test_stores*` |
| FR-10 | Maintenance mode drains gracefully | `maintenance on --drain-timeout N` writes wall+monotonic deadlines; the first process to notice revokes sessions — live sockets close | `test_maintenance.py` |

## 3. Non-functional requirements (measurable)

| ID | Property | Target / mechanism | Where |
|----|----------|--------------------|-------|
| NFR-01 | Install reproducibility | A new operator can install from `.env.example` + install docs with no undocumented steps | `docs/installation/` |
| NFR-02 | Auth latency | Local auth decision (rate-limit + password verify) p95 < 500 ms on RPi-class hardware | measured via `tests/unit` timing + prometheus histograms |
| NFR-03 | Availability | Portal/API answer `GET /health` 99.5% monthly when host is up (single-host service; host down = out of scope) | `docs/runbook/slo.md` |
| NFR-04 | Recovery | RPO ≤ 24 h (scheduled `backup`), RTO ≤ 30 min (service restart) / ≤ 4 h (full restore to a fresh host) | `runbook/recovery.md`, `slo.md` |
| NFR-05 | Confidentiality | No credential (VNC/TTYD/UI/landing passwords, tokens, TOTP secret) stored reversible in the repo or logs; secrets under `data/`/`run/` with owner-only perms | `security/redaction.py`, `file_permissions.py`, CI `check-secrets` |
| NFR-06 | Integrity of supply chain | Release artifacts carry SHA-256 sums, SPDX+CycloneDX SBOM and SLSA build attestation | `.github/workflows/release.yml` |
| NFR-07 | Resource bounds | Clipboard messages capped (`RFB_MAX_CLIPBOARD`), rate limits on auth/API surfaces, WebSocket frames bounded, spawned-shell rlimits + kill-job | `services/rfb_filter.py`, `security/rate_limit.py`, `services/terminal_spawn.py` |
| NFR-08 | Maintainability | No function above cyclomatic complexity 20 (radon); layered engine → application → domain enforced by import-linter | `pyproject.toml` contracts, `lint-arch` |
| NFR-09 | Reliability | All external calls carry timeouts; single-writer locking on lifecycle; PID-tracked start/stop (no `pkill -f`); idempotent ops where repeatable | `core/service_manager.py`, `service_pids.py`, `service_ports.py` |
| NFR-10 | Observability | Structured logs, request correlation, Prometheus metrics endpoint, alert dispatch (webhook/email), audit trail | `monitoring/`, `security/audit.py` |
| NFR-11 | Security posture gates | `vnc-remote security check` fails on critical findings in hardened profiles; health never open on public binds | `cli/commands/security.py`, `security/posture.py` |
| NFR-12 | Accessibility | Portal/admin SPA targets WCAG 2.2 AA basics: full keyboard navigation, visible focus, AA contrast, labelled controls, no color-only signals | `frontend/` + Playwright e2e |

## 4. Constraints

- VNC's legacy DES auth (fixed key, 8-char password) is a **protocol
  limitation** — VNC must sit behind HTTPS/VPN/SSH; the filter layer is
  the compensating control, not a fix for DES.
- Windows adapters rely on UltraVNC + Windows Services; Linux on
  TigerVNC + systemd + nginx — platform logic stays in
  `platform/{linux,windows}/`.
- No multi-tenancy: one deployment = one host's sessions.

## 5. Definition of done

A change is done when: CI green (lint/format/mypy/import-linter/
unit/integration/security + gitleaks + Trivy weekly), docs updated
(README/ADR/api spec when behavior or contract changes), CHANGELOG
entry for user-visible changes, and no weakening of the security rules
in `AGENTS.md`.

## 6. Definition of ready

Before a change enters implementation it must have: a problem
statement and user (operator/admin/guest); scope and explicit
non-goals; acceptance criteria mapped to tests that can verify them;
a review of which `security/risk-register.md` rows it touches; a
deployment/rollback note if it crosses a trust boundary or a config
knob; and for UI work, the required states (loading/empty/error/
no-permission) identified up front.
