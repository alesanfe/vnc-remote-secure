# External Security Audit — Scope & Evidence Package

This document prepares the repository for an independent security
audit. It defines what is in scope, where the security boundaries
live, and how each guarantee can be verified **reproducibly** — the
auditor should be able to confirm every claim without trusting
documentation.

## 1. Scope

**In scope**

- `src/vnc_remote_secure/security/` — auth gateway, sessions,
  ephemeral sessions, MFA, rate limiting, audit chain, shared state,
  WebSocket registry, token signing, step-up auth.
- `src/vnc_remote_secure/services/` — landing portal, noVNC relay +
  RFB input filter, web terminal, audio, gamepad, health.
- `src/vnc_remote_secure/core/` — service manager (PID/process
  lifecycle), backup/restore, config loading + inspector, doctor.
- `src/vnc_remote_secure/cli/` — command surface (upgrade, secrets,
  session, config, security, verify).
- Deployment artifacts: systemd unit, Windows service config,
  nginx template, `.env.example`, packaging scripts.

**Out of scope**

- Third-party daemons (TigerVNC/UltraVNC, nginx, ffmpeg) — reviewed
  only at the integration boundary (bind addresses, auth, process
  hygiene).
- Physical/host OS hardening beyond what `doctor`/`security check`
  validates.
- Browser extensions, mobile clients — none exist.

## 2. Security boundaries

| Boundary | Enforcement point | Verify with |
|----------|-------------------|-------------|
| Public ↔ gateway | `auth_gateway.authorize_request`, `check_websocket_upgrade`, `check_origin` | `tests/unit/security/test_auth_gateway.py`, `test_bypass_prevention.py` |
| Gateway ↔ internal services | `INTERNAL_HOST` binds, `audit_internal_listeners()` | `vnc-remote security check`, `tests/unit/core/test_service_manager*.py` |
| Share-link ↔ session | `ephemeral_sessions.check_permission` (signed tokens, resource binding, single-use, IP binding) | `test_token_binding.py`, `test_per_action_auth.py` |
| Operator ↔ admin surface | `_require_session`, step-up auth, portal operator endpoints | `test_step_up_auth.py`, `tests/unit/services/test_landing*.py` |
| Terminal ↔ host | command executor (no PTY), `_build_child_env` secret scrubbing, `WEBTERM_SHELL` allowlist, `TERMINAL_COMMAND_ALLOWLIST`, Job Objects/process groups | `test_terminal*.py` |
| Backup ↔ restore | manifest validation, tar limits, zip-slip guards, session expiry on restore | `test_backup.py` |
| Audit log ↔ tampering | hash chain + genesis anchor + monotonic seq + tip witness + optional mirror | `test_audit*.py` |

## 3. Reproducible verification

```bash
# Full suite
python -m pytest tests -q            # ~1290 tests, 0 skipped expected

# Security subset
python -m pytest tests/unit/security -q

# Live posture audit
vnc-remote security check            # posture + config + listeners + doctor
vnc-remote doctor --json             # machine-readable readiness
vnc-remote verify audit              # audit chain integrity
vnc-remote verify backup <file>      # backup integrity

# Mutation-relevant suites (security controls, not coverage)
python -m pytest tests/unit/security/test_rate_limit.py \
                 tests/unit/security/test_mfa.py \
                 tests/unit/security/test_token_binding.py -q
```

## 4. Claim inventory (auditor should test each)

1. **Share links are single-credential**: token signature, expiry,
   `max_uses`, IP binding and resource binding are all enforced
   server-side in `check_permission`/`check_session_permission`.
2. **Revocation is immediate**: shared-state flag + live WebSocket
   close via `websocket_registry` + cross-process watcher.
3. **RFB input filtering is fail-closed**: unknown message types and
   unparseable frames close the connection
   (`services/rfb_filter.py`); view-only sessions cannot inject
   input; clipboard is size-capped (`RFB_MAX_CLIPBOARD`).
4. **Single-use atomicity**: `used` claims go through shared-state
   compare-and-set — concurrent activation cannot double-use.
5. **TOTP anti-replay**: consumed time-steps recorded in shared
   state (`mfa._claim_step`); a reused code fails across processes.
6. **Audit is tamper-evident**: hash chain + anchor + `seq` +
   persisted tip detect mid-file edits, truncation, and rollback.
7. **Backups are consistent**: SQLite backup API (WAL-safe), tar
   limits, encrypted option (`BACKUP_PASSWORD`), restored sessions
   expired by default.
8. **Upgrades are reversible**: `vnc-remote upgrade` is backup-first
   with a rollback receipt; failure triggers automatic rollback.
9. **Process hygiene**: Linux process groups, Windows Job Objects
   (`KILL_ON_JOB_CLOSE`), PID-reuse-safe termination, orphan
   reaping.
10. **WebSocket exhaustion**: global cap (`WS_MAX_CONNECTIONS`) +
    per-IP cap (`WS_MAX_CONNECTIONS_PER_IP`).

## 5. Known residual risks (declared, not hidden)

- **VNC DES auth**: 8-char password, fixed key — protocol limitation.
  Mitigation: VNC port is loopback-only; browser access goes through
  the authenticated noVNC relay. Documented in THREAT_MODEL.md.
- **Windows Session 0**: services cannot capture the interactive
  console on modern Windows; the session-broker model is documented
  in `docs/architecture/windows-session-model.md`.
- **Single-operator model**: the Flask UI/portal authenticate one
  operator credential set; multi-user RBAC exists only for ephemeral
  share links (roles/permissions), not for operators.
- **Self-signed default TLS**: hardened profiles require real certs
  or tunnel deployment.
- **No public-exposure claim**: this package deliberately does NOT
  assert internet-facing readiness — that claim requires this
  audit's outcome.

## 6. Suggested audit focus

- Token forgery/replay paths across `ephemeral_sessions`,
  `token_signing`, `sessions` (clock skew, algorithm confusion).
- Concurrency: single-use claims, chain-hash writes, store
  merge-saves under process races.
- The RFB filter's stream parser (fuzzed: `test_rfb_filter_fuzz.py`)
  — desynchronization attacks.
- Restore path: tar edge cases beyond the current guards.
- Windows-specific: Job Object assignment, ACL application, service
  config — hardest to cover in CI (Windows runners only partially).
