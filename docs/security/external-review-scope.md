# External security review — scope document (TD-17 / SEC-002)

Automation posture (verified 2026-11-27): bandit clean on 32.6k LOC,
semgrep + CodeQL + gitleaks + trivy + OpenSSF Scorecard gating in CI,
pip-audit and `npm audit` clean, per-risk coverage floors ≥75% on all
auth-critical modules. This document scopes what automation cannot
cover: an independent human review. Hand it to the reviewer verbatim.

## In scope (highest risk first)

1. **Auth gateway & session lifecycle** — `security/auth_gateway.py`,
   `security/authentication.py`, `security/sessions.py`,
   `security/http_auth.py`. Questions: can any request reach a handler
   bypassing the gateway? Are cookie attributes/SameSite/rotation
   correct? Timing side-channels in comparisons?
2. **Step-up auth & MFA/WebAuthn** — `security/step_up_auth.py`,
   `security/mfa.py`, `security/webauthn.py`. Questions: is the
   single-use grant binding (operation+resource+session, 120s TTL)
   airtight? Replay/downgrade paths? WebAuthn challenge storage?
3. **Ephemeral sessions & share links** —
   `security/ephemeral_sessions.py`, the `/share` fragment flow.
   Questions: token entropy/lifetime, single-use consumption races,
   cookie issuance on activate.
4. **Destructive-op job lifecycle** — `security/jobs.py`,
   `core/deferred_lifecycle.py`, op-class lock. Questions: can a
   queued job be forged/replayed? Does the detached runner re-check
   authorization at execution time?
5. **Token signing & chain of trust** — `security/token_signing.py`,
   `security/shared_state.py`. Questions: key rotation semantics,
   sqlite integrity, symlink/path handling of the db.
6. **Terminal sandbox** — `services/terminal_spawn.py`,
   `services/terminal.py`. Questions: bwrap argument escape surface,
   rlimit coverage, command injection via spawn args, websockify
   bridge auth.

## Explicitly out of scope

VNC DES (documented protocol limitation), vendored `novnc`/`d3des`,
frontend XSS sinks beyond CSP review (bundle is generated, CSP is
declared in `backend/context.py`).

## Methodology expected

Threat-model the auth flow end-to-end; white-box read of the modules
above; targeted dynamic probes against a disposable instance
(`VRS_TEST_MODE=1` isolates state). Deliverable: findings with
severity + reproduction, filed as TECH_DEBT entries.

## Where to find reviewers

Low-cost options for a single-maintainer project: a scoped review on
`SECURITY.md` via the project's disclosure channel, a paid
assessment, or posting the scope to a community (e.g. OWASP/local
security meetups). Budget ballpark for scope ~1-2 reviewer-days.
