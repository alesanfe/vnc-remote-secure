# Posture assessment — 2026-11-27

Second-pass audit after the 2026-11 campaign (CFG-001, bwrap fix,
TST-001, TD-12..TD-18 work). Scoring is evidence-based: a control
scores high only when it is enforced in code/CI, not merely
documented. Frameworks applied: **ISO/IEC 27001:2022** (Annex A),
**ISO/IEC 25010** (product quality), **NIST CSF 2.0**, **OWASP
ASVS 4.0** for the web surfaces.

## Scorecard

| Domain | Framework anchor | Score | Evidence / gap |
|---|---|---|---|
| Access control & auth | ISO 27001 A.8.2–A.8.5, ASVS V2/V4 | 9.0 | auth_gateway on every handler, step-up bound grants (op+resource+session, 120 s), MFA/WebAuthn, fail-closed portal, ephemeral fragment links, expired-preview enumeration closed. −1: no independent review (TD-17). |
| Cryptography & secrets | ISO 27001 A.8.24, ASVS V6 | 9.5 | Fernet backup encryption now default-on (BACKUP_PASSWORD enrolled), hashed session cookies, redaction in child env/logs, rotated signing secret, DES only where protocol-mandated (documented ADR). |
| Logging & monitoring | ISO 27001 A.8.15–A.8.16, CSF DE | 9.0 | hash-chained audit log (verify at startup), remote mirror sink, alert dispatch, /health + doctor (32 checks). −1: MTTR/incident data still thin (TD-16 drills only just started). |
| Vulnerability & supply chain | ISO 27001 A.8.8, CSF PR.PS | 9.0 | uv.lock hashed + `uv lock --check` gate, SBOM + cosign attestation at release, gitleaks/trivy/semgrep/CodeQL/bandit/scorecard in CI, pip-audit & npm audit clean. Signed-tag gate merged — key enrollment pending on maintainer. |
| Secure SDLC & testing | ISO 27001 A.8.25/A.8.29, ASVS V14 | 9.5 | ~1850 tests, pyramid + architecture-boundary contracts, mutation baseline, coverage ratchet **65% global** + per-risk floors 75–90% + diff-cover 95% on PRs, deterministic-order + random runs, cwd-litter guard. Pass-2 campaign found and fixed a real phantom-claim bug in `job_claim` (claim on missing/finished jobs returned True — double-run risk on destructive ops). |
| Continuity & recovery | ISO 27001 A.5.30, CSF RC | 9.0 | First real drill (D2) executed and logged — restore byte-identical in 0.28 s; backups encrypted; runbook battery defined. −1: D1/D10 need a scratch host. |
| Operations & hardening | ISO 27001 A.8.9/A.8.12, CIS | 9.0 | PID-tracked service manager, post-start port verification, loopback-only listeners (doctor-checked), bwrap+prlimit sandbox (nproc inside ns — fixed + tested), setpriv uid drop path, stale systemd unit removed. |
| Product quality (ISO 25010) | Reliability/Maintainability/Portability | 9.0 | Layered architecture enforced by import-linter, ruff/black/mypy/flake8/pydocstyle gates, Linux+Windows adapters, zero regression debt in registry. |

**Overall: 9.2 / 10** — up from ~8.2 pre-campaign. Domains held at
9.0 all have a single structural blocker that is not codeable:
independent eyes (access control, vuln mgmt), incident history
(logging — accrues with operation), scratch-host drills
(continuity). SDLC/testing now scores 9.5 on evidence.

## Positives (verified, not assumed)

- Fail-closed auth: unauthenticated → 401 everywhere; share links
  never transmit the token to the server (fragment URL).
- Audit chain verified on startup; mirror failure cannot break
  primary (test now deterministic cross-platform).
- Sandbox that was silently dead (RLIMIT_NPROC vs unshare) now works
  and is gated by tests.
- Import-time side effects eliminated + architecture gate.
- Test isolation is hermetic: shared_state pinned per test,
  run_dir/env scrubbed, cwd litter fails the session.

## Negatives fixed this pass

- `BACKUP_PASSWORD` was empty → every backup a plaintext
  session-forgery kit. Now generated (43 chars) + doctor check
  `secrets.backup_encryption` warns on plaintext posture.
- `ws_adapter.py` 0 % coverage → 82 % (contract tests).
- `terminal_spawn` sandbox logic untested → bwrap/prlimit/preexec
  contract pinned.
- VNC spawn stdio/session bug — covered by spawn-contract tests.
- No cwd-hygiene guard — session-level litter check added.

## Negatives fixed this pass (pass 2)

- **`job_claim` phantom claim (security/jobs.py)**: claiming an
  unknown `jid` returned True (claim row written, `_update` no-op)
  and a finished job could be re-claimed after claim-TTL expiry —
  double-run risk on destructive ops (restore/upgrade/lifecycle).
  Now requires the job record to exist in `state == "queued"`.
  20 contract tests pin enqueue/claim/finish/expiry semantics.
- `security/jobs.py` 51 % → 82 %, `security/secret_rotation.py`
  59 % → 83 % — both added to per-risk floors at 78 %.
- Global coverage ratchet raised 62 % → 65 %.
- Focused mini-review of `step_up_auth` consume path (TD-17
  scoped): atomic single-use via `set_if_absent`, sid binding,
  fail-closed delete — **clean, no findings**.

## Negatives fixed this pass (pass 3)

- **`preview_session` expired-token enumeration**
  (security/ephemeral_sessions.py): the consent preview returned
  grant details (role, permissions, max_uses, resource) for an
  *expired* share link, distinguishing "was once valid" from
  garbage and contradicting the documented uniform-None contract.
  Now `_session_expired` is part of the None condition; a
  regression test asserts expired ≡ invalid → 403.
- `core/paths.py` 45 % → 80 % — the conftest isolation fixture
  replaces `get_*_dir` module-wide so the real root/XDG/override
  branches NEVER executed in the suite; tests now capture and
  invoke the originals (squat-guard file case, ACL repair sweep,
  elevation probe, find_project_root fallback). Added to floors
  at 75 %.
- Focused mini-review of `ephemeral_sessions` (TD-17 scoped):
  session-token digest (not token) in logs, atomic tmp+rename
  persist, owner-only perms, cross-process revoke honoured via
  shared marker, `raise_on_error` on create so a dead link is
  never handed out — **clean except the preview finding above**.

## Negatives fixed this pass (pass 4)

- **`_operator_store_auth` credential widening** (security/http_auth):
  a user FOUND in the operator store whose `verify()` threw (corrupt
  hash, rehash I/O, exotic argon2 error) was caught by a blanket
  `except` → returned None → evaluated against the env bootstrap
  credential — the exact widening the docstring forbids. Fallback is
  now scoped to (store unreadable | username absent); a record-level
  failure denies and burns lockout budget. Regression tests pin both
  the deny path and the designed env fallback for unreadable stores.
- `security/file_permissions.py` 62 % → 92 % — the Windows icacls
  ACE parser is pure logic and is now exercised via mocked `run_cmd`
  (Everyone/Todos → critical, BUILTIN\Users → warning, path-header
  false-positive guard), plus glob enumeration, backup-archive
  inclusion, fix/deny error paths and the Windows fix delegation.
  Added to floors at 85 %.
- Focused mini-review of `http_auth` (TD-17 scoped): constant-time
  compares, TE/CL desync rejection, last-hop XFF with CIDR-aware
  trusted proxies, shared `ip:` lockout namespace, exactly-one-
  outcome rate limiting — **clean except the widening above**.

## Negatives fixed this pass (pass 5)

- `security/certificates.py` 63 % → 95 % — the openssl CLI fallback
  is exercised via mocked `run_cmd` (CN subject-syntax stripping
  verified against `/O=evil` injection, empty-CN raise, rc!=0
  RuntimeError), the Windows icacls ACL branch via a fake `os`
  namespace (R vs M grants), certbot plugin fallback + symlink
  enrolment, `tls_validation` ImportError fallback context, and the
  `_tls_enabled_env` ImportError path. Added to floors at 85 %.
- Three further TD-17-scoped reviews returned **clean**:
  - `rate_limit`: insert-only attempt records (atomic cross-process),
    progressive lockout escalation with strike decay, atomic
    fixed-window general limiter, corrupt-counter deny.
  - `mfa`: TOTP single-use via atomic per-step claim + per-secret
    high-water mark, fail-closed on backend down, ASCII-digit
    validation; recovery codes claim atomically and prune from env.
  - `audit`: cross-process file lock around read-hash→compute→append,
    monotonic seq gap detection, HMAC-signed tip witness catches
    tail truncation, chain advance only after fsync-level write,
    AUDIT_STRICT fail-closed option.

## Negatives fixed this pass (pass 6)

- **`authenticate()` second widening site** (security/authentication):
  same bug class as pass 4 — `load_store()` and `verify()` shared one
  `except`, so a stored operator whose verify threw (corrupt record)
  fell through to env credentials. Fixed with the identical scoping:
  unreadable store → loud env fallback (designed); record failure →
  deny. Four regression tests pin deny/fallback/absent-user paths.
- `monitoring/otel.py` 24 % → 67 % — opt-in gate contract pinned
  (settings failure disables, enabled-without-SDK never raises,
  idempotent provider, app passthrough).
- TD-17-scoped reviews of `websocket_registry` (TOCTOU double-check,
  marker TTL ≥ max session lifetime, sid/group granularity,
  lock-ordering on close callbacks), `attempt_login` (dual-key
  lockout, MFA before session, maintenance after credential verify)
  and `authenticate` — **clean except the widening above**.
- Accepted residual documented: per-`user:` lockout lets an
  unauthenticated attacker sustain a victim's login DoS — standard
  account-lockout trade-off on a single-admin appliance.

## Remaining debt (honest)

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; 85 % global needs ongoing test
  writing (file_permissions 62 %, certificates 63 %, audio.py).
- **D1/D10 drills** — need a disposable host.

## Pass 7 — token/session trust root + share-link URL derivation

### Reviews (TD-17-scoped, clean)

- `security/token_signing.py` — type-tag bound into the HMAC payload,
  `compare_digest` on bytes, rotation window via
  `previous_signing_secrets`, secret never logged. **Clean.**
- `security/sessions.py` — v3 payload binds
  user/created/last_seen/expiry/sid; epoch revocation checked on every
  verify; SameSite whitelist. **Clean.**
- `core/shared_state.py` — already at 81 % with floor; CAS primitives
  underpin every atomic claim reviewed so far.

### Negatives fixed this pass (pass 7)

- `core/share_url.py` 67 % → 93 % — the TLS-resolution contract is
  now pinned end to end: `create_ssl_context() → None` yields an
  honest `http://` link (a share URL must never claim TLS that does
  not exist); env-flag fallback only applies when the builder raises;
  `DISABLE_SSL` kill-switch overrides `TLS_ENABLED` even in the
  fallback path; `SSL_CERT` alone counts as TLS intent. Four tests
  pin each branch; floor added at 0.85.
- No new defect found in the token/session signing root — the
  widening class from passes 4/6 does not extend there.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; next weakest modules:
  `service_manager.py` 47 %, `services/terminal.py` 51 %,
  `core/doctor.py` 57 %, `core/processes.py` 55 %, `core/logging.py`
  11 %, backend handlers ~13 % (transport code — costlier tests).
- **D1/D10 drills** — need a disposable host.
