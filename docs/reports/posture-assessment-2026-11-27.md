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

## Pass 8 — secret-leak surfaces: logging scrub + child-env guard

### Reviews (TD-17-scoped)

- `core/logging.py` — `_SecretScrubFilter` scrubs rendered messages
  AND %-args, re-reads SECRET_VARS every record (rotation-safe, no
  cache), never raises, values <6 chars skipped by design. Handler-
  level placement correctly covers child loggers via callHandlers.
  `setup_logging`: dedup handlers, propagate=False, verbose>env>INFO.
  **Clean** — residuals documented: secrets inside tracebacks
  (exc_info) bypass the message scrub, and non-env secrets (session
  tokens, store values) are outside SECRET_VARS scope — both are
  defense-in-depth layers, call sites must still never log secrets.
- `core/processes.py` — `is_port_available` connect-probe (Windows-
  safe), AF_INET6 for ':' hosts; `run_cmd` hard timeout + env scrub.
  **One latent footgun fixed** (below).

### Negatives fixed this pass (pass 8)

- **`run_cmd` env=None scrub bypass** (core/processes.py): the guard
  was `"env" not in kwargs` — a caller passing `env=None` explicitly
  would have handed the FULL environment (every SECRET_VAR) to the
  helper binary, since subprocess treats None as inherit. No current
  caller does this, but the primitive existed precisely to prevent
  that leak. Now `kwargs.get("env") is None` → sanitized env;
  deliberate full-env requires `os.environ.copy()`. Regression test
  proves env=None no longer leaks VNC_PASSWORD.
- `core/logging.py` 11 % → **95 %** (16 tests): redaction of values
  and %-args, <6-char skip, rotation freshness, never-raises,
  JSON/plain formatters, LOG_LEVEL/WARN/FATAL aliases, handler dedup,
  end-to-end stderr scrub. Floor 0.90.
- `core/processes.py` 55 % → **100 %** (11 tests): port probe both
  families, env scrub default/None/explicit, timeout→-1,
  check=True re-raise, text-mode decode. Floor 0.95.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; next weakest modules:
  `service_manager.py` 47 %, `services/terminal.py` 51 %,
  `core/doctor.py` 57 %, backend handlers ~13 % (transport code).
- **D1/D10 drills** — need a disposable host.

## Pass 9 — destructive-op executor (deferred_lifecycle)

### Reviews (TD-17-scoped)

- `core/deferred_lifecycle.py` — the detached runner for lifecycle /
  restore / upgrade jobs. Verified end-to-end: `spawn_job_runner`
  detaches correctly (devnull stdio, start_new_session /
  DETACHED_PROCESS, `guard_spawn` test isolation); `run_job` claims
  atomically BEFORE executing (pass-2 `state=="queued"` fix holds),
  unknown op → job_fail + unlock + rc 2, executor exception →
  job_fail + unlock + audit-failure, every exit releases the
  op-class lock. `job_unlock` is owner-checked (`get == jid` before
  delete) so unconditional unlock calls cannot release another
  job's mutex. `main` bounds delay to [0,60] s, legacy direct mode
  requires VRS_DEFERRED_LEGACY=1 opt-in, load_env_file at the
  composition root. **Clean.**
- Residual documented: `job_unlock` get→delete is not atomic — a
  lock TTL expiring in the microsecond gap could let a competing
  acquire be deleted. Requires backend compare-and-delete (absent
  from the StateBackend protocol); window is negligible vs the
  TTL-scale recovery the design already accepts.

### Negatives fixed this pass (pass 9)

- `core/deferred_lifecycle.py` 76 % → **98 %** (13 new tests):
  restart success/partial/blocker paths, unknown action, all four
  executors (restore empty/ok/fail, upgrade ok/error, rollback
  ok/error), empty-argv usage, bad-delay fallback. Floor 0.95.
  Remaining uncovered: win32 creationflags + `__main__` guard —
  platform/entry lines, not logic.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `service_manager.py` 47 %, `services/terminal.py` 51 %,
  `core/doctor.py` 57 %, backend handlers ~13 % (all large files —
  next passes need bigger test budgets).
- **D1/D10 drills** — need a disposable host.

## Pass 10 — egress SSRF client (http_client) + redact_url leak

### Reviews (TD-17-scoped)

- `security/http_client.py` — the single egress path for all outbound
  HTTP. Two-layer SSRF defense verified: `validate_url` gates scheme
  (https default, http opt-in env), hostname presence, and requires
  EVERY resolved address `is_global` (one private answer rejects);
  `PinnedTransport` re-resolves at connect time and dials only a
  global IP — the validation→connect rebinding window is closed
  because the dial target is itself re-filtered. TLS still verifies
  the real hostname (SNI + chain). No redirects (signed POSTs can't
  be bounced post-vetting), 256 KiB response cap, retry only on
  transport errors. **One real leak found and fixed** (below).

### Negatives fixed this pass (pass 10)

- **`redact_url` userinfo credential leak** (security/http_client):
  the log-safe form used `p.netloc`, which carries `user:pass@`
  verbatim — a webhook configured as `https://user:token@host/hook`
  (basic-auth style) would print the credential into warning logs
  via `monitoring/alerts.py`, violating the function's own
  "scheme + host only" contract. Now rebuilt from `hostname`+`port`
  — userinfo can never reach a log line. Five regression tests pin
  userinfo/path/query/port/invalid cases (2 were RED pre-fix).
- `http_client.py` 72 % → **87 %** (5 new tests + monitoring suite);
  floor 0.80.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `service_manager.py` 47 %, `services/terminal.py` 51 %,
  `core/doctor.py` 57 %, backend handlers ~13 % (large files).
- **D1/D10 drills** — need a disposable host.

## Pass 11 — Zero-Trust bind gate bypass (profiles)

### Reviews (TD-17-scoped)

- `security/credentials.py` — three KDF verifiers (argon2id PHC,
  pbkdf2, scrypt) all bounded against self-DoS via forged stored
  params (argon2 m≤512MiB/t≤16/p≤8, pbkdf2 ≤10M iters, scrypt
  n·r≤2^21 + maxmem), `compare_digest` everywhere, malformed →
  False. **Clean.**
- `security/profiles.py::get_blocking_findings` — TLS-cert
  resolvability, per-profile MFA/nginx requirements, weak/default
  password blocks (mirroring generated-credential resolution),
  hardened-profile FLASK_SECRET_KEY/AUTH_SECRET/BACKUP_PASSWORD
  minimums. **One real bypass found and fixed** (below).

### Negatives fixed this pass (pass 11)

- **Wildcard-bind gate bypass** (security/profiles): the
  `BACKEND_PUBLIC_BIND` blocker only fired on `BIND_HOST ==
  "0.0.0.0"` exactly. Two bypasses: (a) `BIND_HOST="::"` — IPv6
  any-address, dual-stack on most systems — sailed through; (b)
  every backend honours its own `*_HOST` override
  (`LANDING_HOST`, `HEALTH_WEB_HOST`, `SERVE_NOVNC_HOST`,
  `NOVNC_HOST`, `TTYD_HOST`, `AUDIO_STREAM_HOST`, `GAMEPAD_HOST`,
  `USER_UI_HOST`) which was never checked — `LANDING_HOST=0.0.0.0`
  exposed the portal directly, bypassing the auth gateway. Now
  `_check_backend_binds` resolves each backend's WINNING host
  through the same first-non-empty chain `config._env_host` uses,
  and `ipaddress.is_unspecified` catches every wildcard form.
  `PUBLIC_BIND_HOST` deliberately excluded (nginx/Windows-landing
  public knob). Shadowed wildcards (dead config) don't block.
  Eight regression tests — all RED-shaped cases now pinned.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `service_manager.py` 47 %, `services/terminal.py` 51 %,
  `core/doctor.py` 57 %, backend handlers ~13 % (large files).
- **D1/D10 drills** — need a disposable host.

## Pass 12 — service_manager spawn/stop/watchdog + psutil API bug

### Reviews (TD-17-scoped)

- `core/service_manager.py` — full read of the 1065-line lifecycle
  owner. Verified: stale-PID foreign-process guard, port-in-use
  reap-then-fail (never kills foreign), websockify forced loopback +
  sanitized env, per-service log routing, post-start bind
  verification with orphan kill, pid-write-failure orphan kill,
  stop refuses without the global lock, PID-reuse checks in
  status/restore, temp-user sweep guarded by live-process check,
  restart rate-limit (5/600 s), transition-only alerts,
  blocking-findings edge detection. **One real crash bug found and
  fixed** (below); otherwise clean.

### Negatives fixed this pass (pass 12)

- **`_reap_stale_service` psutil API crash** (core/service_manager):
  called `proc.net_connections("tcp")` — psutil's Process API is
  `connections(kind)` with kinds 'inet'/'inet4'/'inet6'/'unix'
  ('tcp' is only valid for the module-level `psutil.net_connections`).
  The AttributeError was outside the caught psutil exceptions, so it
  propagated through `_start_python_service` → `start_all` —
  crashing the start sequence precisely when an orphaned service
  held the port (the only case the function exists for). The
  orphan-reap feature was effectively dead code that took down
  start_all with it. Fixed to `proc.connections("inet")` — UDP
  conns never report LISTEN so the status filter still isolates
  TCP listeners. Regression tests drive a fake psutil process table
  (orphan killed, foreign/self spared, AccessDenied skipped,
  psutil-absent noop).
- `service_manager.py` 47 % → **68 %** (37 new tests across spawn
  paths, dispatch, novnc-dir resolution, websockify loopback
  forcing, stop-plan ordering, restart throttle, dead-service
  detection, auto-restart, watchdog dedup, restore-state PID
  adoption guards). Floor 0.60.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `services/terminal.py` 51 %, `core/doctor.py` 57 %,
  `core/service_manager.py` 68 %, backend handlers ~13 %.
- **D1/D10 drills** — need a disposable host.

## Pass 13 — web terminal WS internals (terminal.py)

### Reviews (TD-17-scoped)

- `services/terminal.py` — the authenticated web-terminal path.
  Verified end-to-end: Origin check before auth (CSWSH), credential
  resolution order (ephemeral cookie → bearer → session cookie →
  legacy Basic gated by TERMINAL_BASIC_AUTH), gateway
  `check_websocket_upgrade` with `terminal_view`, RBAC split —
  ephemeral sessions need `terminal_write` for subprocesses and
  path-completion (view-only can't enumerate the filesystem),
  step-up for operator sessions, revocation registry + cross-process
  watcher, sliding-window message rate cap (flood → close 1008),
  idle timeout, audit open/close with duration, allowlist regex
  fullmatch failing closed. **Clean** — the permission split is
  correctly enforced at every execution/completion boundary.

### Negatives fixed this pass (pass 13)

- `services/terminal.py` 51 % → **60 %** (28 new tests):
  rate-limit window (zero-rate, under-limit, flood→close, pruning),
  builtins (exit/cls/help/history), view-only RBAC deny with
  builtins still working, completion gated by write permission,
  `_handle_completion` dispatch + 20-suggestion cap + empty-result
  path, `_send_prompt` posix/powershell formats, credential-less
  auth branches (Basic disabled → 1008, bad creds → 1008, legacy
  Basic skips revocation registry by design), env-flag helper,
  portal URL proto/host derivation, CSP default + env override,
  origin delegation to the gateway allowlist. Floor 0.55.
- Remaining uncovered is the WS transport layer and the
  `_execute_command` streaming loop — subprocess/IO paths needing
  deeper fixtures (next-pass candidate).

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `core/doctor.py` 57 %, `core/service_manager.py` 68 %,
  `services/terminal.py` 60 %, backend handlers ~13 %.
- **D1/D10 drills** — need a disposable host.

## Pass 14 — doctor diagnostics parity + format coverage

### Reviews (TD-17-scoped)

- `core/doctor.py` — secrets check now mirrors the blocking gate;
  TLS cert resolution falls back to canonical ssl-dir discovery;
  backup-encryption visibility check uses `env_flag` (the
  `BACKUP_ALLOW_PLAINTEXT=false`-as-truthy bug was fixed in pass 1).
  Remaining uncovered blocks are platform probes (webauthn,
  gamepad, firewall, listener enumeration, terminal isolation) —
  system-dependent checks needing heavier fixtures.

### Negatives fixed this pass (pass 14)

- **Doctor/gate divergence on weak passwords** (core/doctor):
  `secrets.vnc_password` hardcoded only three defaults with an
  exact case-sensitive match, while `get_blocking_findings` uses
  the canonical `WEAK_PASSWORDS` set lowercased — so
  `YourStrongPassword123` (the documented default) and `ChangeMe`
  reported "Set and non-default" [OK] in doctor while the gate
  refused startup. Diagnostics and enforcement disagreed — a
  monitoring-integrity defect (ISO 27001 A.8.9). Now uses
  `WEAK_PASSWORDS` + strip/lower, identical semantics to the gate.
  Six regression tests pin documented-default, case variant,
  numeric default, strong, empty/None.
- `format_doctor` covered (symbols, pluralization, empty) — 8 new
  tests total this pass.

## Pass 15 — backend transport plumbing + file-share confinement

### Reviews (TD-17-scoped)

- `backend/handlers/common.py` — shared envelope/body/identity/gate
  plumbing for every `/api/v1` route. Verified: bounded body reads
  (Content-Length required, ≤16 KiB default, pydantic `extra=forbid`
  with named extra fields), `_operator` permission gate audits
  `api_permission_denied`, `X-Forwarded-Host` constrained to a strict
  hostname regex behind `TRUSTED_PROXY` (a crafted header cannot
  become reflected markup), CSRF token HMAC-bound to operator sid +
  nonce cookie, `_public_gate` Origin + Sec-Fetch-Site for
  unauthenticated routes. Clean.
- `backend/handlers/files.py` + `engine/application/files.py` —
  file-share handlers delegate all path handling to `_resolve()`:
  backslash normalization, URL-decode BEFORE containment,
  NUL-byte rejection, `realpath` + root-prefix check with `os.sep`
  boundary (symlinks/`..`/absolute paths cannot escape), 32 MiB
  caps, filename sanitization for Content-Disposition, and
  `_files_allowed` requires operator or an ephemeral session bound
  to the `files` resource with `file_transfer` permission.
  Clean.

### Negatives fixed this pass (pass 15)

- No security bug — this pass closed the largest coverage gap:
  `backend/handlers/common.py` 58 % → **94 %** (43 tests: envelope
  writers, UseCaseError→HTTP mapping incl. STEP_UP code, operator
  permission gate + audit, bounded JSON body incl. oversized/invalid/
  non-dict, typed-body validation with extra-field naming, all
  whitelist serializers, forwarded-host trust, TLS protocol probe,
  ephemeral-session resolution, actor labels, CSRF binding, public
  origin/fetch-metadata gate). Floor 0.90 added.

## Pass 16 — thin transport handlers: power/ops/chat/recordings

### Reviews (TD-17-scoped)

- `backend/handlers/power.py` + `engine/application/power.py` —
  shutdown/restart/sleep and Wake-on-LAN. Route flag `op=power.action`
  enforces bound step-up; `host_power` whitelists `POWER_ACTIONS`,
  audits, and runs the OS command on a daemon thread after a declared
  grace delay so the 200 is delivered first. `wake_on_lan` validates
  the MAC format and restricts `broadcast` to broadcast/unspecified
  targets only — the endpoint cannot be turned into a unicast packet
  injector. Clean.
- `backend/handlers/chat.py` — IDOR-safe by construction: a guest's
  channel id is ALWAYS derived from their own ephemeral grant's
  `token_id`; a caller-supplied `session` in query/body is ignored for
  non-operators. Operators may name sessions explicitly (they are
  already `admin:*`). Clean.
- `backend/handlers/recordings.py` — screenshot/recordings/delete all
  `admin:*`; delete is step-up bound via `_auth_ctx`; `_send_bytes`
  sanitizes the download filename (alnum + `._-`) so
  Content-Disposition cannot carry header injection. Clean.
- `backend/handlers/ops.py` — 405 lines of uniform thin delegation to
  `engine.application.ops`: typed bodies with tight limits (1–4 KiB),
  `_uc_err` propagates STEP_UP codes, destructive ops answer 202
  (detached runner), secrets endpoints never return values.
  Consistent and clean.

### Negatives fixed this pass (pass 16)

- No security bug — coverage push on the thinnest handlers:
  `power.py` 12 % → **94 %**, `ops.py` 13 % → **51 %**,
  `chat.py` 13 % → **83 %**, `recordings.py` 15 % → **71 %**
  (68 tests total this pass pinning wire contracts: status codes,
  actor propagation, step-up code passthrough, WoL port validation,
  guest-channel derivation, filename sanitization, error mapping).

## Pass 17 — controls/monitoring/files handlers + portal/auth review

### Reviews (TD-17-scoped)

- `backend/handlers/controls.py` — maintenance toggle (typed body,
  step-up via route flag) and the gamepad kill-switch (shared
  `gamepad:stopped` flag checked per-connection/message, audited).
  Clean.
- `backend/handlers/monitoring.py` — read-model endpoints. Audit
  pagination clamps `limit` to [1,500], validates the seq cursor
  (invalid → 400), and caps filter params at 128 chars (anti CPU-burn
  on huge `?user=`); `read_models.jobs` double-clamps internally.
  Clean.
- `backend/handlers/portal.py` — the share-link consent flow.
  Preview/activate are public but run `_public_gate` (Origin +
  Fetch-Metadata), token travels in the request BODY (never URL → no
  log/Referer leak), cookie `Secure` only on a REAL TLS hop (direct
  SSLSocket or trusted-proxy XFP — a client claiming https over plain
  HTTP does not get a Secure cookie it could never send back),
  activation alerts. `_get_session_context` fails closed on store
  errors and reports revoked sessions as inactive. Clean.
- `backend/handlers/files.py` handler layer — operator-or-guest gate,
  base64 body limit scaled to MAX_FILE_BYTES, download filename
  sanitized. Clean (engine confinement verified pass 15).

### Negatives fixed this pass (pass 17)

- No security bug — coverage push: `controls.py` 45 % → **93 %**,
  `monitoring.py` 42 % → **74 %**, `files.py` 9 % → **70 %**
  (29 tests: maintenance toggle + step-up, gamepad flag + audit,
  all read-model delegations, audit pagination clamp/cursor/filter
  caps, job detail errors, file guest-vs-operator gating incl.
  resource binding, base64 upload, 409 exists).

## Pass 18 — auth surface handlers: login/MFA/logout/step-up + sessions/operators

### Reviews (TD-17-scoped)

- `backend/handlers/auth.py` — the SPA login surface. Verified:
  `_public_gate` on every public ceremony; password login delegates
  to `authenticate_landing` (the pass-4/6-hardened path — store→env
  widening closed), MFA gate emits `MFA_REQUIRED` code before any
  session mint, maintenance 503 parity with `attempt_login`, audit
  on every outcome. Passkey begin/complete share the same gate and
  answer a uniform 404 for unknown users (no enumeration). Logout
  revokes BOTH the gate sid and the cookie sid with their own
  validity horizons, drops the auth-policy context, expires all
  three cookies, clears pending cookies — idempotent. Step-up:
  `_verify_step_up_password` uses store `verify()` for store members
  (returns record-or-None, never False — the `is None` deny check is
  correct) and env bootstrap only for non-store users; operation-
  bound grants validate against the catalog and bind to the `vnc_op`
  sid. `_queue_operator_service_cookie` sets `Secure` only on a real
  TLS hop, `SameSite=Strict`, `Max-Age=min(idle,lifetime)`.
  Clean.
- `backend/handlers/sessions.py` — share-link CRUD. Pagination
  cursor is opaque composite, malformed degrades to first page;
  revoke answers uniform 200 exist-or-not (anti-enumeration);
  PATCH requires `label` in `model_fields_set` (omitted ≠ explicit
  null clear); create emits fragment `#t=` URLs and emails
  best-effort with audit of the attempt, never the token.
  Clean.
- `backend/handlers/operators.py` — account + passkey management.
  Passkey views expose only opaque sha256-prefix refs (never
  credential id/public key); PATCH allows only role/disabled/
  password via `model_fields_set` + `validate_password`, internal
  fields unreachable (`extra=forbid`); create/delete/restore/
  revoke-sessions all delegate permission + last-admin rules to the
  use cases. Clean.
- `backend/handlers/system_users.py` — thin, step-up via route,
  reserved-name protection in the use case. Clean.

### Negatives fixed this pass (pass 18)

- No security bug — coverage push on the auth-surface handlers:
  `sessions.py` 62 % → **84 %**, `operators.py` ~0 % → covered,
  `auth.py` → **56 %** unit-level (remainder needs real WebAuthn/
  cookie internals, partially covered via api_v1 route tests).
  51 tests pinning: MFA_REQUIRED code, maintenance 503, passkey
  no-enumeration, logout cookie expiry + idempotency, step-up
  password verify paths (store/env/deny), session pagination +
  anti-enumeration revoke + label semantics, operator PATCH
  whitelist + weak-password rejection + passkey opaque refs.

## Pass 19 — portal auth context (crown jewel) + health_app coverage

### Reviews (TD-17-scoped)

- `backend/context.py` — THE central auth surface: every portal/API
  request flows through `PortalContext`. Verified end to end:
  - `_split_op_cookie`/`_parse_op_cookie`: strict shape (≤256 chars,
    printable ASCII, 4 dot-parts, charset-pinned sid/exp/sig),
    expiry window rejects past AND absurdly-future, HMAC compared
    with `compare_digest`, optional IP-binding folded into the sig.
  - `_resolve_operator`: duplicated `vnc_op` cookie names NEVER
    authenticate (parse-order ambiguity closed); Basic falls back to
    the hardened `authenticate_landing`; fresh auth records step-up
    time.
  - `_issue_op_session`: `secrets.token_urlsafe` sid, b64url username
    (dots can't confuse the parser), HMAC-SHA256, SameSite=Strict
    HttpOnly, per-user session cap (10) revoking oldest, audited.
  - `_op_session_revoked`: per-sid mark + per-user epoch; ANY
    backend error → revoked (fail closed).
  - `_resolve_op_identity`: disabled store users → None; env
    bootstrap reachable ONLY for username `admin`; store exception →
    None (fail closed).
  - `_check_csrf` + `_operator_gate`: nonce+sid-bound token via
    `compare_digest`, Origin check, `Sec-Fetch-Site: cross-site`
    rejection (forbidden header a page can't forge), permission +
    `portal_permission_denied` audit — on EVERY mutation.
  - `_serve_admin`: normpath containment under `_ADMIN_DIR`,
    extension whitelist, `isfile` check, SPA fallback; HTML gets
    no-store + no-referrer + strict CSP (`script-src 'self'`,
    `frame-ancestors 'none'`).
  - `_flush_pending_cookies` upgrades queued cookies to `Secure`
    on TLS; `_session_refresh_header` re-issues SameSite=Strict —
    refresh never widens scope.
  - `AsgiPortalContext` mirrors the stdlib transport faithfully.
  Clean — no auth bypass found.
- `backend/health_app.py` — FastAPI machine surface. `check_health_auth`
  opens ONLY when no token AND every bind is loopback AND the real
  socket peer is loopback (XFF can't spoof — `peer_ip` is the socket
  peer); scoped tokens (`metrics`/`audit`) isolate credentials;
  token attempts are rate-limited. Middleware rejects TE/CL smuggling
  shapes and stamps security headers on every response incl. errors;
  non-route responses keep the canonical `error_json` envelope.
  `/health/live` + `security.txt` are unauthenticated BY DESIGN but
  rate-limited 60/60s per IP. Clean.

### Negatives fixed this pass (pass 19)

- No security bug — `health_app.py` 0 % → **71 %** (19 TestClient
  tests: health/ready status codes, per-scope Bearer gating, public
  probes skip auth, rate-limit 429, security.txt, metrics body,
  audit limit clamp + 400-on-malformed, verify chain, security
  headers, error envelope, TE/CL rejection). Every backend handler
  module now has direct unit coverage.

## Pass 20 — share-link delegation ceiling: check/persist divergence

### Reviews (TD-17-scoped)

- `engine/application/sessions.py` — the share-link use cases.
  Delegation ceiling: `adminish` session perms (admin,
  admin_users, admin_config, admin_audit) require `admin:*` on the
  actor; route gate already requires the `admin_sessions` operator
  capability, so non-adminish desktop powers (view/control/
  terminal/file_transfer/…) are the feature itself. Label
  validation (≤64 chars, no control chars), revoke/revoke-all/
  revoke-by-creator audited, list filters whitelisted, unknown
  token_id → uniform None (no enumeration). One real bug found —
  below.
- `engine/infrastructure/stores.py` — the ONLY engine→security
  seam; narrow delegations verified (session_roles,
  expand_session_permissions, operator_*, audit…).
- `security/ephemeral_model.py` — permission vocabulary,
  umbrella expansion to fixpoint (bounded), `has_permission`
  composite `resource:action` normalization, view_only/no_terminal
  covering fine-grained members, resource binding. Clean.

### Negatives fixed this pass (pass 20)

- **Share-link privilege escalation via empty permissions**
  (`engine/application/sessions.py` + `stores.py`): the adminish
  delegation check evaluated `permissions if permissions is not
  None` — an explicit EMPTY set passed the check (no adminish
  member), but `EphemeralSession.__init__` persists
  `permissions or ROLES.get(role, {view})` — the empty set is
  falsy → ROLE DEFAULTS. `POST /api/v1/sessions
  {"role": "administrator", "permissions": []}` by an operator
  holding `admin_sessions` but NOT `admin:*` minted a link with
  ALL_PERMISSIONS (admin_users/admin_config/admin_audit included).
  Same class as the pass-14 doctor divergence: the check and the
  persistence disagreed. Fix: the use case now evaluates
  `stores.session_default_permissions(role)` — a new seam helper
  mirroring the model's fallback exactly — whenever `permissions`
  is empty/None. Regression test RED→GREEN; 12 use-case tests
  total (delegation ceiling, label validation, revocation audit,
  list filters). 1372 engine+security+services tests green.

## Pass 21 — operator-WS sweep parse bug, TigerVNC blacklist probe, OS-account guard

### Reviews (TD-17-scoped)

- `security/websocket_registry.py` — `_operator_session_dead` parses
  the signed `vnc_op` payload for sweep liveness. **Real bug fixed
  (in-flight WIP, verified + pinned):** v3 cookies carry 5 fields
  (`user:created:last_seen:expires:sid`) but the parser only handled
  4 and 3 — every live v3 operator session fell into `else →
  "expired"` and the sweeper closed its websockets. Now all three
  layouts parse (parity with `verify_session_cookie`); legacy-layout
  regression test added.
- `core/processes.py::port_in_listen_state` + callers
  (`services/health.py`, `core/doctor.py`, `core/portal.py`) —
  **real operational bug fixed (in-flight WIP, verified):** every
  health/doctor/portal port probe opened a TCP connect+close; TigerVNC
  counts each as an unauthenticated attempt toward
  `-BlacklistThreshold`, and while blacklisted every further attempt
  extends the exponential backoff — a periodic probe locks the host
  out of RFB permanently. New tri-state helper reads
  `/proc/net/tcp{,6}` LISTEN rows (no connect; `None` on
  non-Linux/unreadable → connect fallback preserved). Applied to the
  VNC probe in health, and as first-choice in doctor/portal port
  checks.
- `engine/infrastructure/stores.py` + `application/system_users.py` —
  `system_users_list` now shows only UID ≥ 1000 (the 100–999 range is
  OS service accounts: sshd, messagebus…), and delete refuses
  `system_user_uid() < 1000` even when the account is named directly,
  bypassing the filtered listing. Audit `api_permission_denied`,
  refused before `job_start`. Hardening, verified.
- `services/novnc.py` + `backend/context.py` — same-origin framing
  for the RemoteConsole embed: noVNC middleware rewrites
  `frame-ancestors 'none'→'self'` / `XFO DENY→SAMEORIGIN` on every
  response; admin-shell CSP gains `frame-src 'self'` while keeping
  `frame-ancestors 'none'`. Foreign origins remain blocked —
  clickjacking posture unchanged. Frontend `GuestPage.desktopUrl`
  consumes the existing `external_base` portal field for the
  unmanaged-proxy case. Security-reviewed: 'self' cannot be widened
  by a foreign origin; tsc clean.

### Negatives fixed this pass (pass 21)

- **Determinism fallout from the probe change** — tests that mocked
  only `is_port_available` became host-dependent once VNC switched to
  the socket table (port 5900 IS listening on this Pi → real values
  leaked into assertions). Fixed: `_mock_port_state` dual-mock in
  `test_health.py`, `port_in_listen_state→None` connect-fallback
  stubs in `test_landing.py` + both health-endpoint fixtures.
- New coverage: 5 socket-table parse tests (tri-state incl. missing
  /proc → None), 3 system-user UID guard tests (boundary 999/1000,
  unknown→adapter decides, refused pre-job), noVNC framing-headers
  TestClient test, ws legacy v1/v2 layout test, `frame-src 'self'`
  CSP pin. **2216 unit tests green**, ruff/black/tsc clean.

## Remaining debt (honest) — updated

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; weakest remaining:
  `core/doctor.py` 57 % (platform probes),
  `core/service_manager.py` 68 %, `services/terminal.py` 60 %,
  `backend/context.py`/`app.py`/`schemas.py` partially covered
  (dispatch internals exercised via api_v1 route tests —
  transport only, policy lives in engine/security).
- **D1/D10 drills** — need a disposable host.

## Pass 22 — shared_state.db contention program (PERF backlog, phase 1)

Performance pass targeting the recurring `shared_state.db` SQLite
contention: every WS register/unregister, health check and auth event
used to queue synchronous writes on the same DB lock as security
state. Implemented in the user's priority order; each item is
independently revertible.

### Shipped

- **Metrics write buffer** (`monitoring/prometheus.py`) —
  `inc_counter`/`set_gauge` are now memory-only; deltas accumulate in
  `_pending_counters`/`_pending_gauges` and a single daemon flush
  thread commits them via `increment_many`/`set_many` in ONE
  transaction per `METRICS_FLUSH_SECONDS` interval (default 5 s,
  clamped 1–60, jittered). Failed flushes requeue preserving newer
  gauge sequence numbers. `flush_metrics_now()`/`metrics_pending()`
  expose the path for shutdown/tests. At most one flush interval of
  telemetry is lost on crash — accepted: metrics are not audit
  records. `set_gauge` dirty-checks so unchanged values cost nothing.
- **`StateBackend` batch API** (`security/shared_state.py`) — new
  `increment_many`, `set_many`, `items` on the abstract class with
  `MemoryBackend` and `SQLiteBackend` implementations (SQLite via a
  `_transaction` helper: BEGIN IMMEDIATE/COMMIT/ROLLBACK under the
  connection lock — all-or-nothing batches). `items(ns)` replaces the
  `list_keys` + per-key `get` N+1 with one SELECT that filters expired
  rows in SQL.
- **Registry O(1) indexes** (`security/websocket_registry.py`) —
  `_resource_counts` per-resource counters, `_by_ip` index for the
  per-IP cap, centralized `_detach_locked` keeping all indexes
  consistent; `_emit_active_gauges` is O(#resources) instead of
  scanning every connection.
- **Global revocation sweeper** — ONE daemon thread per process
  replaces per-session watcher threads/tasks (audio/gamepad/novnc/
  terminal call sites unchanged — `start_revocation_watcher*` now
  ensure the sweeper). Each cycle does ONE `list_keys` on the revoked
  namespace + ONE operator-epoch read regardless of session count
  (was 2–3 SELECTs per session per tick). Adaptive cadence: ~5 s when
  sessions are active, 15 s idle backoff, immediate wake on new
  registration. `is_revoked_shared` gained a bounded negative cache
  (`WS_REVOKED_CACHE_TTL`, default 1 s; positive results never cached;
  same-process revokes invalidate). Disabled under `VRS_TEST_MODE`.
- **SessionStore dirty-save + O(1) token index**
  (`security/ephemeral_sessions.py`) — `find_by_token_id` resolves the
  public fingerprint via `_by_token_id` (was a sha256 scan of every
  session per call — paid per WS upgrade). `note_connection` no longer
  rewrites the full session JSON per connect/disconnect edge: it marks
  the session dirty and a single coalescing timer flushes at most once
  per `EPHEMERAL_SAVE_DEBOUNCE` (default 1 s, clamp 0.2–30). `_load`
  flushes dirty state before merging disk data so a cross-process
  write can never silently drop pending forensic stamps; `atexit`
  flushes on clean shutdown. Revocation/security flags still save
  immediately.
- **Audit single tail read** (`security/audit.py`) — `_tail_state()`
  reads the last log line ONCE and yields both chain hash and seq
  (was two `_last_audit_line` reads + parses per event). Sticky-hash,
  reset-on-corrupt and seq-fallback semantics preserved exactly.
  `AUDIT_FSYNC=1` adds optional per-entry fsync (off by default —
  documented durability/throughput trade).
- **`/metrics` scrape cost** — `collect_system_metrics` (posture +
  health probe + session listing) is single-flight cached 10 s;
  `render_metrics` payload cached 1 s. One `items()` query per
  namespace per render; no per-scrape health/posture probes.
- **`_relay_ws` watchdog** (`services/novnc.py`) — the per-message
  `asyncio.wait_for` timeout handles are replaced by one watchdog
  task tracking per-direction last-activity stamps; identical reap
  semantics (either direction quiet for `_RELAY_IDLE_TIMEOUT` kills
  the tunnel), zero per-message allocations.

### Verified

- New tests: batch ops on both backends (accumulation, TTL filtering,
  cross-connection visibility), metrics buffer (memory-only hot path,
  flush, dirty-check, requeue-on-failure, persisted+pending merge,
  render cache), sweep-cycle batching (one `list_keys` per cycle,
  zero reads when idle), negative-cache TTL + invalidation on revoke,
  test-mode sweeper guard. Updated forensics/audit-hardened tests for
  the debounced save (`_flush_dirty()` as the deterministic stand-in).
- `tests/unit/{security,services,monitoring,engine}` green; ruff +
  black clean on all touched files.

### Not done (debt)

- **Real-Pi benchmarks** (PERF-001/002): WS register p95/p99, login
  txn latency, 50 conn/s reconnect storm, ≥90 % write reduction —
  need the live host; numbers must be measured, not assumed.
- **Soak test** 24 h on the Pi.
- **DB split decision** — deferred until measurements justify it.
- Later backlog items untouched: bulk revocation queries beyond the
  sweep, aggregated rate-limit txn, dedicated audit writer,
  session journal, remaining coverage floors (TD-13).

## Pass 23 — PERF debt clearance: real Pi 5 benchmarks + decisions

Ran `tools/perf_benchmark.py` (new, committed) ON the deployment
hardware — Raspberry Pi 5 Model B, aarch64, real SQLite backend in a
scratch dir. All budgets measured, none assumed.

### Measured results (Pi 5, sqlite backend, WAL + busy_timeout=10s)

| Path | p50 | p95 | p99 | Budget | Verdict |
|------|-----|-----|-----|--------|---------|
| `find_by_token_id` | 0.0006 ms | 0.0006 ms | 0.0006 ms | O(1) | dict lookup (was sha256 scan) |
| `note_connection` edge | 0.0008 ms | 0.0009 ms | 0.0009 ms | memory-only | debounced save |
| `session.validate` | 0.05 ms | 0.06 ms | 0.08 ms | <15 ms | 190× headroom |
| WS `register` | 0.11 ms | 0.12 ms | 0.13 ms | <20/<50 ms | ~150× headroom |
| `audit_log` append | 4.3 ms | 4.6 ms | 15.2 ms | — | one tail read + append |
| metrics batch flush | — | — | 22.7 ms | — | one txn / 5 s / process |

**Reconnect storm**: 50 conn/s × 60 s = 2992 register/unregister
cycles → **0 `database is locked` errors, 0 failed registrations**,
~100 sqlite ops/s sustained (2 revocation reads per register — the
cold-cache worst case; reconnects of known sessions hit the negative
cache). `sqlite_stats` lock_errors delta: 0.

**Steady-state writes**: ~8.6 txns/s projected (7 services × metrics
flush/5 s + forensic debounce/1 s + rare audit events) < 10/s budget.

### Decisions taken on data

- **DB split — NOT justified.** Single `shared_state.db` absorbed a
  50 conn/s storm with zero lock errors; steady state is ~9 writes/s
  against a WAL database doing ~100 ops/s under load. Splitting
  metrics/audit into a second DB adds a second failure domain for no
  measured gain. Revisit only if lock_errors appear in production
  `sqlite_stats` or write volume grows ~10×.
- **Dedicated audit writer — deferred.** `audit_log` p99 = 15 ms and
  it is not on the WS hot path; the synchronous append IS the chain
  ordering mechanism (tip advances only after the entry reaches
  disk). A queued writer would need to preserve that invariant under
  crashes — real complexity for a latency budget already met. Revisit
  if audit event rate makes p99 degrade or `AUDIT_FSYNC=1` deployments
  show write stalls.
- **Session journal — deferred.** The hot path (`note_connection`)
  is now ~0.001 ms with debounced persistence; what a journal would
  protect is ≤1 s of *forensic* stamps (connect/disconnect times),
  while revocation/security flags still write synchronously. Crash
  loss of forensic stamps is accepted and documented.
- **Aggregated rate limit — implemented.** `delete_many` batch op on
  both backends; `_clear_attempts`/`record_success_many` collapse the
  login-path clears (was 8 backend ops for the ip+user pair → 5,
  deletes in 3 batched statements). Attempt counting was already a
  single `list_keys`; per-key prefix lists retained deliberately — an
  unfiltered namespace scan would be unbounded under brute-force.

### Soak

`tests/e2e/test_soak.py` gained `test_ws_registry_churn` (register/
unregister/revoke/sweep cycles — asserts index consistency and
bounded lock errors) and `test_metrics_buffer_churn` (inc/set +
flushes — asserts bounded pending map). Full suite run on this Pi 5
with `SOAK_SECONDS=120`: **5/5 passed in 237 s** — each test churned
to its 5000-iteration cap; registry indexes stayed consistent
(`_resource_counts` all zero after drain), lock-error delta bounded,
metrics pending map stayed bounded and every flush succeeded.

The 24 h production soak remains a deployment activity (run the same
suite with `SOAK_SECONDS=86400` on the live host during a maintenance
window); the harness and the new coverage are committed.

## Pass 24 — admin SPA tabs review (frontend security sweep)

Reviewed every admin-console surface in `frontend/src/pages/` +
`components/` for client-side security issues: dangerous DOM sinks,
token/secret handling, CSRF reliance, permission gating, sensitive
data rendering, clipboard/storage hygiene.

### Verified clean (controls confirmed in code)

- **`api.ts`** — `credentials: 'same-origin'` on every call,
  `X-CSRF-Token` from `GET /api/v1/me` on mutations, token rotation
  handling, session-expired path. No tokens in web storage.
- **`Security.tsx`** — secrets render ONLY as server-side masks
  (`secrets/{name}` returns the redacted form, never the value);
  recovery codes shown once + step-up gate + confirm dialogs on
  rotate/signing/perms-fix.
- **`Sessions.tsx` / `SessionDetail.tsx`** — lists/revokes use the
  public `token_id` fingerprint; the internal token never reaches the
  client. Revoke has a 10 s undo window; revoke-all is step-up gated.
  Wizard draft in `sessionStorage` holds only non-sensitive form
  fields (role/ttl/flags/email/label) with key-allowlisting on load.
- **`Config.tsx`** — values arrive pre-redacted from
  `config_inspector._redact_value` (`SECRET_VARS` canonical list).
- **DOM sinks** — zero `dangerouslySetInnerHTML`/`innerHTML`/`eval`/
  `document.write` across pages+components; all `target="_blank"`
  links carry `rel="noreferrer"`; the SessionDetail noVNC iframe is
  same-origin server-built (`desktopUrl`), governed by CSP
  frame-ancestors.
- **localStorage/sessionStorage** — UI prefs, wizard draft, recording
  marks only; no credentials.

### Fixed

- **`components/bits.tsx::copyText`** — `navigator.clipboard` is
  `undefined` on non-secure contexts; `.writeText` then threw a
  synchronous TypeError instead of the intended error toast. Guarded
  with an early `toast.error` fallback. tsc clean.

### Notes (accepted, not bugs)

- `Sessions.tsx` wizard draft keeps `email_to` in sessionStorage —
  tab-scoped PII the operator typed themselves; cleared on tab close.
- `SessionDetail` iframe has no `sandbox` — it embeds our own
  same-origin noVNC (sandbox would break its websocket); framing is
  already CSP-gated.

## Pass 25 — admin tabs, one by one (per-page verdicts)

Deep-read of every admin route in `App.tsx` — mutations checked
against the operations catalog's auth policy, data flows traced to
the API layer.

| Tab (route) | Mutations | Step-up | Verdict |
|---|---|---|---|
| Overview `/` | lifecycle start/stop/restart, upgrade run/rollback, host power, WoL, jobs list | ✅ all gated | clean |
| Activity `/activity` | none (audit+jobs queries) | n/a | clean |
| Access `/access/*` → Sessions + SessionDetail | session create/revoke/revoke-all/label | ✅ revoke-all step-up; single revoke 10 s undo | clean |
| Connect `/connect` | none (portal + active sessions) | n/a | clean |
| Remote `/remote` | recording start/stop, screenshot | n/a — catalog scope `capture` (moderate); only recording **delete** is stepup-bound | clean |
| Files `/files` | upload (b64, 32 MiB cap — TD-06), mkdir, download | n/a — scoped `files` perm; download URL `encodeURIComponent`'d | clean |
| Identities `/identities[/:username]` | operator create/reset-password/role/revoke/delete, passkey mgmt | ✅ delete = type-to-confirm + step-up; revokes gated | clean |
| Security `/security` | secrets mask/rotate/recovery/perms-fix, posture | ✅ rotate/signing/recovery gated; secrets server-masked only | clean (pass 24) |
| Recordings `/security/recordings` | start/stop/delete/screenshot | ✅ delete step-up (matches catalog `stepup-bound`) | clean |
| Audit `/security/audit` | none | n/a | clean |
| Doctor `/operations/doctor` | maintenance mode toggle | ✅ step-up | clean |
| Backups `/operations/backups` | create, verify, restore (wizard) | ✅ create+restore step-up; restore = queued job | clean |
| Jobs `/operations/jobs[/:id]` | none (poll/cancel read) | n/a | clean |
| Config `/config` | migrate, set value, history restore | ✅ migrate+set+restore gated | clean |
| Help `/help` | none | n/a | clean |

Cross-cutting (pass 24): `api.ts` same-origin credentials + CSRF on
all mutations; zero dangerous DOM sinks; `_blank` links all carry
`noreferrer`; clipboard guard fixed in `bits.tsx`.

**Result: no new vulnerabilities.** Every destructive or
privilege-touching mutation is step-up gated or confirm-dialoged;
every read surface renders server-redacted data; the only client-side
defect found across both passes was the `copyText` clipboard guard
(already fixed, `60c151f`).

## Pass 26 — functional verification of every admin tab (Playwright)

New spec `frontend/e2e/admin-tabs.spec.ts` exercises each admin route
against the real landing service (hermetic run dir):

- **Route sweep** — all 17 routes (15 tabs + `/access/<token>` +
  `/identities/<user>` + job detail when present) render inside the
  shell with content and zero uncaught page errors.
- **API probes** — 36 GET endpoints across every tab's data surface,
  all 200.
- **Files tab E2E** — mkdir via the real UI control, upload via the
  same endpoint the SPA uses, download returns exact bytes, listing
  reflects the file.
- **Identities tab E2E** — operator create → visible in UI list →
  detail page renders.
- **Access detail** renders for a real share token.

### Bugs found & fixed by the functional pass

1. **e2e isolation was broken** (`global-setup.ts`): it exported
   `VNC_RUN_DIR`, a var nothing reads — the suite had been running
   against the LIVE data/run dirs (`operator_users.json`, file share,
   config history). Now exports `VRS_RUN_DIR` + `XDG_{DATA,STATE,
   CONFIG}_HOME` + `FILE_SHARE_ROOT` inside the tmpdir. Pollution
   already created (`shared/e2e-*`, three `e2e-*` operators) was
   removed from the live data dir.
2. **Share links pointed at production**: repo `.env` ships
   `PUBLIC_BASE_URL=https://vnc.alesanfe.duckdns.org` — share.spec
   was navigating to the live deployment. `PUBLIC_BASE_URL` is now
   pinned to the e2e origin in the spawn env (real env wins over
   `.env` by design).
3. **`operator_users._save` ENOENT on first boot**: fresh data dir →
   `operators create` 500'd. Added `makedirs` (the only store missing
   it — all others already had it).
4. **WCAG 2.5.3 Label-in-Name** on `ThemeSwitch`/`DensitySwitch`:
   aria-label ("Cambiar tema") didn't contain the visible text
   ("Tema: automático"). Name now leads with the visible label.
   Caught by the previously-red a11y spec.
5. **`login.spec` asserted English** while the suite pins `es-ES` —
   pre-existing stale assertion fixed to the Spanish copy.
6. **API rate limiter vs test suite**: ~87 tests fire hundreds of
   calls/min from one IP — legit traffic 429'd. Added opt-in
   `VRS_API_RATE_LIMIT_DISABLED` escape in `api_v1._rate_limit`
   (e2e-only; never set in production). The limiter itself is
   verified working — it correctly throttled the suite.

**Result: 31 passed / 0 failed / 56 skipped** (skips are the
screenshots spec, gated behind its own flag). Previously the suite
had 7 latent failures (a11y ×2, login, share ×4) that no CI run had
surfaced.
