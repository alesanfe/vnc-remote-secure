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
| Access control & auth | ISO 27001 A.8.2–A.8.5, ASVS V2/V4 | 9.0 | auth_gateway on every handler, step-up bound grants (op+resource+session, 120 s), MFA/WebAuthn, fail-closed portal, ephemeral fragment links. −1: no independent review (TD-17). |
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

## Remaining debt (honest)

- **TD-17 external review** — needs a human third party; scope doc
  ready. Cannot self-resolve.
- **TD-15 key enrollment** — gate merged; maintainer must run the
  documented `gpg.format=ssh` setup.
- **TD-13 ramp** — mechanism live; 85 % global needs ongoing test
  writing (file_permissions 62 %, certificates 63 %, audio.py).
- **D1/D10 drills** — need a disposable host.
