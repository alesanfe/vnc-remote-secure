# Pre-Audit Security Verification

Evidence-based verification of the boundary hypotheses raised in the
external-style review, checked against the actual code. Statuses:

- **CONFIRMED-FIXED** — the gap existed and is now closed (with tests).
- **COVERED** — the mitigation already exists and was verified.
- **PARTIAL** — enforced in the common path, with a documented residual.
- **LIMITATION** — architectural; cannot be closed in code, documented.

## Findings closed in this pass

| # | Area | Before | Fix |
|---|------|--------|-----|
| 1 | RFB view-only enforcement | `_build_rfb_filter` returned `None` on ANY exception → a `view`-only ephemeral session silently got full RFB input | `_RfbFilterError` propagates; `/websockify` answers 403 — restricted sessions never proxy byte-transparent (`services/novnc.py`) |
| 2 | Webhook/alert SSRF | `http://` allowed, no destination validation, redirects followed (signed body could be bounced to an internal host) | HTTPS-only by default (`ALERT_WEBHOOK_ALLOW_HTTP`), every resolved address must be public unicast (`ALERT_WEBHOOK_ALLOW_PRIVATE` opt-out for LAN receivers), redirect following disabled (`monitoring/alerts.py`) |
| 3 | Audit rotation linkage | Rotated file's anchor chained from the fixed zero anchor — a full-file swap for a fabricated log was undetectable | New anchor embeds `prev_tip` (the rotated file's tail hash) inside the hashed entry (`security/audit.py`) |
| 4 | Operator store permissions | `operator_users.json` (PBKDF2 + recovery-code hashes) absent from `validate_secret_files` | Added to the extra_files list (`security/file_permissions.py`) |
| 5 | Stale signing key | `_cached_secret` loaded once per process — rotated keys never reached long-running services, which kept signing with retired keys | mtime re-check every 5 s with baseline tracking (`security/authentication.py`) |
| 6 | PBKDF2 migration | No rehash-on-login — hashes stayed at their minted iteration count forever | Successful `verify()` upgrades stale hashes to the current 600k policy (`security/operator_users.py`) |
| 7 | Upgrade supply chain | `pip install` inherited `PIP_*` env (hostile index/TLS-bypass), arbitrary downgrades accepted, sdists could run build-time code | `pip --isolated`, `--only-binary :all:` on index specs, pinned and resolved-version downgrade refusal with auto-rollback (`core/upgrader.py`) |
| 8 | CSRF on landing POSTs | Origin checked only *when present* | `Sec-Fetch-Site: cross-site` (unforgeable Fetch Metadata) rejected in `_operator_gate`; non-browser clients unaffected (`services/landing.py`) |
| 9 | status.json disclosure | Ephemeral view-only sessions received LAN IPs, system metrics and port topology | `lan_ips`/`system` only emitted for operator identities (`services/landing.py`) |
| 10 | Revocation/expiry degradation | `_is_revoked_shared` and `_session_expired` silently returned "not revoked/expired" on backend failure | Throttled warning + `vnc_remote_shared_state_errors_total` metric — degraded-enforcement windows are now observable |
| 11 | Temp-user process leak | `userdel -r` leaves the deleted uid's processes running | `loginctl terminate-user` + `pkill -9 -u` before `userdel` (`platform/linux/permissions.py`) |
| 12 | SendInput stuck keys | `WindowsInputInjector.close()` was a no-op — held keys kept typing after disconnect/revoke | Held-vk tracking + explicit KEYUP on close (`platform/windows/gamepad.py`) |
| 13 | Audio head-of-line blocking | Serial `ws.send` — one stalled reader blocked all listeners, buffer grew unbounded | Per-send 2 s timeout, slow clients dropped; `_MAX_CLIENTS=32` cap (`services/audio.py`) |
| 14 | Gamepad event flood | No event rate limit — a session could flood SendInput/uinput syscalls | 240 events/s per client, excess → 1008 close (`services/gamepad.py`) |
| 15 | Terminal resource limits | No rlimits — a fork bomb/memory hog could exhaust the host inside CMD_TIMEOUT | `preexec_fn` applies NPROC/AS/CPU/NOFILE/FSIZE/CORE limits on POSIX (`services/terminal.py`) |
| 16 | View-only path completion | `complete` globbed server filenames for view-only sessions | Gated behind `terminal_write` (`services/terminal.py`) |
| 17 | Request smuggling | `http.server` handlers ignored `Transfer-Encoding`/duplicate `Content-Length` | `request_headers_safe()` rejects ambiguous framing on landing/health/noVNC entry points (`security/http_auth.py`) |
| 18 | Plaintext backups | `BACKUP_PASSWORD` unset → plaintext archive of `.env`, TLS keys, signing secret (warning only) | Hardened profiles refuse unless `BACKUP_ALLOW_PLAINTEXT=true` (`core/backup.py`) |

## Verified as already covered

- **Single-use / max-uses atomicity** — `_claim_consumed` (atomic
  `set_if_absent`) and `_claim_use` (atomic `increment`) claim through
  the shared-state backend before local marking; both fail closed.
  Cross-process-safe under the SQLite backend.
- **WS credential transport** — cookies/Bearer only; no query-string
  tokens on any WebSocket. The landing `?session=` share-link exchange
  is the single intentional URL-token surface, mitigated by 302 strip,
  access-log redaction, `access_log off` for `$arg_session`, and a
  prefetch interstitial.
- **Origin validation on every WS upgrade** — absent/`null` rejected;
  terminal, audio, gamepad, noVNC all enforce it.
- **Session fixation** — `session.clear()` + fresh signed token +
  fresh CSRF token on login.
- **Security headers** — CSP/XFO/nosniff/HSTS(TLS) on every response
  including errors and the `SimpleWebApp` fallback.
- **PBKDF2 600k, 16-byte salt, versioned format** — constant-work for
  unknown users via dummy-hash substitution.
- **Recovery codes** — 128 bits (`token_hex(16)`), SHA-256 hashes,
  `hmac.compare_digest`, single-use via `secrets recovery-codes` CLI.
- **X-Forwarded-For trust** — requires `TRUSTED_PROXY` AND a loopback
  or `TRUSTED_PROXY_IPS` peer; last-hop parsing matches
  `$proxy_add_x_forwarded_for` semantics.
- **Health/metrics auth** — `HEALTH_AUTH_TOKEN` Bearer, or open only
  when every bind AND the socket peer are loopback; `/health/live`
  returns only `{"status":"alive"}` under a 60/60s rate limit.
- **RFB filter state machine** — allowlist parser: fragmentation,
  multi-message frames, unknown types → connection teardown.
- **Path traversal** — novnc static via stdlib `translate_path`,
  Tornado `StaticFileHandler`, restore member/link/realpath validation.
- **AppContainer** — zero granted capabilities (no network), scratch
  dir ACL only, Job Object `KILL_ON_JOB_CLOSE` without breakaway.
- **No mutating GETs** besides the prefetch-guarded share-link exchange.
- **`http.server` fallback rejected** under hardened profiles
  (`web/application.py`).
- **Mid-stream expiry for ephemeral sessions** — 5 s watcher closes
  sockets on revocation OR `expires_at`.

## Partial — resolved since the first pass

| Area | Closure |
|------|---------|
| Terminal WS credentials | `TERMINAL_BASIC_AUTH=false` removes the `TTYD_*` Basic path on the page AND the WS upgrade — token credentials (ephemeral/bearer/session) only |
| Ephemeral resource binding | `EPHEMERAL_REQUIRE_RESOURCE=true` makes `SessionStore.create()` raise `ValueError` on a missing binding; the CLI surfaces a clean error |
| Operator-session mid-stream expiry | The WS sweep force-closes `vnc_session` cookies on absolute expiry and operator-epoch bump (credential rotation). The HTTP sliding idle stays HTTP-only by design — a live desktop isn't killed for not polling HTTP |
| Rate limiting | Progressive escalation: each consecutive lockout doubles (`AUTH_LOCKOUT_ESCALATION`, default on) up to `AUTH_LOCKOUT_MAX_SECONDS` (24 h); success resets strikes. Non-auth paths remain per-IP only (no authenticated principal to key on) |
| Clipboard | `desktop:clipboard_read` enforced: the filter rewrites client SetEncodings to the length-decidable subset (Raw/CopyRect/RRE/Hextile/ZRLE + safe pseudo-encodings) and fully decodes the server→client stream — ServerCutText is dropped without the permission, sanitized when granted. ClientCutText payloads are sanitized (C0/DEL/C1 stripped, TAB/LF/CR kept), size-capped, length field rewritten. Un-negotiated/unknown encodings or message types close the connection |
| `ALLOWED_LAN_IPS` origins | Non-loopback LAN hosts now require http/https + a port the services actually bind — `http://<lan-ip>:9999` no longer passes. Loopback keeps any-port acceptance: a hostile local process can read `.env` directly, the check buys nothing there |
| Audit write failure | Throttled `notify()` alert + `vnc_remote_audit_write_errors_total` on every primary/mirror failure; `AUDIT_STRICT=true` aborts the audited action instead |
| `_is_revoked_shared` backend outage | `SHARED_STATE_STRICT=true` denies the session when the check cannot reach the backend; default stays local-flag fallback + warning + metric (availability choice) |
| Shared-state `MemoryBackend` fallback | `backend_degraded()` + `op=backend_init_fallback` metric; `SHARED_STATE_STRICT=true` refuses to start degraded |
| Windows sandbox `auto` | `auto` is promoted to `strict` under `public-hardened`/`private-overlay` — no silent unsandboxed children on hardened profiles; explicit `off` is always honoured |
| Temp user after crash | `_sweep_stale_temp_user()` at `start_all` removes the account when it owns no processes; it is kept (with a warning) when processes are alive — a live orphaned session may still need it |
| Audit tip witness | Additional `<log>.tip` sidecar signed with `HMAC(AUTH_SECRET)` — rewriting both the log and `shared_state.db` still cannot forge a valid witness; a bad signature is itself flagged |
| Webhook DNS-rebinding | `_post_pinned` dials the exact IP that passed the public check (TLS SNI/hostname verification unchanged); re-resolution to private refuses the send; single request — redirects impossible |

## Architectural limitations (cannot be closed in code)

- **Loopback is exposure reduction, not authorization.** Internal
  services bound to 127.0.0.1 trust the host's integrity — local
  malware with the same privileges reaches them. No Unix-socket or
  named-pipe channel exists yet.
- **Env filtering is not filesystem isolation.** `_build_child_env`
  removes `SECRET_VARS` but the shell still runs as the service
  account — it can READ `.env`, `auth_secret.key`, `shared_state.db`
  unless `WEBTERM_USER` (root only), the bwrap sandbox (unprivileged),
  or AppContainer (Windows) applies.
- **In-memory secrets are not zeroized.** Python strings cannot be
  reliably wiped; `_cached_secret` lives until process exit.
- **Windows SendInput ≠ XInput.** Without ViGEmBus, games see no
  gamepad; documented. SendInput keys are now released on disconnect.
- **Session-0**: UltraVNC must run in the interactive session — full
  service-account isolation would break capture (F-035).
- **Temp-user orphan processes**: a crash can leave temp-user-owned
  processes running; the start-time sweep removes the account only
  when it owns none (removing it under live processes orphans their
  files/IPC) — orphaned processes are logged for manual cleanup.

## Operational tasks (outside the code)

- PyPI trusted-publisher registration + real release publication.
- MSI signing certificate + hosted signed artifacts.
- WinGet manifest submission with real URLs/hashes.
- Debian build/install/uninstall test on a supported target.
- ViGEm driver validation on Windows hardware.
- Independent third-party audit execution.
- `audit-evidence/` review for the local tip-mismatch event observed
  during recovery-code generation.
