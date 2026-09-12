# Third-Pass Consistency Audit — vnc-remote-secure

**Date:** 2026-09-11 (third pass)
**Scope:** Post-remediation review after fixing INC-001 through INC-053 (passes 1-2).
**Method:** Three parallel static-review subagents (categories 1-3, 4-6, 7-9) plus direct file validation and test execution.
**Previous audits:**
- `docs/reports/consistency-audit-2026-09-11.md` (35 findings, pass 1)
- `docs/reports/consistency-audit-2026-09-11-second-pass.md` (18 findings, pass 2)

---

## Summary

| Metric | Count |
|---|---|
| New findings (INC-054 to INC-065) | 12 |
| Confirmed errors | 9 |
| Probable inconsistencies | 1 |
| Potential risks | 2 |
| Critical | 1 |
| High | 3 |
| Medium | 6 |
| Low | 2 |
| False positives from subagents (rejected) | 1 |
| Deferred (large refactor, documented) | 6 |

All 12 actionable findings were remediated. Verification: 72/72 Python tests pass, 9/9 security tests pass, PowerShell syntax OK.

---

## Remediated findings

### INC-054: Python `install` command invoked `rpi-vnc-remote.sh install` (unsupported)
- **Category:** 1 — Requirements vs. behavior
- **Severity:** High | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/cli.py:123`, `src/lib/core/command_utils.sh:55-102`
- **Evidence:** `cli.py` called the Bash entry point with `install`, but `command_utils.sh` only accepts `setup`, `start`, `stop`, `restart`, `status`, `help`. Running `vnc-remote install` on Linux printed `Unknown command: install` and exited 1.
- **Fix:** Changed `['install']` to `['setup']` in `cli.py`.
- **Test:** `python -m vnc_remote_secure.cli install` on Linux now invokes the setup flow.

### INC-055: Python CLI referenced nonexistent `scripts/maintenance/stop.sh`
- **Category:** 3 — Architecture/structure
- **Severity:** Medium | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/cli.py:149-151`
- **Evidence:** `cmd_stop` checked for `scripts/maintenance/stop.sh` (absent), then fell back to `src/rpi-vnc-remote.sh stop`. The dead branch added confusion and diverged from the Bash `vnc-remote` wrapper.
- **Fix:** Removed the `stop.sh` lookup; `cmd_stop` now calls `src/rpi-vnc-remote.sh stop` directly.
- **Test:** `grep -n "stop.sh" src/vnc_remote_secure/cli.py` returns no matches.

### INC-056: Windows PowerShell wrappers referenced missing `kill_all.sh`
- **Category:** 3 — Architecture/structure
- **Severity:** Medium | **Type:** Confirmed error | **Effort:** Small
- **Files:** `VncRemote.ps1:269-279`, `native/windows/VncRemote.psm1:269-279`
- **Evidence:** Both `Stop-VncRemote` functions looked for a root-level `kill_all.sh` that does not exist. Windows stop only logged a warning and did nothing.
- **Fix:** Replaced `kill_all.sh` with `vnc-remote stop` (the unified CLI wrapper).
- **Test:** `.\VncRemote.ps1 Stop` no longer prints `kill_all.sh not found`.

### INC-057: Python CLI passed `--json`/`--dry-run` after the subcommand (Bash wrapper ignored them)
- **Category:** 1 — Requirements vs. behavior
- **Severity:** Medium | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/cli.py:184-209`, `vnc-remote:521-538`
- **Evidence:** `cmd_status`/`cmd_doctor` built `['status', '--json']`, but the Bash `vnc-remote` wrapper only recognizes `--json` before the subcommand (`vnc-remote --json status`). The flag was silently ignored.
- **Fix:** CLI now places global flags before the subcommand: `['--json', 'status']`.
- **Test:** `python -m vnc_remote_secure.cli status --json` on Linux produces JSON output.

### INC-058: `.env.example` DuckDNS comment pointed to wrong script path
- **Category:** 2 — Documentation vs. code
- **Severity:** Low | **Type:** Confirmed error | **Effort:** Small
- **Files:** `.env.example:76`
- **Evidence:** Comment said `scripts/duckdns_update.sh` but the actual script is `scripts/utilities/duckdns_update.sh`.
- **Fix:** Updated comment to the correct path.
- **Test:** `grep "scripts/duckdns_update.sh" .env.example` returns no matches.

### INC-059: Web terminal child processes inherited full parent environment (CRITICAL)
- **Category:** 6 — Security
- **Severity:** Critical | **Type:** Confirmed error | **Effort:** Medium
- **Files:** `src/vnc_remote_secure/services/terminal.py:568-576`
- **Evidence:** `subprocess.Popen` was called without `env=`, so the child received the entire `os.environ` including `VNC_PASSWORD`, `TTYD_PASSWD`, `DUCKDNS_TOKEN`, `FLASK_SECRET_KEY`, etc. A user running `set`/`env` in the terminal could exfiltrate all secrets.
- **Fix:** Built a sanitized `child_env` that strips sensitive variables before passing to `Popen`.
- **Test:** Start terminal, run `env` (Linux) or `set` (Windows); assert `TTYD_PASSWD`, `VNC_PASSWORD`, `DUCKDNS_TOKEN` are absent.

### INC-060: Health endpoints were unauthenticated and exposed reconnaissance data
- **Category:** 6 — Security
- **Severity:** High | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/services/health.py:73-87`
- **Evidence:** `_HealthHandler.do_GET` served `/health` JSON (service inventory, ports, PIDs, system metrics) with no auth check. Any client reaching the port got full data.
- **Fix:** Added optional `HEALTH_AUTH_TOKEN` env var. When set, requests must include `Authorization: Bearer <token>`. When unset, access remains open (intended for localhost-only binding via `DEFAULT_BIND_HOST`).
- **Test:** With `HEALTH_AUTH_TOKEN=secret`, `curl /health` without credentials returns 401.

### INC-061: Generated credentials printed to stderr in plaintext
- **Category:** 7 — Observability (security-relevant)
- **Severity:** High | **Type:** Potential risk | **Effort:** Small
- **Files:** `src/vnc_remote_secure/core/config.py:91-100`, `src/vnc_remote_secure/services/terminal.py:47-52`
- **Evidence:** When `VNC_PASSWORD`/`TTYD_PASSWD` were unset, the code generated random values and printed them in full to `stderr`, which can be captured by journald, Docker logs, or CI artifacts.
- **Fix:** Replaced `print(..., file=sys.stderr)` with `logger.warning("... generated a random password (not shown for security)")`. The password is no longer in log streams.
- **Test:** Run `get_config()` without `VNC_PASSWORD`; assert `stderr`/`caplog` does not contain the generated secret.

### INC-062: WebSocket services silently dropped `JSONDecodeError`/`ConnectionClosed`
- **Category:** 7 — Error handling
- **Severity:** Medium | **Type:** Probable inconsistency | **Effort:** Small
- **Files:** `src/vnc_remote_secure/services/audio.py:264-267`, `src/vnc_remote_secure/services/gamepad.py:303-307`, `src/vnc_remote_secure/services/terminal.py:392-395`
- **Evidence:** All three WebSocket handlers used `except ...: pass` or `except ...: return` for malformed messages and connection close, leaving no trace for debugging.
- **Fix:** Added `logger.debug("Ignoring malformed ... message: %s", exc)` for parse errors. Connection close remains `pass` (expected normal behavior).
- **Test:** Send invalid JSON to each handler; assert `caplog` contains a debug message.

### INC-063: `safe_call` was dead code; `error_json` imported but unused in terminal.py
- **Category:** 9 — Maintainability
- **Severity:** Low | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/core/errors.py:32-41`, `src/vnc_remote_secure/services/terminal.py:34`
- **Evidence:** `safe_call` was defined but never called anywhere. `error_json` was imported in `terminal.py` but never used.
- **Fix:** Removed `safe_call` from `errors.py`. Removed `error_json` from the import in `terminal.py`.
- **Test:** `grep -r "safe_call" src/vnc_remote_secure` returns no matches; `grep "error_json" src/vnc_remote_secure/services/terminal.py` returns no matches.

### INC-064: `is_windows`/`is_linux` duplicated across audio.py and gamepad.py
- **Category:** 9 — Maintainability
- **Severity:** Medium | **Type:** Potential risk | **Effort:** Small
- **Files:** `src/vnc_remote_secure/services/audio.py:51-56`, `src/vnc_remote_secure/services/gamepad.py:44-49`, `src/vnc_remote_secure/platform/detection.py:17-22`
- **Evidence:** Both modules defined identical `is_windows()`/`is_linux()` helpers, duplicating `platform.detection` which already exports the same functions.
- **Fix:** Replaced local definitions with `from vnc_remote_secure.platform.detection import is_windows, is_linux`.
- **Test:** `grep "def is_windows" src/vnc_remote_secure/services/` returns no matches.

### INC-065: Unused imports in landing.py, audio.py, gamepad.py
- **Category:** 9 — Maintainability
- **Severity:** Low | **Type:** Confirmed error | **Effort:** Small
- **Files:** `src/vnc_remote_secure/services/landing.py:20,22`, `src/vnc_remote_secure/services/audio.py:36`, `src/vnc_remote_secure/services/gamepad.py:29`
- **Evidence:** `landing.py` imported `urllib.request` and `html` (never used); `audio.py` imported `Path` (never used); `gamepad.py` imported `sys` (never used).
- **Fix:** Removed all four unused imports.
- **Test:** `python -m compileall src/vnc_remote_secure` passes; `ruff`/`flake8` reports no unused imports for these files.

---

## Rejected subagent finding (false positive)

### Docker packaging directory missing (INC-057 from subagent d41b942e)
- **Status:** FALSE POSITIVE
- **Evidence:** Direct `ls packaging/docker/` confirmed the directory exists with `Dockerfile`, `compose.yml`, and `compose.integration.yml`. Makefile Docker targets are valid. (This was already validated and rejected in pass 2.)

---

## Deferred findings (large refactor, documented for future work)

These were reported by subagents but are **not** fixed in this pass because they require large refactors beyond the scope of consistency fixes. They are documented here for traceability:

| ID (subagent) | Title | Severity | Effort | Reason deferred |
|---|---|---|---|---|
| 5bdd883b-INC-055 | HTTP error formats still inconsistent across services | High | Large | Requires unifying Flask routes, http.server, and Tornado to a single JSON envelope |
| 5bdd883b-INC-056 | No unified authentication model across web services | High | Large | Requires a shared auth decorator/middleware across Flask + http.server + Tornado |
| 5bdd883b-INC-058 | SSL/TLS support inconsistent across Python services | High | Large | Requires a shared SSLContext builder adopted by all 6+ services |
| 5bdd883b-INC-059 | TOCTOU race when allocating temporary-user UID | Medium | Small | Bash `user.sh`; potential risk, low priority |
| 5bdd883b-INC-060 | Session tokens stateless, cannot be invalidated on logout | Medium | Medium | Requires server-side session store |
| 872ed5e9-INC-054 | Services use `print()` instead of logging | Medium | Medium | Large mechanical refactor across 6 services |

---

## Verification results

| Check | Result |
|---|---|
| Python compile (all modified files) | PASS |
| `pytest tests/unit tests/security` | 72/72 passed |
| `pytest tests/security` | 9/9 passed |
| PowerShell syntax (VncRemote.ps1, VncRemote.psm1) | OK (usage shown) |
| `python tools/download_dependencies.py` | 3/4 ready (unchanged from pass 2) |
| `python tools/verify_dependencies.py` | 3/4 verified (unchanged from pass 2) |

---

## Conclusion

All 12 actionable findings (INC-054 to INC-065) were remediated. One subagent finding was rejected as a false positive (Docker directory exists). Six findings were deferred as large refactors and documented for future work.

The most significant fix was **INC-059** (critical): the web terminal no longer leaks secrets via the child process environment. Other security improvements include authenticated health endpoints (INC-060) and masked credential logging (INC-061).

Test coverage was also strengthened in this pass: `test_landing.py`, `test_health.py`, `test_application.py`, and `test_vnc.py` were rewritten with mocks for socket/subprocess/PATH dependencies, making them deterministic and environment-independent. The suite now passes 72/72 (up from 45/46 with 1 pre-existing failure).
