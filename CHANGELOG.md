# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Health endpoints fail closed on public binds**: `HEALTH_AUTH_TOKEN`
  empty now only grants open access when every health-serving bind
  (`HEALTH_WEB_HOST`, `USER_UI_HOST`, `BIND_HOST`) is loopback; a public
  bind without a token returns 401 instead of exposing `/audit`,
  `/metrics` and service state.
- **Terminal accepts `vnc_session` cookie**: the terminal page and its
  xterm.js assets now accept the same session cookie the WebSocket
  upgrade already required, removing a double Basic-auth challenge.
- **Stale generated credentials purged**: setting a credential in `.env`
  (or rotating it via `secrets rotate`) removes the stale entry from
  `generated_credentials.env` so deleting the env var later cannot
  resurrect the old generated password.
- **`secrets redact` parity**: falls back to persisted generated
  credentials so `redact` and `status` cannot disagree about whether a
  credential is configured.
- **`vnc_session` cookie name collision resolved**: Flask's own session
  cookie was named `vnc_session` while the non-Flask services (noVNC,
  terminal, audio, gamepad, landing) read the same name expecting the
  raw HMAC session token — WebSocket cookie-auth could never succeed
  for UI logins. Flask's cookie is now `vnc_flask_session`
  (`SESSION_COOKIE_NAME`, collision-guarded), and login issues the
  signed session token as the `vnc_session` cookie the services verify.

### Fixed
- **`.pre-commit-config.yaml` was invalid YAML**: plain-scalar `entry`
  values containing `Run:`/`ERROR:` broke the parser; entries now use
  block scalars so `pre-commit` actually loads.
- **VNC port reported consistently**: `status_all()` (`/health/services`)
  and the landing "VNC nativo" feature card now derive the effective
  Linux RFB port (`5900 + VNC_DISPLAY`) instead of showing the raw
  `VNC_PORT`, matching the doctor probe, websockify target and the
  landing status JSON.
- **Landing feature cards were Windows-only text**: the "Qué puedes
  hacer" section hardcoded "escritorio Windows"/"cmd.exe" and ignored
  its `is_windows` parameter; the wording is now platform-aware.
- **Query strings 404'd on stdlib services**: the health server and the
  landing portal compared `self.path` verbatim, so `/health?x=1` or
  `/status.json?ts=…` (as forwarded by nginx) returned 404 while Flask
  matched the route. Paths are normalized before routing.
- **Readiness/liveness parity**: Flask `/health` now returns 503 when
  the aggregate status is `down`/`unknown` (the stdlib server already
  did), and the stdlib `/health/ready` now returns 503 when any enabled
  service is down (the Flask blueprint already required all listening).
- **Shared-state backend parity**: `SQLiteBackend.increment` now returns
  the stored total after incrementing an expired key — same value the
  memory backend returns (0 previously, divergent).
- **Ephemeral share links could not activate behind a trusted proxy**:
  both landing implementations bound `allowed_ip` sessions to the raw
  socket peer (127.0.0.1 behind nginx) while `check_session_permission`
  resolves the forwarded client IP — IP-restricted sessions were
  permanently unusable through the proxy. Activation now uses the same
  `client_ip_from` resolution.
- **Logout did not clear `vnc_ephemeral`**: a share-link browser session
  survived `/logout` (the link stays valid server-side by design —
  revoking it is the owner's choice, but the browser cookie must go).
- **Revocation marker could expire before the session it killed**:
  `websocket_revoked_sessions` used a fixed 24h TTL; an operator-set
  `SESSION_MAX_LIFETIME` above 24h would let a revoked token
  re-authenticate after the marker expired. The TTL now tracks the
  configured max lifetime (bounded below by 24h).
- **Per-service bind hosts respected in probes**: the landing portal's
  service cards and `status.json` probed every port on `127.0.0.1`, so
  a service bound to a LAN IP showed as down while running; they now
  probe each service's configured `*_HOST` like `doctor` does. Both
  probers also treat wildcard binds (`0.0.0.0`/`::`) as loopback —
  connecting to the wildcard address is unreliable on Windows. The
  `services/health.py` aggregate probes got the same fix — a LAN-bound
  backend previously pinned the aggregate status to `degraded`.
- **`DISABLE_SSL=true` is a real kill-switch**: it used to be ignored
  whenever `TLS_ENABLED` was also set — and `.env.example` ships
  `TLS_ENABLED=true`, so the documented "equivalent" way to disable
  TLS silently did nothing. `config._is_tls_enabled_env()` now checks
  `DISABLE_SSL` first, and `certificates.create_ssl_context` delegates
  to it instead of keeping a third interpretation.
- **`compare_digest` no longer crashes on non-ASCII input**: str-form
  `hmac.compare_digest` raises `TypeError` on non-ASCII — fuzzed Bearer
  tokens, CSRF headers, usernames/passwords, or token signatures turned
  auth checks into 500s. `http_auth.check_bearer_token`,
  `token_signing.verify_token`, `authentication.authenticate`,
  `web/routes/users.py` CSRF checks, and the `credentials.py` pbkdf2
  fallback now compare bytes; `credentials.py` also caps the iteration
  count so a malformed stored hash cannot hang the login thread.
- **Prometheus gauges/counters merged cross-process**:
  `vnc_remote_health_check_total` and all gauges were incremented into
  the shared-state backend but rendered only from the serving
  process's dict — counts from other service processes were dropped.
  `render_metrics()` now merges like the auth counter already did.
- **`secrets rotate AUTH_SECRET|FLASK_SECRET_KEY` clears the stale
  persisted key**: `auth_secret.key` shadowed nothing while the env
  var existed, but deleting the env var later resurrected the old
  signing secret — the same stale-fallback bug class as
  `generated_credentials.env`.
- **`secrets status` resolves the shared signing-secret chain**:
  `AUTH_SECRET` and `FLASK_SECRET_KEY` share `_get_secret()`'s
  fallback — reporting one as empty while the other was set (or the
  persisted key existed) claimed no signing key was configured.
- **`REQUIRED_SECURITY_HEADERS` used the deprecated IE header name**:
  `X-Content-Security-Policy` → `Content-Security-Policy` (the name
  `http_headers.py` actually emits).
- **Linux temp user docstring/docs claimed SSH-key login**: the
  account is created with `useradd -r -s /usr/sbin/nologin` (locked by
  design) — the docs now describe the real semantics and how to enable
  it (`usermod -s`).
- **Stale `VNC_PORT` warning text**: `config validate` claimed a
  mismatched `VNC_PORT` on Linux "breaks health checks" — probes have
  used the display-derived port for a while, so the warning now says
  the value is simply ignored.
- **`--verbose/--quiet/--json/--dry-run` accepted on nested
  subcommands**: `vnc-remote session list --verbose` (and the
  equivalent `secrets`/`config`/`version` forms) used to die with
  "unrecognized arguments" — the leaf parsers lacked the common flags
  and the PowerShell wrapper's `-Verbose`/`-Json` insertion point
  (`session --json list`) hit the same wall. All leaf and parent
  parsers now share the common set, with `argparse.SUPPRESS` on the
  leaves so a parent-level flag is never clobbered by a leaf default.
- **Test isolation leak in `conftest.py`**: modules that bound
  `get_run_dir`/`get_log_dir` at import time (`from paths import …`)
  bypassed the per-test tmpdir patch — PID files and generated
  credentials could land in the real `%LOCALAPPDATA%`/run dir during
  tests. The fixture now rebinds the name inside every importing
  module and covers `get_data_dir`/`get_config_dir`/`get_ssl_dir` too.
- **Port probes were IPv4-only**: `is_port_available`, the doctor's
  `_check_port` and landing's `check_port` all used `AF_INET`, so a
  service bound to an IPv6 literal (`::1`) reported as down.
  `is_port_available` now selects `AF_INET6` for `:`-hosts and all
  probers delegate to it.
- **`config show-effective` missed `common.env`**: the inspector read
  only `config/defaults/{linux,windows}.env`, so provenance for every
  shared default (`VNC_DISPLAY`, `SHARED_STATE_BACKEND`,
  `USER_UI_PORT`, …) was reported as unset instead of
  platform-default. It now merges common.env + the platform file like
  the runtime loader.
- **Windows firewall helpers not idempotent**: the adapter's
  `install_firewall_rule`/`remove_firewall_rule` lacked
  `-ErrorAction SilentlyContinue`, so re-creating an existing rule or
  removing an absent one reported failure — diverging from
  `firewall.configure_firewall`/`remove_firewall_rule` semantics.
- **Unicode digits crashed TOTP verification**: `str.isdigit()`
  accepts Arabic-Indic/full-width digits ('١٢٣٤٥٦', '１２３４５６'),
  which then raised `TypeError` inside `hmac.compare_digest` — a 500
  on the MFA login path. `verify_totp` now requires ASCII digits and
  rejects non-str input; `verify_recovery_code` compares as bytes for
  the same reason.
- **Fourth divergent TLS interpretation in `security/posture.py`**:
  its `_is_tls_enabled` checked `TLS_ENABLED` before `DISABLE_SSL`,
  inverting the canonical kill-switch precedence — the posture report
  could claim "TLS enabled" while the runtime served cleartext. It now
  delegates to `config._is_tls_enabled_env`. The same stale precedence
  was fixed in `certificates.create_ssl_context`'s ImportError
  fallback and the `cli` session-URL env fallback, and
  `config_inspector.validate_config` now evaluates `DISABLE_SSL` too
  (a hardened profile with `DISABLE_SSL=true` previously passed the
  "TLS required" check).
- **`cli.py` split into a package**: the 1200-line single file is now
  `cli/` — `commands/` groups handlers by domain (lifecycle, session,
  secrets, config, ops, misc), `_parser.py` holds the argparse wiring,
  `_app.py` holds `main()`, `_common.py` the shared helpers. Public
  surface unchanged: `vnc_remote_secure.cli:main`, `python -m
  vnc_remote_secure.cli` (new `cli/__main__.py`) and the `cmd_*`
  re-exports all keep working.
- **New `verify` command**: `vnc-remote verify audit` replays the
  audit hash chain from the CLI (previously only reachable via the
  `/audit/verify` HTTP endpoint); `vnc-remote verify backup [FILE]`
  decrypts and CRC-checks every archive member (default: newest
  backup). Both support `--json`.
- **`docs/developer/release-checklist.md`**: 30-scenario E2E matrix
  (deployment, security, operational) for release validation on real
  VMs, linked from the docs index.
- **`AUDIT_MIRROR_FILE`**: optional second append-only audit sink
  (e.g. a mounted network share or WORM store) — each entry is written
  to both sinks inside the file lock so rewriting the primary log
  leaves the mirror intact. Mirror write failures degrade to a log
  error, never breaking the primary log.
- **Landing CSS extracted**: `landing.py`'s 148-line inline
  `_LANDING_CSS` moved to `static/landing.css` (packaged via
  package-data + MANIFEST) and inlined at render time through
  `importlib.resources`.
- **New tests**: `tests/unit/core/test_backup.py` (verify/list, plain
  and encrypted, corrupt archives, wrong password) and audit-mirror
  coverage in `test_audit.py`.
- **Fixed double-encoded mojibake in `AGENTS.md` and
  `test_application.py`**: earlier edits written through a CP1252
  codepage corrupted UTF-8 sequences (`canÃ³nico`, `â€"`); both files
  were repaired back to clean UTF-8.
- **Bare `DUCK_DOMAIN` produced broken hostnames**: `.env.example`
  hints at the full `sub.duckdns.org` form, but an operator entering
  the bare subdomain got `server_name mysub` in nginx, a Let's Encrypt
  request for a non-existent name, a `https://mysub/?session=…` share
  link and an `https://mysub` auto-origin. New
  `config.normalize_duck_domain()` appends `.duckdns.org` to bare
  values and is used by the nginx installer, certbot path, share-link
  URL builder and origin allowlist.

### Added
- **VNC DES password support**: re-introduced `pycryptodome` dependency to back
  `src/vnc_remote_secure/vendor/d3des.py` for standard VNC and UltraVNC
  password encryption (used by `scripts/utilities/generate_vnc_password.py`).
- **Config inspector with provenance**: `vnc-remote config show-effective` shows
  the effective value of each config variable and where it came from (env, .env,
  profile, platform-default, hardcoded-default, security-policy).
- **Config validation**: `vnc-remote config validate` detects contradictory
  configurations (TLS disabled in hardened profiles, MFA missing, etc.).
- **Config diff**: `vnc-remote config diff --profile-a A --profile-b B` shows
  differences between two profiles.
- **Config migration**: `vnc-remote config migrate` migrates legacy config values
  (VNC_REMOTE_PROFILE, CERT_FILE, old profile names).
- **WebSocket connection registry** (`security/websocket_registry.py`): tracks
  active WebSocket connections by session ID for immediate revocation.
- **Immediate WebSocket revocation**: `revoke_session()` now closes all active
  WebSocket connections for the session, not just preventing reconnection.
- **Atomic single-use token consumption**: `consume_ephemeral_session()` uses
  a lock to ensure only one concurrent client can consume a single-use token.
- **Strong token binding**: ephemeral sessions now support resource binding
  (desktop/terminal), instance_id, nonce, and max_uses.
- **Step-up authentication** (`security/step_up_auth.py`): requires recent
  authentication for sensitive actions (terminal, file transfer, admin
  creation, TLS disable, profile change, support session creation).
- **Real bypass tests** (`tests/security/test_real_bypass.py`): tests that
  start real servers and verify backends cannot be reached externally.
- **Windows isolation tests** (`tests/windows/Isolation.Tests.ps1`): Pester
  tests verifying restricted user account, firewall rules, and file access.
- **Profile enforcement of BACKEND_BIND_HOST**: hardened profiles now enforce
  127.0.0.1 even if the user sets 0.0.0.0 in the environment.
- **SameSite policy unified**: Flask and stdlib sessions both default to Lax,
  configurable via SESSION_SAMESITE env var.
- **Flask secret key enforcement**: non-development profiles log an error if
  FLASK_SECRET_KEY is not set; posture check added.
- **Fallback app fails safely**: non-development profiles raise RuntimeError
  if Flask is not installed, instead of using insecure http.server fallback.
- Structured audit logging with tamper-evident SHA-256 chain (`security/audit.py`)
- TLS cipher and certificate validation (`security/tls_validation.py`)
- HTTP security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy (`security/http_headers.py`)
- Secret file permissions validation (`security/file_permissions.py`)
- Prometheus metrics export with `/metrics` endpoint (`monitoring/prometheus.py`)
- OpenAPI 3.0 specification for health, audit, and metrics endpoints (`docs/api/openapi.yaml`)
- `vnc-remote secrets check` command for TLS and file permission validation
- `/audit` and `/audit/verify` endpoints for audit log access
- Centralized error handling with error code registry (`core/errors.py`)
- Idempotency tests for config loading and profile application
- Monitoring runbook (`docs/runbook/monitoring.md`)
- Migration guide (`docs/migration/README.md`)
- **Let's Encrypt issuance**: `security/certificates.py::request_letsencrypt()`
  requests real certificates via certbot (nginx plugin, standalone fallback)
  when `DUCK_DOMAIN`+`EMAIL` are set — restores parity with the legacy
  `make ssl-setup` flow.
- **Alert dispatch** (`monitoring/alerts.py`): Discord embeds, generic JSON
  webhook, and SMTP email channels gated by `ALERTS_ENABLED`; fired on
  service start failures and watchdog state transitions.
- **Per-service watchdog** (`service_manager.watchdog_tick`): runs inside
  `vnc-remote service --run` and `start --foreground`, checks all enabled
  services every `HEALTHCHECK_INTERVAL` seconds, and restarts dead
  services when `AUTO_RESTART=true`.

### Changed
- **Rate limiting consolidated**: `rate_limiting.py` removed; all rate limiting
  is now in `rate_limit.py` (canonical module with both RateLimiter class
  and check_rate_limit function).
- Auth gateway now writes structured audit entries for all login attempts
- Flask app applies security headers to all responses via `after_request`
- ROADMAP updated to reflect completed items
- **Dead code pruned (Python)**: removed `lifecycle.health_check()`,
  `lifecycle.is_running()`, `service_manager.is_running()`,
  `auth_gateway.logout()`, `set_permissions()` in both platform
  `permissions.py` modules, and the unused `install_service`/`start_service`/
  `stop_service`/`service_status`/`configure_firewall`/`configure_permissions`
  methods from `PlatformAdapter` and both adapters (the canonical installers
  in `platform/{linux,windows}/installer.py` use standalone functions).
- **Dead code pruned (Bash)**: removed unused `INDEX_FILE`/`VNC_FILE`
  exports; wired previously-unconnected alert/notify hooks
  (`alert_service_failure`, `alert_ssl_expiry`, `alert_ssl_renewal`,
  `alert_system_error`, `alert_cleanup`, `alert_shutdown`, `notify_ssl_expiry`,
  `notify_ssl_renewal`, `notify_cleanup_complete`, `notify_shutdown`,
  `monitoring_status`, `validate_dependencies`, `update_system_packages`,
  `show_logs`, `validate_input`) into their corresponding call sites.
- **SMTP alert fallback**: `send_email_alert()` now uses `ALERT_SMTP_*`
  config via a Python `smtplib` fallback when `mail`/`sendmail` are absent.
- **Backup listing**: `vnc-remote backup --list` lists available backups
  (previously `list_backups()` was unused).

### Fixed
- `pyproject.toml`: removed Python 3.8/3.9/3.10 classifiers, set ruff/black
  target to py311 (was contradicting requires-python>=3.11).
- SameSite cookie policy: Flask and sessions.py both default to Lax
  (was inconsistent: Flask=Lax, sessions.py=Strict).
- ADR-0007: documented Windows process isolation limitation honestly.
- `start --foreground` used `signal.pause()` which does not exist on
  Windows — the Windows Service path now runs a portable watchdog loop.
- Maintenance scripts (`update.sh`, `cleanup.sh`, `install_systemd.sh`,
  `health-check.sh`, `duckdns_update.sh`) computed `PROJECT_DIR` one
  level too shallow — `.git` detection, `.env` loading, and `make`
  invocations silently failed.
- `native/linux/bin/vnc-remote` resolved the project root two levels too
  shallow and used invalid `exec VAR=val cmd` syntax — it now sets
  `PYTHONPATH` correctly and prints the real version.
- `rpi-vnc-remote.sh`: unreachable `exit 1` after `exec` made unknown
  commands return 0.
- `VncRemote.ps1`/`VncRemote.psm1`/`commands/*.ps1` now set `PYTHONPATH`
  to the source checkout when the package is not pip-installed.
- `__init__.py` version fallback reads `pyproject.toml` instead of
  reporting a hardcoded `0.0.0` in source checkouts.
- `Dockerfile`: quoted pip version specifiers (`>=` was interpreted as
  a shell redirect, producing unpinned installs), added the `test` stage
  used by `compose.integration.yml`, and `CMD` now runs
  `start --foreground` so the container stays alive.
- `.dockerignore` no longer excludes `tests/` (needed by the test stage).
- CI workflows no longer reference deleted test scripts
  (`test_module_loading.sh`, `test_script_load.sh`, `test_security.sh`);
  the `bash-tests` job now installs Python + the package first.
- Removed dead config keys (`MONITORING_ENABLED`, `PROMETHEUS_PORT`,
  `GRAFANA_PORT`, `NODE_EXPORTER_PORT`) that were parsed but never
  consumed.
- `health-check.sh` and `generate_certificate.py` converted to thin
  delegators (canonical logic lives in `core/doctor.py` and
  `security/certificates.py`); `duckdns_update.sh` marked deprecated.
- `run_tests.sh` dropped dead Bats/`tests/shell/` support.
- `generate_certificate.py` wrote certs to `scripts/utilities/data/ssl/`
  (unread location) and auto-pip-installed at runtime — now delegates to
  the canonical package function.
- `.editorconfig`/pre-commit shfmt now agree on 4-space indentation for
  shell files (was: hooks normalized to tabs while `format.sh` wrote
  spaces).
- Self-signed certificates now include SAN entries
  (`localhost`/`127.0.0.1`) so browsers accept them.
- Health server (`services/health.py`) now also serves `/metrics`,
  `/audit` and `/audit/verify` — the endpoints OpenAPI/documents claim
  live on the health port (they were Flask-blueprint-only before).
- `load_env_file()` no longer lets `.env` override real environment
  variables for keys that also appear in the platform defaults (e.g.
  `USER_UI_ENABLED`) — real env now always wins, as documented.
- `SESSION_COOKIE_SECURE` now defaults to the TLS state instead of
  always `true` — a Secure cookie on `--no-ssl` deployments made the
  login flow impossible.
- `create_web_session()` now stores a `TOKEN_TYPE_SESSION` cookie value
  instead of a bearer token — the user-management UI login previously
  succeeded but every authenticated request bounced back to `/login`.
- `posture`: `WEAK_USER_UI_PASSWORD` only blocks when
  `USER_UI_ENABLED=true` (a disabled feature's password must not block
  startup).
- `service_manager`: `status` maps `audio` to `audio_stream_port` (was
  the nonexistent `audio_port` key → audio always reported "down").
- `services/health.py`: optional services (`user_ui`, `audio`,
  `gamepad`) are now port-probed when enabled — `status`/`/health/*`
  previously reported them "down" unconditionally.
- **novnc no longer serves the project root**: `_start_novnc` resolves
  the noVNC assets dir (`NOVNC_DIR` or `<project>/novnc`) and refuses to
  start without one; `services/novnc.py` exits instead of defaulting to
  `.` — the previous behaviour exposed `.env` and the full source tree
  to any authenticated client.
- `services/landing.py`/`terminal.py`: removed stray
  `sys.path.insert(dirname(__file__))` entries.
- `audit.py` writes `audit.jsonl` to the canonical `get_log_dir()`
  (was package-relative `../logs`), resolved lazily.
- Single `find_project_root()` implementation in `core/paths.py`;
  `cli.py`, `config.py`, `config_inspector.py`, `file_permissions.py`
  delegate to it (works for pip-installed layouts too).
- `core/sessions.py` renamed to `core/vnc_sessions.py` (display-session
  registry, distinct from `security/sessions.py` HTTP sessions).
- **noVNC desktop connection restored**: `websockify` now runs as a
  managed loopback-only service (`NOVNC_WS_PORT`, default 5700) bridging
  WebSocket to the VNC server; the authenticated noVNC server proxies
  `/websockify` upgrades to it after the auth-gateway check (the
  endpoint previously 404'd — the page loaded but could never connect).
  `websockify` is also declared in `pyproject.toml` dependencies.
- **Shareable session links work in browsers**: `session create` URLs
  (`/?session=<token>`) are now exchanged at the landing page —
  `activate_ephemeral_session()` burns the link once and issues a
  `vnc_ephemeral` cookie; `check_session_permission()` authenticates
  subsequent requests against the session object, preserving role,
  `view_only`, `no_terminal`, resource binding and `allowed_ip`.
  Previously nothing consumed `?session=` — the link only worked as a
  raw Bearer header (unusable from a browser).
- `single_use` semantics clarified: the *link* burns on first exchange
  while the activated session lives until TTL (direct Bearer use keeps
  the original consume-on-check behaviour).
- `services/landing.py`: `self.request.headers` bug in the session
  exchange fixed (`self.request` is the socket, not the request).
- `core/validation.py` validators wired into the Let's Encrypt path of
  the Linux installer (`validate_domain`/`validate_email` before
  invoking certbot).
- `native/linux/bin/vnc-remote`: no longer `exec`s itself when its own
  directory is on PATH (infinite recursion guard).
- `core/config.py`: `load_env_file()` now also discovers the system
  config (`/etc/vnc-remote-secure/config.env` on Linux,
  `%ProgramData%\VncRemoteSecure\config.env` on Windows). Manual CLI
  invocations on packaged installs previously ran with defaults only —
  the service saw `/etc` config via `EnvironmentFile=` but the CLI did
  not. Precedence: real env > project `.env` > system `config.env` >
  platform defaults.
- `core/config.py`: SSL fallback now resolves `get_ssl_dir()`
  (platform-canonical) first, then legacy `<project>/data/ssl`;
  `windows.env` no longer pins relative `SSL_CERT`/`SSL_KEY` paths.
- `platform/windows/installer.py`: copies the package to
  `%ProgramData%\VncRemoteSecure\src`, writes a `service-run.py`
  launcher, and seeds `config.env` from `.env.example` — the sc.exe
  service can now import the package without pip install or PYTHONPATH
  (sc services cannot set env vars).
- `platform/windows/services.py`: `_resolve_service_binary()` prefers
  the `service-run.py` launcher; `service-config.xml` updated to match.
- `core/doctor.py`: checks Python module dependencies (websockify,
  flask, tornado, websockets, cryptography), not just binaries.
- `services/landing.py`: status.json reports the websockify bridge;
  audio/gamepad cards appear when those features are enabled.
- `cli.py session create`: the generated URL now uses
  `http://<host>:<landing_port>` when nginx+TLS is not deployed instead
  of always producing `https://` links.
- `.env`: removed dead variables from removed features (MONITORING_*,
  PROMETHEUS/GRAFANA/NODE_EXPORTER ports, RECORDING_*, INDEX_FILE,
  VNC_FILE).
- `security/file_permissions.py`: Windows check no longer
  false-positives on every file under `C:\Users\` — it parsed icacls
  output for the substring `\users`, which matches the *path header*
  itself. Now parses ACE `principal:(perms)` entries and covers
  localized group names (Everyone/Todos, Users/Usuarios).
- `cli.py secrets check --fix`: new flag that repairs flagged file
  permissions via `fix_secret_file_permissions()` (the function existed
  but was never invoked — `secrets check` could only report, never
  repair).
- `platform/windows/installer.py::_find_ultravnc()`: also searches
  `<project>/bin/ultravnc/<arch>/` (where `download_dependencies.py`
  extracts the verified archive) — previously VNC failed to start even
  though the binary was present and checksum-verified.
- `tools/verify_dependencies.py`: skips platform-inappropriate
  manifests (ttyd on Windows, UltraVNC on Linux) and reports
  `managed_by: manual` deps as SKIP instead of MISSING — the tool no
  longer fails permanently on Windows dev machines.
- `launch.sh`: delegates to `python -m vnc_remote_secure.cli` of the
  checkout, not a possibly-installed system `vnc-remote` (which would
  point at /opt instead of the working tree). Same fix applied to
  `scripts/maintenance/{backup,restore,uninstall,health-check}.sh`
  (checkout wrapper → `python -m` → system `vnc-remote` last).
- `services/health.py`: health endpoint now uses
  `ThreadingHTTPServer` — a single hung keep-alive probe no longer
  blocks every other health check.
- `security/ephemeral_sessions.py`: `SessionStore.get()` and
  `revoke()` reload the persistence file on cache miss, so sessions
  created by other processes (CLI) after this process started are
  discoverable without waiting for `activate`'s explicit reload.
- `monitoring/prometheus.py`: `vnc_remote_auth_attempts_total` now
  mirrors increments into the shared-state backend — auth attempts
  recorded in other service processes are visible in `/metrics`
  (previously process-local only, so the counter was always empty
  on the health endpoint).
- `core/doctor.py`: added `ports.websockify` probe and made
  `deps.vnc_server` use the same `_find_ultravnc()` discovery as the
  adapter (env → install dir → PATH → project `bin/ultravnc/`).
- `cli.py`: bare `vnc-remote session`/`secrets`/`config` now print
  argparse usage (`required=True` subparsers) instead of
  "Unknown action: None".
- `scripts/maintenance/update.sh`: apt fallback deps now include
  `python3-websockify`, `python3-tornado`, `python3-flask`.
- `scripts/release/build.sh`: resolves version with the checkout's
  `src` on PYTHONPATH (matches build.ps1), fails clearly when the
  version cannot be determined instead of silently tagging `0.0.0`,
  prefers `python` over `python3` (WSL `python3` lacks `build`), and
  treats egg-info cleanup as best-effort.
- `packaging/windows/build-installer.ps1`: warns that the produced
  MSI is an empty skeleton (no payload files) instead of claiming a
  finished build.
- `docs/installation/windows.md`: documents the winvnc.exe search
  order including the project `bin/ultravnc/<arch>/` fallback.
- `docs/api/openapi.yaml`: documents the `/health_status` and
  `/health_status.json` legacy aliases.
- `tests/integration/common/test_config_loading.py`: asserts
  `novnc_ws_port` is present in the loaded config.
- `tests/unit/platform/test_windows_installer.py`: isolates the
  project-bin fallback so a real `bin/ultravnc` in the checkout can't
  leak into tests, and adds coverage for that fallback path.
- `security/auth_gateway.py`: `check_websocket_upgrade` now forwards
  `resource` to `check_permission` — ephemeral bearer tokens bound to
  a resource (e.g. desktop-only) can no longer satisfy a permission
  check for a different resource (e.g. terminal). Also,
  `get_allowed_origins()` now includes every browser-facing local
  service port (landing, noVNC, terminal, health, user UI) so direct
  non-nginx access keeps working while foreign origins stay blocked.
- `services/novnc.py`: the `/websockify` upgrade now validates the
  `Origin` header before proxying (CSWSH protection — the upgrade
  carries ambient cookies), and registers ephemeral-cookie
  connections in the WebSocket registry so revoking an ephemeral
  session kills its live desktop stream (previously only
  `vnc_session`/bearer tokens were extracted, leaving ephemeral
  streams immune to revocation).
- `security/ephemeral_sessions.py`: `is_session_revoked()` and
  `is_session_expired()` now reload the persistence file before
  checking — a session revoked by another process could previously
  read as valid from a stale in-memory cache at other call sites.
- `security/http_headers.py` + `services/{landing,novnc,health,terminal}.py`
  + `web/application.py`: security headers (CSP, X-Frame-Options,
  nosniff, Referrer-Policy, Permissions-Policy) are now applied to
  every HTTP response from the landing portal, noVNC server, health
  service, Tornado terminal, and the SimpleWebApp fallback —
  previously only the Flask user-management app emitted them.
- `config/nginx.conf` + `platform/linux/installer.py`: the nginx
  template now includes `location /` proxying to the landing portal
  (it was missing — the portal and the `/?session=` share-link
  exchange were unreachable through nginx), plus `/audio/` and
  `/gamepad/` for the optional streams, and `X-Forwarded-Host` on all
  proxied locations.
- `services/landing.py`: the portal detects `X-Forwarded-Host`/
  `X-Forwarded-Proto` and renders service links as the public nginx
  paths (`/vnc/`, `/terminal/`, `/health`) — the direct
  `127.0.0.1:<port>` links only work for clients on the server
  itself since backends bind loopback.
- `platform/windows/adapter.py`: `start_vnc_server` no longer passes
  TigerVNC-style flags UltraVNC doesn't have (`-passwordfile`,
  `-geometry`, `-depth` — all silently ignored). It now renders the
  managed keys into `ultravnc.ini` next to winvnc.exe (the actual
  UltraVNC config mechanism in `UseRegistry=0` file mode): the
  DES-encrypted RFB password in the classic vncpasswd format
  (fixed-key DES, replacing a shipped default `vnc12345`
  credential), `passwd`/`passwd2` rewritten in EVERY ini section so
  no stale credential survives, `QueryAccept=0` so unattended
  connections are not gated on a console prompt (previously the VNC
  port never accepted connections), and `PortNumber`/
  `HTTPPortNumber` from config. Dead `_write_vnc_password_file`
  removed.
- `core/service_manager.py`: `restart_all(None)` crashed with
  `'NoneType' object has no attribute 'get'` — `vnc-remote restart`
  was broken; config is now resolved like `start_all` does.
- `services/terminal.py`: the Tornado WebSocket `check_origin` hook
  used a private origin list that rejected `DUCK_DOMAIN`/
  `ALLOWED_ORIGINS` origins — the terminal WS would have failed for
  browsers arriving through nginx. It now delegates to the canonical
  `auth_gateway` origin functions (plus `ALLOWED_LAN_IPS`).
- `security/profiles.py`: warns when `MFA_REQUIRED=true` but neither
  `TOTP_SECRET` nor `RECOVERY_CODES_HASHES` is set — every login
  would fail MFA (silent lockout).
- `vendor/d3des.py`: new `encrypt_vnc_password()` producing the real
  vncpasswd format (padded password DES-encrypted under the fixed
  VNC key) — verified against a real `ultravnc.ini` vector. The
  previous "encrypt the password with itself" output matched no VNC
  server. `platform/linux/adapter.py::_write_vnc_password_file` now
  uses it too, so TigerVNC `-PasswordFile` auth actually accepts the
  configured password.
- `services/vnc.py`: on Windows the port-availability check now
  probes the configured `VNC_PORT` (UltraVNC binds it directly);
  the TigerVNC-style `base + display` offset produced a wrong port
  (`VNC_DISPLAY=:2` → checked 5902 while UltraVNC binds 5900).
- `platform/base.py` + `platform/{linux,windows}/adapter.py`:
  removed dead `stop_vnc_process` — the service manager's
  `_kill_pid` is the single stop path (same taskkill/kill calls).
- `security/certificates.py`: `create_ssl_context()` now falls back
  to the canonical SSL dir (`get_ssl_dir()`) and legacy
  `<project>/data/ssl` — the same discovery `_get_ssl_config` does.
  Previously only services passing config-derived paths (landing,
  terminal) terminated TLS while env-only callers (novnc, health)
  stayed plain HTTP even with `TLS_ENABLED=true` and certs on disk —
  a mixed-TLS deployment where the origin allow-list also rejected
  the HTTPS schemes.
- `security/auth_gateway.py`: allowed origins now include both
  `http://` and `https://` variants for each local service port —
  direct HTTPS access (when certs exist) produced origins the list
  rejected, breaking the `/websockify` upgrade over TLS.
- `security/step_up_auth.py`: added `delete_admin` to
  `SENSITIVE_ACTIONS`; `web/routes/users.py` `/delete_user` was
  checking step-up under the `create_admin` action, mislabeling
  audit events. The `/api/users` POST/DELETE routes performed the
  same privileged operations with NO step-up at all — they now
  require it (`create_admin`/`delete_admin`) like the HTML routes.
- `cli.py session create`: the generated share URL used `http://`
  for direct landing access even when landing serves TLS; it now
  resolves `create_ssl_context()` (same source of truth as the
  service) and emits `https://` when certs exist.
- `core/uninstall.py`: on Windows, uninstall now also removes the
  ProgramData-root artifacts (`src/` package copy, `service-run.py`,
  seeded `config.env`) that lived outside the standard subdirs, and
  removes the Windows Service under its real name `VncRemoteSecure`
  (the 'vnc-remote' systemd name was passed unconditionally, leaving
  the service registered).
- `services/audio.py` + `services/gamepad.py`: upgrade-header
  extraction used `websocket.handler.request.headers`, which does not
  exist on websockets>=13 — every connection was rejected after the
  fallback produced empty headers. They now try
  `connection.request.headers` (modern), then `request_headers`
  (legacy), then the ancient `handler.request` path. `pyproject.toml`
  pin widened to `websockets>=12.0,<17.0`.
- `security/profiles.py`: new `TLS_CERT_MISSING` blocking finding —
  TLS-enabled profiles used to start cleartext when the flag was set
  but no cert/key pair resolved.
- `security/http_headers.py`: `send_security_headers` auto-detects
  TLS from the accepted socket (`ssl.SSLSocket`), so HSTS is now
  emitted on all TLS-serving services; terminal stores the resolved
  flag on the app. Previously `tls_enabled=False` was hardcoded
  everywhere and HSTS was never sent.
- `security/http_auth.py`: `check_landing_auth` accepts `client_ip`
  and feeds the shared auth rate limiter; landing Basic auth had no
  brute-force protection (verified live: lockout rejects even correct
  credentials after repeated failures). `require_auth` passes the
  remote address to checkers that accept it.
- `VncRemote.ps1`: dispatch no longer double-appends
  `--dry-run/--json/--verbose` (Invoke-PythonCli adds them once).
- `native/windows/commands/`: `Install-VncRemote.ps1` dropped the
  dead `-InstallPath`/`-Force` params (`--force` does not exist in
  the Python CLI) and `Uninstall-VncRemote.ps1` dropped dead
  `-RemoveConfig`; matching Pester tests updated.
- `security/auth_gateway.py::check_origin`: the `ALLOWED_LAN_IPS`
  exception moved from `services/terminal.py` into the gateway so
  every WebSocket service enforces the same origin policy (LAN
  clients got 403 on noVNC/audio/gamepad before).
- `services/landing.py`: the `vnc_ephemeral` cookie is marked
  `Secure` on direct-TLS exchanges (SSLSocket detection), not only
  behind `X-Forwarded-Proto: https`.
- `web/routes/landing.py`: Flask landing now implements the same
  `?session=` share-link exchange as the `http.server` landing
  (activate, burn single-use, set cookie, redirect, `Cache-Control:
  no-store`, 403 on invalid) instead of 401ing valid share links.
- `web/application.py`: `SESSION_COOKIE_SECURE` now follows the
  resolved TLS state (env flag AND cert discovery), so a
  `TLS_ENABLED=true` deployment without certs does not emit a
  Secure cookie the browser would never return over cleartext.
- `web/routes/users.py` `/login`: now delegates to
  `auth_gateway.attempt_login`, which enforces per-IP/per-user
  lockouts, MFA/TOTP (`MFA_REQUIRED`), recovery codes, audit events
  and auth counters — the previous `authenticate()` call skipped
  all of them. `login.html` renders the error message and an MFA
  field when required.
- `security/authentication.py`: `USER_UI_USERNAME`/`USER_UI_PASSWORD`
  take precedence over the shared `TTYD_*` credentials for the
  management-UI login (previously the terminal password silently
  won over the dedicated UI password).
- `security/ephemeral_sessions.py`: audit events added for session
  create/activate/revoke — the lifecycle was invisible in the
  audit trail.
- `core/config.py`: `load_env_file()` is idempotent for the default
  merge (was re-parsing three env files on every request through
  the per-request auth path).
- `core/config_inspector.py`: `CREDENTIAL_VARS` now covers
  `LANDING_PASSWORD`, `USER_UI_PASSWORD`, `BACKUP_PASSWORD`,
  `ALERT_SMTP_PASS`, `ALERT_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL` —
  `config show-effective` printed them in plaintext before.
- `core/backup.py`: encryption failure now raises instead of
  silently keeping a plaintext archive when `BACKUP_PASSWORD` was
  explicitly configured.
- `core/doctor.py`: the Windows firewall check reports OK (not a
  warning) on loopback-only deployments where no rules are needed.
- `config/nginx.conf` + `platform/linux/installer.py`: all backend
  `proxy_pass` lines now use `*_BACKEND_PROTOCOL` variables whose
  default resolves to `https` when the services terminate TLS
  (novnc, ttyd, landing, audio, gamepad, health) — plain-HTTP
  proxying to TLS backends produced 502s.
- `cli.py secrets rotate`: now persists the new value into the
  project `.env` (previously it set only `os.environ`, so the
  rotation evaporated on exit and the value was never shown), and
  covers all env-var secrets (was limited to four).
- `tests/conftest.py`: the default `load_env_file()` merge is a
  no-op during tests so the developer's real `.env` can no longer
  change test outcomes (a present `LANDING_PASSWORD` turned
  fallback-app tests into 401s).
- `scripts/utilities/generate_vnc_password.py`: rewritten to
  delegate to `vendor.d3des.encrypt_vnc_password` — both of its
  hand-rolled variants produced `8CAAC2ECA578C62A` for `vnc12345`,
  which no VNC server accepts (the real value is `F50F904B11EE3F7C`).
  Removed `scripts/utilities/configure_ultravnc_gui.py` (dead
  win32-GUI automation superseded by the `ultravnc.ini` rendering).
- `monitoring/prometheus.py`: labeled metrics emitted double braces
  (`vnc_remote_up{{service="vnc"}}`) — invalid Prometheus exposition
  format — because `_format_labels()` already returns the braces.
- `security/file_permissions.py`: the secret-file scan now covers
  the canonical platform ssl dir (`get_ssl_dir()`), the system
  `config.env`, and `ultravnc.ini` — it previously only globbed
  project-relative paths and missed the deployed private key.
- `security/certificates.py`: `_restrict_key_permissions()` —
  `os.chmod(0o600)` is a no-op on Windows ACLs, so generated
  `privkey.pem` stayed readable by the `Users` group; icacls now
  restricts it to owner/SYSTEM/Administrators via universal SIDs.
- `platform/windows/permissions.py`: `create_user`/`set_user_password`
  pipe the password through stdin instead of embedding it in the
  powershell command line (readable by any process via WMI).
- `web/application.py`: the development-profile Flask secret now
  reuses the persisted `auth_secret.key` instead of an ephemeral
  `token_hex`, so sessions survive restarts like every other token.
- `core/config.py`: generated `VNC_PASSWORD` is 8 chars (DES limit)
  so the runtime stops warning about its own generated password.
- `security/posture.py`: the SSL-certificate check resolves the
  canonical ssl dir (same as `create_ssl_context()`), not only the
  `SSL_CERT`/`SSL_KEY` env vars.
- `core/service_manager.py`: `status` reports `NGINX_HTTPS_PORT`
  instead of a hardcoded 443.
- `native/linux/systemd/vnc-remote.service`: `EnvironmentFile` made
  optional (`-` prefix) so a missing config.env cannot block the unit.
- `native/windows/service/service-config.xml`: service name aligned
  with the real registration (`VncRemoteSecure`, not
  `vnc-remote-secure`).
- `config/schema/config.schema.json`: added `PUBLIC_BIND_HOST`
  (profile-set key that was missing from the schema).
- `security/consent.py` + `test_consent.py`: removed — a fully
  implemented consent state machine with zero runtime callers and
  no local approval surface; dead feature code.
- `security/ephemeral_sessions.py`: cross-process revocation now
  propagates to already-cached sessions — `_load_if_changed()`
  reloads the session file when another process rewrote it (mtime),
  so `vnc-remote session revoke` takes effect immediately in the
  landing/novnc/terminal service processes.
- `cli.py session revoke`: accepts the token positionally as well
  as via `--token` (the previous required-flag form silently
  confused callers passing it positionally).
- `core/service_manager.py` `_pid_alive()`: matches the exact CSV
  PID field from `tasklist` instead of a bare substring (pid 12
  would match pid 12345).
- `security/tls_validation.py`: removed `DH` from the weak-cipher
  substring list — it flagged strong ECDHE/DHE suites as weak.
- `core/backup.py` `_collect_paths()`: the system `config.env`
  (ProgramData / `/etc/vnc-remote-secure`) is now included.
- `security/redaction.py` `SECRET_VARS` is now the canonical secret
  list — `config_inspector.CREDENTIAL_VARS` aliases it (the two
  copies had drifted: `BACKUP_PASSWORD`/`RECOVERY_CODES_HASHES`
  missing from redaction).
- `security/auth_gateway.py`: recovery codes are now SINGLE USE —
  the matched hash is removed from `RECOVERY_CODES_HASHES` and
  persisted via the new `core/config.py::set_env_persistent()`
  helper (previously a captured code was reusable forever).
- `cli.py secrets rotate`: deduplicated onto `set_env_persistent()`.
- `security/shared_state.py`: SQLite backend now uses WAL journal
  mode + `busy_timeout` — the default DELETE journal surfaced as
  "database is locked" under concurrent multi-process access.
- `platform/windows/installer.py`: `_ensure_ultravnc()` now verifies
  the extracted `winvnc.exe` SHA-256 against
  `third_party/manifests/ultravnc.json` — the download was previously
  installed unverified.
- `.github/workflows/security.yml`: `trivy-action` pinned to
  `@0.28.0` instead of `@master`.
- `native/windows/commands/Start-VncRemote.ps1`: `-NoSSL` now sets
  `DISABLE_SSL=true` alongside `TLS_ENABLED=false` (CLI `--no-ssl`
  parity).
- `security/certificates.py::_restrict_key_permissions` gained a
  `writable` flag (icacls `(R,W)` vs `(R)`) — applied to
  `auth_secret.key`, `audit.jsonl`, `ephemeral_sessions.json`,
  `shared_state.db` and the seeded `config.env`, all of which were
  readable by the `Users` group on Windows (session hijack / token
  forgery).
- `security/file_permissions.py`: `fix_secret_file_permissions` on
  Windows now grants SYSTEM+Administrators+user via universal SIDs
  (the previous USERNAME-only grant locked out services running as
  SYSTEM); coverage extended to the runtime secret files.
- `security/mfa.py`: TOTP codes are now single-use — the consumed
  counter is persisted via shared state and counters at or below it
  are rejected (replay inside the drift window, NIST 800-63B).
- `security/profiles.py`: hardened profiles now LOCK `TLS_ENABLED`,
  `DISABLE_SSL`, `MFA_REQUIRED` and `NGINX_ENABLED` alongside
  `BACKEND_BIND_HOST` — user-set values no longer silently weaken a
  hardened deployment.
- `core/doctor.py`: `tls.certificates` check now resolves the
  canonical ssl dir (same as `create_ssl_context`), no longer
  warning when `SSL_CERT`/`SSL_KEY` env vars are unset.
- `monitoring/alerts.py`: webhook URLs are redacted in logs (the URL
  embeds the credential); SMTP STARTTLS is attempted whenever
  supported (`ALERT_SMTP_TLS`, default on) instead of only when auth
  is configured.
- `security/shared_state.py`: the `-wal`/`-shm` SQLite sidecars now
  get the same restricted ACLs as the main db — they hold identical
  data and were created with inherited (Users-readable) permissions.
- `monitoring/prometheus.py`: `_shared_counters()` merge now prefers
  the cross-process shared value over the process-local one — the
  previous order undercounted counters incremented by other
  processes.
- `web/routes/users.py`: login regenerates the Flask session
  (`session.clear()`) before populating it — pre-login keys could
  otherwise carry over into the authenticated session (fixation).
- `security/authentication.py`: `authenticate()` now performs exactly
  one expensive verification per attempt (real hash or dummy) — the
  early return on an unknown username leaked its validity via timing.
- `cli.py start --no-ssl`: refused under hardened profiles
  (`public-hardened`/`private-overlay`/`trusted-lan`) and applied
  before `startup()` — previously it ran after `apply_profile()` and
  silently defeated the TLS lock.
- `cli.py restart`: now calls `startup()` + `get_blocking_findings()`
  like `start` — a fresh `restart` process previously skipped the
  hardened-profile locks and blocker checks.
- `cli.py config migrate`: key-aware rewrite instead of substring
  `str.replace` — `MY_CERT_FILE` was corrupted to `MY_SSL_CERT`, and
  profile-value aliases on a renamed `VNC_REMOTE_PROFILE` line are
  now migrated too.

## [0.2.0] - 2026-09-11

### Added
- Unified HTTP authentication model (`security/http_auth.py`) shared across all services
- Shared SSL/TLS context creation (`security/certificates.py::create_ssl_context()`)
- Unified Flask JSON error envelope (`core/errors.py::error_json_response()`, aliased as `json_error`)
- Optional health endpoint authentication via `HEALTH_AUTH_TOKEN`
- Sanitized environment for terminal subprocesses (no secret leakage)
- Cross-platform test runner with Windows Python fallback from WSL

### Changed
- Migrated landing, terminal, and health services to shared auth helpers
- All 7 HTTP/WebSocket services now support TLS consistently via `create_ssl_context()`
- Flask routes return unified JSON error schema
- `Firewall.ps1` parameter `Action` no longer mandatory (defaults to `List`)
- CRLF-safe `.env` loading in all Bash scripts
- `run_tests.sh` detects and uses Windows Python from WSL
- `shellcheck` test skips gracefully when not functional

### Fixed
- `subprocess.CREATE_NO_WINDOW` now conditional on Windows (was crashing Linux)
- Flask health and landing routes now require authentication
- `VncRemote.ps1` correctly finds `bash.exe` in Git for Windows
- `VncRemote.ps1` uses `vnc-remote` instead of deprecated `launch.sh`
- `launch.sh` respects `KEEP_TEMP_USER` from `.env` (was forced to `true`)
- `config.sh` fallback password no longer generates the prohibited `ChangeMe!` pattern
- `common.env` no longer forces Windows ports on Linux
- Removed unused `pycryptodome` dependency; added `werkzeug`
- Dead variables removed from `landing.py`

## [0.1.0] - 2026-09-11

### First public release

Initial release of VNC Remote Secure — secure, browser-based remote access
to Linux/Raspberry Pi and Windows machines.

### Added
- Modular Bash architecture (`src/lib/` with 6 categories: core, security, web, monitoring, communication, platform)
- noVNC desktop access via browser (TigerVNC on Linux, UltraVNC on Windows)
- Web terminal (ttyd on Linux, Tornado-based on Windows)
- SSL/TLS support with self-signed or Let's Encrypt certificates
- Duck DNS dynamic DNS integration (cross-platform: Bash + Python scripts)
- Health monitoring dashboard with real-time system metrics
- Landing page portal with service links and status
- Temporary user isolation on Linux (created on start, removed on exit)
- Rate limiting and Fail2ban support
- Session recording (limited functionality, not fully implemented — see docs)
- Backup and restore scripts with SSL path consistency
- Test pyramid: 116 tests across 5 levels (static, unit, integration, e2e, security)
- CI/CD pipeline: parallel lint, test, security scanning, multi-arch
- Pre-commit hooks: shellcheck, shfmt, ruff, black, yamllint, CRLF detection
- Windows local/LAN support (UltraVNC + Python stack with documented limitations)
- Bluetooth audio streaming (server → client headphones via WebSocket + ffmpeg)
- Bluetooth gamepad forwarding (client gamepad → server input via WebSocket)
- Systemd service units with security hardening (NoNewPrivileges, ProtectSystem, etc.)
- Full uninstaller (reversible installation: removes services, nginx config, certs, users)
- Professional documentation: README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, ROADMAP
- GitHub issue templates (bug report, feature request, security report)
- Pull request template with checklist
- `.editorconfig` and `.gitattributes` for consistent line endings
- CI security scanning: Gitleaks (secret detection), Trivy (container/filesystem)

### Security
- Removed all hardcoded credentials from Python and Bash files
- Landing page no longer exposes passwords in HTML or JSON
- Fixed Cross-Site WebSocket Hijacking (CSWSH) in `src/vnc_remote_secure/services/terminal.py`
- Fixed timing attack in auth: uses `hmac.compare_digest()`
- VNC server binds to localhost when nginx is enabled (was: all interfaces)
- ttyd credentials read from temp file (not command-line args) to avoid process list exposure
- Flask error messages no longer expose raw exception text
- Rate limiter supports `X-Forwarded-For` only under trusted proxy configuration
- Password validation rejects weak passwords (changeme, admin123, etc.)
- SSL certificate and key files never committed (gitignored)

### Changed
- Consolidated `launch.sh` and `launch_nossl.sh` into single script with `--no-ssl` flag
- Makefile reorganized with categorized help and prerequisite validation
- `.gitignore` expanded to cover all runtime artifacts, logs, caches, and temp files
- Python tooling centralized in `pyproject.toml` (black, ruff configuration)
- `update.sh` respects current git branch (was: hardcoded main/master)
- `cleanup.sh` uses safe nullglob and quoted array expansion
- `health-check.sh` validates non-empty env vars (was: accepted empty values)
- Portable password generation with OpenSSL/urandom/Python fallbacks

### Compatibility
- **Linux/Raspberry Pi**: Raspberry Pi OS (64-bit), Ubuntu 22.04+, Debian 12+
- **Windows**: Windows 10+ with Git Bash, Python 3.11+, UltraVNC binaries
- **Client**: Any modern web browser (Chrome, Firefox, Safari, Edge)
