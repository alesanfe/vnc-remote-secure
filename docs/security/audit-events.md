# Audit Event Catalog

Canonical catalog of events written to the tamper-evident audit log
(`<log_dir>/audit.jsonl`). Every entry is a JSON line containing:

| Field | Description |
|-------|-------------|
| `ts` | ISO-8601 timestamp |
| `event` | Event name (see tables below) |
| `user` | Authenticated actor or `unknown` |
| `ip` | Client IP (when available) |
| `result` | `success` / `failure` |
| `detail` | Event-specific context (never contains secrets) |
| `prev_hash` / `hash` | Chain link for tamper evidence |

The chain is anchored by a genesis entry, verified on startup, and
rotated at `AUDIT_LOG_MAX_BYTES` (default 10 MiB). An optional mirror
can be configured with `AUDIT_MIRROR_FILE`.

## Authentication & sessions

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `login` | Legacy env-credential login attempt — success, bad credentials, lockout, MFA required/invalid | info / warning on failure |
| `operator_login` | `POST /api/v1/auth/login` and `/auth/passkey/complete` — detail carries `method=password|webauthn` | info / warning on failure |
| `operator_session_issued` | The portal mints a `vnc_op` operator session cookie | info |
| `portal_logout` | `POST /api/v1/logout` revokes the operator session | info |
| `legacy_session_refresh_rejected` | A `vnc_session` cookie fails structural/epoch checks | warning |
| `session_revoked` | `security.revocation` revokes a session mark | warning |
| `session_revoke_failed` | A revocation could not be recorded | warning |
| `revocation_index_invalid_sid` | A malformed sid reached the revocation index | warning |
| `auth_policy` | `security.auth_policy.evaluate` denied an action | warning |
| `api_permission_denied` | A use case refused a capability/policy violation | warning |
| `portal_permission_denied` | The portal gate rejected a mutation on capability grounds | warning |
| `webauthn_register` / `webauthn_assert` | WebAuthn ceremonies (registration / assertion) | info / warning on failure |
| `signing_key_rotate` | `security.authentication` rotated the HMAC signing key | warning |

## Step-up authentication

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `step_up_required` | A step-up-gated route was hit without a recent-auth mark | warning |
| `step_up_granted` | `POST /api/v1/step-up` verified the operator password | info |
| `step_up_denied` | Step-up verification failed | warning |

## Ephemeral share-link sessions

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `ephemeral_session_create` | A share link is issued (CLI `session create` or `POST /api/v1/sessions`) | info |
| `session_preview` | `POST /api/v1/session/preview` returned a grant preview (rate-limited) | info |
| `ephemeral_session_activate` | A share link is exchanged for the `vnc_ephemeral` cookie | info |
| `ephemeral_session_revoke` | A share-link session is revoked (CLI `session revoke`) | warning |
| `ephemeral_session_revoke_all` / `ephemeral_session_revoke_user` | CLI mass / per-creator revocation | warning |
| `portal_session_revoke` | `POST /api/v1/sessions/revoke` | warning |
| `portal_session_revoke_all` | `POST /api/v1/sessions/revoke-all` (step-up gated) | warning |
| `portal_session_revoke_user` | Share links of a creator revoked (CLI path) | warning |

## Operator accounts

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `operator_created` | `POST /api/v1/operators` or `vnc-remote operator add` | warning |
| `operator_updated` | `PATCH /api/v1/operators/{u}` or `vnc-remote operator passwd/role/disable/enable` — detail names the changed fields | warning |
| `operator_deleted` | `DELETE /api/v1/operators/{u}` or `vnc-remote operator remove` (tombstone kept ~30 d) | warning |
| `operator_restored` | `POST /api/v1/operators/{u}/restore` | warning |
| `operator_sessions_revoked` | `POST /api/v1/operators/{u}/sessions/revoke-all` | warning |
| `passkey_register_begin` | `POST …/passkeys/register/begin` (step-up gated) | info |
| `passkey_auth_begin` | `POST /api/v1/auth/passkey/begin` | info / warning on failure |
| `passkey_registered` | `POST …/passkeys/register/complete` | warning |
| `passkey_renamed` | `PATCH …/passkeys/{ref}` | info |
| `passkey_revoked` | `DELETE …/passkeys/{ref}` (step-up gated) | warning |

## Portal services

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `portal_gamepad_stop` / `portal_gamepad_resume` | Gamepad kill-switch toggles | warning |
| `maintenance_changed` | `POST /api/v1/maintenance` or `vnc-remote maintenance on|off` — detail carries `active`, `drained`, `reason` | warning |
| `terminal_open` / `terminal_close` | A terminal WebSocket session opens/closes | info |

## User management

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `user_create` | `POST /api/v1/system-users` (after step-up auth) | warning |
| `user_delete` | `DELETE /api/v1/system-users/{username}` (after step-up auth) | warning |

## Secrets & backups

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `secret_rotate` | `vnc-remote secrets rotate` completes | warning |
| `recovery_codes_generate` | `vnc-remote secrets` recovery-code regeneration | warning |
| `backup_create` | `vnc-remote backup` or `POST /api/v1/backups` succeeds or fails | info / warning on failure |
| `backup_verify` | `vnc-remote verify backup` or `POST /api/v1/backups/verify` | info |
| `backup_restore` | `vnc-remote restore` or `POST /api/v1/backups/restore` (step-up) | warning |
| `lifecycle_action` | `POST /api/v1/lifecycle` queued start/stop/restart (step-up) | warning |
| `secrets_check` | `vnc-remote secrets check` or `POST /api/v1/secrets/check` | info |
| `config_migrate` | `vnc-remote config migrate` or `POST /api/v1/config/migrate` applied changes (step-up) | warning |
| `upgrade_run` | `vnc-remote upgrade` or `POST /api/v1/upgrade` completed (step-up) | warning |
| `upgrade_rollback` | `vnc-remote upgrade --rollback` or `POST /api/v1/upgrade/rollback` (step-up) | warning |

## System lifecycle

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `uninstall` | `vnc-remote uninstall` completes | warning |
| `anchor` | Genesis entry written when the log is (re)created | info |
| `listener_audit_failure` | A service listener could not write an audit entry | warning |

## Coverage rules

- Authentication failures are logged with the remaining-attempts or
  lockout detail — brute force is visible in the log.
- Sensitive CLI actions (`session`, `secrets`, `backup`, `restore`,
  `uninstall`, `operator`, `maintenance`) are audited via
  `cli/_common._audit_cli` with the OS username as actor.
- API mutations are audited by the use case
  (`engine/application/*` via `stores.audit`) or the route handler
  (`services/api_v1.py` via `audit_event`) with the authenticated
  operator username as actor — the store layer itself does not audit,
  so one action produces exactly one entry.
- Details never include passwords, tokens, or key material; tokens are
  recorded as truncated SHA-256 fingerprints.
