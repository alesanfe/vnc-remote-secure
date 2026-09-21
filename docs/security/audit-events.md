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
| `login` | Every login attempt — success, bad credentials, lockout, MFA required, invalid MFA | info / warning on failure |

## Ephemeral sessions

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `ephemeral_session_create` | `vnc-remote session create` issues a share link | info |
| `ephemeral_session_activate` | A share link is exchanged for the `vnc_ephemeral` cookie | info |
| `ephemeral_session_revoke` | `vnc-remote session revoke` terminates a session | warning |

## User management

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `user_create` | `/create_user` or `POST /api/users` (after step-up auth) | warning |
| `user_delete` | `/delete_user` or `DELETE /api/users` (after step-up auth) | warning |

## Secrets & backups

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `secret_rotate` | `vnc-remote secrets rotate` completes | warning |
| `backup_create` | `vnc-remote backup` succeeds or fails | info / warning on failure |
| `backup_restore` | `vnc-remote restore` succeeds or fails | warning |

## System lifecycle

| Event | Emitted when | Severity |
|-------|--------------|----------|
| `uninstall` | `vnc-remote uninstall` completes | warning |
| `anchor` | Genesis entry written when the log is (re)created | info |

## Coverage rules

- Authentication failures are logged with the remaining-attempts or
  lockout detail — brute force is visible in the log.
- Sensitive CLI actions (`session`, `secrets`, `backup`, `restore`,
  `uninstall`) are audited via `cli/_common._audit_cli`.
- Web admin actions are audited via `web/routes/users._audit_user_action`.
- Details never include passwords, tokens, or key material; tokens are
  recorded as truncated SHA-256 fingerprints.
