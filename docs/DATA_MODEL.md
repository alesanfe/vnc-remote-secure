# Data Model — VNC Remote Secure

Persistent state lives under `data/` (SQLite via `shared_state` +
files with strict permissions). No external database is required.

## Core entities

| Entity | Store | Purpose |
|---|---|---|
| Operator | `engine/application/operators.py` | Admin identities (passkeys, roles) |
| Session | `engine/application/sessions.py` | Auth sessions + ephemeral share grants |
| Passkey | `engine/application/passkeys.py` | WebAuthn credentials |
| System user | `engine/application/system_users.py` | Managed OS users (temporary `TEMP_USER`) |
| Job | `security/jobs.py` | QUEUED/claimed deferred destructive ops |
| Audit event | `security/audit.py` | Append-only security events |
| Rate-limit bucket | `security/rate_limit.py` | Throttle state per identity/IP |
| WebSocket registration | `security/websocket_registry.py` | Live sockets for revocation |

## Operation catalog

`engine/domain/operations.py` is the canonical catalog: every
transport-checkable operation declares permission, auth policy
(`stepup` recency vs `stepup-bound` grant), execution mode
(`sync`/`job`/`deferred`), confirmation, audit event and
reversibility. `tools/parity_matrix.py` regenerates
`docs/api/parity-matrix.md` from it.

## Files

| Path | Contents |
|---|---|
| `data/` | state DBs, run pids, audit |
| `data/ssl/` | TLS material (never committed) |
| `backups/` | config backups (treated as secrets) |
| `*.vrsrec` | session recordings (version-stable format — see `docs/RECORDING_FORMAT.md`) |

## Invariants

- Secrets never in state DBs readable by other services — see
  `security/profiles` and `docs/architecture/trust-boundaries.md`.
- `VRS_TEST_MODE=1` (`core/test_isolation.py`) aborts writes to
  repo-root `.env`/backups during tests.
- Destructive ops persist a QUEUED job before answering 202 — a
  persisted job, not a sleep, is what guarantees execution.
