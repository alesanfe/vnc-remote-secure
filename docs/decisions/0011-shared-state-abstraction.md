# ADR 0011: Shared state abstraction for multi-process deployments

## Status
Accepted

## Context
The project's stateful components — `RateLimiter`, `WebSocketRegistry`,
audit chain hash, and login-attempt counters — were held in
process-local singletons. This is correct for the canonical
single-process deployment but breaks down when running multiple
workers (e.g. `gunicorn --workers > 1`):

- Rate-limit budgets double (each worker has its own counter).
- Tokens issued by one worker are not recognised by another.
- WebSocket revocation in one worker does not close connections in
  another.
- The audit chain hash diverges across workers, breaking tamper
  detection.

## Decision
Introduce a pluggable shared-state backend
(`security.shared_state`) with two implementations:

1. **`MemoryBackend`**: in-process dict. No external
   dependencies. Correct only for single-process test/dev scenarios.
   Selected via `SHARED_STATE_BACKEND=memory`.
2. **`SQLiteBackend`** (platform default): durable, file-based shared
   state. Works across processes on a single host — which is the
   canonical deployment shape, since the service manager spawns one
   process per service. `config/defaults/common.env` sets
   `SHARED_STATE_BACKEND=sqlite`; the database path defaults to
   `<run_dir>/shared_state.db` and can be overridden via
   `SHARED_STATE_DB_PATH`.

The backend provides a simple key-value API with TTL support:
`get`, `set`, `delete`, `set_ttl`, `list_keys`, `increment`.

### Component integration

- **`RateLimiter`**: attempt timestamps and lockout expiry are
  stored in the backend. Two workers sharing a SQLite backend see
  the same rate-limit state.
- **`WebSocketRegistry`**: close callbacks remain process-local
  (they are Python callables and cannot be serialised). However,
  revocation is propagated via a shared
  `websocket_revoked_sessions` namespace: when a session is revoked,
  its ID is written to the backend with a TTL. Other processes check
  this namespace before allowing new WebSocket upgrades, ensuring
  revocation takes effect cluster-wide.
- **Audit chain**: the chain hash is re-read from the audit log file
  before each write, so entries written by other processes are
  correctly chained. This is correct for both single-process and
  multi-process deployments.

## Alternatives considered
1. **Redis backend.** Rejected as the default — would introduce a
   mandatory external dependency. Can be added in the future as a
   third backend implementation.
2. **File-based locking (fcntl/msvcrt) for all state.** Rejected —
   complex to implement correctly for sliding-window rate limiting
   and would be slow for high-volume audit logging.
3. **Always use SQLite.** Initially rejected for I/O overhead on the
   single-process case — but later accepted as the platform default
   (via `config/defaults/common.env`) because the canonical
   deployment is already multi-process: without it, step-up auth
   times, rate-limit budgets and revocation never cross process
   boundaries and per-process checks silently see empty state.

## Consequences
- Cross-process state (rate limits, revocation, step-up auth) is
  correct out of the box via the SQLite default.
- `SHARED_STATE_BACKEND=memory` remains available for tests and
  single-process dev setups.
- WebSocket close callbacks remain process-local: revocation
  propagates as "reject new connections" rather than "close
  existing connections in another process". Existing connections in
  another process will close naturally on the next message or
  timeout.
- The audit chain is always consistent because the hash is re-read
  from the file before each write.

## Risks
- SQLite has a single-writer limitation. Under very high audit
  volume, writes may contend. Mitigated by SQLite's WAL mode and the
  fact that audit writes are infrequent relative to request handling.
- The shared revocation TTL (24h) is a safe upper bound; sessions
  that expire naturally are not cleaned from the revocation set
  until the TTL expires. This is acceptable because the set is
  small (only revoked sessions).
