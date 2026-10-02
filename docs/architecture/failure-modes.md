# Failure Modes Matrix (Release It! style)

For every dependency and resource: what happens when it is down,
slow, corrupt, or lying. Patterns applied are listed per row —
a gap means *designed degradation*, not neglect.

| Dependency / resource | Down | Slow | Corrupt / invalid | Pattern applied |
|---|---|---|---|---|
| TigerVNC / UltraVNC (RFB server) | `health` → degraded; novnc/terminal keep serving | socket read deadline; RFB filter fails closed on undecodable bytes | RFB filter validates encodings/types; unknown → drop connection | Timeout, fail-closed, bulkhead (loopback port) |
| websockify bridge | noVNC cards degrade; `health/services` reports port down | N/A (local TCP) | proxy only forwards bytes after auth | Health check, process supervision |
| nginx reverse proxy | portal unreachable → `doctor` reports; direct ports still serve | OS-level | config generated + `nginx -t` preflight before apply | Preflight validation, restart-supervision |
| Shared-state SQLite | writes degrade → ops become single-process best-effort | file lock contention bounded | corrupted DB detected → falls back or errors loudly per `SHARED_STATE_STRICT` | Idempotent ops, `destructive` lock |
| `.env` / config | `config validate` + `doctor` fail fast at boot | — | schema `config.schema.json` + `migrate` path | Startup validation, versioned migrations |
| Audit log file | `stores.audit` failure is logged, never silently dropped | — | hash chain broken → `/audit/verify` reports `intact:false` | Tamper-evident chain, append-only |
| Session/signing secret | sessions fail to verify (all logged out) — fail closed | — | `secrets check` + `secrets recovery-codes` | Key rotation with grace (`secrets rotate`) |
| TLS cert files | HTTPS service refuses to start or falls back per profile | — | `tls_validation` checks expiry/chain/permissions | Startup validation, `security check` |
| UltraVNC download mirror | install aborts with verified-checksum error | httpx timeout + tenacity retry | SHA-256 manifest mismatch → refuse to install | Checksum pinning, no redirects, DNS pinning |
| Filesystem (`data/`, `run/`) | services degrade; PID/lock writes fail | slow disk → IPC slower | atomic tmp+rename everywhere; backup/restore verified | Atomic writes, RPO/RTO (`slo.md`) |
| Inbound WebSocket peers | — | per-IP rate limit + connection caps | `request_headers_safe` framing checks; message caps | Rate limiting, load shedding |
| Alert webhooks (Discord/HTTP) | alert logged, dispatch retried bounded | `_SYSLOG_TIMEOUT`-style send timeout | redaction strips secrets before dispatch | Bounded retry, redaction |

## Load-shedding order

Under resource pressure the services shed in this order (least
critical first): gamepad → audio → terminal → file share → landing
portal → noVNC/RFB path → health/metrics. The health surface is last:
the ability to *observe* a degraded system outranks every feature.

## What is deliberately not handled

- Volumetric DDoS — out of scope (`SECURITY.md`); belongs to network
  layer / CDN.
- Split-brain multi-node — the product is single-host by design
  (`shared_state` coordinates processes on one host, not replicas).
- Kernel/hypervisor compromise — outside the trust model
  (`docs/THREAT_MODEL.md`).
