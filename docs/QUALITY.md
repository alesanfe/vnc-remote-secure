# Quality Attribute Priorities & Budgets

Explicit ordering — not all qualities weigh the same for a
self-hosted security tool.

```yaml
quality_priorities:
  security: critical
  reliability: critical
  maintainability: high
  auditability: high          # everything sensitive leaves a chain entry
  recoverability: high
  usability: medium           # operator-facing, not mass-market
  performance: medium         # LAN-scale, single host
  portability: medium         # Linux + Windows, deliberate limits
  scalability: low            # one host, a handful of concurrent users
  multi_tenancy: none         # out of scope (REQUIREMENTS.md)
```

## Budgets (measured or enforced)

| Attribute | Budget | Enforced by |
|---|---|---|
| Cyclomatic complexity | ≤ 18 per function (current max) | ratchet audits; radon grades D–F = 0 |
| Test suite | 100% of public ops covered by contract/parity tests | `tests/unit/engine` + `parity_matrix.py` |
| Mypy | 0 errors on `src/` | CI |
| Import boundaries | domain/app never import transport/infra | `test_import_boundaries.py` |
| Frontend bundle | keep `web/static/admin/` lean — no new runtime deps without a reason | review checklist |
| API latency | p95 < 500 ms for `/api/v1/*` reads | `slo.md` |
| Auth rate limits | lockout after `AUTH_MAX_ATTEMPTS`; per-IP caps | `rate_limit.py`, security tests |
| Recovery | RPO ≤ 24 h / RTO ≤ 4 h / rollback ≤ 15 min | `slo.md`, `drills.md` |
| Secrets | 0 in git history | gitleaks + detect-secrets CI |
| Audit | every sensitive action emits a chain entry | `audit-events.md` + parity catalog |
| Session cleanup | temp user removed on exit unless `KEEP_TEMP_USER` | default + rule in AGENTS.md |

## Trade-off rules (Software Engineering at Google)

Decisions are evaluated on three axes — **time** (how long the
system must live), **scale** (how many users/ops), and
**compromises** (what we give up to get what we need). Examples in
this codebase:

- VNC DES kept for protocol compatibility → wrapped, documented,
  *accepted* as R-01 — not silently shipped.
- JSON+base64 file transfer (32 MiB) instead of streaming/multipart —
  simpler trust boundary for a feature that is not the product's core.
- No embedded OIDC (ADR-0012) — a permanent attack surface traded
  for a feature a reverse proxy provides better.
- `websockets-sansio` only on the HTTP-only health app — the safer
  backend everywhere else because `send_denial_response` depends on
  the legacy API (documented in `health_app.py`).

An attribute never named in `quality_priorities` is *not* a defect —
it is a conscious non-goal. Write it down before someone "fixes" it.
