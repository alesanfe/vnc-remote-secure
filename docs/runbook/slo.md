# Service Level Objectives — SLI/SLO, RPO/RTO

Verifiable reliability objectives for a VNC Remote Secure deployment.
Self-hosted, single-host service: "availability" covers the gateway
surfaces while the host itself is up (host hardware/OS failure is out
of scope of these SLOs — that is what the backup/restore path covers).

See [monitoring.md](monitoring.md) for scrape setup and dashboards,
[recovery.md](recovery.md) for the restore procedure.

## Service Level Indicators

| SLI | Definition | Source |
|-----|------------|--------|
| Availability | Fraction of `GET /health/ready` scrapes returning 200 | Prometheus `up` on the health job |
| API latency | `p95` of `/api/v1/*` GET responses | `http_request_duration_seconds` histogram |
| Auth latency | `p95` of operator authentication decisions | auth metrics (see monitoring.md) |
| Error rate | Fraction of `/api/v1/*` responses ≥ 500 | request counter + status label |
| Audit integrity | `GET /audit/verify` chain-valid = true | audit metrics / scheduled check |

## Objectives

| SLO | Target | Error budget |
|-----|--------|--------------|
| Health/readiness availability | ≥ 99.5% / 30 d (rolling) | ~3.6 h down per month |
| API read latency | p95 < 300 ms | burn alert on 2 consecutive scrapes p95 > 800 ms |
| Error rate | < 1% of API requests ≥ 500 / 30 d | alert dispatch above 5% over 15 min |
| Audit chain | 100% valid, checked hourly | any failure = critical page |
| Posture score | ≥ 80, zero critical findings | `vnc-remote security check` exits 1 |

## Recovery objectives

| Objective | Value | Mechanism |
|-----------|-------|-----------|
| RPO | ≤ 24 h | `vnc-remote backup` on schedule (cron/Task Scheduler) — restores carry `run/` secrets, system config, certs, service state |
| RTO (service restart) | ≤ 30 min | `vnc-remote start` / systemd restart; health endpoint confirms readiness |
| RTO (full restore) | ≤ 4 h | fresh install → `vnc-remote restore <backup>` → `doctor` green |
| Rollback after bad upgrade | ≤ 15 min | `vnc-remote upgrade` keeps a pre-install backup and auto-rolls back on install/verification failure |

## Alerting policy

Alerts must be **actionable** — every alert names the runbook section
that resolves it. Map: health down → "Service down"; audit chain
failure → incident response + rotate; posture drop →
[../user-guide/production-hardening.md](../user-guide/production-hardening.md).

Escalation channels configured in `monitoring/alerts.py`
(Discord/webhook/email). An alert with no owner action is noise —
tune thresholds before adding new alerts.

## What is NOT covered

- Client-side network (home ISP, mobile) — unmeasurable from the host.
- The upstream VNC server crash-looping (its own process) — surfaced
  via `/health/services` degradation, outside availability SLO math.
- Concurrent-operator conflicts — single-operator model by design.
