# Operations

Operational surface for a deployed instance. This document is the
entry point — the detailed index lives in
[`operations/README.md`](operations/README.md) and the per-incident
runbooks in [`runbook/`](runbook/).

## Daily commands

```bash
vnc-remote doctor        # full diagnosis (config, ports, certs, firewall)
vnc-remote status        # service states
vnc-remote backup        # encrypted backup
vnc-remote restore       # restore with auto-rollback
vnc-remote session list  # active sessions
```

## References

| Doc | Content |
|---|---|
| [operations/README.md](operations/README.md) | procedures index |
| [runbook/incident-response.md](runbook/incident-response.md) | severity classes, containment, disclosure |
| [runbook/recovery.md](runbook/recovery.md) | backup/restore and disaster recovery |
| [runbook/slo.md](runbook/slo.md) | SLO/SLI + RPO/RTO |
| [runbook/monitoring.md](runbook/monitoring.md) | health, metrics, alerting |
| [runbook/drills.md](runbook/drills.md) | recovery exercise battery + drill log |
| [installation/upgrade.md](installation/upgrade.md) | version upgrades |
| [FEATURE_FLAGS.md](FEATURE_FLAGS.md) | toggles and `.env` knobs |
