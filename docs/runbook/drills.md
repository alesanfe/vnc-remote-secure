# Recovery & Resilience Drills

"Tener backup" ≠ "saber recuperarse". This page defines the drill
battery and the log each exercise must produce. Recommended cadence:
**one drill per release**; a full restore from scratch at least
**once a year**.

## Drill battery

| # | Exercise | Command / method | Pass criterion |
|---|----------|------------------|----------------|
| D1 | Full restore on a clean host | install → `vnc-remote restore <backup>` | all services healthy in < 30 min |
| D2 | Restore single config | `backup` → break `.env` → `restore` | config bytes identical |
| D3 | Upgrade then roll back | `vnc-remote upgrade` → inject failure | auto-rollback leaves old version healthy |
| D4 | Revoke mid-session | open share link → `session revoke` | live sockets close < 5 s |
| D5 | Rotate secrets live | `secrets rotate` | sessions invalid, re-issue works, audit clean |
| D6 | Corrupt audit entry | edit a byte in audit log | `/audit/verify` → `intact:false` |
| D7 | Process kill | kill `vnc`/`novnc`/`terminal` pid | supervisor restarts; `/health` shows transient degraded |
| D8 | Disk full in `run/` | fill run dir | services degrade, never corrupt shared_state |
| D9 | Bad release artifact | wrong checksum download | installer refuses (verified checksum) |
| D10 | Cold rebuild | new VM, only backup + repo | full service in < 4 h (RTO bound) |

## Drill log (fill per exercise)

```
date:        drill:        operator:
real_time:   data_loss:    verdict: pass/fail/partial
problems:
undocumented_steps:
human_dependencies:
followups:   (each with owner + date)
```

Log completed drills under `docs/reports/drill-YYYY-MM-DD.md`.

## Chaos budget

Gradual fault injection, cheapest first: latency on loopback sockets
→ killed processes (D7) → corrupt shared_state → full disk (D8).
No production-destroying chaos tooling: the failure modes matrix
(`architecture/failure-modes.md`) is the system map; the soak suite
(`tests/soak/`) already exercises sustained load.
