# Incident Response Runbook

Procedure for handling security incidents and service outages in a
VNC Remote Secure deployment. Related:
[monitoring.md](monitoring.md) (detection), [recovery.md](recovery.md)
(restore), [../THREAT_MODEL.md](../THREAT_MODEL.md) (threat matrix),
[../security/risk-register.md](../security/risk-register.md) (prior
risks), [slo.md](slo.md) (targets).

## Severity classes

| Sev | Definition | Examples | Response |
|-----|-----------|----------|----------|
| S1 — Critical | Active compromise or total loss | RFB filter bypass, session token forgery, audit chain broken remotely, credential exfiltration | Stop exposure first; fix before next public release |
| S2 — High | Security control degraded | Health endpoints unauthenticated on public bind, auth lockout broken, sandbox failure | Fix within current release cycle |
| S3 — Medium | Partial outage / exploitable only with preconditions | single service down, degraded posture score | Next maintenance window |
| S4 — Low | No immediate risk | cosmetic, docs drift | Backlog |

## Phases

### 1. Detect & declare

Sources: alerts (`monitoring/alerts.py`), `/audit` anomalies,
`/audit/verify` chain failure, `vnc-remote security check`, external
report (see `SECURITY.md` / `/.well-known/security.txt`).

- Record: what was observed, when, on which version
  (`vnc-remote version`), which host.
- Assign severity per the table above. When in doubt, take the
  higher severity.

### 2. Contain

| Incident | Immediate containment |
|----------|-----------------------|
| Suspected session-token compromise | `vnc-remote session list` → `revoke`; `vnc-remote operator disable <user>`; live sockets close automatically |
| Credential leak (.env, tokens) | `vnc-remote secrets rotate` (signing + stored secrets); rotate TOTP; invalidate sessions |
| Active hostile connection | `vnc-remote maintenance on` (drain), or `vnc-remote stop`; firewall the peer |
| Host compromise suspected | `vnc-remote stop`, isolate host, preserve `data/` + `run/` + audit log for forensics |
| Bad release / upgrade | `vnc-remote upgrade` auto-rolls back; manual: `rollback` |

Containment beats evidence preservation for S1 when they conflict —
except the audit log: copy `data/audit*` before rotating anything.

### 3. Eradicate & recover

- Identify the entry vector from the audit trail (`GET /audit` or
  `vnc-remote ... audit` tail) — look for the *first* denied→granted
  transition or foreign `instance_id`.
- Patch or reconfigure; verify with `vnc-remote doctor` and
  `vnc-remote security check` (zero criticals).
- Restore from backup only if integrity is in doubt —
  `runbook/recovery.md`. Rotate *every* secret after a confirmed
  compromise, not just the one believed leaked.

### 4. Post-incident

- Timeline + root cause + blast radius in a short postmortem
  (`docs/reports/` or the issue tracker — private until disclosure).
- Every S1/S2 must produce: a regression test, a monitor/alert or an
  audit check — "we fixed the code" is not closure.
- External report: coordinate disclosure per `SECURITY.md`
  (ack ≤ 72 h, public fix ≤ 60 days).

## Communications

- Internal note: severity, status, next update time.
- If user data or credentials may be exposed: notify affected
  operators through the configured alert channel; recommend
  credential rotation.
- Advisory publication happens via GitHub Security Advisories once a
  fix ships.

## Contact & ownership

Single-maintainer project: the maintainer owns detection, triage and
disclosure. `/.well-known/security.txt` (RFC 9116) is the canonical
contact pointer served by every deployment.
