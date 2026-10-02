# Risk Register

Formal risk assessment for VNC Remote Secure — likelihood × impact,
existing controls, and the residual risk the project accepts.
Complements [../THREAT_MODEL.md](../THREAT_MODEL.md) (attack-centric
STRIDE view) with an *acceptance* view: every residual risk is either
mitigated by a control or explicitly accepted here.

Ratings: L/I ∈ {low, medium, high}. Residual is what remains *after*
the listed controls.

## Register

| ID | Risk | L | I | Controls | Residual | Owner |
|----|------|---|---|----------|----------|-------|
| R-01 | VNC DES auth is cryptographically broken (fixed key, 8-char cap) | H | H | VNC bound to loopback; all external access via TLS/noVNC + auth gateway; RFB filter enforces permission scope | **Accepted** — protocol limitation, documented everywhere VNC is exposed | design |
| R-02 | Share-link token theft (URL leak, clipboard) | M | H | Fragment URLs (`#t=` never sent to server); short TTL; IP/CIDR binding; single-use budgets; live revoke propagates to open sockets | Low | maintainer |
| R-03 | Credential brute force on landing/API | M | M | Rate limiting + lockout (`AUTH_MAX_ATTEMPTS`), MFA/TOTP, step-up for sensitive ops, audit trail, optional fail2ban | Low | maintainer |
| R-04 | RFB parser desync (server↔filter byte disagreement) | M | M | Fail-closed on unknown encodings/types; allowlist renegotiation (`_rewrite_encodings`); per-encoding length dispatch table; 51-test harness + fuzz | Low | maintainer |
| R-05 | UltraVNC download tampered (mirror/MITM) | L | H | HTTPS-only download, zip-slip path check, SHA-256 manifest verification of `winvnc.exe` before use | Low | maintainer |
| R-06 | `.env` / secret exfiltration | M | H | Secrets never logged (`security/redaction.py`); owner-only file perms hardened; `SECRET_VARS` stripped from spawned shells; secrets CI scans (gitleaks, detect-secrets baseline) | Low | maintainer |
| R-07 | Audit log tampering | M | M | Hash-chained entries + `verify_chain`; append-only seq; owner-only perms | Accepted residual: root attacker can rewrite history — documented | design |
| R-08 | Supply chain (pip/npm deps, GitHub Actions) | M | M | SHA-pinned actions, Dependabot, pip-audit gate, Trivy, SBOM per release, SLSA attestation, OpenSSF Scorecard | Low | maintainer |
| R-09 | Upgrade installs broken/malicious version | L | M | Pre-install backup, anti-downgrade pin check, hardened-profile preflight, fresh-interpreter verify, automatic rollback | Low | maintainer |
| R-10 | Health/metrics endpoints leak info on public bind | M | M | Scoped tokens (`HEALTH`/`METRICS`/`AUDIT_AUTH_TOKEN`), loopback-only-open policy, Bearer rate limiting, `security check` gate | Low | maintainer |
| R-11 | Sandbox escape from spawned web-terminal shell | L | H | bubblewrap namespace + rlimits + setpriv uid drop (POSIX); Windows Job Object + AppContainer; `SECRET_VARS` env scrub | Medium — kernel exploit is out of model; controls layered | design |
| R-12 | Data loss (config, sessions, secrets) | M | M | Scheduled backups, verified restore path, atomic writes (`tmp`+rename), persisted SessionStore | RPO ≤ 24 h / RTO ≤ 4 h — see [../runbook/slo.md](../runbook/slo.md) | maintainer |
| R-13 | CSRF on admin API | M | M | SameSite cookies + Origin/Sec-Fetch checks + CSRF token gate for mutations; step-up bound grants single-use | Low | maintainer |
| R-14 | Bus factor — single maintainer | M | M | CODEOWNERS, ADRs, docs index, tests-as-spec, `CONTRIBUTING.md` | **Accepted** — personal project | owner |
| R-15 | DoS on public endpoint | H | M | Per-IP rate limits, request size caps, handshake deadlines, WS frame bounds, connection caps | Accepted residual: volumetric DDoS out of scope (SECURITY.md) | design |

## Review policy

- Revisit after every S1/S2 incident, every new feature crossing a
  trust boundary, and at each minor release.
- A control removal or weakening is itself a risk-register change —
  PRs touching `security/` must state which rows they affect.
- New accepted risks need a written rationale here, not tribal
  knowledge.
