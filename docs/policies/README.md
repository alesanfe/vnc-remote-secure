# Policies

The project's explicit policies — one page, one section each, so a
reader can answer "what is the rule for X?" without archaeology.

## Versioning (SemVer)

- Package version lives **only** in `pyproject.toml`; every consumer
  reads it dynamically (`AGENTS.md` — version management).
- SemVer: breaking API/CLI/config changes → major; features → minor;
  fixes/patches → patch. `/api/v1/*` is the contract — a path change
  that breaks consumers is major.
- Deprecation (§41 of the maturity model): announce in
  `CHANGELOG.md` + one release with a warning → remove next minor.
  Completed example: legacy `GET /?session=<token>` links (announced,
  then removed).

## Compatibility & support matrix

| Surface | Supported |
|---|---|
| Server OS | Linux (systemd), Windows 10/11 |
| Runtime | Python versions in the CI matrix |
| Client | any modern browser (ES2020+) |
| RFB | TigerVNC (Linux), UltraVNC (Windows) |
| API | `/api/v1/*` only — legacy `openapi-legacy.yaml` is archived |
| Config | `config.schema.json` + `vnc-remote config migrate` |

End of support for a platform/Python version is announced one minor
release ahead in `CHANGELOG.md`.

## Dependencies

- Declared only in `pyproject.toml` / `frontend/package.json`.
- New deps: ≥7 days old, pinned or bounded, license-checked
  (`third_party/licenses/`).
- Security updates: Dependabot (weekly, grouped); pip-audit gate in
  CI; Trivy weekly.
- Actions in workflows are SHA-pinned.

## Secrets

- Never in git (gitleaks + detect-secrets CI; `.gitignore` covers
  `*.pem/*.key/.env/data/ssl/`).
- Rotation: `vnc-remote secrets rotate` (signing + stored secrets);
  procedure in `runbook/recovery.md`.
- Exposure procedure: `runbook/incident-response.md` §2.
- No shared credentials; operator store holds individuals.

## Backups & retention

- `vnc-remote backup` before every upgrade; scheduled backups per
  `recovery.md`; retention of recordings/audit in
  `user-guide/privacy-retention.md`.
- RPO ≤ 24 h / RTO ≤ 4 h / rollback ≤ 15 min (`runbook/slo.md`).

## Incidents & disclosure

- Severities S1–S4 and procedure: `runbook/incident-response.md`.
- Vulnerability intake: `SECURITY.md` + `/.well-known/security.txt`;
  ack ≤ 72 h, public fix ≤ 60 days.
- Postmortem: `runbook/postmortem-template.md`.

## Contributions & review

- `CONTRIBUTING.md` + Conventional Commits + PR template.
- Reviewer checklist: `developer/code-review-checklist.md`.
- Comment classes: blocker / important / suggestion / question / nit.

## Exceptions

A control can be waived only with: the reason in writing, an expiry
or review date, and an entry in `security/risk-register.md`.
Examples today: VNC DES (protocol-bound, R-01), audit tampering by a
root attacker (R-07), single-maintainer bus factor (R-14).

## Data & privacy

- Minimal telemetry: none leaves the host by default; alerts go only
  to operator-configured channels.
- Privacy & retention: `user-guide/privacy-retention.md`.
