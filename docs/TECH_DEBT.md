# Technical Debt Register

Every entry carries origin, consequence, cost, owner and a review
trigger. Debt is not a graveyard of TODOs — an entry is either being
paid down, being accepted with a rationale, or scheduled.

| ID | Area | Debt | Origin | Cost / risk | Plan | Review |
|----|------|------|--------|-------------|------|--------|
| TD-01 | security | VNC uses legacy DES auth (fixed key, 8-char cap) | protocol constraint | transport must be wrapped (TLS/VPN/SSH); documented everywhere | **Accepted** — R-01; not fixable in-product | n/a |
| TD-02 | code | `services/terminal.py` still large after the spawn/completion split | historic | readability; CC now ≤ 18 | keep split boundary clean; no further action unless growth resumes | quarterly audit |
| ~~TD-03~~ | data | `.vrsrec` custom recording format | product | no external player | **RESOLVED** — spec published in `docs/RECORDING_FORMAT.md` (parseable without the code); MP4 export deferred (FFmpeg dep) | done |
| TD-04 | ops | No lockfile for pip deps | design choice | builds rely on ranges + dependabot + pip-audit | **Accepted** — source-install app; reproducibility comes from attestations + SBOM | yearly |
| ~~TD-05~~ | api | Legacy `GET /?session=<token>` share URLs | compat shim | widened token surface | **RESOLVED** — shim removed; fragment links only | done |
| TD-06 | code | File transfer is JSON+base64 (32 MiB cap, no streaming) | transport constraint | large transfers impractical | documented cap; real file flows belong to native paths | on demand |
| TD-07 | security | No embedded SSO/OIDC | ADR-0012 | none today (delegated to reverse proxy) | revisit only if multi-operator tenancy emerges | on demand |
| TD-08 | team | Single maintainer | reality | bus factor R-14 | mitigate via ADRs + tests-as-spec + GOVERNANCE | yearly |
| TD-09 | arch | `ephemeral_sessions.py` is the top hotspot AND the top co-change hub (churn 46/6m, paired with terminal, service_manager, landing, novnc, cli) | it is the session authority — expected, but signals that every new surface drags it along | medium | already split (`ephemeral_model.py`); next step if churn persists: a narrower public interface so services stop depending on internals | next audit |
| ~~TD-10~~ | code | vulture ≥80 findings | compat shims | noise in the audit | **RESOLVED** — `tools/vulture_whitelist.py` + `_`-renames; dead-code section now reports only *new* findings | done |

## Detection — `make debt-audit`

`tools/debt_audit.py` automates the measurable parts of the
methodology: debt markers, largest files, **hotspots (git churn ×
radon CC)**, co-change pairs (hidden coupling), disabled tests,
vulture dead code, and schema↔`.env.example` drift. Run per release;
the triage (what is *debt* vs *signal*) stays human.

Last run findings worth noting: 4 `TEMP` markers (the `TEMP_USER`
contract, intentional); 6 `skip` markers (platform-conditional);
9 env knobs undocumented → **fixed** (AUDIT/METRICS auth tokens,
WS caps, RFB clipboard cap, terminal allowlist/sandbox dirs,
WebAuthn UV, RESTORE_KEEP_SESSIONS).

## Rules

- Monthly-or-release review: drop irrelevant rows, re-score impact,
  link any incident to the debt that enabled it.
- A PR that *reduces* a row updates this file in the same change.
- An accepted risk belongs to `security/risk-register.md`; an accepted
  *implementation* gap belongs here. Don't double-count.
