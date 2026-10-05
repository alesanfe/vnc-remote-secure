# Governance

## Model

**Benevolent maintainer.** VNC Remote Secure is maintained by a single
owner ([@alesanfe](https://github.com/alesanfe)) who makes final
decisions on scope, design and releases. This is documented per the
OpenSSF silver criterion — a small project does not need a committee,
it needs a clear answer to "who decides".

## How decisions get made

1. **Proposals** — GitHub issue or PR describing the change and its
   motivation. Security-sensitive changes (`security/`, `services/
   rfb_filter.py`, auth surfaces) require the reasoning in writing,
   not just code.
2. **Review** — the maintainer reviews; CI must be green
   (lint/format/mypy/import-linter/tests/security scans). Merging
   someone else's PR implies the maintainer accepts maintenance of
   that change.
3. **Disputes** — unresolved disagreements are decided by the
   maintainer. Forking is always legitimate (MIT).
4. **Releases** — cut by the maintainer per
   `docs/developer/releasing.md`; tags follow SemVer.

## Roles

| Role | Who | Responsibility |
|------|-----|----------------|
| Maintainer | @alesanfe | Everything final: merges, releases, security triage, risk register sign-off |
| Security contact | @alesanfe | Vulnerability intake (`SECURITY.md`, `/.well-known/security.txt`), incident response owner |
| Contributors | anyone | PRs under `CONTRIBUTING.md` + Conventional Commits |

## Bus-factor note

Single-maintainer risk is an *accepted* entry in
`docs/security/risk-register.md` (R-14): the mitigation is
documentation (ADRs, REQUIREMENTS, runbooks) and a test suite that
acts as executable spec, so a successor could pick the project up
without oral history.
