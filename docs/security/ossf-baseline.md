# OpenSSF Best Practices — Self-Assessment

Mapping of the project against the
[OpenSSF Best Practices](https://www.bestpractices.dev/) **passing**
criteria (and selected silver items). Purpose: make the evidence
explicit so the badge questionnaire can be filled in minutes, and so
gaps are visible rather than assumed.

## Basics

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Describe what the software does | ✅ | `README.md` — secure browser-based remote access (noVNC/terminal/audio/gamepad) |
| How to obtain / feedback / contribute | ✅ | Install docs, Issues, `CONTRIBUTING.md`, PR template |
| FLOSS license in standard location | ✅ | `LICENSE` (MIT) |
| HTTPS on project sites | ✅ | GitHub-hosted; product itself defaults to TLS |
| Install/run/use-securely docs | ✅ | `docs/installation/`, `docs/user-guide/production-hardening.md` |
| Interface reference documentation | ✅ | `docs/api/openapi.v1.yaml`, CLI `--help`, parity matrix |
| Unique versioned releases + change summaries | ✅ | SemVer tags, `CHANGELOG.md`, release workflow |
| Vulnerability reporting process | ✅ | `SECURITY.md` + `/.well-known/security.txt` (RFC 9116) |
| Acknowledge ≤ 14 days, fix ≤ 60 days | ✅ | `SECURITY.md` response-time table (72 h ack, ≤60 d public fixes) |

## Change control & quality

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Public version control, commit per change | ✅ | GitHub, PR-based |
| Working build with standard tools | ✅ | `pip install -e .`, `python -m build`, Makefile |
| Automated test suite covering most functionality | ✅ | 1758+ unit tests + integration/e2e/security/soak pyramid |
| Tests on every change | ✅ | CI matrix (3 OS × 3 Python versions), Playwright e2e |
| New tests required for new code | ✅ | `CONTRIBUTING.md` + contract tests that fail on drift |
| Warnings/lint enabled and clean | ✅ | ruff, black, mypy, pylint, flake8 plugins, shellcheck, PSScriptAnalyzer — all CI-gated |
| Static analysis beyond lint | ✅ | bandit, semgrep, CodeQL, import-linter architecture contracts |
| Dynamic checks (fuzzer/web scanner) | ✅ | hypothesis property tests (`test_properties.py`), fuzz/adversarial security suite, Trivy |

## Security

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Secure development knowledge | ✅ | threat model, risk register, ASVS-aligned controls |
| Public crypto protocols, no reimplementation | ✅ | TLS via stdlib/OpenSSL, `hmac`, `secrets`; VNC DES is vendored `d3des` for *protocol compatibility* and documented as legacy, never a trust boundary |
| Signed/protected release | ✅ | SLSA `attest-build-provenance`, SHA-256 sums, SBOM (SPDX+CDX) |
| Dependencies checked for vulnerabilities | ✅ | pip-audit CI gate, Trivy weekly, Dependabot |
| Secrets out of the repo | ✅ | gitleaks + detect-secrets baseline, gitignore rules |

## Silver-level items already met

- **Governance documented** — `GOVERNANCE.md`.
- **Two-person review** — N/A (single maintainer; documented as such).
- **Bus factor** — partially mitigated (docs-as-spec, ADRs); accepted
  residual in the risk register (R-14).

## Known gaps for gold

- Multi-maintainer review and organizational continuity.
- External/independent security audit (funded/pentest).
- Signed commits policy.

## How to claim the badge

1. Register the repo at <https://www.bestpractices.dev/>.
2. Answer each criterion using this table's evidence links.
3. Add the badge to `README.md`.
