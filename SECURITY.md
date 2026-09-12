# Security Policy

This document defines the security policy for the VNC Remote Secure project,
including the responsible disclosure process, scope, and expected response
times.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | Yes |
| Tagged releases | Yes |
| Older branches | No |

## Responsible Disclosure Policy

The maintainer is committed to handling security vulnerabilities with the
utmost seriousness. Researchers who identify a vulnerability are asked to
follow a responsible disclosure process:

1. Do NOT open a public GitHub issue, pull request, or discussion describing
   the vulnerability.
2. Report the issue privately through one of the secure channels listed
   below before publishing any details.
3. Provide sufficient information to reproduce and assess the vulnerability:
   - A clear description of the vulnerability and the affected component.
   - Step-by-step reproduction instructions, including configuration and
     environment details.
   - An assessment of the potential impact.
   - A suggested remediation, if available.
4. Allow a reasonable time for triage and remediation before any public
   disclosure. Coordinated disclosure is preferred.
5. Do not access, modify, or destroy data that does not belong to you, and do
   not degrade service availability for other users while testing.

## Secure Contact Channels

| Channel | Use |
|---------|-----|
| Private security advisory | Preferred. Open a private vulnerability report via GitHub Security Advisories ("Security" tab, "Report a vulnerability"). |
| Email | Send a report to the maintainer's email listed on the GitHub profile. Use the subject line `[SECURITY] VNC Remote Secure`. |
| PGP (optional) | If you prefer encrypted communication, request the maintainer's public key by email first. PGP is optional and provided on a best-effort basis. |

When using PGP, include your own public key so the maintainer can reply
encrypted. If PGP is unavailable, a private GitHub Security Advisory is the
recommended channel.

## Expected Response Times

| Stage | Target time |
|-------|-------------|
| Acknowledgement of receipt | 72 hours |
| Initial triage and severity assessment | 7 days |
| Status update on remediation progress | 30 days (or sooner for critical issues) |
| Fix release or mitigation guidance | Best-effort, severity-dependent |

These targets are commitments on a best-effort basis. This is a personal
project maintained outside of business hours, so response times may vary.
The reporter will be kept informed of progress and notified before any
public disclosure.

## Scope

### In Scope

The following are considered in scope for vulnerability reports:

- Source code in the `src/`, `native/`, `scripts/`, `tools/`, and `bin/`
  directories of this repository.
- Configuration templates and examples in `config/` and `.env.example`.
- The Flask web application, VNC/noVNC integration, web terminal, and health
  dashboard components shipped by this project.
- Default deployment scripts (`launch.sh`, `vnc-remote`, `VncRemote.ps1`)
  and their handling of credentials, permissions, and network binding.
- Documentation that could lead to an insecure deployment if followed as
  written.

### Out of Scope

The following are explicitly out of scope and will not be accepted as
vulnerability reports:

- Vulnerabilities in third-party dependencies (TigerVNC, UltraVNC, noVNC,
  ttyd, nginx, Flask, etc.). Report these to their respective upstream
  maintainers. Dependency CVEs are tracked separately via automated scanning.
- Physical attacks against the host hardware or network.
- Social engineering attacks against the maintainer or users.
- Denial of Service (DoS / DDoS) attacks against the public endpoint,
  including volumetric or resource-exhaustion attacks that require no
  authentication.
- Vulnerabilities requiring prior, authenticated, full-system compromise of
  the host (i.e., issues that are only exploitable once the attacker already
  has root/administrator access).
- Findings from automated scanners without a demonstrated, reproducible
  impact.
- Issues in deployments that deviate from the documented configuration in a
  way that reduces security (e.g., binding services to `0.0.0.0` against
  documented guidance).

## Rewards

This is a personal project. No monetary reward, bounty, or swag is offered
for vulnerability reports. The maintainer will, however:

- Acknowledge the reporter in `CHANGELOG.md` after the fix is released,
  unless the reporter prefers to remain anonymous.
- Credit coordinated disclosure in the relevant release notes.

## Reporting Process

1. Verify the issue is in scope (see above).
2. Do not open a public issue.
3. Open a private GitHub Security Advisory, or send an encrypted email to
   the maintainer.
4. Include description, reproduction steps, impact assessment, and any
   suggested fix.
5. Await acknowledgement within 72 hours.
6. Coordinate with the maintainer on remediation and a mutually agreed
   public disclosure date.

## Disclosure

This project is provided as-is. Security depends on proper configuration and
network hygiene. See `README.md` for configuration guidance and
`docs/THREAT_MODEL.md` for the formal threat model.
