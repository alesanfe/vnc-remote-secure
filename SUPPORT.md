# Support

| What you need | Where |
|---|---|
| Report a bug | [Issues](https://github.com/alesanfe/vnc-remote-secure/issues) — include the version, OS, VNC backend and reproduction steps |
| Propose a feature | Issue with the "Feature request" template |
| Usage question | Issue with the `question` label |
| Security vulnerability | **Do not** open a public issue — see [SECURITY.md](SECURITY.md) and the private security report template |
| Installation / deployment | [docs/installation](docs/installation) and [README](README.md#installation) |
| Operations runbook | [docs/runbook](docs/runbook) |

## Before reporting

- Run the built-in doctor (`vnc-remote doctor` or Admin → Doctor in the
  web UI) and attach its output — most configuration problems are
  diagnosed there.
- Include whether you are on the packaged install (`VncRemote.ps1`),
  a pip install, or Docker.
- Redact tokens, passwords and real IPs/hostnames from logs and
  config snippets.
