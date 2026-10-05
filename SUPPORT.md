# Support

| What you need | Where |
|---|---|
| Report a bug | [Issues](https://github.com/alesanfe/vnc-remote-secure/issues) — include OS, install method (Linux/Windows/Docker) and repro steps |
| Propose a feature | Issue with the "Feature request" template |
| Usage question | Issue labeled `question` |
| Security vulnerability | **Do not** open a public issue — see [SECURITY.md](SECURITY.md) |

## Before reporting

- Install logs live under the install dir; health status via the
  `/health` endpoint (see `docs/user-guide/health.md`).
- Session problems: check `docs/user-guide/sessions.md` and
  `docs/runbook/incident-response.md` first.
- Include whether the issue is desktop (noVNC), terminal, audio or
  file share — each has its own adapter.
