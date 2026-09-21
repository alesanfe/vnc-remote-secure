# Docker Installation

> **Status: not yet shipped.** There is no `packaging/docker/` directory
> in the current tree — no Dockerfile or compose files exist. The
> documented commands below are the intended layout and will not run
> until the packaging lands (tracked in ROADMAP.md).

Planned layout:

- `packaging/docker/Dockerfile` — self-contained image (noVNC desktop,
  web terminal, health dashboard, Flask management UI)
- `packaging/docker/compose.yml` — single-service deployment
- `packaging/docker/compose.integration.yml` — integration-test overrides
  (a `test-runner` service gated behind the `test` Compose profile)

For a working installation today, use bare-metal:

- [Linux installation](linux.md)
- [Windows installation](windows.md)
- [Upgrade guide](upgrade.md)
