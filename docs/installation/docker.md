# Docker Installation

Container packaging lives in `packaging/docker/`:

- `packaging/docker/Dockerfile` — self-contained image (noVNC desktop,
  web terminal, health dashboard, Flask management UI)
- `packaging/docker/compose.yml` — single-service deployment
- `packaging/docker/compose.integration.yml` — integration-test overrides
  (a `test-runner` service gated behind the `test` Compose profile)

## Run with Docker Compose

```bash
# From the repository root, with a configured .env
docker compose -f packaging/docker/compose.yml --env-file .env up -d
```

The service exposes port 443 (nginx SSL reverse proxy) as the public
entry point. Persistent state is stored in named volumes
(`vncrs-config`, `vncrs-data`, `vncrs-logs`, `vncrs-run`).

## Run the integration test suite in containers

```bash
docker compose \
  -f packaging/docker/compose.yml \
  -f packaging/docker/compose.integration.yml \
  --profile test \
  run --rm test-runner
```

## Notes

- The `make docker-*` / `make demo` targets are intentionally omitted;
  invoke `docker compose` directly.
- For bare-metal installation, see:
  - [Linux installation](linux.md)
  - [Windows installation](windows.md)
  - [Upgrade guide](upgrade.md)
