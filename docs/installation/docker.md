# Docker Installation

Container packaging lives in `packaging/docker/`:

- `packaging/docker/Dockerfile` — self-contained Linux image (TigerVNC
  desktop, noVNC, web terminal, health/metrics service, React admin
  SPA + public portal served by the FastAPI portal),
  with a `test` stage for the integration runner
- `packaging/docker/compose.yml` — single-service deployment
- `packaging/docker/compose.integration.yml` — integration-test overrides
  (a `test-runner` service gated behind the `test` Compose profile)

> **Linux containers only.** The Windows adapter (UltraVNC, ACLs,
> Windows Firewall) requires a Windows host and is not containerized.

## Run with Docker Compose

```bash
# From the repository root, with a configured .env
cp .env.example .env   # set real passwords first
docker compose -f packaging/docker/compose.yml --env-file .env up -d
```

The image runs the unified service manager in the foreground
(`start --foreground`), which supervises all service PIDs. `init: true`
is set so zombie children are reaped correctly, and resource bounds
(`pids_limit`, `mem_limit`, `cpus`) contain runaway processes.

Only port **443** is published: the nginx TLS reverse proxy fronts
every backend, which binds to loopback inside the container (Zero
Trust — no service is reachable without the authenticated gateway).
Persistent state is stored in named volumes (`vncrs-config`,
`vncrs-data`, `vncrs-logs`, `vncrs-run`).

## Run the integration test suite in containers

```bash
docker compose \
  -f packaging/docker/compose.yml \
  -f packaging/docker/compose.integration.yml \
  --profile test \
  run --rm test-runner
```

The `test-runner` builds from the Dockerfile `test` stage (pytest +
tests bundled) and runs the integration suite against the stack.

## Notes

- The `make docker-*` / `make demo` targets are intentionally omitted;
  invoke `docker compose` directly.
- For bare-metal installation, see:
  - [Linux installation](linux.md)
  - [Windows installation](windows.md)
  - [Upgrade guide](upgrade.md)
