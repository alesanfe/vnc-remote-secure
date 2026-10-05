# Dependencies

## Runtime

| Dependency | Version | Purpose | License |
|---|---|---|---|
| Python | ≥3.10 | canonical CLI + all services (`vnc_remote_secure`) | PSF |
| FastAPI + uvicorn | per `pyproject.toml` | all HTTP/WS surfaces (landing, api_v1, health) | MIT / BSD-3 |
| pydantic (+pydantic-settings) | 2.x | request validation (`extra='forbid'`), typed env | MIT |
| nginx | distro | reverse proxy + TLS termination + static SPA | BSD-2 |
| TigerVNC | distro | VNC server on Linux | GPL-2.0 |
| UltraVNC | pinned installer | VNC server on Windows | GPL-2.0 |
| noVNC + websockify | pinned | browser desktop access | MPL-2.0 / LGPL |
| systemd / Windows Services | platform | service management (ADR-0003) | — |
| Docker | optional | packaged deployment (Linux only) | Apache-2.0 |

Runtime deps are managed in `pyproject.toml` (single source of
truth). Third-party downloads are pinned with manifests +
checksums under `src/vnc_remote_secure/third_party/`.

## Frontend build (dev only)

| Dependency | Purpose |
|---|---|
| Node.js 20 + Vite | SPA bundle → `web/static/admin/` |
| React + react-router-dom + TanStack Query | portal, share links, admin console |
| openapi types codegen | `npm run gen:types` from `docs/api/openapi.v1.yaml` |

The SPA needs no Node at runtime — it is a static bundle.

## Development/CI

| Tool | Purpose |
|---|---|
| pytest | Python suite (unit/integration/security) |
| Pester (`*.Tests.ps1`) | PowerShell/Windows tests |
| Playwright | SPA E2E |
| shellcheck, darglint, bandit, semgrep, detect-secrets, gitleaks | lint/security gates |
| actionlint/yamllint | CI workflows |

## Update policy

- Dependabot for npm/pip/docker/GHA.
- Versions <7 days old mature before merge unless CVE.
- Vendored/third-party binaries are updated via
  `tools/download_dependencies.py` + checksum verification.
