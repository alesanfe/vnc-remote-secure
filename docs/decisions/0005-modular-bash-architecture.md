# ADR 0005: Modular Bash architecture

## Status
Superseded — the `src/lib/` Bash module tree has been removed; all
business logic now lives in the canonical Python package
(`src/vnc_remote_secure/`). `src/rpi-vnc-remote.sh` is a thin delegator
that does not source any Bash library (see AGENTS.md — Python-canonical
architecture).

## Context
A single monolithic Bash script for a project of this complexity (VNC, nginx,
SSL, fail2ban, monitoring, user management, backup) would be unmaintainable:
thousands of lines, no separation of concerns, difficult to test.

## Decision
Organize Bash code into modular categories under `src/lib/`:
- `core/` — config, logging, utils, validation, error handling, services
- `security/` — SSL, fail2ban, user management
- `web/` — nginx, Flask user UI
- `monitoring/` — health checks, dashboard
- `communication/` — alerts, notifications
- `platform/` — OS detection, Windows backend

Each module has a single responsibility and a reduced interface. The entry
point (`src/rpi-vnc-remote.sh`) sources modules in dependency order.

## Alternatives considered
1. **Single script**: Rejected for maintainability reasons.
2. **Python rewrite**: Rejected — Bash is appropriate for system administration tasks
   (package installation, user management, service control).
3. **Ansible playbook**: Rejected — adds dependency, less interactive.
4. **commands/services/security/config/ layout**: Considered but rejected —
   would break 116 existing tests without functional benefit. Current
   `src/lib/{category}/` layout is already modular.

## Consequences
- Each module can be tested independently (unit tests source single module)
- Module loading order is important (documented in AGENTS.md)
- Adding a feature means creating a new module, not editing a monolith
- Functions must not be duplicated across modules (enforced by convention)

## Risks
- Module loading order bugs (mitigated by integration tests)
- Function name collisions (mitigated by naming conventions)
- Circular dependencies (mitigated by layered architecture: core → security → web → etc.)
