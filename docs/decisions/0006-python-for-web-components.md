# ADR 0006: Python for web components, Bash for orchestration

## Status
Superseded by ADR-0009 (Bash/Python coexistence) and the Python-canonical
architecture documented in `AGENTS.md`. The unified Python CLI
(`vnc_remote_secure.cli`) is now the single authoritative runtime for both
web components and orchestration; Bash and PowerShell are thin
compatibility wrappers that delegate to it.

## Context
The project needs both system administration tasks (install packages, manage
users, configure nginx, control services) and web services (health dashboard,
user management UI, web terminal, landing page).

Bash is excellent for system administration but poor for web servers, WebSocket
handling, and HTTP request processing. Python has excellent libraries for these
(Flask, Tornado, websockify) but is less natural for system administration.

## Decision
Use the right tool for each job:
- **Bash**: Orchestration, system administration, service management, package
  installation, user management, nginx configuration, firewall rules
- **Python**: Web components that need HTTP/WebSocket servers
  - `src/vnc_remote_secure/services/health.py` — health dashboard (http.server)
  - `src/vnc_remote_secure/web/application.py` — user management UI (Flask)
  - `src/vnc_remote_secure/services/terminal.py` — web terminal (Tornado WebSocket)
  - `src/vnc_remote_secure/services/landing.py` — landing page portal (http.server)
  - `src/vnc_remote_secure/services/audio.py` — audio streaming (websockets)
  - `src/vnc_remote_secure/services/gamepad.py` — gamepad forwarding (websockets)

Bash scripts call Python components as background processes and manage their
lifecycle (start, stop, PID tracking).

## Alternatives considered
1. **All Bash**: Use `nc` or `socat` for HTTP.
   Rejected: no WebSocket support, no proper HTTP parsing, extremely fragile.
2. **All Python**: Rewrite everything in Python.
   Rejected: system administration in Python is less idiomatic, adds complexity
   for simple tasks like `apt-get install` or `useradd`.
3. **Go**: Compiled, fast, good for services.
   Rejected: adds compilation step, less accessible for contributors.

## Consequences
- Two languages in the project (Bash + Python)
- Python dependencies must be managed (pyproject.toml)
- Bash scripts must handle Python process lifecycle
- Testing requires both Bash tests and Python compilation checks

## Risks
- Python version differences between platforms (mitigated by pyproject.toml)
- Process management complexity (Bash starts Python, must track PIDs)
- Two-language projects are harder for some contributors
