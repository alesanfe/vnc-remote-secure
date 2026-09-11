# ADR 0006: Python for web components, Bash for orchestration

## Status
Accepted

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
  - `health_web_server.py` — health dashboard (http.server)
  - `user_ui_app.py` — user management UI (Flask)
  - `web_terminal.py` — web terminal (Tornado WebSocket)
  - `landing_page.py` — landing page portal (http.server)
  - `audio_stream_server.py` — audio streaming (websockets)
  - `gamepad_server.py` — gamepad forwarding (websockets)

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
- Python dependencies must be managed (requirements.txt)
- Bash scripts must handle Python process lifecycle
- Testing requires both Bash tests and Python compilation checks

## Risks
- Python version differences between platforms (mitigated by requirements.txt)
- Process management complexity (Bash starts Python, must track PIDs)
- Two-language projects are harder for some contributors
