# ADR 0003: Use systemd for service management

## Status
Accepted

## Context
Originally, all services were managed by the main Bash script (`rpi-vnc-remote.sh`)
which stayed running (`wait`) to keep background processes alive. If the script
crashed or was killed, all services died with no automatic restart.

This is not production-grade: services should survive script termination,
restart on failure, and start on boot.

## Decision
Provide systemd service units (`systemd/*.service`) for each component:
- `vnc-remote-vnc.service` — TigerVNC server
- `vnc-remote-novnc.service` — websockify/noVNC proxy
- `vnc-remote-ttyd.service` — web terminal
- `vnc-remote-health.service` — health monitoring

Each unit includes:
- `Restart=on-failure` with `RestartSec`
- Security hardening (`NoNewPrivileges`, `ProtectSystem=strict`, etc.)
- `User=` with non-privileged service user
- `EnvironmentFile=` from protected secrets directory
- Explicit dependencies (`Requires=`, `After=`)

The Bash script remains for development/testing; systemd is for production.

## Alternatives considered
1. **Keep Bash script as sole manager**: Simpler but not production-grade.
   Rejected: no auto-restart, no boot persistence, no resource limits.
2. **Supervisord**: Python process manager.
   Rejected: adds Python dependency for process management, less native than systemd.
3. **Docker for everything**: Containerize all services.
   Rejected: VNC needs display access, containers add complexity for this use case.

## Consequences
- Two modes of operation: script (dev) and systemd (production)
- systemd units must be maintained alongside script changes
- Security hardening options need testing per-service (VNC needs home access)
- `systemd-analyze security` can score each unit

## Risks
- Hardening too aggressively can break services (e.g., `ProtectHome=true` breaks VNC)
- Two code paths (script + systemd) can diverge
- systemd is Linux-only (Windows uses the Bash script)
