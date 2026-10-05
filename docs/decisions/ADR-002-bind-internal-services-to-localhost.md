# ADR 0002: Bind internal services to localhost

## Status
Accepted

## Context
When nginx is enabled as a reverse proxy, internal services (VNC, noVNC,
terminal, health server) do not need to be accessible from external networks.
Binding them to 0.0.0.0 exposes them directly, bypassing nginx's SSL, rate
limiting, and access controls.

Previously, TigerVNC was started with `-localhost no`, which bound it to all
interfaces. This was a security issue identified during review.

## Decision
All internal services bind to 127.0.0.1 when nginx is enabled:
- TigerVNC: `-localhost yes`
- noVNC/websockify: `--listen 127.0.0.1:PORT`
- terminal (Python Tornado `services.terminal` on both platforms):
  bound to 127.0.0.1
- Health server: binds to 127.0.0.1

When nginx is disabled (development mode), services may bind to 0.0.0.0 for
direct access, but a warning is printed.

## Alternatives Considered
1. **Always bind to localhost**: Even in development mode.
   Rejected: makes development testing harder without nginx.
2. **Use iptables/ufw to block external access**: Firewall rules instead of bind address.
   Rejected: more complex, depends on firewall state, less explicit.

## Consequences
- External access only through nginx (port 443)
- Reduced attack surface (only one port exposed)
- Development mode requires explicit `NGINX_ENABLED=false`
- Services are not directly accessible from other machines without nginx

## Risks
- If nginx is misconfigured, services are unreachable (not just unsecured)
- Users in development mode may not realize services are exposed
