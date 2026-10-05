# ADR 0001: Use nginx as reverse proxy

## Status
Accepted

## Context
The project exposes multiple services (noVNC, ttyd, health dashboard) that each
run on their own port. Without a reverse proxy, users would need to access each
service directly on its port, which:
- Exposes internal services to the internet
- Requires multiple ports open in the firewall
- Makes SSL/TLS termination complex (each service would need its own cert)
- Provides no unified access point or rate limiting

## Decision
Use nginx as a reverse proxy in front of all internal services. nginx handles:
- SSL/TLS termination (certificates managed in one place)
- Request routing (/vnc/ → noVNC, /terminal/ → ttyd, /health/ → health server)
- Rate limiting and access control
- HTTP to HTTPS redirection

## Alternatives Considered
1. **Direct port exposure**: Each service exposed on its own port with its own SSL.
   Rejected: complex certificate management, larger attack surface.
2. **Caddy**: Automatic HTTPS, simpler config.
   Rejected: less ubiquitous than nginx, fewer hardening guides available.
3. **HAProxy**: Excellent for TCP/HTTP load balancing.
   Rejected: overkill for a single-server setup, less intuitive config for this use case.

## Consequences
- nginx must be installed and configured (adds a dependency)
- Internal services can bind to localhost only (reduced attack surface)
- SSL certificates managed in one location
- Single point of entry for all traffic (port 443)
- nginx config must be maintained and tested

## Risks
- nginx misconfiguration could expose internal services
- nginx becomes a single point of failure
- Config syntax errors could block all access
