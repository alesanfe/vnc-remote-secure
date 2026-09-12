# ADR 0008: DuckDNS for dynamic DNS

## Status
Accepted

## Context
The project needs dynamic DNS to maintain a stable domain name when the server's
IP address changes (common with home internet connections). Without dynamic DNS,
SSL certificates and external access would break whenever the IP changes.

## Decision
Use DuckDNS (https://www.duckdns.org/) as the default dynamic DNS provider:
- Free, no registration required beyond a DuckDNS account
- Simple API: `https://www.duckdns.org/update?domains=SUBDOMAIN&token=TOKEN&ip=`
- Supports both IPv4 and IPv6
- Cross-platform update scripts (Bash + Python fallback)

Implemented in `scripts/utilities/duckdns_update.sh` and `scripts/utilities/duckdns_update.py`,
integrated into both `launch.sh` (Windows) and `src/rpi-vnc-remote.sh` (Linux).

## Alternatives considered
1. **Cloudflare DNS API**: More features, better API.
   Rejected as default: requires a registered domain (not free), more complex setup.
   Planned as optional provider in v0.4.0 (DNS provider abstraction).
2. **No-ip.com**: Free tier available.
   Rejected: requires monthly confirmation, more restrictive free tier.
3. **Manual IP updates**: User updates DNS by hand.
   Rejected: defeats the purpose of automation.
4. **Tailscale/WireGuard**: VPN-based access, no DNS needed.
   Recommended as an alternative in documentation, but not a DNS solution.

## Consequences
- Users need a DuckDNS account (free, takes 1 minute)
- DuckDNS token stored in `.env` (gitignored)
- Update runs automatically on startup and can run as daemon
- Domain format: `SUBDOMAIN.duckdns.org`
- Let's Encrypt can use this domain for SSL certificates (Linux)

## Risks
- DuckDNS service outage would break DNS resolution
- DuckDNS is a free service with no SLA
- Token leakage would allow DNS hijacking (mitigated by .gitignore + Gitleaks)
- Future DuckDNS API changes could break update scripts
