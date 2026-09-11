# Architecture Decision Records (ADR)

This directory contains Architecture Decision Records for VNC Remote Secure.

ADRs document the "why" behind architectural choices — not just what was decided,
but the context, alternatives considered, and consequences of each decision.

## Format

Each ADR follows this structure:

```
# ADR NNNN: Title

## Status
Accepted | Deprecated | Superseded by ADR NNNN

## Context
What is the problem being addressed?

## Decision
What is the decision?

## Alternatives Considered
What other options were evaluated?

## Consequences
What are the implications of this decision?

## Risks
What could go wrong?
```

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-use-nginx-as-reverse-proxy.md) | Use nginx as reverse proxy | Accepted |
| [0002](0002-bind-internal-services-to-localhost.md) | Bind internal services to localhost | Accepted |
| [0003](0003-use-systemd-for-service-management.md) | Use systemd for service management | Accepted |
| [0004](0004-separate-secrets-from-configuration.md) | Separate secrets from configuration | Accepted |
| [0005](0005-modular-bash-architecture.md) | Modular Bash architecture | Accepted |
| [0006](0006-python-for-web-components.md) | Python for web components, Bash for orchestration | Accepted |
| [0007](0007-cross-platform-windows-support.md) | Cross-platform Windows support with documented limitations | Accepted |
| [0008](0008-duckdns-for-dynamic-dns.md) | DuckDNS for dynamic DNS | Accepted |
