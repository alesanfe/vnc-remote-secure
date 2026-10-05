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
| [0001](ADR-001-use-nginx-as-reverse-proxy.md) | Use nginx as reverse proxy | Accepted |
| [0002](ADR-002-bind-internal-services-to-localhost.md) | Bind internal services to localhost | Accepted |
| [0003](ADR-003-use-systemd-for-service-management.md) | Use systemd for service management | Accepted |
| [0004](ADR-004-separate-secrets-from-configuration.md) | Separate secrets from configuration | Accepted |
| [0005](ADR-005-modular-bash-architecture.md) | Modular Bash architecture | Superseded (Bash stack removed) |
| [0006](ADR-006-python-for-web-components.md) | Python for web components, Bash for orchestration | Superseded (Python-canonical) |
| [0007](ADR-007-cross-platform-windows-support.md) | Cross-platform Windows support with documented limitations | Accepted |
| [0008](ADR-008-duckdns-for-dynamic-dns.md) | DuckDNS for dynamic DNS | Accepted |
| [0009](ADR-009-bash-python-coexistence.md) | Coexistence of Bash and Python implementations | Superseded (Python-canonical) |
| [0010](ADR-010-unified-token-signing.md) | Unified token signing with type separation | Accepted |
| [0011](ADR-011-shared-state-abstraction.md) | Shared state abstraction for multi-process deployments | Accepted |
| [0012](ADR-012-delegated-sso-and-operator-session-ip-binding.md) | Delegated SSO and opt-in operator-session IP binding | Accepted |
