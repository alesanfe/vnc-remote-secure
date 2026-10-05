# Architecture — entry point

The system is a **modular installer + adapter stack**: one Python
CLI orchestrates bash modules and per-platform adapters that expose
desktop (noVNC), terminal, audio and file share behind nginx.

Full detail lives in [`architecture/`](architecture/overview.md):

| Doc | Content |
|---|---|
| [Overview](architecture/overview.md) | system design and request flow |
| [Components](architecture/components.md) | project structure and components |
| [Service catalog](architecture/catalog.md) | runtime components + criticality |
| [Adapter contracts](architecture/adapter-contracts.md) | platform adapter interface (Linux/Windows) |
| [Compatibility matrix](architecture/compatibility-matrix.md) | supported OS/browser combinations |
| [Failure modes](architecture/failure-modes.md) | dependency failure matrix (Release It! style) |
| [Configuration](architecture/configuration.md) | configuration reference |
| [Security model](architecture/security-model.md) | auth, tokens, trust boundaries |
| [Threat model](architecture/threat-model.md) | see also top-level [THREAT_MODEL.md](THREAT_MODEL.md) |
| [Windows session model](architecture/windows-session-model.md) | session semantics on Windows |

Decisions: [`decisions/`](decisions/README.md) (numbered ADRs, 0012
entries). Operations: [`runbook/`](runbook/incident-response.md).
