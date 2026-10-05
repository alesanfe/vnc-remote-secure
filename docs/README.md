# VNC Remote Secure Documentation

## Requirements & Governance
- [Requirements](REQUIREMENTS.md) - Verifiable FRs, measurable NFRs, DoD + DoR
- [Data Model](DATA_MODEL.md) - Persistent state, formats and boundaries
- [Privacy](PRIVACY.md) - Data inventory and privacy stance
- [Dependencies](DEPENDENCIES.md) - Runtime/dev stack and update policy
- [Maturity Model](MATURITY.md) - A–E self-assessment + 0–4 professionalism matrix
- [Quality Attributes](QUALITY.md) - Priorities, budgets, trade-off rules
- [Deprecations](DEPRECATION.md) - Lifecycle and removal policy
- [Operations](OPERATIONS.md) - Index of runbooks and procedures
- [Policies](policies/README.md) - Versioning, compatibility, deps, secrets, backups, incidents
- [Feature Flags](FEATURE_FLAGS.md) - Toggle registry with owners and lifecycle
- [Technical Debt](TECH_DEBT.md) - Formal debt register (TD-xx)
- [Governance](GOVERNANCE.md) - Roles, decisions, ownership

## Architecture
- [Architecture entry point](ARCHITECTURE.md) - Index of the architecture docs
- [Overview](architecture/overview.md) - System architecture and design
- [Components](architecture/components.md) - Project structure and components
- [Service Catalog](architecture/catalog.md) - Runtime component inventory + criticality
- [Failure Modes](architecture/failure-modes.md) - Dependency failure matrix (Release It! style)
- [Configuration](architecture/configuration.md) - Configuration reference
- [Security Model](architecture/security-model.md) - Security design and policies

## Architecture Decision Records (ADRs)
- [ADR Index](decisions/README.md) - List of all architecture decisions

## Installation
- [Linux](installation/linux.md) - Install on Linux/Raspberry Pi
- [Windows](installation/windows.md) - Install on Windows
- [Docker](installation/docker.md) - Docker packaging (Dockerfile + compose, Linux only)
- [Upgrade](installation/upgrade.md) - Upgrade from previous versions
- [Uninstall](installation/uninstall.md) - Remove VNC Remote Secure

## Migration
- [Migration Guide](migration/README.md) - Migrate from previous versions

## User Guide
- [Getting Started](user-guide/getting-started.md) - Quick start guide
- [Desktop](user-guide/desktop.md) - Browser desktop access via noVNC
- [Terminal](user-guide/terminal.md) - Web terminal access
- [Audio](user-guide/audio.md) - Audio streaming (optional)
- [Gamepad](user-guide/gamepad.md) - Gamepad forwarding (optional)
- [Temporary Sessions](user-guide/sessions.md) - Shareable ephemeral access links
- [Health Endpoint](user-guide/health.md) - Health monitoring
- [Troubleshooting](user-guide/troubleshooting.md) - Common issues and solutions

## Operations
- [Monitoring Runbook](runbook/monitoring.md) - Health, metrics, posture and alerting
- [SLO/SLI + RPO/RTO](runbook/slo.md) - Reliability and recovery objectives
- [Recovery Runbook](runbook/recovery.md) - Backup/restore and disaster recovery
- [Incident Response](runbook/incident-response.md) - Severity classes, containment, disclosure
- [Recovery Drills](runbook/drills.md) - Recovery/chaos exercise battery + drill log
- [Postmortem Template](runbook/postmortem-template.md) - Blameless incident review format
- [OpenAPI Spec](api/openapi.v1.yaml) - `/api/v1/*` schema (canonical)
- [Recording Format](RECORDING_FORMAT.md) - `.vrsrec` spec (external, version-stable)

## Developer
- [Development Setup](developer/development-setup.md) - Set up dev environment
- [Testing](developer/testing.md) - Test suite guide
- [Releasing](developer/releasing.md) - Release process
- [Release Checklist](developer/release-checklist.md) - E2E scenario matrix for release validation
- [Code Review Checklist](developer/code-review-checklist.md) - Reviewer gate (blocker/important/suggestion/question/nit)
- [Adding Platform Support](developer/adding-platform-support.md) - Platform adapter guide
- [UI/UX Conventions](developer/ui-ux.md) - Design tokens, component states and accessibility contract for the SPA

## Security
- [Threat Model](THREAT_MODEL.md) - Formal STRIDE threat model and risk matrix
- [Risk Register](security/risk-register.md) - Formal risk acceptance and controls
- [OpenSSF Best Practices](security/ossf-baseline.md) - Badge criteria self-assessment
- [Security Policy](../SECURITY.md) - Responsible disclosure and scope

## Reports
- [Consistency audit 2026-09-11](reports/consistency-audit-2026-09-11.md) - First pass
- [Consistency audit — second pass](reports/consistency-audit-2026-09-11-second-pass.md)
- [Consistency audit — third pass](reports/consistency-audit-2026-09-11-third-pass.md)
- [Consistency audit — fourth pass](reports/consistency-audit-2026-09-11-fourth-pass.md)
- [Consistency audit — fifth pass](reports/consistency-audit-2026-09-11-fifth-pass.md)

## Archive
- [Original README](archive/README-original.md) - Original project README
