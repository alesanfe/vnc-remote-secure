# ADR-0009: Coexistence of Bash and Python implementations

**Date:** 2026-09-11
**Status:** Superseded — The Python CLI (`vnc_remote_secure.cli`) is now
the single canonical runtime on every platform. Bash and PowerShell are
thin compatibility wrappers that delegate to it. See `AGENTS.md` for the
current architecture.

## Context

The VNC Remote Secure project contains two parallel implementations:

1. **Bash/Linux** (`src/rpi-vnc-remote.sh` + `src/lib/`): The original
   implementation for Raspberry Pi / Linux servers. Uses TigerVNC, ttyd,
   nginx, systemd, certbot, fail2ban, and other Linux-native tools.

2. **Python cross-platform** (`src/vnc_remote_secure/`): The newer
   implementation designed to run on both Linux and Windows. Uses a
   platform adapter pattern to delegate OS-specific operations.

3. **Windows PowerShell** (`src/vnc_remote_secure/native/windows/`): Native Windows commands
   for managing UltraVNC, Windows Firewall, and Windows Services.

This dual (and partially triple) architecture raises questions about
which implementation is canonical, when to use each, and how to avoid
divergence.

## Decision

We accept the coexistence of both implementations with the following
rules:

### Canonical implementations by platform

| Platform | Canonical entry point | Implementation |
|----------|----------------------|----------------|
| Linux | `vnc-remote` CLI (Python) | Python + Bash (`src/rpi-vnc-remote.sh` legacy) |
| Windows | `vnc-remote` CLI / `VncRemote.ps1` | Python + PowerShell |

### Shared Python services

Both platforms share the Python service layer (`src/vnc_remote_secure/services/`):
- `landing.py` — landing page
- `health.py` — health dashboard
- `terminal.py` — web terminal (Tornado WebSocket)
- `vnc.py` — VNC management
- `novnc.py` — noVNC/websockify
- `audio.py` — audio streaming
- `gamepad.py` — gamepad forwarding

### Platform-specific code

- **Linux**: `src/rpi-vnc-remote.sh` sources `src/lib/` modules for
  system management (systemd, nginx, fail2ban, certbot, tigervncserver).
- **Windows**: `src/vnc_remote_secure/native/windows/` PowerShell commands manage UltraVNC,
  Windows Firewall, and Windows Services.
- **Python platform adapters**: `src/vnc_remote_secure/platform/{linux,windows}/`
  provide OS-specific operations to the shared service layer.

### Migration path

The Bash implementation is the mature, production-tested path for Linux.
The Python implementation is the cross-platform future. New features
should be implemented in Python when feasible, with Bash wrappers
delegating to Python services where possible.

## Consequences

- **Positive**: Linux users keep the stable Bash path; Windows users get
  native PowerShell management; shared Python services avoid duplication
  for cross-platform features (web terminal, landing, health).
- **Negative**: Two codebases require maintenance. Configuration defaults
  must be kept in sync. Tests must cover both paths.
- **Mitigation**: This ADR documents the boundary. The `src/vnc_remote_secure/core/constants.py`
  module is the single source of truth for defaults. The `src/vnc_remote_secure/config/defaults/`
  files provide platform-specific overrides.

## Related

- [ADR-0007: Cross-platform Windows support](0007-cross-platform-windows-support.md)
- `AGENTS.md` — project overview and verification commands
