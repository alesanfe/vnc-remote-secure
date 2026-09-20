# Documentation Overview

This directory contains comprehensive documentation for the VNC Remote Secure project.

## Documentation Structure

```
docs/
├── THREAT_MODEL.md             # Formal STRIDE threat model (canonical)
├── architecture/               # System architecture
│   ├── overview.md             # This file
│   ├── components.md           # Project structure and modules
│   ├── configuration.md        # Configuration reference
│   ├── security-model.md       # Security architecture
│   └── threat-model.md         # Redirects to ../THREAT_MODEL.md
├── adr/                        # Architecture Decision Records (see adr/README.md for index)
│   ├── 0001-use-nginx-as-reverse-proxy.md
│   ├── 0002-bind-internal-services-to-localhost.md
│   ├── 0003-use-systemd-for-service-management.md
│   ├── 0004-separate-secrets-from-configuration.md
│   ├── 0005-modular-bash-architecture.md
│   ├── 0006-python-for-web-components.md
│   ├── 0007-cross-platform-windows-support.md
│   ├── 0008-duckdns-for-dynamic-dns.md
│   ├── 0009-bash-python-coexistence.md
│   ├── 0010-unified-token-signing.md
│   └── 0011-shared-state-abstraction.md
├── api/                        # OpenAPI specification (openapi.yaml)
├── installation/               # Installation guides
│   ├── linux.md                 # Linux installation
│   ├── windows.md               # Windows installation
│   ├── docker.md                # Docker installation
│   ├── upgrade.md               # Upgrade guide
│   └── uninstall.md             # Uninstallation guide
├── migration/                  # Migration notes (README.md)
├── runbook/                    # Operational runbooks (monitoring.md)
├── user-guide/                 # User documentation
├── developer/                  # Developer guides
├── archive/                    # Archived documentation
└── reports/                    # Audit and review reports
```

## Quick Navigation

### For New Users
1. **[Project Structure](components.md)** - Understand the codebase layout
2. **[Installation (Windows)](../installation/windows.md)** - Get running on Windows
3. **[Security Model](security-model.md)** - Security architecture

### For System Administrators
1. **[Installation (Windows)](../installation/windows.md)** - Complete setup
2. **[Uninstall Guide](../installation/uninstall.md)** - Removal instructions
3. **`.env.example`** - All configuration options

### For Developers
1. **[Project Structure](components.md)** - System design and modules
2. **[ADR-0009](../adr/0009-bash-python-coexistence.md)** - Bash/Python coexistence
3. **[ADR-0007](../adr/0007-cross-platform-windows-support.md)** - Windows support
4. **`AGENTS.md`** - Operational guide and verification commands

### For Operations
1. **`Makefile`** - Build, test, and lint targets
2. **`scripts/maintenance/`** - Backup, restore, cleanup, update
3. **`vnc-remote doctor`** - System diagnostics (canonical, in `src/vnc_remote_secure/core/doctor.py`)

## Contributing to Documentation

Found an error or want to improve the documentation?

1. Check `CONTRIBUTING.md` at the project root
2. Submit a pull request with your improvements
3. Follow the existing documentation style

---

**Tip:** Start with the [Project Structure](components.md) guide if you're new to the project!
