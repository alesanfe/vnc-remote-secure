# Documentation Overview

This directory contains comprehensive documentation for the VNC Remote Secure project.

## Documentation Structure

```
docs/
├── architecture/               # System architecture
│   ├── overview.md             # This file
│   ├── components.md           # Project structure and modules
│   └── security-model.md       # Security architecture
├── adr/                        # Architecture Decision Records
│   ├── 0007-cross-platform-windows-support.md
│   └── 0008-bash-python-coexistence.md
├── installation/               # Installation guides
│   ├── windows.md              # Windows installation
│   └── uninstall.md           # Uninstallation guide
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
2. **[ADR-0008](../adr/0008-bash-python-coexistence.md)** - Bash/Python coexistence
3. **[ADR-0007](../adr/0007-cross-platform-windows-support.md)** - Windows support
4. **`AGENTS.md`** - Operational guide and verification commands

### For Operations
1. **`Makefile`** - Build, test, and lint targets
2. **`scripts/maintenance/`** - Backup, restore, cleanup, update
3. **`tools/doctor.py`** - System diagnostics

## Contributing to Documentation

Found an error or want to improve the documentation?

1. Check `CONTRIBUTING.md` at the project root
2. Submit a pull request with your improvements
3. Follow the existing documentation style

---

**Tip:** Start with the [Project Structure](components.md) guide if you're new to the project!
