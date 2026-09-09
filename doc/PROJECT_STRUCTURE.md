# 🏗️ Project Structure

## 📋 Overview

Complete documentation of the Raspberry Pi VNC Remote project structure and organization.

## 🎯 Project Organization

### 📁 Final Structure

```
raspberrypinoVNC/
├── src/rpi-vnc-remote.sh      # Main entry point script
├── src/                       # Source code organized
│   ├── lib/                   # Modules by category
│   │   ├── core/              # Core functionality (modular structure)
│   │   │   ├── config.sh      # Configuration management
│   │   │   ├── logging.sh     # Structured logging system
│   │   │   ├── validation.sh  # Input validation system
│   │   │   ├── error_handling.sh # Error handling & recovery
│   │   │   ├── process_utils.sh # Graceful process management
│   │   │   ├── utils.sh       # Main utilities (loads specialized modules)
│   │   │   ├── display_utils.sh # UI & display functions
│   │   │   ├── dependency_utils.sh # Package management
│   │   │   ├── command_utils.sh # Command handling
│   │   │   ├── cleanup_utils.sh # Cleanup functions
│   │   │   └── services.sh    # Service management
│   │   ├── security/          # Security modules
│   │   │   ├── ssl.sh         # SSL/TLS management
│   │   │   ├── user.sh        # User management
│   │   │   └── fail2ban.sh    # Fail2ban integration
│   │   ├── web/              # Web components
│   │   │   ├── nginx.sh      # Nginx configuration
│   │   │   ├── user_ui.sh    # User UI management (Bash)
│   │   │   ├── user_ui_app.py # Flask user-management UI
│   │   │   └── templates/    # HTML templates for UI
│   │   │       ├── index.html
│   │   │       ├── login.html
│   │   │       └── users.html
│   │   ├── communication/     # Notifications & alerts
│   │   │   ├── notifications.sh # Discord notifications
│   │   │   └── alerts.sh     # Webhook/email alerts
│   │   ├── monitoring/        # System monitoring
│   │   │   ├── healthcheck.sh # Health monitoring
│   │   │   ├── health_web_server.sh # Health web server (Bash)
│   │   │   ├── health_web_server.py # Python health web server
│   │   │   └── monitoring.sh  # Prometheus/Grafana monitoring
│   │   └── features/         # Additional features
│   │       └── recording.sh  # Session recording
│   ├── config/                # Configuration templates
│   │   └── nginx.conf        # Nginx configuration
│   └── templates/             # Health dashboard HTML templates
│       ├── health.css
│       ├── health.html
│       └── health.js
├── data/                      # Runtime data (gitignored)
│   ├── ssl/                   # SSL certificates
│   └── logs/                  # System logs
├── scripts/                   # Maintenance scripts
│   ├── backup.sh              # Complete backup
│   ├── restore.sh             # Restore from backup
│   ├── health-check.sh        # System verification
│   ├── cleanup.sh             # System cleanup
│   └── update.sh              # System update
├── tests/                     # Automated tests (pyramid strategy)
│   ├── run_tests.sh           # Test runner
│   ├── lib/                   # Test framework
│   │   └── test_framework.sh
│   ├── static/                # Level 0: lint, syntax, shellcheck
│   ├── unit/                  # Level 1: isolated function tests
│   │   └── core/              # Core module unit tests
│   ├── integration/           # Level 3: multi-module interaction
│   ├── e2e/                   # Level 5: entry-point and full-flow
│   └── security/              # Level 7: password, sanitization, hardening
├── docker/                    # Docker configuration
│   ├── Dockerfile             # Test environment image
│   └── docker-compose.yml     # Docker Compose services
├── doc/                       # Complete documentation
│   ├── developer/             # Developer guides
│   ├── installation/          # Installation guides
│   └── user-guide/            # User guides
├── .github/workflows/         # CI/CD pipeline
│   └── ci-cd.yml              # GitHub Actions workflow
├── .env.example               # Environment variable template
├── requirements.txt           # Python dependencies (Flask)
├── Makefile                   # Build, test, and lint targets
└── AGENTS.md                  # Operational guide for agents/contributors
```

## 🔧 Reorganization Changes

### ✅ **1. Eliminated Redundancies**
- **Wrapper script removed** - Single main script in `src/`
- **Duplicate paths fixed** - Updated all internal references
- **Makefile updated** - Points to new script location and modular test structure

### ✅ **2. Consolidated Configuration**
- **Data directory created** - `data/ssl/`, `data/logs/`
- **Config directory created** - `src/config/nginx.conf`
- **SSL paths updated** - nginx.conf uses `data/ssl/`
- **Code vs config separation** - Clear boundaries

### ✅ **3. Maintenance Scripts Added**
- **backup.sh** - Automated backup with timestamps
- **restore.sh** - Safe restore with confirmation
- **health-check.sh** - Complete system verification
- **cleanup.sh** - Log and temp file cleanup
- **update.sh** - System and project updates

### ✅ **4. Documentation Enhanced**
- **API documentation** - Health endpoint reference
- **Troubleshooting guide** - Common issues and solutions
- **Contributing guide** - Development guidelines
- **Docker guide** - Container testing environments

### ✅ **5. Configuration Improved**
- **.gitignore updated** - New structure support
- **.env.example synced** - Matches .env variables
- **Professional structure** - Production-ready organization

### ✅ **6. Code Separation & Standardization**
- **Python/Shell separation** - Each language in its own files
- **User UI refactored** - Flask app moved to dedicated Python file
- **HTML templates separated** - Templates in dedicated directory
- **Standardized shell structure** - All shell files follow consistent pattern
- **Error handling unified** - `set -e` and `set -o pipefail` in all scripts
- **ShellCheck directives** - Proper linting controls in all modules

### ✅ **7. Advanced Modular Architecture**
- **Graceful Process Management** - Replaced `kill -9` with timeout-based termination
- **Structured Logging System** - Multi-level logging with timestamps and file output
- **Robust Input Validation** - Comprehensive validation for passwords, ports, domains, emails
- **Advanced Error Handling** - Automatic recovery with retry mechanisms and backoff
- **Modular Utilities** - Large functions split into specialized, maintainable modules
- **Enhanced Security** - Improved user management and process isolation

### ✅ **8. CI/CD & Dependency Management**
- **GitHub Actions** - CI/CD pipeline using Makefile targets
- **requirements.txt** - Pinned Python dependencies (Flask)
- **Docker integration** - Dockerfile installs from requirements.txt
- **Test pyramid** - Tests organized by level (static, unit, integration, e2e, security)

## 🔧 Core System Modules

### 📋 Core System Modules
| Module | Purpose | Key Features |
|--------|---------|--------------|
| `logging.sh` | Structured logging | Levels (DEBUG/INFO/WARN/ERROR/FATAL), timestamps, file output |
| `validation.sh` | Input validation | Password strength, port/domain validation, sanitization |
| `error_handling.sh` | Error recovery | Automatic retry, backoff, error tracking, recovery actions |
| `process_utils.sh` | Process management | Graceful termination, timeout handling, user process cleanup |
| `display_utils.sh` | UI functions | Banners, progress bars, access info display |
| `dependency_utils.sh` | Package management | Safe installation, architecture detection, validation |
| `command_utils.sh` | Command handling | Service management, status checking, command validation |
| `cleanup_utils.sh` | Cleanup operations | Resource cleanup, network cleanup, emergency cleanup |

## 🚀 Usage Examples

### Maintenance Scripts
```bash
# Complete system backup
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh backup_20260428_211300.tar.gz

# System health check
./scripts/health-check.sh

# System cleanup
./scripts/cleanup.sh

# System update
./scripts/update.sh
```

### File Locations
```bash
# Main script
./src/rpi-vnc-remote.sh

# Configuration template
./.env.example

# Python dependencies
./requirements.txt

# SSL certificates
./data/ssl/fullchain.pem
./data/ssl/privkey.pem

# System logs
./data/logs/
```

### Testing
```bash
# Run all tests
make test-all

# Run specific test levels
make test-unit
make test-integration
make test-security

# Lint all shell scripts
make lint
```

## 📊 Benefits Achieved

- ✅ **Clean code** - No redundancies, better structure
- ✅ **Organized configuration** - Separated from code and data
- ✅ **Automated maintenance** - Scripts for backup, restore, health-check
- ✅ **Complete documentation** - API, troubleshooting, contribution guides
- ✅ **Professional structure** - Production-ready organization
- ✅ **Language separation** - Python, Bash, and HTML in dedicated files
- ✅ **Standardized error handling** - Consistent failure behavior across all scripts
- ✅ **Improved maintainability** - Each component has clear responsibilities
- ✅ **CI/CD integration** - Automated testing via GitHub Actions and Makefile
- ✅ **Dependency management** - Python deps pinned in requirements.txt

## 🔄 Migration Guide

If upgrading from an older version:

1. **Backup current setup**
   ```bash
   ./scripts/backup.sh
   ```

2. **Update project files**
   ```bash
   git pull origin main
   ```

3. **Move SSL certificates**
   ```bash
   mkdir -p data/ssl
   mv ssl/* data/ssl/
   ```

4. **Update configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

5. **Install Python dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

6. **Restart services**
   ```bash
   ./src/rpi-vnc-remote.sh restart
   ```

The project now has a much more professional and maintainable organization with all best practices implemented.
