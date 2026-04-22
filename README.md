# Raspberry Pi VNC Remote Setup

Secure remote access to Raspberry Pi via browser using noVNC (desktop) and ttyd (terminal) with optional SSL/TLS support.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Overview

This project provides a secure, easy-to-use solution for remote access to Raspberry Pi systems through a web browser. It combines:

- **noVNC**: HTML5 VNC client for full desktop access
- **ttyd**: Web-based terminal for command-line access
- **SSL/TLS**: Optional encryption using Let's Encrypt certificates
- **Security Features**: Input sanitization, Fail2ban, port knocking, and more
- **Monitoring**: Optional Prometheus + Grafana integration
- **User Management**: Web interface for user administration

The solution is designed for:
- Remote administration of Raspberry Pi devices
- Secure headless server management
- Educational environments
- IoT device management
- Development and testing environments

## Features

### Core Features
- **Web-based Desktop Access**: Full desktop GUI via noVNC in any modern browser
- **Web-based Terminal**: Command-line access via ttyd
- **SSL/TLS Support**: Automatic Let's Encrypt certificate generation and renewal
- **Multi-architecture Support**: Works on armhf, arm64, and amd64
- **Temporary User Isolation**: Dedicated user for remote access sessions
- **Automatic Cleanup**: Removes temporary users and processes on exit

### Security Features
- **Input Sanitization**: All user inputs sanitized to prevent command injection
- **Secure Defaults**: Strong password validation and secure session management
- **Fail2ban Integration**: Protection against brute force attacks
- **Port Knocking**: Additional security layer (optional)
- **User Management UI**: Web interface with proper validation
- **SSL Certificate Auto-renewal**: Certificates renewed before expiration

### Advanced Features
- **Monitoring Stack**: Prometheus + Grafana + Node Exporter (optional)
- **Session Recording**: Terminal and VNC session recording (placeholder)
- **BeEF Integration**: Browser exploitation framework for security testing (optional, disabled by default)
- **Notifications**: Email alerts for service status
- **Health Monitoring**: Automatic service restart on failure

## Requirements

### System Requirements
- **Operating System**: Raspberry Pi OS (Bullseye or Bookworm), Ubuntu 20.04+, Debian 11+
- **Architecture**: armhf (Raspberry Pi 3/4), arm64 (Raspberry Pi 5), amd64 (x86_64)
- **RAM**: Minimum 1GB (2GB+ recommended for desktop environments)
- **Storage**: Minimum 8GB free space
- **Network**: Internet connection for SSL certificates and dependencies

### Software Requirements
- **bash**: Version 4.0 or higher
- **sudo**: Required for system operations
- **python3**: For User Management UI (optional)
- **curl**: For downloading dependencies
- **git**: For cloning the repository (optional)

### Optional Requirements
- **Domain Name**: For SSL/TLS (e.g., via DuckDNS)
- **Email Address**: For Let's Encrypt certificate notifications
- **Docker**: For containerized testing (optional)

## Installation

### Method 1: Clone and Run (Recommended)

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Make the script executable
chmod +x src/rpi-vnc-remote.sh

# Run with basic configuration
TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

### Method 2: Using Makefile

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Install system dependencies
make deps-install

# Run the script
make run
```

### Method 3: System-wide Installation

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Install script to /usr/local/bin
make install

# Run from anywhere
rpi-vnc-remote.sh
```

### Installing Desktop Environment

The script requires a desktop environment for VNC access. If not already installed:

```bash
# For Raspberry Pi OS (lightweight)
sudo apt update
sudo apt install xfce4 xfce4-goodies

# For Ubuntu/Debian
sudo apt update
sudo apt install xfce4 xfce4-goodies tigervnc-standalone-server
```

## Quick Start

### Basic Usage (No SSL)

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Make the script executable
chmod +x src/rpi-vnc-remote.sh

# Run with basic configuration
TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

**Access**: 
- Desktop: `http://your-raspberry-pi-ip:6080`
- Terminal: `http://your-raspberry-pi-ip:5000`

### With SSL/TLS (Recommended for Production)

```bash
# Run with SSL enabled
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org EMAIL=myemail@example.com ./src/rpi-vnc-remote.sh
```

**Access**:
- Desktop: `https://mydomain.duckdns.org:6080`
- Terminal: `https://mydomain.duckdns.org:5000`

### Using Makefile

The project includes a comprehensive Makefile for common tasks:

```bash
make help              # Show all available commands

# Installation
make install           # Install script to /usr/local/bin
make uninstall         # Remove script from /usr/local/bin

# Testing
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests only
make test-security     # Run security tests only
make docker-test       # Run tests in Docker

# Script Execution
make run               # Run the script
make run-ssl           # Run with SSL
make stop              # Stop services

# SSL Management
make ssl-setup         # Setup SSL certificates
make ssl-renew         # Renew SSL certificates
make ssl-check         # Check SSL certificate expiry

# User Management
make user-create       # Create temporary user
make user-remove       # Remove temporary user

# Dependencies
make deps-install      # Install system dependencies
make ttyd-install      # Install ttyd

# Service Management
make vnc-start         # Start VNC server
make vnc-stop          # Stop VNC server
make ttyd-start        # Start ttyd
make ttyd-stop         # Stop ttyd
make novnc-start       # Start noVNC
make services-start    # Start all services
make services-stop     # Stop all services

# Other
make cleanup           # Run cleanup
make status            # Show service status
make clean             # Clean temporary files
make lint              # Run shellcheck linting
```

## Configuration

The script uses environment variables for configuration. You can set these variables before running the script or in a `.env` file.

### Required Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `TTYD_PASSWD` | Password for authentication | `changeme` | Minimum 8 characters, must include uppercase, lowercase, and numbers. **Change immediately!** |

### Optional Variables for SSL

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `DUCK_DOMAIN` | Domain for SSL certificate | (empty) | Required for SSL/TLS (e.g., `mydomain.duckdns.org`) |
| `EMAIL` | Email for SSL certificate notifications | `user@example.com` | Used by Let's Encrypt |

### Common Configuration Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `NOVNC_PORT` | Port for noVNC web interface | `6080` | Desktop access port |
| `TTYD_PORT` | Port for ttyd web interface | `5000` | Terminal access port |
| `VNC_PORT` | Port for VNC server | `5901` | Internal VNC port |
| `TEMP_USER` | Temporary user name for remote access | `remote` | User created for remote sessions |
| `VNC_DISPLAY` | VNC display number | `:1` | X11 display for VNC |
| `VNC_GEOMETRY` | VNC screen resolution | `1920x1080` | Desktop resolution |
| `VNC_DEPTH` | VNC color depth | `24` | Color depth (16, 24, or 32) |
| `VNC_PASSWORD` | Password for VNC authentication | `YourStrongPassword123` | Separate from TTYD_PASSWD |

### Security Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `FLASK_SECRET_KEY` | Secret key for User Management UI | (auto-generated) | Set explicitly in production |
| `FAIL2BAN_ENABLED` | Enable Fail2ban protection | `false` | Protects against brute force attacks |
| `PORT_KNOCK_ENABLED` - Enable port knocking | `false` | Additional security layer |
| `PORT_KNOCK_INTERFACE` | Network interface for port knocking | `eth0` | Network interface to use |
| `SSL_DIR` | Directory for SSL certificates | `./ssl` | SSL certificate storage |
| `SSL_CERT` | Path to SSL certificate file | `$SSL_DIR/cert.pem` | Auto-generated |
| `SSL_KEY` | Path to SSL private key file | `$SSL_DIR/key.pem` | Auto-generated |

### Monitoring Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `MONITORING_ENABLED` | Enable Prometheus + Grafana | `false` | Monitoring stack |
| `PROMETHEUS_PORT` | Prometheus web interface port | `9090` | Metrics collection |
| `GRAFANA_PORT` | Grafana web interface port | `3000` | Visualization dashboard |
| `NODE_EXPORTER_PORT` | Node Exporter metrics port | `9100` | System metrics |

### Recording Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `RECORDING_ENABLED` | Enable session recording | `false` | **Placeholder feature** |
| `RECORDING_DIR` | Recording directory | `./recordings` | Session recordings storage |
| `RECORDING_FORMAT` | Recording format | `asciinema` | asciinema or script |

**Note**: Session recording is currently a placeholder feature. See [Recording Limitations](#recording-limitations) below.

### Advanced Configuration Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `LOG_LEVEL` | Logging verbosity level | `info` | debug, info, warn, error |
| `CONNECTION_TIMEOUT` | Connection timeout in seconds | `30` | Network timeout |
| `MAX_CONNECTIONS` | Maximum concurrent connections | `10` | Connection limit |
| `VERBOSE` | Enable verbose output | `false` | Debug information |
| `SKIP_DEPS` | Skip dependency installation | `false` | Faster startup if deps installed |
| `KEEP_TEMP_USER` - Keep temporary user on exit | `false` | Don't cleanup on exit |
| `AUTO_START` | Auto-start services on boot | `false` | Systemd integration |

### BeEF Configuration Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `BEEF_ENABLED` | Enable BeEF injection | `false` | **Security testing only** |
| `BEEF_HOOK_URL` | URL for BeEF hook script | (empty) | BeEF server endpoint |
| `INDEX_FILE` | noVNC index file path | `/usr/share/novnc/index.html` | Web interface file |
| `VNC_FILE` | noVNC VNC file path | `/usr/share/novnc/vnc.html` | VNC client file |

### Using a .env File

Create a `.env` file in the project root:

```bash
# Copy example file
cp .env .env

# Edit with your configuration
nano .env
```

Example `.env` file:

```bash
# Required
TTYD_PASSWD=MySecurePassword123

# SSL Configuration
DUCK_DOMAIN=mydomain.duckdns.org
EMAIL=myemail@example.com

# Ports
NOVNC_PORT=6080
TTYD_PORT=5000
VNC_PORT=5901

# User Configuration
TEMP_USER=remote
TTYD_USERNAME=pi

# Security
FAIL2BAN_ENABLED=true
PORT_KNOCK_ENABLED=false

# Monitoring
MONITORING_ENABLED=false

# Advanced
LOG_LEVEL=info
VERBOSE=false
```

Then run:

```bash
# Load .env file and run
set -a && source .env && set +a
./src/rpi-vnc-remote.sh
```

## Deployment

### Running as a Systemd Service

For production deployment, it's recommended to run the application as a systemd service for automatic startup on boot and better process management.

#### Create Systemd Service File

Create a new service file:

```bash
sudo nano /etc/systemd/system/rpi-vnc-remote.service
```

Add the following content:

```ini
[Unit]
Description=Raspberry Pi VNC Remote Service
After=network.target

[Service]
Type=simple
User=alesanfe
WorkingDirectory=/home/alesanfe/raspberrypinoVNC
Environment="TTYD_PASSWD=your_secure_password"
Environment="DUCK_DOMAIN=yourdomain.duckdns.org"
Environment="EMAIL=youremail@example.com"
ExecStart=/home/alesanfe/raspberrypinoVNC/src/rpi-vnc-remote.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Important**: Replace the environment variables with your actual values.

#### Enable and Start the Service

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable rpi-vnc-remote.service

# Start the service immediately
sudo systemctl start rpi-vnc-remote.service

# Check service status
sudo systemctl status rpi-vnc-remote.service
```

#### Service Management Commands

```bash
# Start the service
sudo systemctl start rpi-vnc-remote.service

# Stop the service
sudo systemctl stop rpi-vnc-remote.service

# Restart the service
sudo systemctl restart rpi-vnc-remote.service

# View service status
sudo systemctl status rpi-vnc-remote.service

# View service logs
sudo journalctl -u rpi-vnc-remote.service -f

# Disable auto-start on boot
sudo systemctl disable rpi-vnc-remote.service
```

#### Using Environment File with Systemd

For better security, use an environment file instead of hardcoding variables:

```bash
# Create environment file
sudo nano /etc/rpi-vnc-remote.env
```

Add your configuration:

```bash
TTYD_PASSWD=your_secure_password
DUCK_DOMAIN=yourdomain.duckdns.org
EMAIL=youremail@example.com
NOVNC_PORT=6080
TTYD_PORT=5000
```

Set secure permissions:

```bash
sudo chmod 600 /etc/rpi-vnc-remote.env
```

Update the service file to use the environment file:

```ini
[Unit]
Description=Raspberry Pi VNC Remote Service
After=network.target

[Service]
Type=simple
User=alesanfe
WorkingDirectory=/home/alesanfe/raspberrypinoVNC
EnvironmentFile=/etc/rpi-vnc-remote.env
ExecStart=/home/alesanfe/raspberrypinoVNC/src/rpi-vnc-remote.sh
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart rpi-vnc-remote.service
```

### Docker Deployment

For containerized deployment, use Docker Compose:

```bash
cd docker
docker-compose up -d
```

This will:
- Build the Docker image
- Start the services in detached mode
- Enable automatic restart on failure

View logs:

```bash
docker-compose logs -f
```

Stop services:

```bash
docker-compose down
```

### Production Checklist

Before deploying to production:

- [ ] Change default password (TTYD_PASSWD)
- [ ] Enable SSL/TLS with valid domain
- [ ] Configure firewall rules
- [ ] Enable Fail2ban for brute force protection
- [ ] Set up monitoring (Prometheus + Grafana)
- [ ] Configure email notifications
- [ ] Test backup procedures
- [ ] Review security settings
- [ ] Update system packages
- [ ] Document configuration

### Monitoring the Service

#### Using Systemd

```bash
# Check if service is running
sudo systemctl is-active rpi-vnc-remote.service

# Check service status
sudo systemctl status rpi-vnc-remote.service

# View recent logs
sudo journalctl -u rpi-vnc-remote.service -n 50
```

#### Using Makefile

```bash
make status
```

#### Manual Check

```bash
# Check if processes are running
ps aux | grep vnc
ps aux | grep ttyd
ps aux | grep novnc

# Check if ports are listening
sudo netstat -tulpn | grep -E '6080|5000|5901'
```

## Usage

### Starting the Services

#### Basic Start (No SSL)

```bash
TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

This will:
1. Install required dependencies
2. Create a temporary user for remote access
3. Start the VNC server
4. Start ttyd for terminal access
5. Start noVNC for desktop access
6. Display access information

#### Start with SSL/TLS

```bash
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org EMAIL=myemail@example.com ./src/rpi-vnc-remote.sh
```

This will additionally:
1. Generate SSL certificates using Let's Encrypt
2. Configure SSL for all services
3. Set up automatic SSL renewal

#### Start with Security Features

```bash
# With Fail2ban
FAIL2BAN_ENABLED=true TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh

# With Port Knocking
PORT_KNOCK_ENABLED=true PORT_KNOCK_SEQUENCE=1000,2000,3000 TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh

# With User Management UI
USER_UI_ENABLED=true FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

#### Start with Monitoring

```bash
MONITORING_ENABLED=true TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

This will:
1. Install Prometheus for metrics collection
2. Install Grafana for visualization
3. Install Node Exporter for system metrics
4. Configure dashboards
5. Start all monitoring services

### Accessing the Services

After starting the services, you can access them:

#### Desktop Access (noVNC)

- **Without SSL**: `http://your-raspberry-pi-ip:6080`
- **With SSL**: `https://your-domain:6080`

Use the credentials specified in `TTYD_USERNAME` and `TTYD_PASSWD`.

#### Terminal Access (ttyd)

- **Without SSL**: `http://your-raspberry-pi-ip:5000`
- **With SSL**: `https://your-domain:5000`

Use the credentials specified in `TTYD_USERNAME` and `TTYD_PASSWD`.

#### Monitoring Dashboards

- **Prometheus**: `http://your-raspberry-pi-ip:9090`
- **Grafana**: `http://your-raspberry-pi-ip:3000` (default credentials: admin/admin)

### Stopping the Services

```bash
# Stop all services
./src/rpi-vnc-remote.sh stop

# Or using Make
make stop
```

This will:
1. Stop all running services
2. Remove the temporary user
3. Clean up temporary files
4. Kill background processes

### Restarting Services

```bash
# Stop and start again
./src/rpi-vnc-remote.sh stop
TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

### Viewing Service Status

```bash
# Check if services are running
make status

# Or manually check
ps aux | grep vnc
ps aux | grep ttyd
ps aux | grep novnc
```

### Advanced Usage Examples

#### Custom Ports

```bash
TTYD_PASSWD=mypassword NOVNC_PORT=8080 TTYD_PORT=9000 VNC_PORT=5902 ./src/rpi-vnc-remote.sh
```

#### Custom Resolution

```bash
TTYD_PASSWD=mypassword VNC_GEOMETRY=2560x1440 VNC_DEPTH=32 ./src/rpi-vnc-remote.sh
```

#### Debug Mode

```bash
TTYD_PASSWD=mypassword LOG_LEVEL=debug VERBOSE=true ./src/rpi-vnc-remote.sh
```

#### Skip Dependency Installation

```bash
TTYD_PASSWD=mypassword SKIP_DEPS=true ./src/rpi-vnc-remote.sh
```

Useful when dependencies are already installed and you want faster startup.

#### Keep Temporary User

```bash
TTYD_PASSWD=mypassword KEEP_TEMP_USER=true ./src/rpi-vnc-remote.sh
```

The temporary user will not be removed on exit. Useful for testing.

### Command Line Options

```bash
# Show help
./src/rpi-vnc-remote.sh help

# Show configuration
./src/rpi-vnc-remote.sh config

# Run specific command
./src/rpi-vnc-remote.sh install
./src/rpi-vnc-remote.sh cleanup
```

## Project Structure

```
raspberrypinoVNC/
├── src/
│   ├── rpi-vnc-remote.sh    # Main entry point
│   └── lib/
│       ├── config.sh        # Configuration variables
│       ├── utils.sh         # Logging, utilities, cleanup
│       ├── ssl.sh           # SSL/TLS management
│       ├── user.sh          # User management
│       └── services.sh      # Service management (ttyd, VNC, noVNC)
├── tests/
│   ├── unit/
│   │   ├── test_syntax.sh   # Syntax validation tests
│   │   ├── test_config.sh   # Configuration validation tests
│   │   ├── test_utils.sh    # Utility function tests
│   │   ├── test_modules.sh  # Module loading tests
│   │   ├── test_edge_cases.sh
│   │   └── test_error_handling.sh
│   ├── integration/
│   │   └── test_docker.sh  # Docker integration tests
│   ├── security/
│   │   └── test_security.sh
│   └── run_tests.sh         # Test runner
├── docker/
│   ├── Dockerfile           # Test environment
│   └── docker-compose.yml   # Orchestration
└── ssl/                    # SSL certificates (gitignored)
```

## Testing

The project includes comprehensive unit and integration tests to ensure reliability and security.

### Test Runner

The project includes a test runner that allows you to run all tests or specific test suites:

```bash
# Show test runner help
cd tests && bash run_tests.sh -h

# List all available tests
cd tests && bash run_tests.sh -l

# Run all tests
cd tests && bash run_tests.sh -a

# Run specific test
cd tests && bash run_tests.sh unit/test_syntax.sh
```

### Using Makefile for Testing

```bash
# Show test help
make test

# Run all tests
make test-all

# List available tests
make test-list

# Run unit tests
make test-unit

# Run integration tests
make test-integration

# Run security tests
make test-security

# Run security improvements tests
make test-security-improvements
```

### Running Individual Test Suites

```bash
# Syntax validation (requires shellcheck)
./tests/unit/test_syntax.sh

# Configuration validation
./tests/unit/test_config.sh

# Utility function tests
./tests/unit/test_utils.sh

# Module loading tests
./tests/unit/test_modules.sh

# Edge case tests
./tests/unit/test_edge_cases.sh

# Error handling tests
./tests/unit/test_error_handling.sh

# Performance tests
./tests/unit/test_performance.sh

# Compatibility tests
./tests/unit/test_compatibility.sh

# Security improvements tests
./tests/unit/test_security_improvements.sh

# Docker integration tests
./tests/integration/test_docker.sh

# Dependency integration tests
./tests/integration/test_dependencies.sh

# Security validation tests
./tests/security/test_security.sh
```

### Test Requirements

- **bash**: Version 4.0 or higher
- **shellcheck**: Required for syntax validation tests (auto-installed if missing)
- **sudo**: Some tests may require root privileges
- **curl**: For downloading dependencies

### Test Coverage

#### Unit Tests
- **Syntax Validation**: Shellcheck linting for all bash scripts
- **Configuration Validation**: Variable validation and default values
- **Utility Functions**: Testing of logging, cleanup, and helper functions
- **Module Loading**: Verification that all modules load correctly
- **Edge Cases**: Testing boundary conditions and special inputs
- **Error Handling**: Verification of error handling and recovery
- **Performance**: Ensuring operations complete within acceptable time limits
- **Compatibility**: Testing across different bash versions and systems
- **Security Improvements**: Validation of security enhancements

#### Integration Tests
- **Docker Integration**: Testing in containerized environments
- **Dependency Integration**: Verification of external dependencies
- **Service Integration**: Testing service interactions

#### Security Tests
- **Password Validation**: Strong password requirements
- **SSL/TLS Security**: Certificate management and validation
- **Input Sanitization**: Prevention of injection attacks
- **File Permissions**: Secure file and directory permissions
- **Secret Management**: No hardcoded secrets or credentials

### Test Output

Each test suite provides:
- Total number of tests
- Number of passed tests
- Number of failed tests
- Detailed failure information
- Color-coded output (green for pass, red for fail, yellow for warnings)

### Writing New Tests

To add a new test:

1. Create a new test file in the appropriate directory:
   ```bash
   touch tests/unit/test_my_feature.sh
   chmod +x tests/unit/test_my_feature.sh
   ```

2. Use the standard test structure:
   ```bash
   #!/bin/bash
   # ============================================================================
   # MY FEATURE TESTS
   # ============================================================================

   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

   # Colors
   RED='\033[0;31m'
   GREEN='\033[0;32m'
   NC='\033[0m'

   test_count=0
   pass_count=0
   fail_count=0

   run_test() {
       local test_name="$1"
       local test_command="$2"
       
       test_count=$((test_count + 1))
       echo -n "Test $test_count: $test_name... "
       
       if eval "$test_command" > /dev/null 2>&1; then
           echo -e "${GREEN}PASS${NC}"
           pass_count=$((pass_count + 1))
           return 0
       else
           echo -e "${RED}FAIL${NC}"
           fail_count=$((fail_count + 1))
           return 1
       fi
   }

   # Your tests here
   run_test "My test" "your_test_command"

   echo ""
   echo "=== Results ==="
   echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

   if [ $fail_count -eq 0 ]; then
       echo -e "${GREEN}All tests passed!${NC}"
       exit 0
   else
       echo -e "${RED}Some tests failed.${NC}"
       exit 1
   fi
   ```

3. Add the test to the test runner in `tests/run_tests.sh`:
   ```bash
   test_files=(
       # ... existing tests ...
       "unit/test_my_feature.sh"
   )
   ```

## Docker Testing

The project includes Docker support for testing in isolated environments.

### Running Tests with Docker

```bash
# Build and run tests in Docker
cd docker
docker-compose run test

# Run specific test service
docker-compose run syntax-check

# Run on multiple distributions
docker-compose run test-ubuntu
docker-compose run test-debian
```

### Docker Compose Services

- **test**: Main test environment (Ubuntu 22.04)
- **test-ubuntu**: Ubuntu-specific tests
- **test-debian**: Debian 11 tests
- **syntax-check**: Lightweight syntax validation only

### CI/CD with GitHub Actions

The project includes automated testing via GitHub Actions that runs:
- Syntax checks
- Local unit tests
- Docker integration tests
- Multi-distro testing

Tests run automatically on push to `main` or `develop` branches and on pull requests.

## Architecture

### System Architecture

The project follows a modular architecture with separate concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Web Browser                          │
│  ┌──────────────┐              ┌──────────────┐          │
│  │   noVNC      │              │    ttyd      │          │
│  │  (Desktop)   │              │  (Terminal)  │          │
│  └──────────────┘              └──────────────┘          │
└─────────────────┬────────────────────────┬──────────────┘
                  │                        │
                  │ HTTP/HTTPS             │ HTTP/HTTPS
                  │                        │
┌─────────────────┴────────────────────────┴──────────────┐
│              SSL/TLS Layer (Optional)                    │
│           Let's Encrypt Certificates                     │
└─────────────────┬────────────────────────────────────────┘
                  │
┌─────────────────┴────────────────────────────────────────┐
│              Application Layer                            │
│  ┌──────────────┐              ┌──────────────┐          │
│  │ noVNC Proxy  │              │    ttyd      │          │
│  │  :6080       │              │   :5000       │          │
│  └──────────────┘              └──────────────┘          │
└─────────────────┬────────────────────────┬──────────────┘
                  │                        │
┌─────────────────┴────────────────────────┴──────────────┐
│              VNC Server Layer                             │
│  ┌──────────────────────────────────────────────┐       │
│  │         TigerVNC Server (:5901)               │       │
│  │         Xfce Desktop Environment              │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────┬────────────────────────────────────────┘
                  │
┌─────────────────┴────────────────────────────────────────┐
│              System Layer                               │
│  ┌──────────────┐              ┌──────────────┐          │
│  │  Temporary   │              │   System     │          │
│  │    User      │              │   Services   │          │
│  └──────────────┘              └──────────────┘          │
└──────────────────────────────────────────────────────────┘
```

### Module Architecture

The codebase is organized into modular components:

**Main Script (`src/rpi-vnc-remote.sh`)**
- Entry point and orchestration
- Command handling
- Dependency management
- Service lifecycle

**Library Modules (`src/lib/`)**

| Module | Responsibility |
|--------|---------------|
| `config.sh` | Configuration variables and defaults |
| `utils.sh` | Logging, cleanup, utility functions |
| `ssl.sh` | SSL certificate management and renewal |
| `user.sh` | User creation and management |
| `services.sh` | Service management (VNC, ttyd, noVNC) |
| `healthcheck.sh` | Service health monitoring and auto-restart |
| `portknock.sh` | Port knocking configuration |
| `fail2ban.sh` | Fail2ban integration |
| `monitoring.sh` | Prometheus/Grafana setup |
| `recording.sh` | Session recording (placeholder) |
| `user_ui.sh` | Web-based user management UI |
| `notifications.sh` | Email notifications |
| `alerts.sh` | Alert management |

### Data Flow

1. **Configuration Loading**
   - Environment variables loaded
   - `.env` file sourced (if present)
   - Defaults applied
   - Validation performed

2. **Dependency Installation**
   - System packages installed
   - ttyd binary downloaded
   - Python packages installed (for UI)

3. **User Setup**
   - Temporary user created
   - Permissions configured
   - Desktop environment configured

4. **Service Startup**
   - VNC server started
   - ttyd started
   - noVNC proxy started
   - Monitoring services started (if enabled)

5. **Cleanup**
   - Services stopped
   - Temporary user removed
   - Temporary files cleaned

### Security Architecture

**Authentication Flow**
1. User connects to web interface
2. Credentials validated against `TTYD_USERNAME`/`TTYD_PASSWD`
3. Session established
4. Access granted to temporary user context

**Isolation**
- Temporary user has limited permissions
- No direct root access
- Sudo used only for specific operations
- File permissions restricted

**Network Security**
- SSL/TLS encryption (optional)
- Fail2ban protection (optional)
- Port knocking (optional)
- Firewall configuration

### Monitoring Architecture

When monitoring is enabled:

```
┌─────────────────────────────────────────────────────────┐
│                    Grafana (3000)                        │
│              Visualization Dashboard                     │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ HTTP
┌────────────────────────┴────────────────────────────────┐
│                  Prometheus (9090)                        │
│              Metrics Collection & Storage                 │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ HTTP
┌────────────────────────┴────────────────────────────────┐
│              Node Exporter (9100)                       │
│              System Metrics Exporter                      │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ System Metrics
┌────────────────────────┴────────────────────────────────┐
│              System & Services                           │
│  CPU, Memory, Disk, Network, VNC, ttyd                  │
└──────────────────────────────────────────────────────────┘
```

- **noVNC**: HTML5 VNC client for desktop access via browser
- **ttyd**: Terminal sharing over web
- **SSL/TLS**: Secure connections with Let's Encrypt certificates
- **Auto-renewal**: SSL certificate renewal before expiration
- **Multi-arch**: Supports armhf, arm64, and amd64
- **Temporary user**: Isolated user for remote access
- **Cleanup**: Automatic cleanup on exit or with `./rpi-vnc-remote.sh stop`
- **Security**: Input sanitization, secure defaults, and optional hardening features
- **Monitoring**: Optional Prometheus + Grafana integration
- **Fail2ban**: Protection against brute force attacks
- **Port Knocking**: Additional security layer (optional)
- **User Management UI**: Web interface for user management (optional)

## Security

This project includes comprehensive security features to protect your remote access.

### Built-in Security Features

#### Input Sanitization
- All user inputs in the web UI are sanitized to prevent command injection
- Username validation uses regex patterns to prevent malicious input
- String sanitization removes dangerous characters (`, `;`, `|`, `$`, `(`, `)`)
- No use of `eval()` with user input

#### Secure Defaults
- Strong password validation (minimum 8 characters, mixed case, numbers)
- Secure session management
- Temporary user isolation (remote access uses dedicated user)
- SSL/TLS encryption for all connections (when enabled)
- Automatic cleanup on exit

#### Authentication
- Password-based authentication for both noVNC and ttyd
- Separate credentials for desktop and terminal access
- Support for custom username via `TTYD_USERNAME`
- VNC password configured via `VNC_PASSWORD` environment variable (separate from TTYD_PASSWD)

### Optional Security Features

#### Fail2ban Integration
Fail2ban protects against brute force attacks by banning IPs after multiple failed login attempts.

**How to Enable:**
```bash
FAIL2BAN_ENABLED=true TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

**Configuration:**
- `FAIL2BAN_MAX_RETRY`: Maximum failed attempts before ban (default: 5)
- `FAIL2BAN_BANTIME`: Ban duration in seconds (default: 3600)
- `FAIL2BAN_FINDTIME`: Time window for failed attempts (default: 600)

**What it does:**
- Monitors login attempts to ttyd and noVNC
- Automatically bans suspicious IP addresses
- Logs all banned attempts
- Can be configured for custom rules

#### Port Knocking
Port knocking adds an additional security layer by requiring a specific port sequence before opening VNC ports.

**How to Enable:**
```bash
PORT_KNOCK_ENABLED=true PORT_KNOCK_SEQUENCE=1000,2000,3000 TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

**Configuration:**
- `PORT_KNOCK_SEQUENCE`: Comma-separated list of ports to knock (default: 1000,2000,3000)
- `PORT_KNOCK_INTERFACE`: Network interface to use (default: eth0)

**How it works:**
- Ports are closed by default
- Client must send connection requests to sequence of ports
- Only after correct sequence, VNC ports are opened
- Prevents port scanning attacks

#### User Management UI
Web interface for managing users with proper input validation and sanitization.

**How to Enable:**
```bash
USER_UI_ENABLED=true FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

**Features:**
- Web-based user creation and management
- Password validation and strength checking
- Input sanitization to prevent injection attacks
- Secure session management with Flask
- Access control and permissions

**Important Security Notes:**
- **Always set `FLASK_SECRET_KEY` in production** - never use the auto-generated key
- Use strong, unique passwords for the UI
- Keep the UI behind SSL/TLS
- Restrict UI access to trusted networks if possible

### SSL/TLS Security

#### Certificate Management
- Automatic Let's Encrypt certificate generation
- Certificate renewal before expiration (configurable via `SSL_RENEW_DAYS`)
- Secure certificate storage in `./ssl/` directory (gitignored)
- Certificate validation using `openssl -checkend`

#### SSL Configuration
- Certificates stored in `SSL_DIR` (default: `./ssl/`)
- Certificate file: `SSL_CERT` (default: `$SSL_DIR/cert.pem`)
- Private key file: `SSL_KEY` (default: `$SSL_DIR/key.pem`)
- Automatic renewal configured via cron or systemd timer

#### SSL Best Practices
- Always use SSL/TLS in production environments
- Ensure port 80 is open for Let's Encrypt HTTP challenge
- Keep certificates updated (auto-renewal is enabled by default)
- Monitor certificate expiration
- Use strong domain names (avoid predictable ones)

### Security Best Practices

1. **Strong Passwords**
   - Minimum 8 characters
   - Mix of uppercase, lowercase, numbers, and special characters
   - Change default passwords immediately
   - Use password managers for complex passwords

2. **Network Security**
   - Enable SSL/TLS for all remote access
   - Use Fail2ban in exposed environments
   - Consider port knocking for additional protection
   - Restrict access to trusted IP addresses when possible
   - Use firewalls to limit port exposure

3. **System Security**
   - Keep the system and dependencies updated
   - Regular security updates via `apt update && apt upgrade`
   - Review logs regularly for suspicious activity
   - Monitor system resources and processes

4. **User Security**
   - Use the temporary user feature - don't expose your main user
   - Limit temporary user permissions
   - Remove temporary users when not needed
   - Use separate credentials for different services

5. **Application Security**
   - Review and understand all configuration options
   - Test security features before production deployment
   - Keep backups of configuration files
   - Document security configurations

### Security Auditing

The project includes security tests to verify:
- No hardcoded passwords in scripts
- No hardcoded API keys or tokens
- SSL certificates are not committed to git
- Temporary user is not root by default
- Input sanitization is implemented
- No use of `eval()` with user input
- Secure file permissions
- Proper use of sudo

Run security tests:
```bash
make test-security
# Or
cd tests/security && bash test_security.sh
```

## BeEF Integration (Optional)

⚠️ **Security Warning**: This project includes optional BeEF (Browser Exploitation Framework) integration for **security testing and penetration testing purposes only**.

### What is BeEF?
BeEF is a security tool used for testing browser vulnerabilities and conducting authorized security assessments. It should **only** be used in:
- Controlled penetration testing environments
- Educational security demonstrations
- Authorized security audits with explicit permission

### How to Use BeEF
BeEF is **disabled by default**. To enable it:

```bash
BEEF_ENABLED=true BEEF_HOOK_URL="https://your-beef-server/hook.js" TTYD_PASSWD=mypassword ./rpi-vnc-remote.sh
```

### Important Notes
- **Never use BeEF without explicit authorization**
- BeEF injects JavaScript hooks into the noVNC interface
- Original files are backed up before modification with timestamp
- This feature is intended for security professionals only
- Misuse of BeEF may be illegal in your jurisdiction
- The authors are not responsible for misuse of this feature

### Disabling BeEF
BeEF is disabled by default. If you see BeEF-related warnings, ensure `BEEF_ENABLED` is not set to `true`.

## Usage Examples

### Basic (no SSL)
```bash
TTYD_PASSWD=mypassword ./rpi-vnc-remote.sh
```

### With SSL
```bash
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org EMAIL=my@email.com ./rpi-vnc-remote.sh
```

### Custom ports
```bash
TTYD_PASSWD=mypassword NOVNC_PORT=8080 TTYD_PORT=9000 ./rpi-vnc-remote.sh
```

### Stop services
```bash
./rpi-vnc-remote.sh stop
```

## Access Information

After running the script, access the services:

- **noVNC (Desktop)**: `http://localhost:6080` or `https://localhost:6080` (with SSL)
- **ttyd (Terminal)**: `http://localhost:5000` or `https://localhost:5000` (with SSL)

Use the credentials specified in `TTYD_USERNAME` and `TTYD_PASSWD`.

## Manual Configuration

For manual setup without the script, refer to the following sections:


# Explanation of the bash script

### Accessing rpi cmd over a browser using ttyd

ttyd is a simple command-line tool for sharing terminal over the web.

Download .arm version of ttyd binary from the following command
```
wget https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.armhf 
```

Copy the binary to /usr/local/bin/ttyd
```
sudo cp ttyd.armhf /usr/local/bin/ttyd
```

Changing permission
```
sudo chmod +x /usr/local/bin/ttyd
```

Running ttyd
```
sudo ttyd -c username:password -p {PORT_NUMBER} bash &
```

You can now access terminal by entering http://localhost:{PORT-NUMBER} on your browser.







## noVNC

noVNC is both a HTML VNC client JavaScript library and an application built on top of that library. noVNC runs well in any modern browser including mobile browsers (iOS and Android).

For more information you can check their official documentation here https://github.com/novnc/noVNC

#### Installing noVNC and TigerVNC server
```
sudo apt install novnc tigervnc-standalone-server
```

```
cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
```

#### Installing Xfce desktop environment

Packages for the latest Xfce desktop environment and the TightVNC package available from the official Ubuntu repository. Both Xfce and TightVNC are known for being lightweight and fast, which will help ensure that the VNC connection will be smooth and stable even on slower internet connections.
```
sudo apt install xfce4 xfce4-goodies 
```

#### Starting vncserver
```
vncserver
```
You’ll be prompted to enter and verify a password to access your machine remotely:
<img width="736" alt="Screenshot 2023-03-05 at 10 58 25 PM" src="https://user-images.githubusercontent.com/30818966/222976171-f3fb79cb-ef65-40cc-8866-3a23414d0f37.png">


Launching novnc
```
/usr/share/novnc/utils/launch.sh --vnc 127.0.0.1:5901 --listen 6080
```



![image](https://user-images.githubusercontent.com/30818966/222971558-2cd26002-633e-47c4-862b-47371cdef967.png)



## Writing crontab for ttyd and noVNC

Crontab (CRON TABle) is a file which contains the schedule of cron entries to be run and at specified times.

```
sudo vim /etc/crontab
```

Add your  command as shown in the image below

![image](https://user-images.githubusercontent.com/30818966/222971787-3813d848-e257-4ad0-b364-4483fa5657b1.png)


## Recording Limitations

The session recording module (`RECORDING_ENABLED`) is currently a **placeholder** with limited functionality:

### Current Limitations
- ttyd does not natively support session recording
- VNC recording requires external screen capture tools (not implemented)
- Current implementation only sets environment variables
- No actual recording occurs with current implementation

### Future Enhancements
- Wrap ttyd with 'script' command for terminal recording
- Integrate with VNC recording tools (e.g., vnc2flv, pyvnc2swf)
- Add automatic recording management and rotation
- Implement recording playback interface

For now, this module provides the framework for future implementation.

## Troubleshooting

This section covers common issues and their solutions.

### Common Issues

#### Port Already in Use

**Error**: `Port XXXX is already in use`

**Symptoms**:
- Services fail to start
- Error message indicating port conflict

**Solution**:
```bash
# Find process using the port
sudo lsof -i :6080
# Or
sudo netstat -tulpn | grep :6080

# Kill the process
sudo kill -9 <PID>

# Or use different ports
NOVNC_PORT=6081 TTYD_PORT=5001 ./src/rpi-vnc-remote.sh
```

**Prevention**:
- Use `make stop` before starting new instances
- Check for existing processes with `ps aux | grep vnc`

#### SSL Certificate Issues

**Error**: `Failed to generate SSL certificate`

**Symptoms**:
- SSL certificate generation fails
- Let's Encrypt HTTP challenge fails

**Solutions**:

1. **Check Port 80**:
```bash
# Ensure port 80 is open and not blocked
sudo netstat -tulpn | grep :80
sudo ufw allow 80/tcp
```

2. **Verify Domain Configuration**:
```bash
# Check if domain points to your server
nslookup mydomain.duckdns.org
# Should return your Raspberry Pi's IP
```

3. **Check Firewall Rules**:
```bash
# Ensure ports 80 and 443 are open
sudo ufw status
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

4. **Try Without SSL First**:
```bash
# Verify basic functionality without SSL
TTYD_PASSWD=mypassword ./src/rpi-vnc-remote.sh
```

5. **Manual Certificate Generation**:
```bash
# Generate self-signed certificate for testing
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ./ssl/key.pem -out ./ssl/cert.pem
```

#### VNC Server Won't Start

**Error**: `Failed to start TigerVNC server`

**Symptoms**:
- VNC server fails to start
- Desktop access not available

**Solutions**:

1. **Check for Existing VNC Servers**:
```bash
# Check if another VNC server is running
ps aux | grep vnc

# Kill existing VNC servers
vncserver -kill :1
vncserver -kill :2
```

2. **Ensure Desktop Environment is Installed**:
```bash
# Install Xfce (lightweight)
sudo apt update
sudo apt install xfce4 xfce4-goodies

# Or install LXDE (alternative lightweight)
sudo apt install lxde-core
```

3. **Check VNC Display**:
```bash
# Ensure display number is available
vncserver -list

# Try different display number
VNC_DISPLAY=:2 ./src/rpi-vnc-remote.sh
```

4. **Check Permissions**:
```bash
# Ensure temporary user has proper permissions
sudo usermod -aG video $TEMP_USER
```

#### ttyd Connection Refused

**Error**: Cannot connect to ttyd

**Symptoms**:
- Terminal access not available
- Connection refused error

**Solutions**:

1. **Verify ttyd Installation**:
```bash
# Check if ttyd is installed
which ttyd

# If not installed, download manually
wget https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.armhf
sudo cp ttyd.armhf /usr/local/bin/ttyd
sudo chmod +x /usr/local/bin/ttyd
```

2. **Check Process Status**:
```bash
# Check if ttyd is running
ps aux | grep ttyd

# Check logs
journalctl -u ttyd -f
```

3. **Check Firewall Rules**:
```bash
# Ensure TTYD_PORT is open
sudo ufw allow 5000/tcp
# Or custom port
sudo ufw allow $TTYD_PORT/tcp
```

#### Permission Denied Errors

**Error**: `Permission denied` when running script

**Symptoms**:
- Script cannot be executed
- File permission errors

**Solutions**:

1. **Make Script Executable**:
```bash
# Make the main script executable
chmod +x src/rpi-vnc-remote.sh

# Make all library files executable
chmod +x src/lib/*.sh
```

2. **Run with Sudo**:
```bash
# Run with sudo if needed
sudo ./src/rpi-vnc-remote.sh
```

3. **Check File Ownership**:
```bash
# Ensure you own the files
ls -la src/
sudo chown -R $USER:$USER src/
```

#### Desktop Environment Issues

**Error**: Desktop appears blank or crashes

**Symptoms**:
- noVNC connects but shows blank screen
- Desktop environment crashes

**Solutions**:

1. **Restart Desktop Environment**:
```bash
# Kill and restart VNC server
vncserver -kill :1
vncserver :1
```

2. **Check Desktop Environment**:
```bash
# Ensure desktop environment is properly configured
echo "xfce4-session" > ~/.xsession
```

3. **Check System Resources**:
```bash
# Check available memory
free -h
# Check disk space
df -h
```

#### Dependency Installation Fails

**Error**: Failed to install dependencies

**Symptoms**:
- Package installation fails
- Missing dependencies

**Solutions**:

1. **Update Package Lists**:
```bash
sudo apt update
sudo apt upgrade
```

2. **Install Dependencies Manually**:
```bash
# Install required packages
sudo apt install -y tigervnc-standalone-server novnc xfce4 xfce4-goodies

# Install python dependencies
sudo apt install -y python3 python3-pip
```

3. **Skip Dependency Installation**:
```bash
# If dependencies are already installed
SKIP_DEPS=true ./src/rpi-vnc-remote.sh
```

### Debug Mode

To run the script with verbose output:

```bash
# Enable debug mode
bash -x src/rpi-vnc-remote.sh

# Or with verbose flag
VERBOSE=true LOG_LEVEL=debug ./src/rpi-vnc-remote.sh
```

### Getting Help

If you encounter issues not covered here:

1. **Check Logs**:
```bash
# System logs
sudo journalctl -xe

# Application logs
cat /var/log/syslog | grep vnc
cat /var/log/syslog | grep ttyd
```

2. **Review Configuration**:
```bash
# Show available options
./src/rpi-vnc-remote.sh help

# Show current configuration
./src/rpi-vnc-remote.sh config
```

3. **Run Tests**:
```bash
# Run all tests to check for issues
make test-all

# Run specific tests
make test-security
```

4. **Check Service Status**:
```bash
# Check if services are running
make status

# Or manually check
ps aux | grep vnc
ps aux | grep ttyd
ps aux | grep novnc
```

### Known Limitations

1. **Session Recording**: Currently a placeholder feature - no actual recording occurs
2. **Desktop Environment**: Requires lightweight desktop (Xfce recommended) for best performance
3. **Concurrent Users**: Only one VNC session per display number
4. **Network Latency**: VNC performance depends on network bandwidth and latency
5. **Mobile Support**: noVNC works on mobile browsers but performance may vary

### Performance Tips

1. **Use Lower Resolution**:
```bash
VNC_GEOMETRY=1280x720 ./src/rpi-vnc-remote.sh
```

2. **Reduce Color Depth**:
```bash
VNC_DEPTH=16 ./src/rpi-vnc-remote.sh
```

3. **Disable SSL for Local Use**:
```bash
# SSL adds overhead, disable for local network
DISABLE_SSL=true ./src/rpi-vnc-remote.sh
```

4. **Use Wired Connection**: Network performance is better over Ethernet than Wi-Fi

## Contributing

Contributions are welcome! This project is open source and community-driven.

### How to Contribute

1. **Fork the Repository**
   ```bash
   # Fork the repository on GitHub
   # Clone your fork
   git clone https://github.com/your-username/vnc-remote-secure.git
   cd vnc-remote-secure
   ```

2. **Create a Branch**
   ```bash
   # Create a new branch for your feature
   git checkout -b feature/my-feature
   ```

3. **Make Your Changes**
   - Follow the existing code style
   - Add tests for new features
   - Update documentation as needed
   - Ensure all tests pass

4. **Run Tests**
   ```bash
   # Run all tests
   make test-all

   # Run specific tests
   make test-unit
   make test-security
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add my feature"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/my-feature
   ```

7. **Create a Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Describe your changes
   - Submit for review

### Development Guidelines

#### Code Style

- **Bash Scripting**: Follow [ShellCheck](https://www.shellcheck.net/) recommendations
- **Indentation**: Use 4 spaces (no tabs)
- **Comments**: Add comments for complex logic
- **Functions**: Use descriptive function names
- **Variables**: Use uppercase for exported variables, lowercase for local variables

#### Testing

- **Unit Tests**: Add unit tests for new functions
- **Integration Tests**: Add integration tests for new features
- **Security Tests**: Ensure security best practices are followed
- **Documentation**: Update documentation for new features

#### Documentation

- **README**: Update README for user-facing changes
- **Comments**: Add inline comments for complex code
- **Examples**: Add usage examples for new features
- **Changelog**: Update CHANGELOG.md (if present)

### Reporting Issues

When reporting issues, please include:

1. **System Information**
   - Operating system and version
   - Architecture (armhf, arm64, amd64)
   - Bash version

2. **Error Messages**
   - Full error message
   - Steps to reproduce
   - Expected behavior vs actual behavior

3. **Configuration**
   - Environment variables used
   - Configuration file (if any)
   - Any custom settings

4. **Logs**
   - Relevant log output
   - System logs
   - Application logs

### Feature Requests

For feature requests, please:

1. **Describe the Feature**
   - What you want to add
   - Why it's needed
   - How it should work

2. **Provide Context**
   - Use case scenario
   - Alternative solutions considered
   - Potential impact

3. **Be Specific**
   - Clear requirements
   - Expected behavior
   - Edge cases to consider

### Security Vulnerabilities

If you discover a security vulnerability, please:

1. **Do NOT** create a public issue
2. Email the maintainers directly
3. Provide details about the vulnerability
4. Allow time for a fix to be released

### Code Review Process

All contributions go through code review:

1. **Automated Checks**
   - Tests must pass
   - Linting must pass
   - Security tests must pass

2. **Manual Review**
   - Code quality check
   - Documentation review
   - Security review (if applicable)

3. **Approval**
   - At least one maintainer approval
   - All CI/CD checks pass
   - No outstanding issues

### Community Guidelines

- **Be Respectful**: Treat all contributors with respect
- **Be Constructive**: Provide helpful feedback
- **Be Patient**: Reviews take time
- **Be Collaborative**: Work together to improve the project

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing!

## License

[MIT](https://choosealicense.com/licenses/mit/)
