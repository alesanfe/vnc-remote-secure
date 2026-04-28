# Configuration Guide

Complete reference for all configuration options in Raspberry Pi VNC Remote Setup.

## 📋 Configuration Files

### Primary Configuration: `.env`

The main configuration file is `.env` in the project root. Copy from the example:

```bash
cp .env.example .env
```

### Configuration Structure

```bash
# ============================================================================
# REQUIRED VARIABLES
# ============================================================================

# Password for terminal access
TTYD_PASSWD=your_secure_password

# ============================================================================
# OPTIONAL VARIABLES
# ============================================================================

# User configuration
TEMP_USER=remote
TEMP_USER_PASS=your_temp_user_password

# Network configuration
NOVNC_PORT=6080
TTYD_PORT=5000
VNC_PORT=5901

# SSL/TLS configuration
NGINX_ENABLED=true
DUCK_DOMAIN=your-domain.duckdns.org
EMAIL=your-email@example.com

# VNC configuration
VNC_DISPLAY=:2
VNC_GEOMETRY=1920x1080
VNC_DEPTH=24
VNC_PASSWORD=your_vnc_password

# Advanced options
LOG_LEVEL=info
VERBOSE=false
AUTO_START=false
```

## 🔧 Core Configuration

### Authentication

```bash
# Terminal (ttyd) authentication
TTYD_PASSWD=your_secure_password
TTYD_USERNAME=$(whoami)  # Default: current user

# VNC authentication
VNC_PASSWORD=your_vnc_password

# Temporary user for remote sessions
TEMP_USER=remote
TEMP_USER_PASS=your_temp_user_password
```

**Security Notes:**
- Use strong passwords (12+ characters, mixed case, numbers, symbols)
- Change default passwords before first use
- Consider using password managers

### Network Configuration

```bash
# Service ports
NOVNC_PORT=6080      # noVNC web interface
TTYD_PORT=5000       # Terminal web interface
VNC_PORT=5901        # VNC server port

# Nginx reverse proxy
NGINX_ENABLED=true
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
```

**Port Guidelines:**
- Use ports above 1024 to avoid conflicts
- Ensure ports are not blocked by firewall
- Consider using non-standard ports for additional security

## 🌐 SSL/TLS Configuration

### Basic SSL Setup

```bash
# Domain for SSL certificate
DUCK_DOMAIN=your-domain.duckdns.org

# Email for Let's Encrypt
EMAIL=your-email@example.com

# SSL certificate directory
SSL_DIR=./ssl

# Certificate renewal (days before expiration)
SSL_RENEW_DAYS=30
```

### SSL Options

```bash
# Disable SSL (not recommended for production)
DISABLE_SSL=false

# SSL protocols (recommended defaults)
# TLSv1.2 TLSv1.3 configured automatically
```

**SSL Requirements:**
- Domain name pointing to your Raspberry Pi
- Port 80 accessible for certificate validation
- Valid email address for certificate notifications

## 🖥️ VNC Configuration

### Display Settings

```bash
# VNC display number
VNC_DISPLAY=:2

# Screen resolution
VNC_GEOMETRY=1920x1080  # Common options: 1280x720, 1920x1080, 2560x1440

# Color depth
VNC_DEPTH=24  # Options: 16, 24, 32
```

### VNC File Paths

```bash
# noVNC files
INDEX_FILE=/usr/share/novnc/index.html
VNC_FILE=/usr/share/novnc/vnc.html
```

**Performance Tips:**
- Lower resolution for better performance on slow connections
- 16-bit color depth for bandwidth-constrained environments
- Higher resolution for better desktop experience

## 🔐 Security Configuration

### Fail2ban Protection

```bash
# Enable Fail2ban
FAIL2BAN_ENABLED=true

# Fail2ban settings
FAIL2BAN_MAX_RETRY=5          # Max failed attempts
FAIL2BAN_FINDTIME=600         # Time window (10 minutes)
FAIL2BAN_BANTIME=3600         # Ban duration (1 hour)
```

### Port Knocking

```bash
# Enable port knocking
PORT_KNOCK_ENABLED=false

# Knock sequence (comma-separated ports)
PORT_KNOCK_SEQUENCE=1000,2000,3000

# Knock settings
PORT_KNOCK_TIMEOUT=5
PORT_KNOCK_METHOD=iptables
PORT_KNOCK_INTERFACE=eth0
```

### User Management UI

```bash
# Enable web interface
USER_UI_ENABLED=false

# UI settings
USER_UI_PORT=8081
USER_UI_PASSWORD=admin123

# Flask security
FLASK_SECRET_KEY=  # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 📊 Monitoring Configuration

### Prometheus + Grafana

```bash
# Enable monitoring stack
MONITORING_ENABLED=false

# Service ports
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
NODE_EXPORTER_PORT=9100
```

### Health Monitoring

```bash
# Health check settings
HEALTHCHECK_ENABLED=true
HEALTHCHECK_INTERVAL=30  # seconds

# Auto-restart failed services
AUTO_RESTART=false
```

### Session Recording

```bash
# Enable session recording
RECORDING_ENABLED=false

# Recording settings
RECORDING_DIR=./recordings
RECORDING_FORMAT=asciinema  # Options: asciinema, script
```

## 📢 Notifications Configuration

### Discord Notifications

```bash
# Enable Discord notifications
DISCORD_ENABLED=false

# Discord webhook
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_URL
```

### Email Alerts

```bash
# Enable email alerts
ALERTS_ENABLED=false

# Email settings
ALERT_EMAIL_TO=your-email@example.com
ALERT_EMAIL_FROM=vnc-alerts@localhost
ALERT_SMTP_SERVER=localhost:587
ALERT_SMTP_USER=
ALERT_SMTP_PASS=
```

## 🛠️ Advanced Configuration

### Logging

```bash
# Log level (debug, info, warn, error)
LOG_LEVEL=info

# Verbose output
VERBOSE=false

# Log directory
LOG_DIR=./logs

# Show logs in real-time
SHOW_LOGS=true
```

### Performance

```bash
# Connection timeout (seconds)
CONNECTION_TIMEOUT=30

# Maximum concurrent connections
MAX_CONNECTIONS=10

# Skip dependency installation
SKIP_DEPS=false
```

### System Behavior

```bash
# Keep temporary user on exit
KEEP_TEMP_USER=false

# Auto-start services on boot
AUTO_START=false
```

## 🔧 Environment Variables

### Runtime Variables

These are set automatically by the script:

```bash
# SSL status (do not modify manually)
DISABLE_SSL=false

# System detection (automatic)
ARCH=arm64  # or armhf, amd64
OS=raspios  # or ubuntu, debian
```

### Path Variables

```bash
# Script directories
SCRIPT_DIR=/path/to/src
PROJECT_DIR=/path/to/project
LIB_DIR=/path/to/src/lib
```

## 📝 Configuration Examples

### Basic Setup (HTTP Only)

```bash
# Required
TTYD_PASSWD=secure123
VNC_PASSWORD=vnc123

# Optional
TEMP_USER=remote
TEMP_USER_PASS=remote123
```

### Production Setup (SSL + Security)

```bash
# Required
TTYD_PASSWD=VerySecurePassword123!
VNC_PASSWORD=AnotherSecurePassword456!

# SSL
NGINX_ENABLED=true
DUCK_DOMAIN=my-rpi.duckdns.org
EMAIL=admin@example.com

# Security
FAIL2BAN_ENABLED=true
USER_UI_ENABLED=true
USER_UI_PASSWORD=AdminPass789!

# Monitoring
HEALTHCHECK_ENABLED=true
MONITORING_ENABLED=true
```

### Development Setup

```bash
# Required
TTYD_PASSWD=dev123
VNC_PASSWORD=dev123

# Development settings
LOG_LEVEL=debug
VERBOSE=true
SHOW_LOGS=true

# Testing
MONITORING_ENABLED=true
RECORDING_ENABLED=true
```

## 🔍 Configuration Validation

### Check Configuration

```bash
# Validate configuration file
./src/rpi-vnc-remote.sh --validate-config

# Test configuration without starting services
./src/rpi-vnc-remote.sh --dry-run
```

### Common Validation Issues

#### Missing Required Variables
```bash
# Error: TTYD_PASSWD not set
# Solution: Set TTYD_PASSWD in .env
TTYD_PASSWD=your_password
```

#### Invalid Domain
```bash
# Error: Domain resolution failed
# Solution: Check DNS settings
nslookup your-domain.duckdns.org
```

#### Port Conflicts
```bash
# Error: Port already in use
# Solution: Change port or kill conflicting process
sudo lsof -i :6080
```

## 🔄 Configuration Updates

### Hot Reload

Some configuration changes require restart:

```bash
# Restart services
sudo systemctl restart nginx
sudo pkill -f "novnc_proxy" && ./src/rpi-vnc-remote.sh
```

### Full Reconfiguration

```bash
# Stop services
Ctrl+C

# Update configuration
nano .env

# Restart with new config
./src/rpi-vnc-remote.sh
```

## 📚 Configuration Reference

### Variable Categories

| Category | Variables | Description |
|----------|-----------|-------------|
| **Required** | `TTYD_PASSWD`, `VNC_PASSWORD` | Essential authentication |
| **Network** | `*_PORT`, `NGINX_ENABLED` | Network and port settings |
| **SSL** | `DUCK_DOMAIN`, `EMAIL` | Certificate configuration |
| **Security** | `FAIL2BAN_*`, `PORT_KNOCK_*` | Security features |
| **Monitoring** | `HEALTHCHECK_*`, `MONITORING_*` | System monitoring |
| **Advanced** | `LOG_LEVEL`, `VERBOSE` | Debugging and logging |

### Default Values

| Variable | Default | Description |
|----------|---------|-------------|
| `TTYD_USERNAME` | `$(whoami)` | Terminal username |
| `TEMP_USER` | `remote` | Temporary user name |
| `NOVNC_PORT` | `6080` | noVNC port |
| `TTYD_PORT` | `5000` | Terminal port |
| `VNC_PORT` | `5901` | VNC server port |
| `LOG_LEVEL` | `info` | Logging level |
| `VERBOSE` | `false` | Verbose output |

## 🆘 Configuration Help

### Getting Help

```bash
# Show configuration help
./src/rpi-vnc-remote.sh --help

# Show current configuration
./src/rpi-vnc-remote.sh --show-config

# Validate configuration
./src/rpi-vnc-remote.sh --validate
```

### Troubleshooting

1. **Syntax Errors**: Check .env file format
2. **Missing Variables**: Use .env.example as reference
3. **Permission Issues**: Check file permissions
4. **Port Conflicts**: Use different ports or kill processes

---

**Next:** [User Guide](../user-guide/getting-started.md) for usage instructions
