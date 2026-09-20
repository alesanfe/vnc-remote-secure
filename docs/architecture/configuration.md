# Configuration Guide

Complete reference for all configuration options in VNC Remote Secure.

## 📋 Configuration Files

### Primary Configuration: `.env`

The main configuration file is `.env` in the project root. Copy from the example:

```bash
cp .env.example .env
```

### Precedence

When several sources define the same variable, highest wins:

1. **Real environment** (process env / `EnvironmentFile=` from systemd)
2. **Project `.env`** (`<project_root>/.env`)
3. **System `config.env`** (`/etc/vnc-remote-secure/config.env` on
   Linux, `%ProgramData%\VncRemoteSecure\config.env` on Windows) —
   the file the packaged installer writes
4. **Platform defaults** (`src/vnc_remote_secure/config/defaults/`)

`vnc-remote secrets rotate` and recovery-code consumption persist to
whichever file already defines the key (system `config.env` wins over
the project `.env` when both contain it).

### Configuration Structure

```bash
# ============================================================================
# AUTHENTICATION VARIABLES (set for production; auto-generated if empty)
# ============================================================================

# Password for Web Terminal access
TTYD_PASSWD="your-strong-password"

# ============================================================================
# OPTIONAL VARIABLES
# ============================================================================

# User configuration
TEMP_USER=remote
TEMP_USER_PASS="your-strong-password"

# Network configuration
NOVNC_PORT=6080
TTYD_PORT=5000
VNC_PORT=5901

# SSL/TLS configuration
NGINX_ENABLED=true
DUCK_DOMAIN=your-domain.duckdns.org
EMAIL=your-email@your-domain.duckdns.org

# VNC configuration
VNC_DISPLAY=:1
VNC_GEOMETRY=1280x720
VNC_DEPTH=24
VNC_PASSWORD="your-strong-password"

# Advanced options
LOG_LEVEL=INFO
VERBOSE=false

# ============================================================================
# NEW MODULAR ARCHITECTURE OPTIONS (modular architecture)
# ============================================================================

# Error handling configuration
AUTO_RESTART=false          # Auto-restart failed services (watchdog)

VERBOSE=false
```

## 🆕 New Modular Architecture Features

### Enhanced Logging System

The new modular architecture includes a structured logging system with multiple levels:

```bash
# Logging levels: DEBUG, INFO, WARN, ERROR, FATAL (WARNING/CRITICAL accepted as aliases)
LOG_LEVEL=INFO              # Default logging level
```

**Features:**
- Multi-level logging with colors and timestamps
- File logging support
- Component-specific logging
- Performance and security event logging

### Advanced Input Validation

Comprehensive validation system for all user inputs, enforced by `vnc-remote
doctor` / `validate_config` at startup.

**Validated Inputs:**
- **Passwords**: Minimum 8 chars, complexity requirements, weak password detection
- **Ports**: Range validation (1-65535), privilege warnings
- **Domains**: Format validation, localhost warnings
- **Emails**: Format validation, domain blacklist
- **Usernames**: Reserved name checking, format validation

### Graceful Process Management

Process termination uses SIGTERM ? SIGKILL progression with internal
timeouts. Service-specific recovery actions and user process isolation
are handled by the lifecycle modules in `src/vnc_remote_secure/core/`
(`lifecycle.py`, `service_manager.py`).

**Features:**
- Timeout-based termination with SIGTERM → SIGKILL progression
- User process isolation and cleanup
- Service-specific recovery actions
- Network resource cleanup

### Error Handling & Recovery

Automatic error recovery with retry mechanisms:

```bash
AUTO_RESTART=false          # Auto-restart failed services
```

**Features:**
- Error pattern detection and tracking
- Automatic retry with exponential backoff
- Service-specific recovery actions
- Error statistics and reporting

### Enhanced Security

Improved security features:

**Features:**
- Automatic user process cleanup on exit
- Temporary file cleanup
- Network resource cleanup
- SSL certificate permission management

## 🔧 Core Configuration

### Authentication

```bash
# Web Terminal authentication
TTYD_PASSWD="your-strong-password"
TTYD_USERNAME=  # Default: current user on Linux, 'admin' on Windows; leave empty for OS default

# VNC authentication
VNC_PASSWORD="your-strong-password"

# Temporary user for remote sessions
TEMP_USER=remote
TEMP_USER_PASS="your-strong-password"
```

**Security Notes:**
- Use strong passwords (8+ characters minimum, mixed case, numbers, symbols)
- Change default passwords before first use
- Consider using password managers

### Network Configuration

```bash
# Service ports
NOVNC_PORT=6080      # noVNC web interface
TTYD_PORT=5000       # Web Terminal interface
VNC_PORT=5901        # VNC server port (5901 on Linux, 5900 on Windows)

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
EMAIL=your-email@your-domain.duckdns.org

# Certificate and key paths (optional — defaults to the canonical ssl dir)
SSL_CERT=
SSL_KEY=
```

### SSL Options

```bash
# Enable TLS for the current session (default: true when certificates are configured).
# Set to false to force plain HTTP/WS even if SSL_CERT/SSL_KEY are set.
TLS_ENABLED=true

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
VNC_DISPLAY=:1

# Screen resolution
VNC_GEOMETRY=1280x720  # Common options: 1280x720, 1920x1080, 2560x1440

# Color depth
VNC_DEPTH=24  # Options: 8, 16, 24, 32
```

### VNC File Paths

The noVNC web assets are served from the system noVNC install path
(`/usr/share/novnc/`); the launcher discovers `vnc.html`/`index.html`
at runtime, so no explicit path variables are required.

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

### User Management UI

```bash
# Enable web interface
USER_UI_ENABLED=false

# UI settings
USER_UI_PORT=8081
USER_UI_PASSWORD="your-strong-password"  # Set a real password; weak/placeholder values are rejected by validate_config

# Flask security
FLASK_SECRET_KEY=  # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 📊 Monitoring Configuration

### Metrics

The health server exposes Prometheus-format metrics at `/metrics` on
the health port (no separate Prometheus/Grafana daemons are managed —
external stacks can scrape that endpoint).

### Health Monitoring

```bash
# Watchdog: periodic service liveness checks inside
# `vnc-remote service --run` / `start --foreground`
HEALTHCHECK_ENABLED=true
HEALTHCHECK_INTERVAL=30  # seconds

# Auto-restart dead services via the watchdog
AUTO_RESTART=false
```

## 📢 Notifications Configuration

Alerts are dispatched by the service manager (`monitoring/alerts.py`)
on start failures and watchdog transitions when `ALERTS_ENABLED=true`.
All configured channels are tried; each is best-effort.

### Discord Notifications

```bash
# Enable alert dispatch
ALERTS_ENABLED=true

# Enable the Discord channel
DISCORD_ENABLED=false

# Discord webhook
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-token-here
```

### Generic Webhook

```bash
# POSTs a JSON payload to any HTTP endpoint
ALERT_WEBHOOK_URL=
```

### Email Alerts

```bash
# Email channel settings
ALERT_EMAIL_TO=your-email@your-domain.duckdns.org
ALERT_EMAIL_FROM=vnc-remote-secure@localhost
ALERT_SMTP_SERVER=127.0.0.1:587
ALERT_SMTP_USER=
ALERT_SMTP_PASS=
```

## 🛠️ Advanced Configuration

### Logging

```bash
# Log level (DEBUG, INFO, WARN, ERROR, FATAL; WARNING/CRITICAL accepted as aliases)
LOG_LEVEL=INFO

# Verbose output
VERBOSE=false

# Log directory override (optional — empty uses the canonical
# platform locations: /var/log/vnc-remote-secure, XDG state dir,
# or %ProgramData%\VncRemoteSecure\logs on elevated Windows /
# %LOCALAPPDATA%\VncRemoteSecure\logs otherwise — AppData\LocalLow
# instead when running under a Store/MSIX-packaged Python, which
# virtualizes LocalAppData per package)
LOG_DIR=
```

### System Behavior

```bash
# Keep temporary user on exit
KEEP_TEMP_USER=false
```

## 🔧 Environment Variables

### Runtime Variables

These are set automatically by the script:

```bash
# TLS status (do not modify manually)
TLS_ENABLED=true

# System detection (automatic)
ARCH=arm64  # or armhf, amd64
OS=raspios  # or ubuntu, debian
```

### Path Variables

```bash
# Script directories
SCRIPT_DIR=/path/to/src
PROJECT_DIR=/path/to/project
```

## 📝 Configuration Examples

### Basic Setup (HTTP Only)

```bash
# Set for production; if empty, strong passwords are auto-generated
TTYD_PASSWD="your-strong-password"
VNC_PASSWORD="your-strong-password"

# Optional
TEMP_USER=remote
TEMP_USER_PASS="your-strong-password"
```

### Production Setup (SSL + Security)

```bash
# Set for production; if empty, strong passwords are auto-generated
TTYD_PASSWD="your-strong-password"
VNC_PASSWORD="your-strong-password"

# SSL
NGINX_ENABLED=true
DUCK_DOMAIN=your-domain.duckdns.org
EMAIL=your-email@your-domain.duckdns.org

# Security
FAIL2BAN_ENABLED=true
USER_UI_ENABLED=true
USER_UI_PASSWORD="your-strong-password"  # Set a real password; weak/placeholder values are rejected

# Monitoring
HEALTHCHECK_ENABLED=true
```

### Development Setup

```bash
# Set for production; if empty, strong passwords are auto-generated
TTYD_PASSWD="your-strong-password"
VNC_PASSWORD="your-strong-password"

# Development settings
LOG_LEVEL=debug
VERBOSE=true
```

## 🔍 Configuration Validation

### Check Configuration

```bash
# Validate configuration file
vnc-remote doctor

# Show resolved configuration
vnc-remote config show-effective
```

### Common Validation Issues

#### Missing Authentication Variables
```bash
# Note: TTYD_PASSWD and VNC_PASSWORD are auto-generated if empty.
# Set them explicitly for production to avoid random passwords.
TTYD_PASSWD="your-strong-password"
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
vnc-remote restart
```

### Full Reconfiguration

```bash
# Stop services
Ctrl+C

# Update configuration
nano .env

# Restart with new config
./vnc-remote restart
```

## 📚 Configuration Reference

### Variable Categories

| Category | Variables | Description |
|----------|-----------|-------------|
| **Authentication** | `TTYD_PASSWD`, `VNC_PASSWORD` | Generated if empty; required for production |
| **Network** | `*_PORT`, `NGINX_ENABLED` | Network and port settings |
| **SSL** | `DUCK_DOMAIN`, `EMAIL` | Certificate configuration |
| **Security** | `FAIL2BAN_*` | Security features |
| **Monitoring** | `HEALTHCHECK_*`, `AUTO_RESTART` | Service watchdog |
| **Advanced** | `LOG_LEVEL`, `VERBOSE` | Debugging and logging |

### Default Values

| Variable | Default | Description |
|----------|---------|-------------|
| `TTYD_USERNAME` | current user on Linux, `admin` on Windows | Web Terminal username |
| `TEMP_USER` | `remote` | Temporary user name |
| `NOVNC_PORT` | `6080` | noVNC port |
| `TTYD_PORT` | `5000` | Web Terminal port |
| `VNC_PORT` | `5901` (Linux) / `5900` (Windows) | VNC server port |
| `LOG_LEVEL` | `INFO` | Logging level |
| `VERBOSE` | `false` | Verbose output |

## 📚 Complete Variable Reference

Every variable accepted by .env (mirrors .env.example). Variables marked
*(generated)* are auto-generated at runtime when left empty.

### Authentication & Secrets

| Variable | Default | Description |
|----------|---------|-------------|
| VNC_PASSWORD | *(generated)* | VNC server password (max 8 chars — legacy DES) |
| TTYD_USERNAME | OS user / admin | Web Terminal username |
| TTYD_PASSWD | *(generated)* | Web Terminal password |
| TEMP_USER | remote | Restricted runtime user name |
| TEMP_USER_PASS | empty | Password applied to the restricted user. On Linux the account is created with `nologin` shell (locked by design); set a shell via `usermod -s` to enable interactive use |
| KEEP_TEMP_USER | false | Keep the temp user after shutdown |
| LANDING_PASSWORD | generated | Landing portal Basic-auth password (user admin); a strong random value is generated and persisted to generated_credentials.env when empty |
| USER_UI_ENABLED | false | Enable the Flask user-management UI |
| USER_UI_USERNAME | TTYD_USERNAME / OS user (Linux) / admin (Windows) | Management UI username |
| USER_UI_PASSWORD | empty | Management UI password |
| FLASK_SECRET_KEY | *(persisted)* | Flask session signing key |
| AUTH_SECRET | *(persisted)* | Token signing secret (falls back to FLASK_SECRET_KEY) |
| HEALTH_AUTH_TOKEN | empty | Bearer token for health/metrics/audit endpoints; empty is allowed only on loopback binds (public bind without a token fails closed) |
| BACKUP_PASSWORD | empty | Encrypt backups with Fernet when set |
| EMAIL | empty | Contact email (Let's Encrypt registration) |

### Network & Ports

| Variable | Default | Description |
|----------|---------|-------------|
| VNC_PORT | 5901 Linux / 5900 Windows | VNC RFB port |
| VNC_HTTP_PORT | 5800 | UltraVNC HTTP port (Windows) |
| NOVNC_PORT | 6080 | noVNC web port |
| NOVNC_WS_PORT | 5700 | Loopback websockify bridge port |
| NOVNC_DIR | ./novnc | noVNC static assets directory |
| TTYD_PORT | 5000 | Web Terminal port |
| LANDING_PORT | 8000 | Landing portal port |
| HEALTH_WEB_PORT | 8080 Linux / 8090 Windows | Health server port |
| USER_UI_PORT | 8081 | Flask management UI port |
| AUDIO_STREAM_PORT | 7777 | Audio stream port |
| GAMEPAD_PORT | 7788 | Gamepad forward port |
| NGINX_ENABLED | false | Enable nginx reverse proxy |
| NGINX_HTTP_PORT | 80 | nginx plain HTTP port |
| NGINX_HTTPS_PORT | 443 | nginx TLS port (public entry) |

### Bind Hosts

| Variable | Default | Description |
|----------|---------|-------------|
| BIND_HOST | 127.0.0.1 | Generic bind host fallback |
| PUBLIC_BIND_HOST | 127.0.0.1 | Public-facing services bind |
| BACKEND_BIND_HOST | 127.0.0.1 | Backend services bind (locked in hardened profiles) |
| TTYD_HOST | 127.0.0.1 | Web Terminal bind |
| LANDING_HOST | 127.0.0.1 | Landing portal bind |
| HEALTH_WEB_HOST | 127.0.0.1 | Health server bind |
| USER_UI_HOST | 127.0.0.1 | Management UI bind |
| SERVE_NOVNC_HOST | 127.0.0.1 | noVNC static server bind |
| NOVNC_HOST | — | *Deprecated*: legacy fallback for SERVE_NOVNC_HOST |
| AUDIO_STREAM_HOST | 127.0.0.1 | Audio stream bind |
| GAMEPAD_HOST | 127.0.0.1 | Gamepad forward bind |
| ALLOWED_LAN_IPS | empty | Extra IPs allowed as WebSocket origins |

### TLS / SSL

| Variable | Default | Description |
|----------|---------|-------------|
| TLS_ENABLED | auto | `false` forces plain HTTP/WS |
| DISABLE_SSL | false | Legacy negative-logic TLS opt-out |
| SSL_CERT | canonical ssl dir | Certificate file path |
| SSL_KEY | canonical ssl dir | Private key file path |
| SSL_CIPHERS | platform defaults | OpenSSL cipher list |
| DUCK_DOMAIN | empty | DuckDNS domain |
| DUCKDNS_TOKEN | empty | DuckDNS update token |
| DUCKDNS_UPDATE_INTERVAL | 5 | DuckDNS update period (minutes) |
| ULTRAVNC_PATH | empty | winvnc.exe path (Windows) |
| ULTRAVNC_URL | — | UltraVNC download URL override |

### Security Policy

| Variable | Default | Description |
|----------|---------|-------------|
| SECURITY_PROFILE | development | development, trusted-lan, private-overlay, public-hardened |
| VNC_REMOTE_PROFILE | — | *Deprecated*: fallback read only when SECURITY_PROFILE is unset |
| MFA_REQUIRED | profile | Require TOTP second factor |
| TOTP_SECRET | empty | TOTP shared secret |
| RECOVERY_CODES_HASHES | empty | Comma-separated recovery code hashes |
| AUTH_MAX_ATTEMPTS | 5 | Failed logins before lockout |
| AUTH_LOCKOUT_SECONDS | 900 | Lockout duration |
| AUTH_WINDOW_SECONDS | 600 | Attempt counting window |
| ALLOWED_ORIGINS | auto | Extra allowed WebSocket origins (comma-separated) |
| TRUSTED_PROXY | false | Trust X-Forwarded-* headers |
| CSP_POLICY | hardened default | Content-Security-Policy header |
| HSTS_HEADER | hardened default | Strict-Transport-Security header |
| SESSION_SAMESITE | Lax | Session cookie SameSite |
| SESSION_COOKIE_SECURE | true | Secure flag on session cookie |
| SESSION_COOKIE_NAME | vnc_flask_session | Flask session cookie name (the raw session token cookie `vnc_session` is reserved) |
| SESSION_IDLE_TIMEOUT | 1800 | Idle session timeout (s) |
| SESSION_MAX_LIFETIME | 28800 | Absolute session lifetime (s) |
| WEB_MAX_CONTENT_LENGTH | 65536 | Max request body size (bytes) for the web UI |

### Services & Features

| Variable | Default | Description |
|----------|---------|-------------|
| HEALTH_WEB_ENABLED | true | Standalone health server |
| AUDIO_STREAM_ENABLED | false | Audio streaming |
| AUDIO_DEVICE | auto | Audio capture device |
| AUDIO_BITRATE | 128 | Stream bitrate (kbps) |
| GAMEPAD_ENABLED | false | Gamepad forwarding |
| WEBTERM_SHELL | bash/powershell | Terminal shell |
| VNC_DISPLAY | :1 | VNC display number (Linux) |
| VNC_GEOMETRY | 1280x720 | Desktop resolution |
| VNC_DEPTH | 24 | Color depth |
| FAIL2BAN_ENABLED | false | fail2ban integration (Linux) |
| FAIL2BAN_MAX_RETRY | 5 | Retries before ban |
| FAIL2BAN_FINDTIME | 600 | Ban window (s) |
| FAIL2BAN_BANTIME | 3600 | Ban duration (s) |

### Monitoring & Operations

| Variable | Default | Description |
|----------|---------|-------------|
| HEALTHCHECK_ENABLED | true | Service watchdog checks |
| HEALTHCHECK_INTERVAL | 30 | Watchdog interval (s) |
| AUTO_RESTART | false | Restart dead services |
| AUDIT_LOG_FILE | <log_dir>/audit.jsonl | Hash-chained audit log |
| AUDIT_LOG_MAX_BYTES | 10485760 | Audit rotation size |
| AUDIT_MIRROR_FILE | empty | Optional second append-only sink (network share / WORM store); tampering with the primary log leaves the mirror intact |
| ALERTS_ENABLED | false | Master alert gate |
| ALERT_WEBHOOK_URL | empty | Generic JSON webhook |
| DISCORD_ENABLED | false | Discord alert channel |
| DISCORD_WEBHOOK_URL | empty | Discord webhook URL |
| ALERT_EMAIL_TO / ALERT_EMAIL_FROM | empty / vnc-remote-secure@localhost | Alert email addresses (EMAIL_FROM falls back to `vnc-remote-secure@localhost`) |
| ALERT_SMTP_SERVER / ALERT_SMTP_TLS / ALERT_SMTP_USER / ALERT_SMTP_PASS | empty | SMTP relay settings |

### Internal / Advanced

| Variable | Default | Description |
|----------|---------|-------------|
| *_BACKEND_PROTOCOL | auto | Per-service http/https upstream scheme (HEALTH, NOVNC, TTYD, LANDING, AUDIO, GAMEPAD) — used by the nginx template |
| SHARED_STATE_BACKEND | sqlite | Shared state: sqlite or memory (tests/dev) |
| SHARED_STATE_DB_PATH | <run_dir>/shared_state.db | SQLite shared-state file |
| LOG_DIR | canonical | Optional log directory override |
| LOG_LEVEL | INFO | DEBUG, INFO, WARN, ERROR, FATAL |
| VERBOSE | false | Verbose output |
| PYTHON | auto | Python interpreter used when registering the Windows service |

## 🆘 Configuration Help

### Getting Help

```bash
# Show configuration help
vnc-remote help

# Show current configuration
vnc-remote config show-effective

# Validate configuration
vnc-remote doctor
```

### Troubleshooting

1. **Syntax Errors**: Check .env file format
2. **Missing Variables**: Use .env.example as reference
3. **Permission Issues**: Check file permissions
4. **Port Conflicts**: Use different ports or kill processes

---

**Next:** [User Guide](../user-guide/getting-started.md) for usage instructions
