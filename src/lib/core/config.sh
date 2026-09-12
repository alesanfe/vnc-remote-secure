#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# CONFIGURATION
# ============================================================================

# User Configuration
# Default to current user, but lowercase it to satisfy username validation
_TTYD_USERNAME_DEFAULT="$(whoami)"
_TTYD_USERNAME_DEFAULT="${_TTYD_USERNAME_DEFAULT,,}"
export TTYD_USERNAME="${TTYD_USERNAME:-$_TTYD_USERNAME_DEFAULT}"
unset _TTYD_USERNAME_DEFAULT

# Generate a strong random password that meets all validation requirements:
# uppercase, lowercase, digit, and special character (!@#).
# Uses openssl if available, falls back to /dev/urandom, then python3.
_generate_strong_password() {
    local pw base
    # Try openssl first (most portable across platforms)
    if command -v openssl &>/dev/null; then
        base="$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 19)"
        # Append a special character to guarantee complexity
        pw="${base}#"
    fi
    # Fallback to /dev/urandom (Linux/macOS)
    if [[ -z "$pw" ]] && [[ -r /dev/urandom ]]; then
        base="$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 19)"
        pw="${base}#"
    fi
    # Fallback to python3 (works on Windows/MSYS)
    if [[ -z "$pw" ]] && command -v python3 &>/dev/null; then
        pw="$(python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(19))+'#')" 2>/dev/null)"
    fi
    # Ensure all character types are present
    if [[ "$pw" =~ [A-Z] ]] && \
       [[ "$pw" =~ [a-z] ]] && \
       [[ "$pw" =~ [0-9] ]] && \
       [[ "$pw" =~ [^a-zA-Z0-9] ]]; then
        printf '%s' "$pw"
    else
        # Last resort: use a deterministic but non-weak password.
        # "ChangeMe!" is rejected by validate_password, so we use a
        # random-looking string that passes complexity checks.
        printf 'Xy7%s#Ab' "$(date +%s | tail -c 5)"
    fi
}

# No default password — generate a strong random one if not set
if [[ -z "${TTYD_PASSWD:-}" ]]; then
    TTYD_PASSWD="$(_generate_strong_password)"
    export TTYD_PASSWD
fi
export TEMP_USER="${TEMP_USER:-remote}"
export TEMP_USER_PASS="${TEMP_USER_PASS:-$TTYD_PASSWD}"
# No default email — must be set by user for SSL certificate registration
export EMAIL="${EMAIL:-}"

# Network Configuration
export NOVNC_PORT="${NOVNC_PORT:-6080}"
export TTYD_PORT="${TTYD_PORT:-5000}"
export VNC_PORT="${VNC_PORT:-5901}"
# Host addresses for nginx upstreams (default: localhost when nginx is enabled)
export NOVNC_HOST="${NOVNC_HOST:-${SERVE_NOVNC_HOST:-127.0.0.1}}"
export TTYD_HOST="${TTYD_HOST:-127.0.0.1}"
export HEALTH_WEB_HOST="${HEALTH_WEB_HOST:-127.0.0.1}"
# Protocol nginx uses to reach the health backend ("http" or "https").
# Set to "https" when the health server terminates TLS itself.
export HEALTH_BACKEND_PROTOCOL="${HEALTH_BACKEND_PROTOCOL:-http}"
export LANDING_HOST="${LANDING_HOST:-127.0.0.1}"
export LANDING_PASSWORD="${LANDING_PASSWORD:-}"
export AUTH_SECRET="${AUTH_SECRET:-}"
export HEALTH_AUTH_TOKEN="${HEALTH_AUTH_TOKEN:-}"
export VNC_HTTP_PORT="${VNC_HTTP_PORT:-5800}"
export WEBTERM_SHELL="${WEBTERM_SHELL:-/bin/bash}"
export USER_UI_SESSION_TIMEOUT="${USER_UI_SESSION_TIMEOUT:-1800}"
export TRUSTED_PROXY="${TRUSTED_PROXY:-}"

# SSL Configuration
# Get absolute path to project directory (config.sh is in src/lib/core/)
_PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export SSL_DIR="${SSL_DIR:-$_PROJECT_DIR/data/ssl}"
export DUCK_DOMAIN="${DUCK_DOMAIN:-}"
# Duck DNS token for automatic IP updates (get from https://www.duckdns.org/)
export DUCKDNS_TOKEN="${DUCKDNS_TOKEN:-}"
# Duck DNS update interval in minutes (for daemon mode)
export DUCKDNS_UPDATE_INTERVAL="${DUCKDNS_UPDATE_INTERVAL:-5}"
# Only construct DUCK_DIR if DUCK_DOMAIN is set
export DUCK_DIR="${DUCK_DOMAIN:+/etc/letsencrypt/live/$DUCK_DOMAIN}"
# Respect SSL_CERT/SSL_KEY from environment if set; otherwise default to SSL_DIR
export SSL_CERT="${SSL_CERT:-$SSL_DIR/fullchain.pem}"
export SSL_KEY="${SSL_KEY:-$SSL_DIR/privkey.pem}"
export SSL_RENEW_DAYS="${SSL_RENEW_DAYS:-30}"

# BeEF Configuration (OPTIONAL)
export BEEF_ENABLED="${BEEF_ENABLED:-false}"
export BEEF_HOOK_URL="${BEEF_HOOK_URL:-}"
export INDEX_FILE="${INDEX_FILE:-/usr/share/novnc/index.html}"
export VNC_FILE="${VNC_FILE:-/usr/share/novnc/vnc.html}"

# Discord Notifications (OPTIONAL)
export DISCORD_ENABLED="${DISCORD_ENABLED:-false}"
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

# Fail2ban Configuration (OPTIONAL)
export FAIL2BAN_ENABLED="${FAIL2BAN_ENABLED:-false}"
export FAIL2BAN_MAX_RETRY="${FAIL2BAN_MAX_RETRY:-5}"
export FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-600}"
export FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-3600}"

# nginx Configuration (OPTIONAL)
export NGINX_ENABLED="${NGINX_ENABLED:-false}"
export NGINX_HTTP_PORT="${NGINX_HTTP_PORT:-80}"
export NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"

# Healthcheck Configuration
export HEALTHCHECK_ENABLED="${HEALTHCHECK_ENABLED:-true}"
export HEALTHCHECK_INTERVAL="${HEALTHCHECK_INTERVAL:-30}"
export AUTO_RESTART="${AUTO_RESTART:-false}"
export HEALTH_WEB_ENABLED="${HEALTH_WEB_ENABLED:-true}"
export HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8080}"


# Monitoring Configuration (OPTIONAL)
export MONITORING_ENABLED="${MONITORING_ENABLED:-false}"
export PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
export GRAFANA_PORT="${GRAFANA_PORT:-3000}"
export NODE_EXPORTER_PORT="${NODE_EXPORTER_PORT:-9100}"

# Session Recording Configuration (OPTIONAL)
export RECORDING_ENABLED="${RECORDING_ENABLED:-false}"
export RECORDING_DIR="${RECORDING_DIR:-./recordings}"
export RECORDING_FORMAT="${RECORDING_FORMAT:-asciinema}"

# User Management UI Configuration (OPTIONAL)
export USER_UI_ENABLED="${USER_UI_ENABLED:-false}"
export USER_UI_PORT="${USER_UI_PORT:-8081}"
# No default UI password — generate a strong random one if not set
if [[ -z "${USER_UI_PASSWORD:-}" ]]; then
    USER_UI_PASSWORD="$(_generate_strong_password)"
    export USER_UI_PASSWORD
fi

# Alerts Configuration (OPTIONAL)
export ALERTS_ENABLED="${ALERTS_ENABLED:-false}"
export ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
export ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
export ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-vnc-alerts@localhost}"
export ALERT_SMTP_SERVER="${ALERT_SMTP_SERVER:-localhost:587}"
export ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
export ALERT_SMTP_PASS="${ALERT_SMTP_PASS:-}"

# VNC Server Configuration
export VNC_DISPLAY="${VNC_DISPLAY:-:1}"
export VNC_GEOMETRY="${VNC_GEOMETRY:-1280x720}"
export VNC_DEPTH="${VNC_DEPTH:-24}"
# No default VNC password — generate a strong random one if not set
if [[ -z "${VNC_PASSWORD:-}" ]]; then
    VNC_PASSWORD="$(_generate_strong_password)"
    export VNC_PASSWORD
fi

# Runtime State
# TLS_ENABLED is the canonical toggle (aligned with the Python stack).
# DISABLE_SSL/USE_SSL are kept for backward compatibility with the Bash
# entry points (launch.sh, rpi-vnc-remote.sh) and are derived from it.
if [[ -z "${TLS_ENABLED:-}" ]]; then
    # Infer from legacy DISABLE_SSL if TLS_ENABLED is unset
    if [[ "${DISABLE_SSL:-false}" == "true" ]]; then
        export TLS_ENABLED="false"
    else
        export TLS_ENABLED="true"
    fi
fi
export DISABLE_SSL="$([[ "$TLS_ENABLED" == "false" ]] && echo true || echo false)"
export USE_SSL="$([[ "$TLS_ENABLED" == "true" ]] && echo true || echo false)"
export SHOW_LOGS="${SHOW_LOGS:-true}"
export LOG_DIR="${LOG_DIR:-./logs}"
# Whether to keep the temporary user after exit (default: false = remove on exit)
export KEEP_TEMP_USER="${KEEP_TEMP_USER:-false}"

# Logging Configuration
export LOG_LEVEL="${LOG_LEVEL:-INFO}"
export VERBOSE="${VERBOSE:-false}"

# Flask Secret Key (for user_ui_app.py session signing)
# No default — must be set by user for stable sessions in production
export FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-}"
