#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# CONFIGURATION
# ============================================================================

# User Configuration
export TTYD_USERNAME="${TTYD_USERNAME:-$(whoami)}"
# No default password — generate a strong random one if not set
# Uses /dev/urandom directly with tr. Retry until at least one special char
# is present (probability of no special char in 20 draws is ~38%, so retry
# is needed to guarantee validation passes).
if [[ -z "${TTYD_PASSWD:-}" ]]; then
    while true; do
        TTYD_PASSWD="$(tr -dc 'A-Za-z0-9!@#' </dev/urandom | head -c 20)"
        [[ "$TTYD_PASSWD" =~ [^a-zA-Z0-9] ]] && break
    done
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

# SSL Configuration
# Get absolute path to project directory (config.sh is in src/lib/core/)
_PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export SSL_DIR="${SSL_DIR:-$_PROJECT_DIR/data/ssl}"
export DUCK_DOMAIN="${DUCK_DOMAIN:-}"
# Only construct DUCK_DIR if DUCK_DOMAIN is set
export DUCK_DIR="${DUCK_DOMAIN:+/etc/letsencrypt/live/$DUCK_DOMAIN}"
export SSL_CERT="$SSL_DIR/fullchain.pem"
export SSL_KEY="$SSL_DIR/privkey.pem"
export SSL_RENEW_DAYS="${SSL_RENEW_DAYS:-30}"

# BeEF Configuration (OPTIONAL)
export BEEF_ENABLED="${BEEF_ENABLED:-false}"
export BEEF_HOOK_URL="${BEEF_HOOK_URL:-}"
export INDEX_FILE="/usr/share/novnc/index.html"
export VNC_FILE="/usr/share/novnc/vnc.html"

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
    while true; do
        USER_UI_PASSWORD="$(tr -dc 'A-Za-z0-9!@#' </dev/urandom | head -c 20)"
        [[ "$USER_UI_PASSWORD" =~ [^a-zA-Z0-9] ]] && break
    done
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
export VNC_DISPLAY="${VNC_DISPLAY:-:2}"
export VNC_GEOMETRY="${VNC_GEOMETRY:-1920x1080}"
export VNC_DEPTH="${VNC_DEPTH:-24}"
# No default VNC password — generate a strong random one if not set
if [[ -z "${VNC_PASSWORD:-}" ]]; then
    export VNC_PASSWORD="$(tr -dc 'A-Za-z0-9!@#' </dev/urandom | head -c 20)"
fi

# Runtime State
export DISABLE_SSL="${DISABLE_SSL:-false}"
export SHOW_LOGS="${SHOW_LOGS:-true}"
export LOG_DIR="${LOG_DIR:-./logs}"
# Whether to keep the temporary user after exit (default: false = remove on exit)
export KEEP_TEMP_USER="${KEEP_TEMP_USER:-false}"
