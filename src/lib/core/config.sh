#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# CONFIGURATION
# ============================================================================

# User Configuration
export TTYD_USERNAME="${TTYD_USERNAME:-$(whoami)}"
export TTYD_PASSWD="${TTYD_PASSWD:-changeme}"
export TEMP_USER="${TEMP_USER:-remote}"
export TEMP_USER_PASS="${TEMP_USER_PASS:-$TTYD_PASSWD}"
export EMAIL="${EMAIL:-user@example.com}"

# Network Configuration
export NOVNC_PORT="${NOVNC_PORT:-6080}"
export TTYD_PORT="${TTYD_PORT:-5000}"
export VNC_PORT="${VNC_PORT:-5901}"

# SSL Configuration
# Get absolute path to project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export SSL_DIR="${SSL_DIR:-$SCRIPT_DIR/ssl}"
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

# Healthcheck Configuration
export HEALTHCHECK_ENABLED="${HEALTHCHECK_ENABLED:-true}"
export HEALTHCHECK_INTERVAL="${HEALTHCHECK_INTERVAL:-30}"
export AUTO_RESTART="${AUTO_RESTART:-false}"

# Port Knocking Configuration (OPTIONAL)
export PORT_KNOCK_ENABLED="${PORT_KNOCK_ENABLED:-false}"
export PORT_KNOCK_SEQUENCE="${PORT_KNOCK_SEQUENCE:-1000,2000,3000}"
export PORT_KNOCK_TIMEOUT="${PORT_KNOCK_TIMEOUT:-5}"
export PORT_KNOCK_METHOD="${PORT_KNOCK_METHOD:-iptables}"
export PORT_KNOCK_INTERFACE="${PORT_KNOCK_INTERFACE:-eth0}"

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
export USER_UI_PASSWORD="${USER_UI_PASSWORD:-admin123}"

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
export VNC_PASSWORD="${VNC_PASSWORD:-YourStrongPassword123}"

# Runtime State
export DISABLE_SSL=false
export SHOW_LOGS="${SHOW_LOGS:-true}"
export LOG_DIR="${LOG_DIR:-./logs}"
