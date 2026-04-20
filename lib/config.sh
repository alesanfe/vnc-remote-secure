#!/bin/bash
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
export SSL_DIR="${SSL_DIR:-$(pwd)/ssl}"
export DUCK_DOMAIN="${DUCK_DOMAIN:-}"
export DUCK_DIR="/etc/letsencrypt/live/$DUCK_DOMAIN"
export SSL_CERT="$SSL_DIR/fullchain.pem"
export SSL_KEY="$SSL_DIR/privkey.pem"
export SSL_RENEW_DAYS="${SSL_RENEW_DAYS:-30}"

# BeEF Configuration (OPTIONAL)
export BEEF_ENABLED="${BEEF_ENABLED:-false}"
export BEEF_HOOK_URL="${BEEF_HOOK_URL:-}"
export INDEX_FILE="/usr/share/novnc/index.html"
export VNC_FILE="/usr/share/novnc/vnc.html"

# VNC Server Configuration
export VNC_DISPLAY="${VNC_DISPLAY:-:2}"
export VNC_GEOMETRY="${VNC_GEOMETRY:-1920x1080}"
export VNC_DEPTH="${VNC_DEPTH:-24}"

# Runtime State
export DISABLE_SSL=false
