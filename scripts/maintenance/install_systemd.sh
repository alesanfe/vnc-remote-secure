#!/bin/bash
# ============================================================================
# Install systemd service units for VNC Remote Secure
# ============================================================================
# Templates and installs systemd .service files with actual configuration values.
# After installation, services can be managed with:
#   sudo systemctl start vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health
#   sudo systemctl enable vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health
#   sudo systemctl status vnc-remote-vnc
#
# Usage:
#   sudo bash scripts/install_systemd.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SYSTEMD_SRC="$PROJECT_DIR/systemd"
SYSTEMD_DST="/etc/systemd/system"
SECRETS_DIR="/etc/vnc-remote/secrets"

# Must be root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root (use sudo)${NC}"
    exit 1
fi

# Load .env
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

# Get values
TEMP_USER="${TEMP_USER:-remote}"
VNC_DISPLAY="${VNC_DISPLAY:-:2}"
VNC_GEOMETRY="${VNC_GEOMETRY:-1920x1080}"
VNC_DEPTH="${VNC_DEPTH:-24}"
VNC_PORT="${VNC_PORT:-5901}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
TTYD_PORT="${TTYD_PORT:-5000}"
HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8080}"

echo -e "${BLUE}Installing systemd service units for VNC Remote Secure...${NC}"
echo "  Temp user:   $TEMP_USER"
echo "  VNC display: $VNC_DISPLAY"
echo "  VNC port:    $VNC_PORT"
echo "  noVNC port:  $NOVNC_PORT"
echo "  ttyd port:   $TTYD_PORT"
echo ""

# Create secrets directory
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Create environment file for systemd
ENV_FILE="$SECRETS_DIR/vnc.env"
cat > "$ENV_FILE" << EOF
# Environment variables for VNC Remote Secure systemd services
# This file has restricted permissions (600) and is only readable by root
TEMP_USER=$TEMP_USER
VNC_DISPLAY=$VNC_DISPLAY
VNC_GEOMETRY=$VNC_GEOMETRY
VNC_DEPTH=$VNC_DEPTH
VNC_PORT=$VNC_PORT
NOVNC_PORT=$NOVNC_PORT
TTYD_PORT=$TTYD_PORT
HEALTH_WEB_PORT=$HEALTH_WEB_PORT
VNC_PASSWORD=${VNC_PASSWORD:-}
TTYD_USERNAME=${TTYD_USERNAME:-}
TTYD_PASSWD=${TTYD_PASSWD:-}
EOF
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE"
echo -e "  ${GREEN}✓ Created $ENV_FILE (permissions: 600)${NC}"

# Create ttyd credentials file
TTYD_CRED_FILE="$SECRETS_DIR/ttyd-credentials"
if [[ -n "${TTYD_USERNAME:-}" && -n "${TTYD_PASSWD:-}" ]]; then
    echo "${TTYD_USERNAME}:${TTYD_PASSWD}" > "$TTYD_CRED_FILE"
    chmod 600 "$TTYD_CRED_FILE"
    chown root:root "$TTYD_CRED_FILE"
    echo -e "  ${GREEN}✓ Created $TTYD_CRED_FILE (permissions: 600)${NC}"
fi

# Template and install each unit
for unit_file in "$SYSTEMD_SRC"/*.service; do
    [[ -f "$unit_file" ]] || continue
    unit_name=$(basename "$unit_file")

    # Template substitution
    sed \
        -e "s|__TEMP_USER__|$TEMP_USER|g" \
        -e "s|__VNC_DISPLAY__|$VNC_DISPLAY|g" \
        -e "s|__VNC_GEOMETRY__|$VNC_GEOMETRY|g" \
        -e "s|__VNC_DEPTH__|$VNC_DEPTH|g" \
        -e "s|__VNC_PORT__|$VNC_PORT|g" \
        -e "s|__NOVNC_PORT__|$NOVNC_PORT|g" \
        -e "s|__TTYD_PORT__|$TTYD_PORT|g" \
        -e "s|__HEALTH_WEB_PORT__|$HEALTH_WEB_PORT|g" \
        -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
        "$unit_file" > "$SYSTEMD_DST/$unit_name"

    chmod 644 "$SYSTEMD_DST/$unit_name"
    echo -e "  ${GREEN}✓ Installed $unit_name${NC}"
done

# Reload systemd
systemctl daemon-reload
echo -e "  ${GREEN}✓ Reloaded systemd daemon${NC}"

echo ""
echo -e "${BLUE}Service units installed. To enable and start:${NC}"
echo "  sudo systemctl enable vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health"
echo "  sudo systemctl start vnc-remote-vnc vnc-remote-novnc vnc-remote-ttyd vnc-remote-health"
echo ""
echo -e "${BLUE}To check status:${NC}"
echo "  sudo systemctl status vnc-remote-vnc"
echo ""
echo -e "${YELLOW}Note: Services bind to localhost. Use nginx (NGINX_ENABLED=true) for external access.${NC}"
