#!/bin/bash
# ============================================================================
# Install systemd service units for VNC Remote Secure
# ============================================================================
# Installs the committed systemd unit(s) into /etc/systemd/system and
# reloads the daemon. The committed unit
# (src/vnc_remote_secure/native/linux/systemd/vnc-remote.service) is
# already hardcoded to the canonical layout used
# by packaging/linux/install.sh:
#   - EnvironmentFile=/etc/vnc-remote-secure/config.env
#   - WorkingDirectory=/opt/vnc-remote-secure
#   - User=vnc-remote / Group=vnc-remote
# so no template substitution is required.
#
# This script is a thin convenience wrapper. For a full installation
# (service user, runtime dirs, CLI wrapper, etc.) use
# packaging/linux/install.sh instead.
#
# Usage:
#   sudo bash scripts/maintenance/install_systemd.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SYSTEMD_SRC="$PROJECT_DIR/src/vnc_remote_secure/native/linux/systemd"
# Fallback to legacy root-level location (pre-consolidation layout).
if [[ ! -d "$SYSTEMD_SRC" ]]; then
    SYSTEMD_SRC="$PROJECT_DIR/native/linux/systemd"
fi
SYSTEMD_DST="/etc/systemd/system"

# Must be root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${BLUE}Installing systemd service units for VNC Remote Secure...${NC}"
echo "  Source: $SYSTEMD_SRC"
echo "  Dest:   $SYSTEMD_DST"
echo ""

# Install the committed unit(s) verbatim (no templating required).
installed=0
for unit_file in "$SYSTEMD_SRC"/*.service; do
    [[ -f "$unit_file" ]] || continue
    unit_name=$(basename "$unit_file")
    install -m 644 "$unit_file" "$SYSTEMD_DST/$unit_name"
    echo -e "  ${GREEN}✓ Installed $unit_name${NC}"
    installed=$((installed + 1))
done

if [[ "$installed" -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  No .service files found in $SYSTEMD_SRC${NC}"
    exit 1
fi

# Ensure the canonical config directory exists so systemd can load the
# EnvironmentFile referenced by the unit. The full installer
# (packaging/linux/install.sh) populates this file; here we only ensure
# the directory exists so the unit can start.
mkdir -p /etc/vnc-remote-secure
if [[ ! -f /etc/vnc-remote-secure/config.env ]]; then
    echo -e "  ${YELLOW}⚠️  /etc/vnc-remote-secure/config.env is missing.${NC}"
    echo -e "  ${YELLOW}    Run packaging/linux/install.sh or copy your .env there.${NC}"
fi

# Reload systemd
systemctl daemon-reload
echo -e "  ${GREEN}✓ Reloaded systemd daemon${NC}"

echo ""
echo -e "${BLUE}Service units installed. To enable and start:${NC}"
echo "  sudo systemctl enable vnc-remote"
echo "  sudo systemctl start vnc-remote"
echo ""
echo -e "${BLUE}To check status:${NC}"
echo "  sudo systemctl status vnc-remote"
echo ""
echo -e "${YELLOW}Note: For a full installation (service user, runtime dirs, CLI${NC}"
echo -e "${YELLOW}wrapper, config file) use packaging/linux/install.sh instead.${NC}"
