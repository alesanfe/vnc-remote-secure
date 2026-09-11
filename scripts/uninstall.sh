#!/bin/bash
# ============================================================================
# Uninstaller for VNC Remote Secure
# ============================================================================
# Reverses all changes made by the project:
#   - Stops all running services
#   - Removes systemd service units (if installed)
#   - Removes nginx configuration
#   - Removes temporary users
#   - Optionally removes SSL certificates, data, and firewall rules
#   - Does NOT remove shared system packages (tigervnc, nginx, etc.)
#
# Usage:
#   sudo bash scripts/uninstall.sh              # Interactive (asks before destructive steps)
#   sudo bash scripts/uninstall.sh --force      # Non-interactive (removes everything)
#   sudo bash scripts/uninstall.sh --keep-data  # Remove services but keep certs/data/backups
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse arguments
FORCE=false
KEEP_DATA=false
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=true ;;
        --keep-data) KEEP_DATA=true ;;
        --help|-h)
            echo "Usage: sudo bash scripts/uninstall.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force       Non-interactive, remove everything without asking"
            echo "  --keep-data   Keep SSL certs, data directory, and backups"
            echo "  --help        Show this help"
            exit 0
            ;;
    esac
done

# Must be root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Must run as root (use sudo)${NC}"
    exit 1
fi

# Load config if available
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

# Defaults from config.sh
TEMP_USER="${TEMP_USER:-remote}"
VNC_PORT="${VNC_PORT:-5901}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
TTYD_PORT="${TTYD_PORT:-5000}"
HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8080}"
DUCK_DOMAIN="${DUCK_DOMAIN:-}"

# Track what was removed
declare -a REMOVED=()

confirm() {
    if $FORCE; then return 0; fi
    local prompt="$1"
    read -rp "$(echo -e "${YELLOW}${prompt} [y/N] ${NC}")" answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

remove_systemd_units() {
    echo -e "${BLUE}Checking for systemd service units...${NC}"
    local units=(
        vnc-remote-vnc.service
        vnc-remote-novnc.service
        vnc-remote-ttyd.service
        vnc-remote-health.service
    )
    for unit in "${units[@]}"; do
        if [[ -f "/etc/systemd/system/$unit" ]]; then
            systemctl stop "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
            rm -f "/etc/systemd/system/$unit"
            REMOVED+=("systemd unit: $unit")
            echo -e "  ${GREEN}✓ Removed $unit${NC}"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
}

stop_running_services() {
    echo -e "${BLUE}Stopping running services...${NC}"

    # Kill processes on known ports
    for port in "$VNC_PORT" "$NOVNC_PORT" "$TTYD_PORT" "$HEALTH_WEB_PORT"; do
        local pid
        pid=$(lsof -ti :"$port" 2>/dev/null || true)
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            REMOVED+=("process on port $port (PID: $pid)")
            echo -e "  ${GREEN}✓ Stopped process on port $port${NC}"
        fi
    done

    # Kill VNC server
    if command -v vncserver &>/dev/null; then
        sudo -u "$TEMP_USER" vncserver -kill :* 2>/dev/null || true
    fi

    # Kill any remaining project processes
    pkill -f "rpi-vnc-remote" 2>/dev/null || true
    pkill -f "health_web_server" 2>/dev/null || true
    pkill -f "web_terminal" 2>/dev/null || true
}

remove_nginx_config() {
    echo -e "${BLUE}Checking nginx configuration...${NC}"

    local nginx_configs=(
        "/etc/nginx/sites-available/vnc-remote"
        "/etc/nginx/sites-enabled/vnc-remote"
        "/etc/nginx/conf.d/vnc-remote.conf"
    )

    for config in "${nginx_configs[@]}"; do
        if [[ -f "$config" ]]; then
            rm -f "$config"
            REMOVED+=("nginx config: $config")
            echo -e "  ${GREEN}✓ Removed $config${NC}"
        fi
    done

    # Reload nginx if it's running
    if systemctl is-active nginx &>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        echo -e "  ${BLUE}Reloaded nginx${NC}"
    fi
}

remove_temp_user() {
    echo -e "${BLUE}Checking for temporary user '$TEMP_USER'...${NC}"
    if id "$TEMP_USER" &>/dev/null; then
        if confirm "Remove user '$TEMP_USER' and its home directory?"; then
            userdel -r "$TEMP_USER" 2>/dev/null || userdel "$TEMP_USER" 2>/dev/null || true
            REMOVED+=("user: $TEMP_USER")
            echo -e "  ${GREEN}✓ Removed user $TEMP_USER${NC}"
        else
            echo -e "  ${YELLOW}Kept user $TEMP_USER${NC}"
        fi
    fi
}

remove_firewall_rules() {
    echo -e "${BLUE}Checking firewall rules...${NC}"

    if command -v ufw &>/dev/null; then
        # Check if any rules reference our ports
        if ufw status 2>/dev/null | grep -qE "($VNC_PORT|$NOVNC_PORT|$TTYD_PORT|$HEALTH_WEB_PORT)"; then
            if confirm "Remove firewall rules for project ports ($VNC_PORT, $NOVNC_PORT, $TTYD_PORT, $HEALTH_WEB_PORT)?"; then
                ufw delete allow "$VNC_PORT"/tcp 2>/dev/null || true
                ufw delete allow "$NOVNC_PORT"/tcp 2>/dev/null || true
                ufw delete allow "$TTYD_PORT"/tcp 2>/dev/null || true
                ufw delete allow "$HEALTH_WEB_PORT"/tcp 2>/dev/null || true
                REMOVED+=("ufw rules for project ports")
                echo -e "  ${GREEN}✓ Removed firewall rules${NC}"
            fi
        fi
    fi
}

remove_ssl_certificates() {
    if $KEEP_DATA; then
        echo -e "  ${YELLOW}Keeping SSL certificates (--keep-data)${NC}"
        return
    fi

    echo -e "${BLUE}Checking SSL certificates...${NC}"

    # Project-local certificates
    local ssl_dirs=("$PROJECT_DIR/data/ssl" "$PROJECT_DIR/ssl")
    for dir in "${ssl_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            if confirm "Remove SSL certificates in $dir?"; then
                rm -rf "$dir"
                REMOVED+=("SSL certificates: $dir")
                echo -e "  ${GREEN}✓ Removed $dir${NC}"
            fi
        fi
    done

    # Let's Encrypt certificates
    if [[ -n "$DUCK_DOMAIN" ]]; then
        local letsencrypt_dir="/etc/letsencrypt/live/$DUCK_DOMAIN"
        if [[ -d "$letsencrypt_dir" ]]; then
            if confirm "Remove Let's Encrypt certificate for $DUCK_DOMAIN?"; then
                certbot delete --cert-name "$DUCK_DOMAIN" --non-interactive 2>/dev/null || true
                rm -rf "$letsencrypt_dir"
                REMOVED+=("Let's Encrypt cert: $DUCK_DOMAIN")
                echo -e "  ${GREEN}✓ Removed Let's Encrypt certificate${NC}"
            fi
        fi
    fi
}

remove_fail2ban_config() {
    echo -e "${BLUE}Checking fail2ban configuration...${NC}"
    local f2b_config="/etc/fail2ban/jail.d/vnc-remote.conf"
    if [[ -f "$f2b_config" ]]; then
        rm -f "$f2b_config"
        REMOVED+=("fail2ban config: $f2b_config")
        echo -e "  ${GREEN}✓ Removed $f2b_config${NC}"
        if systemctl is-active fail2ban &>/dev/null; then
            systemctl restart fail2ban 2>/dev/null || true
        fi
    fi
}

remove_data_directory() {
    if $KEEP_DATA; then
        echo -e "  ${YELLOW}Keeping data directory (--keep-data)${NC}"
        return
    fi

    local data_dir="$PROJECT_DIR/data"
    if [[ -d "$data_dir" ]]; then
        if confirm "Remove data directory ($data_dir)? This includes logs, VNC data, grafana, etc."; then
            rm -rf "$data_dir"
            REMOVED+=("data directory: $data_dir")
            echo -e "  ${GREEN}✓ Removed $data_dir${NC}"
        fi
    fi
}

remove_installed_symlink() {
    echo -e "${BLUE}Checking installed symlink...${NC}"
    if [[ -f "/usr/local/bin/rpi-vnc-remote" ]]; then
        rm -f /usr/local/bin/rpi-vnc-remote
        REMOVED+=("symlink: /usr/local/bin/rpi-vnc-remote")
        echo -e "  ${GREEN}✓ Removed /usr/local/bin/rpi-vnc-remote${NC}"
    fi
    if [[ -d "/usr/local/share/rpi-vnc-remote" ]]; then
        rm -rf /usr/local/share/rpi-vnc-remote
        REMOVED+=("share dir: /usr/local/share/rpi-vnc-remote")
        echo -e "  ${GREEN}✓ Removed /usr/local/share/rpi-vnc-remote${NC}"
    fi
}

show_summary() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Uninstallation Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""

    if [[ ${#REMOVED[@]} -eq 0 ]]; then
        echo -e "${YELLOW}  Nothing was removed. Project was not installed or already clean.${NC}"
    else
        echo -e "${GREEN}  Removed ${#REMOVED[@]} item(s):${NC}"
        for item in "${REMOVED[@]}"; do
            echo -e "    ${GREEN}✓${NC} $item"
        done
    fi

    echo ""
    echo -e "${BLUE}  NOT removed (shared system packages):${NC}"
    echo "    - tigervnc-server (install with: sudo apt remove tigervnc-server)"
    echo "    - nginx (install with: sudo apt remove nginx)"
    echo "    - ttyd (install with: sudo apt remove ttyd)"
    echo "    - certbot (install with: sudo apt remove certbot)"
    echo "    - fail2ban (install with: sudo apt remove fail2ban)"
    echo ""
    echo -e "${BLUE}  Project source code in $PROJECT_DIR was NOT removed.${NC}"
    echo -e "${BLUE}  To remove it: rm -rf $PROJECT_DIR${NC}"
    echo ""
}

# ============================================================================
# Main
# ============================================================================
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  VNC Remote Secure - Uninstaller${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

if ! $FORCE; then
    echo -e "${YELLOW}This will stop services and remove project-specific configuration.${NC}"
    echo -e "${YELLOW}Shared packages (tigervnc, nginx, etc.) will NOT be removed.${NC}"
    echo -e "${YELLOW}Use --force to skip confirmations.${NC}"
    echo ""
fi

stop_running_services
remove_systemd_units
remove_nginx_config
remove_fail2ban_config
remove_temp_user
remove_firewall_rules
remove_ssl_certificates
remove_data_directory
remove_installed_symlink

show_summary
