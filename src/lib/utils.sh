#!/bin/bash
# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log() {
    local level="$1"
    local message="$2"
    local emoji="$3"
    
    local colors=(
        ["red"]="\033[0;31m"
        ["green"]="\033[0;32m"
        ["yellow"]="\033[0;33m"
        ["blue"]="\033[0;34m"
        ["purple"]="\033[0;35m"
        ["cyan"]="\033[0;36m"
        ["white"]="\033[0;37m"
        ["reset"]="\033[0m"
    )
    
    local color="${colors[$level]:-${colors[reset]}}"
    echo -e "${color}${emoji} ${message}${colors[reset]}"
}

die() {
    log "red" "$1" "❌"
    exit 1
}

warn() {
    log "yellow" "$1" "⚠️"
}

info() {
    log "blue" "$1" "ℹ️"
}

success() {
    log "green" "$1" "✅"
}

# ============================================================================
# COMMAND HANDLING
# ============================================================================

show_help() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
  stop    Stop all services and cleanup
  help    Show this help message

Environment Variables:
  TTYD_USERNAME       Username for ttyd authentication (default: current user)
  TTYD_PASSWD         Password for ttyd authentication (default: changeme)
  TEMP_USER           Temporary user name (default: remote)
  TEMP_USER_PASS      Temporary user password (default: TTYD_PASSWD)
  EMAIL               Email for SSL certificate (default: user@example.com)
  NOVNC_PORT          Port for noVNC (default: 6080)
  TTYD_PORT           Port for ttyd (default: 5000)
  VNC_PORT            Port for VNC (default: 5901)
  SSL_DIR             Directory for SSL certificates (default: ./ssl)
  DUCK_DOMAIN         Domain for SSL certificate (required for SSL)
  SSL_RENEW_DAYS      Days before SSL expiration to renew (default: 30)
  BEEF_ENABLED        Enable BeEF injection (default: false)
  BEEF_HOOK_URL       URL for BeEF hook script
  VNC_DISPLAY         VNC display number (default: :2)
  VNC_GEOMETRY        VNC resolution (default: 1920x1080)
  VNC_DEPTH           VNC color depth (default: 24)

Examples:
  TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org $0
  $0 stop
EOF
    exit 0
}

handle_command() {
    case "$1" in
        stop)
            log "yellow" "Stopping services..." "🛑"
            cleanup
            exit 0
            ;;
        help|--help|-h)
            show_help
            ;;
    esac
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

kill_process_on_port() {
    local port="$1"
    local pid=$(lsof -t -i :"$port" 2>/dev/null)
    
    if [[ -n "$pid" ]]; then
        log "yellow" "Stopping process on port $port (PID: $pid)..." "🛑"
        sudo kill -9 "$pid" 2>/dev/null || true
    fi
}

kill_vnc_server() {
    if pgrep -x "Xtigervnc" > /dev/null; then
        log "yellow" "Stopping TigerVNC server..." "🛑"
        sudo -u "$TEMP_USER" tigervncserver -kill "$VNC_DISPLAY" 2>/dev/null || true
        sudo pkill -f 'tigervncserver' 2>/dev/null || true
    fi
}

remove_temp_user() {
    if id "$TEMP_USER" &>/dev/null; then
        log "yellow" "Removing temporary user $TEMP_USER..." "🚨"
        sudo pkill -u "$TEMP_USER" 2>/dev/null || true
        sudo deluser --remove-home "$TEMP_USER" 2>/dev/null || true
    fi
}

cleanup() {
    log "blue" "Cleaning up environment..." "🩹"
    
    kill_process_on_port "$NOVNC_PORT"
    kill_process_on_port "$TTYD_PORT"
    kill_process_on_port "$VNC_PORT"
    kill_vnc_server
    remove_temp_user
    
    rm -f ttyd.armhf* 2>/dev/null || true
    
    success "Cleanup complete."
}

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

install_dependencies() {
    log "yellow" "Installing required packages..." "⚙️"
    
    sudo apt update && sudo apt install -y \
        wget iproute2 lsof tigervnc-standalone-server novnc \
        xfce4 xfce4-goodies x11-xserver-utils certbot \
        python3-certbot-dns-standalone acl
    
    success "Dependencies installed successfully."
}

detect_ttyd_arch() {
    local arch=$(uname -m)
    
    case "$arch" in
        armv7l|armhf) echo "armhf" ;;
        aarch64|arm64) echo "arm64" ;;
        x86_64) echo "amd64" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac
}

install_ttyd() {
    if command -v ttyd &>/dev/null; then
        success "ttyd is already installed."
        return
    fi
    
    log "yellow" "Installing ttyd..." "⚙️"
    rm -f ttyd.armhf* 2>/dev/null || true
    
    local ttyd_arch=$(detect_ttyd_arch)
    log "cyan" "Downloading ttyd for $(uname -m)..." "📥"
    
    wget -q "https://github.com/tsl0922/ttyd/releases/download/1.7.4/ttyd.linux-$ttyd_arch" -O ttyd || {
        warn "Failed to download ttyd. Trying fallback version..."
        wget "https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.$ttyd_arch" -O ttyd
    }
    
    if [[ $? -eq 0 ]]; then
        sudo cp ttyd /usr/local/bin/ttyd
        sudo chmod +x /usr/local/bin/ttyd
        rm -f ttyd
        success "ttyd installed successfully."
    else
        die "Failed to install ttyd."
    fi
}

# ============================================================================
# DISPLAY FUNCTIONS
# ============================================================================

print_banner() {
    cat << "EOF"

==========================================
  Raspberry Pi VNC Remote Setup
==========================================

EOF
}

print_access_info() {
    local protocol="http"
    [[ "$DISABLE_SSL" == false ]] && protocol="https"
    
    cat << EOF

==========================================
  Access Information
==========================================

noVNC (Desktop): $protocol://localhost:$NOVNC_PORT
ttyd (Terminal):  $protocol://localhost:$TTYD_PORT

Username: $TTYD_USERNAME
Password: $TTYD_PASSWD

==========================================

EOF
}
