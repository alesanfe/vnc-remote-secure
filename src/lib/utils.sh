#!/bin/bash
# shellcheck disable=SC2034,SC2155,SC2086,SC2181
set -e
set -o pipefail
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
        ["yellow"]="\033[1;33m"
        ["blue"]="\033[0;34m"
        ["purple"]="\033[0;35m"
        ["cyan"]="\033[0;36m"
        ["white"]="\033[0;37m"
        ["bright"]="\033[1;37m"
        ["reset"]="\033[0m"
    )

    local color="${colors[$level]:-${colors[reset]}}"
    local timestamp=""
    [[ "$VERBOSE" == "true" ]] && timestamp="[$(date '+%H:%M:%S')] "

    echo -e "${color}${timestamp}${emoji} ${message}${colors[reset]}"
}

print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    local line=""

    for ((i=0; i<width; i++)); do
        line+="═"
    done

    echo -e "\033[1;36m${line}\033[0m"
    printf "\033[1;36m%*s%s%*s\033[0m\n" $padding "" "$title" $padding ""
    echo -e "\033[1;36m${line}\033[0m"
}

print_section() {
    local title="$1"
    echo ""
    echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[1;34m  ${title}\033[0m"
    echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

print_separator() {
    echo -e "\033[0;90m────────────────────────────────────────────────────────────\033[0m"
}

print_step() {
    local step="$1"
    local total="$2"
    local message="$3"
    echo -e "\033[1;33m[Step ${step}/${total}] ${message}\033[0m"
}

print_progress() {
    local current="$1"
    local total="$2"
    local message="$3"
    local percent=$(( current * 100 / total ))
    local filled=$(( percent / 2 ))
    local empty=$(( 50 - filled ))

    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    echo -e "\033[0;36m${message}\033[0m"
    echo -e "\033[0;36m[${bar}] ${percent}%\033[0m"
}

die() {
    echo ""
    echo -e "\033[1;41m  ❌ ERROR: $1 \033[0m"
    echo ""
    exit 1
}

warn() {
    log "yellow" "$1" "⚠️"
}

info() {
    log "blue" "$1" "ℹ️"
}

success() {
    log "green" "$1"
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
    
    # Send notification if Discord enabled
    if [[ "$DISCORD_ENABLED" == "true" ]]; then
        notify_cleanup_complete
    fi
    
    # Send alert if alerts enabled
    if [[ "$ALERTS_ENABLED" == "true" ]]; then
        alert_cleanup
    fi
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

# Validate password strength
# Arguments:
#   $1 - Password to validate
# Returns:
#   0 if password is strong, 1 otherwise
validate_password_strength() {
    local password="$1"
    local min_length=8
    
    if [[ ${#password} -lt $min_length ]]; then
        return 1
    fi
    
    if [[ "$password" == "changeme" ]]; then
        return 1
    fi
    
    # Check for at least one uppercase, one lowercase, one digit
    if ! [[ "$password" =~ [A-Z] ]] || ! [[ "$password" =~ [a-z] ]] || ! [[ "$password" =~ [0-9] ]]; then
        return 1
    fi
    
    return 0
}

# Validate port number
# Arguments:
#   $1 - Port number to validate
# Returns:
#   0 if valid, 1 otherwise
validate_port() {
    local port="$1"
    
    # Check if numeric
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # Check if in valid range (1-65535)
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    
    return 0
}

# Validate domain name format
# Arguments:
#   $1 - Domain to validate
# Returns:
#   0 if valid or empty, 1 otherwise
validate_domain() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        return 0  # Empty is valid (SSL disabled)
    fi
    
    # Basic domain validation
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])+$ ]]; then
        return 1
    fi
    
    return 0
}

# Check if port is available (not in use)
# Arguments:
#   $1 - Port to check
# Returns:
#   0 if available, 1 if in use
check_port_available() {
    local port="$1"
    
    if lsof -i :"$port" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Validate configuration
# Arguments: None
# Returns:
#   0 if all configuration is valid, 1 if validation fails
# Globals:
#   TTYD_PASSWD, NOVNC_PORT, TTYD_PORT, VNC_PORT, DUCK_DOMAIN
validate_config() {
    local errors=0
    
    # Validate password strength
    if ! validate_password_strength "$TTYD_PASSWD"; then
        log "red" "TTYD_PASSWD must be at least 8 characters and contain uppercase, lowercase, and digits. Cannot be 'changeme'." "❌"
        errors=$((errors + 1))
    fi
    
    # Validate ports
    if ! validate_port "$NOVNC_PORT"; then
        log "red" "NOVNC_PORT must be a valid port number (1-65535)" "❌"
        errors=$((errors + 1))
    fi
    
    if ! validate_port "$TTYD_PORT"; then
        log "red" "TTYD_PORT must be a valid port number (1-65535)" "❌"
        errors=$((errors + 1))
    fi
    
    if ! validate_port "$VNC_PORT"; then
        log "red" "VNC_PORT must be a valid port number (1-65535)" "❌"
        errors=$((errors + 1))
    fi
    
    # Validate domain
    if ! validate_domain "$DUCK_DOMAIN"; then
        log "red" "DUCK_DOMAIN must be a valid domain name" "❌"
        errors=$((errors + 1))
    fi
    
    # Check port availability
    if ! check_port_available "$NOVNC_PORT"; then
        log "red" "Port $NOVNC_PORT is already in use" "❌"
        errors=$((errors + 1))
    fi
    
    if ! check_port_available "$TTYD_PORT"; then
        log "red" "Port $TTYD_PORT is already in use" "❌"
        errors=$((errors + 1))
    fi
    
    if ! check_port_available "$VNC_PORT"; then
        log "red" "Port $VNC_PORT is already in use" "❌"
        errors=$((errors + 1))
    fi
    
    if (( errors > 0 )); then
        log "red" "Configuration validation failed with $errors error(s)" "❌"
        return 1
    fi
    
    return 0
}

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

install_dependencies() {
    log "yellow" "Installing required packages..." "⚙️"

    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq > /dev/null 2>&1
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        wget iproute2 lsof tigervnc-standalone-server novnc \
        xfce4 xfce4-goodies x11-xserver-utils certbot \
        python3-certbot-dns-standalone acl > /dev/null 2>&1

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
    echo ""
    echo -e "\033[1;36m══════════════════════════════════════════════════════════════════════════\033[0m"
    echo -e "\033[1;33m   🖥️  Raspberry Pi VNC Remote Setup - Secure Remote Access\033[0m"
    echo -e "\033[1;36m══════════════════════════════════════════════════════════════════════════\033[0m"
    echo ""
}

print_access_info() {
    local protocol="http"
    [[ "$DISABLE_SSL" == false ]] && protocol="https"

    echo ""
    echo -e "\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m"
    echo -e "\033[1;36m║\033[1;33m                    🌐 ACCESS INFORMATION 🌐                  \033[1;36m║\033[0m"
    echo -e "\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m"
    echo ""
    echo -e "\033[1;34m  📺 Desktop Access (noVNC):\033[0m"
    echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}:${NOVNC_PORT}\033[0m"
    echo ""
    echo -e "\033[1;34m  💻 Terminal Access (ttyd):\033[0m"
    echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}:${TTYD_PORT}\033[0m"
    echo ""
    echo -e "\033[1;34m  👤 Username:\033[0m \033[1;33m$TTYD_USERNAME\033[0m"
    echo -e "\033[1;34m  🔑 Password:\033[0m \033[1;33m$TTYD_PASSWD\033[0m"
    echo ""
    if [[ "$DISABLE_SSL" == true ]]; then
        echo -e "\033[1;33m  ⚠️  SSL is disabled. For production, set DUCK_DOMAIN.\033[0m"
    fi
    echo ""
}

# ============================================================================
# LOG VIEWING
# ============================================================================

show_logs() {
    if [[ "$SHOW_LOGS" != "true" ]]; then
        log "yellow" "Log viewing is disabled. Set SHOW_LOGS=true to enable." "📝"
        wait
        return
    fi

    log "blue" "Monitoring service logs (Press CTRL+C to stop)..." "📋"
    echo ""

    # Create a combined log viewer
    if command -v multitail &>/dev/null; then
        # Use multitail if available for better viewing
        multitail "$LOG_DIR/ttyd.log" "$LOG_DIR/novnc.log" "$LOG_DIR/vnc.log"
    elif command -v tail &>/dev/null; then
        # Use tail to follow all logs
        tail -f "$LOG_DIR"/*.log 2>/dev/null || {
            log "yellow" "No log files found yet. Waiting for logs..." "⏳"
            sleep 5
            tail -f "$LOG_DIR"/*.log 2>/dev/null || wait
        }
    else
        # Fallback to just wait
        log "yellow" "tail command not available. Using wait..." "⏳"
        wait
    fi
}
