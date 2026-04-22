#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# FAIL2BAN MODULE
# ============================================================================

# Fail2ban Configuration
export FAIL2BAN_ENABLED="${FAIL2BAN_ENABLED:-false}"
export FAIL2BAN_MAX_RETRY="${FAIL2BAN_MAX_RETRY:-5}"
export FAIL2BAN_FINDTIME="${FAIL2BAN_FINDTIME:-600}"
export FAIL2BAN_BANTIME="${FAIL2BAN_BANTIME:-3600}"

# Install Fail2ban
install_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing Fail2ban..." "⚙️"
    
    if ! command -v fail2ban-server &>/dev/null; then
        sudo apt update
        sudo apt install -y fail2ban
    fi
    
    success "Fail2ban installed."
}

# Configure Fail2ban for VNC services
configure_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    log "yellow" "Configuring Fail2ban..." "⚙️"
    
    # Create jail configuration
    sudo tee /etc/fail2ban/jail.d/vnc-remote.local > /dev/null <<EOF
[vnc-remote-novnc]
enabled = true
port = $NOVNC_PORT
filter = vnc-remote
logpath = /var/log/syslog
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME

[vnc-remote-ttyd]
enabled = true
port = $TTYD_PORT
filter = vnc-remote
logpath = /var/log/syslog
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME

[vnc-remote-vnc]
enabled = true
port = $VNC_PORT
filter = vnc-remote
logpath = /var/log/syslog
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME
EOF
    
    # Create filter configuration
    sudo tee /etc/fail2ban/filter.d/vnc-remote.conf > /dev/null <<EOF
[Definition]
failregex = ^.*Failed password for .* from <HOST>
            ^.*Authentication failure for .* from <HOST>
            ^.*Invalid login attempt from <HOST>
ignoreregex =
EOF
    
    # Restart Fail2ban
    sudo systemctl restart fail2ban || sudo fail2ban-client reload
    
    success "Fail2ban configured."
}

# Start Fail2ban
start_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting Fail2ban..." "🚀"
    
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    
    success "Fail2ban started."
}

# Stop Fail2ban
stop_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    log "yellow" "Stopping Fail2ban..." "🛑"
    
    sudo systemctl stop fail2ban
    
    success "Fail2ban stopped."
}

# Check Fail2ban status
check_fail2ban_status() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    sudo fail2ban-client status vnc-remote-novnc
    sudo fail2ban-client status vnc-remote-ttyd
    sudo fail2ban-client status vnc-remote-vnc
}

# Unban IP
# Arguments:
#   $1 - IP address to unban
unban_ip() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    
    local ip="$1"
    
    log "yellow" "Unbanning IP: $ip" "🔓"
    
    sudo fail2ban-client set vnc-remote-novnc unbanip "$ip"
    sudo fail2ban-client set vnc-remote-ttyd unbanip "$ip"
    sudo fail2ban-client set vnc-remote-vnc unbanip "$ip"
    
    success "IP $ip unbanned."
}
