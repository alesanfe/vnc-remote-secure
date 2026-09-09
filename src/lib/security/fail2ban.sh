#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# FAIL2BAN MODULE
# ============================================================================
# Configuration is centralized in core/config.sh (single source of truth).

# Install Fail2ban
install_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return

    log "yellow" "Installing Fail2ban..."

    if ! command -v fail2ban-server &>/dev/null; then
        sudo apt update
        sudo apt install -y fail2ban
    fi

    success "Fail2ban installed."
}

# Configure Fail2ban for VNC services
configure_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return

    log "yellow" "Configuring Fail2ban..."

    # Ensure log directory exists for fail2ban to monitor
    local log_dir="${LOG_DIR:-./logs}"
    mkdir -p "$log_dir" 2>/dev/null || true

    # Back up existing config if present
    if [[ -f /etc/fail2ban/jail.d/vnc-remote.local ]]; then
        local backup_suffix
        backup_suffix=$(date +%s)
        sudo cp /etc/fail2ban/jail.d/vnc-remote.local "/etc/fail2ban/jail.d/vnc-remote.local.bak.$backup_suffix" 2>/dev/null || true
    fi

    # Create jail configuration pointing at actual application logs
    sudo tee /etc/fail2ban/jail.d/vnc-remote.local > /dev/null <<EOF
[vnc-remote-novnc]
enabled = true
port = $NOVNC_PORT
filter = vnc-remote
logpath = $log_dir/novnc.log
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME

[vnc-remote-ttyd]
enabled = true
port = $TTYD_PORT
filter = vnc-remote
logpath = $log_dir/ttyd.log
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME

[vnc-remote-vnc]
enabled = true
port = $VNC_PORT
filter = vnc-remote
logpath = $log_dir/vnc.log
maxretry = $FAIL2BAN_MAX_RETRY
findtime = $FAIL2BAN_FINDTIME
bantime = $FAIL2BAN_BANTIME
EOF

    # Create filter configuration with patterns matching actual service log formats
    sudo tee /etc/fail2ban/filter.d/vnc-remote.conf > /dev/null <<EOF
[Definition]
# ttyd authentication failures
failregex = ^.*ttyd.*(?:failed|invalid|denied|unauthorized).*from <HOST>
            ^.*authentication failed.*from <HOST>
            ^.*invalid (?:password|credentials|login).*from <HOST>
            ^.*access denied.*from <HOST>
            ^.*connection (?:refused|rejected).*from <HOST>
            ^.*<HOST>.*(?:failed|invalid|denied)
# noVNC/websockify connection errors
            ^.*websockify.*(?:error|reject).*<HOST>
# VNC server auth failures
            ^.*vnc.*(?:auth|fail|reject).*<HOST>
ignoreregex =
EOF

    # Restart Fail2ban
    sudo systemctl restart fail2ban || sudo fail2ban-client reload

    success "Fail2ban configured."
}

# Start Fail2ban
start_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return

    log "yellow" "Starting Fail2ban..."

    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    success "Fail2ban started."
}

# Stop Fail2ban
stop_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return

    log "yellow" "Stopping Fail2ban..."

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
