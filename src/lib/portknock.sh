#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# PORT KNOCKING MODULE
# ============================================================================

# Port Knocking Configuration
export PORT_KNOCK_ENABLED="${PORT_KNOCK_ENABLED:-false}"
export PORT_KNOCK_SEQUENCE="${PORT_KNOCK_SEQUENCE:-1000,2000,3000}"
export PORT_KNOCK_TIMEOUT="${PORT_KNOCK_TIMEOUT:-5}"
export PORT_KNOCK_METHOD="${PORT_KNOCK_METHOD:-iptables}"
export PORT_KNOCK_INTERFACE="${PORT_KNOCK_INTERFACE:-eth0}"

# Install knockd
install_knockd() {
    [[ "$PORT_KNOCK_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing knockd..." "⚙️"
    
    if ! command -v knockd &>/dev/null; then
        sudo apt update
        sudo apt install -y knockd
    fi
    
    success "knockd installed."
}

# Configure knockd
configure_knockd() {
    [[ "$PORT_KNOCK_ENABLED" != "true" ]] && return
    
    log "yellow" "Configuring knockd..." "⚙️"
    
    # Create knockd configuration
    sudo tee /etc/knockd.conf > /dev/null <<EOF
[options]
    UseSyslog
    Interface = $PORT_KNOCK_INTERFACE

[openVNC]
    sequence    = $PORT_KNOCK_SEQUENCE
    seq_timeout = $PORT_KNOCK_TIMEOUT
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport $NOVNC_PORT -j ACCEPT && /sbin/iptables -A INPUT -s %IP% -p tcp --dport $TTYD_PORT -j ACCEPT && /sbin/iptables -A INPUT -s %IP% -p tcp --dport $VNC_PORT -j ACCEPT
    tcpflags    = syn

[closeVNC]
    sequence    = 3000,2000,1000
    seq_timeout = $PORT_KNOCK_TIMEOUT
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport $NOVNC_PORT -j ACCEPT && /sbin/iptables -D INPUT -s %IP% -p tcp --dport $TTYD_PORT -j ACCEPT && /sbin/iptables -D INPUT -s %IP% -p tcp --dport $VNC_PORT -j ACCEPT
    tcpflags    = syn
EOF
    
    # Enable knockd
    sudo sed -i 's/^START_KNOCKD=0/START_KNOCKD=1/' /etc/default/knockd
    
    success "knockd configured."
}

# Start knockd
start_knockd() {
    [[ "$PORT_KNOCK_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting knockd..." "🚀"
    
    sudo systemctl enable knockd
    sudo systemctl start knockd
    
    success "knockd started."
}

# Stop knockd
stop_knockd() {
    [[ "$PORT_KNOCK_ENABLED" != "true" ]] && return
    
    log "yellow" "Stopping knockd..." "🛑"
    
    sudo systemctl stop knockd
    
    success "knockd stopped."
}

# Knock to open ports
# Arguments:
#   $1 - Target IP (default: localhost)
#   $2 - Knock sequence (default: from config)
knock_open() {
    local target="${1:-localhost}"
    local sequence="${2:-$PORT_KNOCK_SEQUENCE}"
    
    log "yellow" "Knocking to open ports on $target..." "🚪"
    
    IFS=',' read -ra ports <<< "$sequence"
    for port in "${ports[@]}"; do
        if command -v knock &>/dev/null; then
            knock "$target" "$port"
        else
            # Fallback using nmap or nc
            nc -z -w 1 "$target" "$port" 2>/dev/null || true
        fi
        sleep 0.5
    done
    
    success "Ports should be open now."
}

# Knock to close ports
knock_close() {
    local target="${1:-localhost}"
    local sequence="3000,2000,1000"
    
    log "yellow" "Knocking to close ports on $target..." "🔒"
    
    IFS=',' read -ra ports <<< "$sequence"
    for port in "${ports[@]}"; do
        if command -v knock &>/dev/null; then
            knock "$target" "$port"
        else
            nc -z -w 1 "$target" "$port" 2>/dev/null || true
        fi
        sleep 0.5
    done
    
    success "Ports should be closed now."
}

# Setup iptables rules for port knocking
setup_port_knocking_firewall() {
    [[ "$PORT_KNOCK_ENABLED" != "true" ]] && return
    
    log "yellow" "Setting up firewall rules for port knocking..." "🔒"
    
    # Block VNC ports by default
    sudo iptables -A INPUT -p tcp --dport "$NOVNC_PORT" -j DROP
    sudo iptables -A INPUT -p tcp --dport "$TTYD_PORT" -j DROP
    sudo iptables -A INPUT -p tcp --dport "$VNC_PORT" -j DROP
    
    # Allow established connections
    sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (don't block yourself out)
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    success "Firewall rules configured for port knocking."
}
