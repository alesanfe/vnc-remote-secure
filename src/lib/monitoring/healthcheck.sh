#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# HEALTHCHECK MODULE
# ============================================================================

# Healthcheck Configuration
export HEALTHCHECK_ENABLED="${HEALTHCHECK_ENABLED:-true}"
export HEALTHCHECK_INTERVAL="${HEALTHCHECK_INTERVAL:-15}"

# Check if service is running on port
# Arguments:
#   $1 - Port to check
#   $2 - Service name
check_service_port() {
    local port="$1"
    local service="$2"
    local pid=""
    local process_name=""
    local listening_address=""
    
    # Use ss to check if anything is listening on the port (more reliable than lsof)
    local port_info=$(ss -tlnp | grep ":$port ")
    
    if [[ -n "$port_info" ]]; then
        # Extract PID from ss output
        pid=$(echo "$port_info" | grep -o 'pid=[0-9]*' | cut -d= -f2 | head -1)
        
        if [[ -n "$pid" ]]; then
            process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
        fi
        
        # Extract listening address
        listening_address=$(echo "$port_info" | awk '{print $4}' | head -1)
        
        # Check if service is listening on localhost (when nginx is enabled)
        if [[ "$NGINX_ENABLED" == "true" ]]; then
            if [[ "$listening_address" == *"127.0.0.1"* ]]; then
                log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: 127.0.0.1 - nginx mode)"
            else
                log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: $listening_address)"
            fi
        else
            # Check all interfaces when nginx is disabled
            log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: $listening_address)"
        fi
        return 0
    else
        # Fallback: try lsof if ss doesn't find it
        local lsof_info=$(lsof -i :"$port" 2>/dev/null)
        if [[ -n "$lsof_info" ]]; then
            pid=$(lsof -ti :"$port" 2>/dev/null)
            process_name=$(ps -p "$pid" -o comm= 2>/dev/null)
            listening_address=$(echo "$lsof_info" | grep LISTEN | awk '{print $8}' | head -1)
            
            if [[ "$NGINX_ENABLED" == "true" ]]; then
                if [[ "$listening_address" == *"127.0.0.1"* ]]; then
                    log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: 127.0.0.1 - nginx mode)"
                else
                    log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: $listening_address)"
                fi
            else
                log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: $listening_address)"
            fi
            return 0
        else
            log "red" "$service NOT running on port $port"
            # Show what's actually running
            log "blue" "Checking all listening ports..."
            local all_ports=$(ss -tlnp | head -5)
            if [[ -n "$all_ports" ]]; then
                log "blue" "Currently listening ports:"
                echo "$all_ports" | while IFS= read -r line; do
                    log "blue" "  $line"
                done
            else
                log "blue" "No listening ports found"
            fi
            return 1
        fi
    fi
}

# Check if process is running
# Arguments:
#   $1 - Process name
check_process() {
    local process="$1"
    local pids=$(pgrep -f "$process" 2>/dev/null)
    local pid_count=$(echo "$pids" | wc -l)
    
    if pgrep -f "$process" >/dev/null 2>&1; then
        log "green" "$process running ($pid_count instances, PIDs: $pids)"
        return 0
    else
        log "red" "$process NOT running"
        return 1
    fi
}

# Check noVNC service
check_novnc() {
    check_service_port "$NOVNC_PORT" "noVNC"
}

# Check ttyd service
check_ttyd() {
    check_service_port "$TTYD_PORT" "ttyd"
}

# Check VNC server
check_vnc() {
    # Use the same check_service_port function for consistency
    check_service_port "$VNC_PORT" "VNC Server"
    
    # Always check for Xtigervnc processes
    check_process "Xtigervnc"
}

# Check temporary user
check_temp_user() {
    if id "$TEMP_USER" &>/dev/null; then
        local user_id=$(id -u "$TEMP_USER" 2>/dev/null)
        local user_gid=$(id -g "$TEMP_USER" 2>/dev/null)
        local user_home=$(getent passwd "$TEMP_USER" 2>/dev/null | cut -d: -f6)
        local user_shell=$(getent passwd "$TEMP_USER" 2>/dev/null | cut -d: -f7)
        local user_groups=$(groups "$TEMP_USER" 2>/dev/null | cut -d: -f2)
        
        log "green" "User $TEMP_USER exists (UID: $user_id, GID: $user_gid, Home: $user_home, Shell: $user_shell, Groups: $user_groups)"
        return 0
    else
        log "red" "Temporary user $TEMP_USER does NOT exist"
        return 1
    fi
}

# Check SSL certificate
check_ssl_cert() {
    if [[ -z "$DUCK_DOMAIN" ]]; then
        log "yellow" "SSL not configured (no domain)"
        return 0
    fi
    
    if [[ -f "$SSL_CERT" ]]; then
        local expiry_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        local issue_date=$(openssl x509 -startdate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        local subject=$(openssl x509 -subject -noout -in "$SSL_CERT" 2>/dev/null | sed 's/subject=//')
        local issuer=$(openssl x509 -issuer -noout -in "$SSL_CERT" 2>/dev/null | sed 's/issuer=//')
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        local cert_serial=$(openssl x509 -serial -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        
        if (( days_left > 30 )); then
            log "green" "SSL: Valid $days_left days | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 0
        elif (( days_left > 0 )); then
            log "yellow" "SSL: Expires in $days_left days | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 0
        else
            log "red" "SSL: EXPIRED | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 1
        fi
    else
        log "red" "SSL certificate not found for domain: $DUCK_DOMAIN"
        return 1
    fi
}

# Check system memory usage
check_memory() {
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_free=$(free -m | awk '/Mem:/ {print $4}')
    local mem_available=$(free -m | awk '/Mem:/ {print $7}')
    local mem_percent=$(( mem_used * 100 / mem_total ))
    local mem_cached=$(free -m | awk '/Mem:/ {print $6}')
    local mem_swap_total=$(free -m | awk '/Swap:/ {print $2}')
    local mem_swap_used=$(free -m | awk '/Swap:/ {print $3}')
    
    if (( mem_percent < 80 )); then
        log "green" "Memory: ${mem_percent}% (${mem_used}MB/${mem_total}MB) | Free: ${mem_free}MB | Available: ${mem_available}MB | Cached: ${mem_cached}MB | Swap: ${mem_swap_used}MB/${mem_swap_total}MB"
        return 0
    elif (( mem_percent < 90 )); then
        log "yellow" "Memory: ${mem_percent}% (${mem_used}MB/${mem_total}MB) | Free: ${mem_free}MB | Available: ${mem_available}MB | Cached: ${mem_cached}MB | Swap: ${mem_swap_used}MB/${mem_swap_total}MB"
        return 0
    else
        log "red" "Memory: ${mem_percent}% (${mem_used}MB/${mem_total}MB) | Free: ${mem_free}MB | Available: ${mem_available}MB | Cached: ${mem_cached}MB | Swap: ${mem_swap_used}MB/${mem_swap_total}MB"
        return 1
    fi
}

# Check CPU usage
check_cpu() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local cpu_int=${cpu_usage%.*}
    local cpu_idle=$(top -bn1 | grep "Cpu(s)" | awk '{print $8}' | cut -d'%' -f1)
    local cpu_load_1min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    local cpu_load_5min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $2}' | tr -d ',')
    local cpu_load_15min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $3}' | tr -d ',')
    local cpu_cores=$(nproc)
    
    if (( cpu_int < 70 )); then
        log "green" "CPU: ${cpu_usage}% | Idle: ${cpu_idle}% | Load: ${cpu_load_1min}/${cpu_load_5min}/${cpu_load_15min} | Cores: ${cpu_cores}"
        return 0
    elif (( cpu_int < 90 )); then
        log "yellow" "CPU: ${cpu_usage}% | Idle: ${cpu_idle}% | Load: ${cpu_load_1min}/${cpu_load_5min}/${cpu_load_15min} | Cores: ${cpu_cores}"
        return 0
    else
        log "red" "CPU: ${cpu_usage}% | Idle: ${cpu_idle}% | Load: ${cpu_load_1min}/${cpu_load_5min}/${cpu_load_15min} | Cores: ${cpu_cores}"
        return 1
    fi
}

# Check disk usage
check_disk() {
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
    local disk_int=${disk_usage%.*}
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')
    local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_free=$(df -h / | awk 'NR==2 {print $4}')
    local disk_inodes_total=$(df -i / | awk 'NR==2 {print $2}')
    local disk_inodes_used=$(df -i / | awk 'NR==2 {print $3}')
    local disk_inodes_percent=$(( disk_inodes_used * 100 / disk_inodes_total ))
    
    if (( disk_int < 80 )); then
        log "green" "Disk: ${disk_usage} (${disk_used}/${disk_total}) | Free: ${disk_free} | Inodes: ${disk_inodes_percent}% (${disk_inodes_used}/${disk_inodes_total})"
        return 0
    elif (( disk_int < 90 )); then
        log "yellow" "Disk: ${disk_usage} (${disk_used}/${disk_total}) | Free: ${disk_free} | Inodes: ${disk_inodes_percent}% (${disk_inodes_used}/${disk_inodes_total})"
        return 0
    else
        log "red" "Disk: ${disk_usage} (${disk_used}/${disk_total}) | Free: ${disk_free} | Inodes: ${disk_inodes_percent}% (${disk_inodes_used}/${disk_inodes_total})"
        return 1
    fi
}

# Run all health checks
run_healthcheck() {
    local errors=0
    
    echo "SERVICE STATUS"
    echo "================================"
    # Check services
    check_novnc || errors=$((errors + 1))
    check_ttyd || errors=$((errors + 1))
    check_vnc || errors=$((errors + 1))
    echo ""
    
    echo "USER & AUTHENTICATION"
    echo "================================"
    # Check user
    check_temp_user || errors=$((errors + 1))
    echo ""
    
    echo "SSL CERTIFICATE"
    echo "================================"
    # Check SSL
    check_ssl_cert || errors=$((errors + 1))
    echo ""
    
    echo "SYSTEM RESOURCES"
    echo "================================"
    # Check system resources
    check_memory || errors=$((errors + 1))
    check_cpu || errors=$((errors + 1))
    check_disk || errors=$((errors + 1))
    echo ""
    
    echo "HEALTH SUMMARY"
    echo "================================"
    if (( errors == 0 )); then
        log "green" "All health checks passed - System healthy"
        return 0
    else
        log "red" "Health checks failed with $errors error(s)"
        return 1
    fi
}

# Auto-restart failed services
# Arguments:
#   $1 - Service name
#   $2 - Port to check
auto_restart_service() {
    local service="$1"
    local port="$2"
    
    if ! lsof -i :"$port" >/dev/null 2>&1; then
        log "yellow" "Attempting to restart $service..."
        
        case "$service" in
            "noVNC")
                if start_novnc; then
                    log "green" "$service restarted successfully"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service"
                    notify_service_failure "$service"
                fi
                ;;
            "ttyd")
                if start_ttyd; then
                    log "green" "$service restarted successfully"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service"
                    notify_service_failure "$service"
                fi
                ;;
            "VNC Server")
                if start_vnc_server; then
                    log "green" "$service restarted successfully"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service"
                    notify_service_failure "$service"
                fi
                ;;
            *)
                log "red" "Unknown service: $service"
                ;;
        esac
    fi
}

# Auto-restart all services
auto_restart_all() {
    log "cyan" "Checking and restarting services..."
    
    auto_restart_service "noVNC" "$NOVNC_PORT" "start_novnc"
    auto_restart_service "ttyd" "$TTYD_PORT" "start_ttyd"
    auto_restart_service "VNC Server" "$VNC_PORT" "start_vnc_server"
}

# Continuous health monitoring
start_health_monitor() {
    [[ "$HEALTHCHECK_ENABLED" != "true" ]] && return
    
    log "cyan" "CONTINUOUS HEALTH MONITORING STARTED"
    log "cyan" "   Interval: ${HEALTHCHECK_INTERVAL} seconds"
    log "cyan" "   Press CTRL+C to stop monitoring"
    echo ""
    
    while true; do
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                    HEALTH MONITOR - $(date '+%Y-%m-%d %H:%M:%S')                    ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        run_healthcheck
        
        # Auto-restart if enabled
        if [[ "$AUTO_RESTART" == "true" ]]; then
            echo ""
            log "yellow" "Checking for service restarts..."
            auto_restart_all
        fi
        
        # Show next check time with countdown
        local next_check=$(date -d "+${HEALTHCHECK_INTERVAL} seconds" '+%H:%M:%S')
        echo ""
        echo "┌─────────────────────────────────────────────────────────────────────────────┐"
        echo "│  Next health check at: $next_check                                    │"
        echo "└─────────────────────────────────────────────────────────────────────────────┘"
        echo ""
        
        sleep "$HEALTHCHECK_INTERVAL"
    done
}
