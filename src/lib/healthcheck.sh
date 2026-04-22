#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# HEALTHCHECK MODULE
# ============================================================================

# Healthcheck Configuration
export HEALTHCHECK_ENABLED="${HEALTHCHECK_ENABLED:-true}"
export HEALTHCHECK_INTERVAL="${HEALTHCHECK_INTERVAL:-30}"

# Check if service is running on port
# Arguments:
#   $1 - Port to check
#   $2 - Service name
check_service_port() {
    local port="$1"
    local service="$2"
    
    if lsof -i :"$port" >/dev/null 2>&1; then
        log "green" "$service is running on port $port" "✅"
        return 0
    else
        log "red" "$service is NOT running on port $port" "❌"
        return 1
    fi
}

# Check if process is running
# Arguments:
#   $1 - Process name
check_process() {
    local process="$1"
    
    if pgrep -f "$process" >/dev/null 2>&1; then
        log "green" "$process is running" "✅"
        return 0
    else
        log "red" "$process is NOT running" "❌"
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
    check_service_port "$VNC_PORT" "VNC Server"
    check_process "Xtigervnc"
}

# Check temporary user
check_temp_user() {
    if id "$TEMP_USER" &>/dev/null; then
        log "green" "Temporary user $TEMP_USER exists" "✅"
        return 0
    else
        log "red" "Temporary user $TEMP_USER does NOT exist" "❌"
        return 1
    fi
}

# Check SSL certificate
check_ssl_cert() {
    if [[ -z "$DUCK_DOMAIN" ]]; then
        log "yellow" "SSL not configured (no domain)" "⚠️"
        return 0
    fi
    
    if [[ -f "$SSL_CERT" ]]; then
        local expiry_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s)
        local current_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if (( days_left > 30 )); then
            log "green" "SSL certificate valid for $days_left days" "✅"
            return 0
        elif (( days_left > 0 )); then
            log "yellow" "SSL certificate expires in $days_left days" "⚠️"
            return 0
        else
            log "red" "SSL certificate expired" "❌"
            return 1
        fi
    else
        log "red" "SSL certificate not found" "❌"
        return 1
    fi
}

# Run all health checks
run_healthcheck() {
    local errors=0
    
    log "cyan" "Running health checks..." "🏥"
    
    # Check services
    check_novnc || errors=$((errors + 1))
    check_ttyd || errors=$((errors + 1))
    check_vnc || errors=$((errors + 1))
    
    # Check user
    check_temp_user || errors=$((errors + 1))
    
    # Check SSL
    check_ssl_cert || errors=$((errors + 1))
    
    if (( errors == 0 )); then
        log "green" "All health checks passed" "✅"
        return 0
    else
        log "red" "Health checks failed with $errors error(s)" "❌"
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
        log "yellow" "Attempting to restart $service..." "🔄"
        
        case "$service" in
            "noVNC")
                if start_novnc; then
                    log "green" "$service restarted successfully" "✅"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service" "❌"
                    notify_service_failure "$service"
                fi
                ;;
            "ttyd")
                if start_ttyd; then
                    log "green" "$service restarted successfully" "✅"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service" "❌"
                    notify_service_failure "$service"
                fi
                ;;
            "VNC Server")
                if start_vnc_server; then
                    log "green" "$service restarted successfully" "✅"
                    notify_service_start "$service"
                else
                    log "red" "Failed to restart $service" "❌"
                    notify_service_failure "$service"
                fi
                ;;
            *)
                log "red" "Unknown service: $service" "❌"
                ;;
        esac
    fi
}

# Auto-restart all services
auto_restart_all() {
    log "cyan" "Checking and restarting services..." "🔄"
    
    auto_restart_service "noVNC" "$NOVNC_PORT" "start_novnc"
    auto_restart_service "ttyd" "$TTYD_PORT" "start_ttyd"
    auto_restart_service "VNC Server" "$VNC_PORT" "start_vnc_server"
}

# Continuous health monitoring
start_health_monitor() {
    [[ "$HEALTHCHECK_ENABLED" != "true" ]] && return
    
    log "cyan" "Starting health monitor (interval: ${HEALTHCHECK_INTERVAL}s)..." "🏥"
    
    while true; do
        run_healthcheck
        
        # Auto-restart if enabled
        if [[ "$AUTO_RESTART" == "true" ]]; then
            auto_restart_all
        fi
        
        sleep "$HEALTHCHECK_INTERVAL"
    done
}
