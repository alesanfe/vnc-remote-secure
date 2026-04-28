#!/bin/bash
# shellcheck disable=SC2155,SC2034
set -e
set -o pipefail
# ============================================================================
# HEALTH WEB SERVER
# ============================================================================

# Health web server configuration
export HEALTH_WEB_ENABLED="${HEALTH_WEB_ENABLED:-true}"
export HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8080}"

# Source required modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")"))")"
LIB_DIR="$(dirname "$SCRIPT_DIR")"

# Load environment and modules
if [[ -f "$PROJECT_DIR/.env" ]]; then
    source "$PROJECT_DIR/.env"
fi

# Load modules with error handling
load_module() {
    local module_file="$LIB_DIR/$1"
    if [[ -f "$module_file" ]]; then
        source "$module_file"
    else
        echo "Warning: Module $1 not found at $module_file"
        return 1
    fi
}

load_module "core/config.sh"
load_module "core/utils.sh"
load_module "monitoring/healthcheck.sh"

# Generate HTML health status
generate_health_html() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local uptime=$(uptime -p 2>/dev/null || echo "Unknown")
    
    # Get system info
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local os=$(lsb_release -d 2>/dev/null | cut -f2 || uname -s)
    
    # Run health checks and capture output
    local temp_file=$(mktemp)
    run_healthcheck > "$temp_file" 2>&1
    
    # Parse health check output and convert to HTML
    local service_status_html=""
    local in_service_section=false
    local in_user_section=false
    local in_ssl_section=false
    local in_resources_section=false
    local in_summary_section=false
    
    while IFS= read -r line; do
        if [[ "$line" == *"SERVICE STATUS"* ]]; then
            in_service_section=true
            continue
        elif [[ "$line" == *"USER & AUTHENTICATION"* ]]; then
            in_service_section=false
            in_user_section=true
            continue
        elif [[ "$line" == *"SSL CERTIFICATE"* ]]; then
            in_user_section=false
            in_ssl_section=true
            continue
        elif [[ "$line" == *"SYSTEM RESOURCES"* ]]; then
            in_ssl_section=false
            in_resources_section=true
            continue
        elif [[ "$line" == *"HEALTH SUMMARY"* ]]; then
            in_resources_section=false
            in_summary_section=true
            continue
        fi
        
        # Skip separator lines
        if [[ "$line" == *"=="* ]]; then
            continue
        fi
        
        # Process status lines
        if [[ "$line" == *"OK:"* ]] || [[ "$line" == *"running"* ]]; then
            local service=$(echo "$line" | sed 's/OK:.*//g' | sed 's/running.*//g' | xargs)
            local details=$(echo "$line" | grep -o "OK:.*" | grep -o "running.*" | xargs)
            local icon="fas fa-check-circle"
            service_status_html+="            <div class=\"status-item\">\n"
            service_status_html+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            service_status_html+="                <span class=\"status-value status-ok\">OK: $details</span>\n"
            service_status_html+="            </div>\n"
        elif [[ "$line" == *"ERROR:"* ]] || [[ "$line" == *"NOT running"* ]]; then
            local service=$(echo "$line" | sed 's/ERROR:.*//g' | sed 's/NOT running.*//g' | xargs)
            local details=$(echo "$line" | grep -o "ERROR:.*" | grep -o "NOT running.*" | xargs)
            local icon="fas fa-times-circle"
            service_status_html+="            <div class=\"status-item\">\n"
            service_status_html+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            service_status_html+="                <span class=\"status-value status-error\">ERROR: $details</span>\n"
            service_status_html+="            </div>\n"
        elif [[ "$line" == *"WARNING:"* ]]; then
            local service=$(echo "$line" | sed 's/WARNING:.*//g' | xargs)
            local details=$(echo "$line" | sed 's/.*WARNING://g' | xargs)
            local icon="fas fa-exclamation-triangle"
            service_status_html+="            <div class=\"status-item\">\n"
            service_status_html+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            service_status_html+="                <span class=\"status-value status-warning\">WARNING: $details</span>\n"
            service_status_html+="            </div>\n"
        fi
    done < "$temp_file"
    
    rm -f "$temp_file"
    
    # Process template with environment variables
    local template_file="$PROJECT_DIR/src/templates/health.html"
    
    if [[ -f "$template_file" ]]; then
        # Set environment variables for template substitution
        export HOSTNAME="$hostname"
        export OS="$os"
        export KERNEL="$kernel"
        export UPTIME="$uptime"
        export TIMESTAMP="$timestamp"
        export SERVICE_STATUS="$service_status_html"
        
        # Process template
        envsubst < "$template_file"
    else
        log "red" "Health HTML template not found at $template_file"
        return 1
    fi
}

# Start health web server
start_health_web_server() {
    [[ "$HEALTH_WEB_ENABLED" != "true" ]] && return
    
    log "cyan" "Starting health web server on port $HEALTH_WEB_PORT..."
    
    # Kill existing web server if running
    pkill -f "python3.*$HEALTH_WEB_PORT" 2>/dev/null || true
    sleep 1
    
    # Start Python web server from separate file
    cd "$PROJECT_DIR"
    python3 src/lib/monitoring/health_web_server.py &
    
    local web_pid=$!
    echo "$web_pid" > /tmp/health_web_server.pid
    
    sleep 2
    
    if kill -0 "$web_pid" 2>/dev/null; then
        log "green" "Health web server started successfully (PID: $web_pid)"
    else
        log "red" "Failed to start health web server"
        return 1
    fi
}

# Stop health web server
stop_health_web_server() {
    if [[ -f "/tmp/health_web_server.pid" ]]; then
        local pid=$(cat /tmp/health_web_server.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "yellow" "Stopping health web server (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f /tmp/health_web_server.pid
    fi
    
    # Kill any remaining processes
    pkill -f "python3.*$HEALTH_WEB_PORT" 2>/dev/null || true
}

# Check if web server is running
check_health_web_server() {
    if [[ -f "/tmp/health_web_server.pid" ]]; then
        local pid=$(cat /tmp/health_web_server.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "green" "Health web server is running (PID: $pid)"
            return 0
        else
            log "red" "Health web server PID file exists but process not running"
            rm -f /tmp/health_web_server.pid
            return 1
        fi
    else
        log "blue" "Health web server is not running"
        return 1
    fi
}

# Handle command line arguments
case "${1:-start}" in
    start)
        start_health_web_server
        ;;
    stop)
        stop_health_web_server
        ;;
    restart)
        stop_health_web_server
        sleep 1
        start_health_web_server
        ;;
    status)
        check_health_web_server
        ;;
    generate_html)
        generate_health_html
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|generate_html}"
        exit 1
        ;;
esac
