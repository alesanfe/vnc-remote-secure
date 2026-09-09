#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC1090,SC1091
# ============================================================================
# HEALTH WEB SERVER
# ============================================================================
# Configuration is centralized in core/config.sh (single source of truth).

# Source required modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"
LIB_DIR="$(dirname "$SCRIPT_DIR")"

# Load environment and modules
if [[ -f "$PROJECT_DIR/.env" ]]; then
    source "$PROJECT_DIR/.env"
fi

# Load modules with error handling (guarded to avoid re-sourcing when this
# file is sourced from the main entry point which already loaded them)
load_module() {
    local module_file="$LIB_DIR/$1"
    if [[ -f "$module_file" ]]; then
        source "$module_file"
    else
        echo "Warning: Module $1 not found at $module_file"
        return 1
    fi
}

# Only load modules when run standalone (not when sourced by the main script)
if [[ -z "${TTYD_PORT:-}" ]]; then
    load_module "core/config.sh"
    load_module "core/utils.sh"
    load_module "monitoring/healthcheck.sh"
fi

# Generate HTML health status
# Parse health check output file and convert service status lines to HTML.
# Arguments:
#   $1 - Path to the temporary file containing health check output
# Outputs:
#   Sets the global _SERVICE_STATUS_HTML variable
_parse_health_status_to_html() {
    local temp_file="$1"
    local line service details icon
    _SERVICE_STATUS_HTML=""

    while IFS= read -r line; do
        # Skip section headers and separator lines
        [[ "$line" == *"=="* ]] && continue
        [[ "$line" == *"SERVICE STATUS"* ]] && continue
        [[ "$line" == *"USER & AUTHENTICATION"* ]] && continue
        [[ "$line" == *"SSL CERTIFICATE"* ]] && continue
        [[ "$line" == *"SYSTEM RESOURCES"* ]] && continue
        [[ "$line" == *"HEALTH SUMMARY"* ]] && continue

        # Process status lines
        if [[ "$line" == *"OK:"* ]] || [[ "$line" == *"running"* ]]; then
            service=$(echo "$line" | sed 's/OK:.*//g' | sed 's/running.*//g' | xargs)
            details=$(echo "$line" | grep -o "OK:.*" | grep -o "running.*" | xargs)
            icon="fas fa-check-circle"
            _SERVICE_STATUS_HTML+="            <div class=\"status-item\">\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-value status-ok\">OK: $details</span>\n"
            _SERVICE_STATUS_HTML+="            </div>\n"
        elif [[ "$line" == *"ERROR:"* ]] || [[ "$line" == *"NOT running"* ]]; then
            service=$(echo "$line" | sed 's/ERROR:.*//g' | sed 's/NOT running.*//g' | xargs)
            details=$(echo "$line" | grep -o "ERROR:.*" | grep -o "NOT running.*" | xargs)
            icon="fas fa-times-circle"
            _SERVICE_STATUS_HTML+="            <div class=\"status-item\">\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-value status-error\">ERROR: $details</span>\n"
            _SERVICE_STATUS_HTML+="            </div>\n"
        elif [[ "$line" == *"WARNING:"* ]]; then
            service=$(echo "$line" | sed 's/WARNING:.*//g' | xargs)
            details=$(echo "$line" | sed 's/.*WARNING://g' | xargs)
            icon="fas fa-exclamation-triangle"
            _SERVICE_STATUS_HTML+="            <div class=\"status-item\">\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-label\"><i class=\"$icon\"></i> $service</span>\n"
            _SERVICE_STATUS_HTML+="                <span class=\"status-value status-warning\">WARNING: $details</span>\n"
            _SERVICE_STATUS_HTML+="            </div>\n"
        fi
    done < "$temp_file"
}

# Gather system metrics and export them as environment variables for template substitution.
_gather_system_metrics() {
    local cpu_load memory_usage disk_usage cpu_temp system_load process_count network_connections

    cpu_load=$(top -bn1 2>/dev/null | grep "load average" | awk '{print $10}' | awk -F, '{print $1}')
    memory_usage=$(free 2>/dev/null | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2{print $5}' | sed 's/%//')
    if command -v vcgencmd &>/dev/null; then
        cpu_temp=$(vcgencmd measure_temp 2>/dev/null | grep -o '[0-9]*\.[0-9]*' | head -1)
    else
        cpu_temp="N/A"
    fi
    system_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    process_count=$(ps aux 2>/dev/null | wc -l)
    if command -v netstat &>/dev/null; then
        network_connections=$(netstat -an 2>/dev/null | grep -c ESTABLISHED)
    elif command -v ss &>/dev/null; then
        network_connections=$(ss -an 2>/dev/null | grep -c ESTAB)
    else
        network_connections="N/A"
    fi

    export CPU_LOAD="$cpu_load"
    export MEMORY_USAGE="$memory_usage%"
    export DISK_USAGE="$disk_usage%"
    export CPU_TEMP="${cpu_temp}°C"
    export SYSTEM_LOAD="$system_load"
    export PROCESS_COUNT="$process_count"
    export NETWORK_CONNECTIONS="$network_connections"
}

generate_health_html() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local uptime
    uptime=$(uptime -p 2>/dev/null || echo "Unknown")

    # Get system info
    local hostname
    hostname=$(hostname)
    local kernel
    kernel=$(uname -r)
    local os
    os=$(lsb_release -d 2>/dev/null | cut -f2 || uname -s)

    # Run health checks and capture output
    local temp_file
    temp_file=$(mktemp) || return 1
    # Ensure temp file is cleaned up even if the while loop fails
    trap 'rm -f "$temp_file"' RETURN
    run_healthcheck > "$temp_file" 2>&1

    # Parse health check output into HTML
    _parse_health_status_to_html "$temp_file"

    # Gather system metrics (exports CPU_LOAD, MEMORY_USAGE, etc.)
    _gather_system_metrics

    # Process template with environment variables
    local template_file="$PROJECT_DIR/src/templates/health.html"

    if [[ -f "$template_file" ]]; then
        # Set environment variables for template substitution
        export HOSTNAME="$hostname"
        export OS="$os"
        export KERNEL="$kernel"
        export UPTIME="$uptime"
        export TIMESTAMP="$timestamp"
        export SERVICE_STATUS="$_SERVICE_STATUS_HTML"

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
    pkill -f "python3.*health_web_server.py" 2>/dev/null || true
    sleep 2

    # Kill any process using the configured port
    lsof -ti:"$HEALTH_WEB_PORT" | xargs -r kill -9 2>/dev/null || true
    sleep 1

    # Start Python web server directly (no subshell) to capture the correct PID
    cd "$PROJECT_DIR" || return 1
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

    # Kill any remaining processes by script name
    pkill -f "python3.*health_web_server.py" 2>/dev/null || true
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

# Handle command line arguments — only when executed directly, not when sourced
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
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
fi
