#!/bin/bash
# shellcheck disable=SC2034,SC1091
# ============================================================================
# MAIN UTILITIES MODULE (Refactored)
# ============================================================================
# This module sources specialized utility sub-modules and provides only
# functions that are NOT defined elsewhere. Definitions in the sub-modules
# (logging.sh, display_utils.sh, command_utils.sh, cleanup_utils.sh,
# validation.sh, dependency_utils.sh) are the single source of truth.
#
# Sourcing order: the main entry point sources logging.sh, validation.sh,
# error_handling.sh, then utils.sh. utils.sh in turn sources:
#   display_utils.sh, dependency_utils.sh, command_utils.sh, cleanup_utils.sh

# Import specialized utility modules
source "$(dirname "${BASH_SOURCE[0]}")/display_utils.sh"
source "$(dirname "${BASH_SOURCE[0]}")/dependency_utils.sh"
source "$(dirname "${BASH_SOURCE[0]}")/process_utils.sh"
source "$(dirname "${BASH_SOURCE[0]}")/command_utils.sh"
source "$(dirname "${BASH_SOURCE[0]}")/cleanup_utils.sh"

# ============================================================================
# DEBUG AND DIAGNOSTIC HELPERS (unique to this module)
# ============================================================================

# Enhanced debug logging with service status and timing
debug_log() {
    [[ "$VERBOSE" != "true" ]] && return

    local service="$1"
    local action="$2"
    local status="$3"
    local duration="${4:-N/A}"

    log "cyan" "[$service] $action - Status: $status, Duration: ${duration}s"
}

# Log system resources (verbose mode)
log_system_resources() {
    [[ "$VERBOSE" != "true" ]] && return

    local cpu_usage mem_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')

    log "cyan" "System Resources - CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}"
}

# ============================================================================
# VALIDATION (password strength and port availability, unique to this module)
# ============================================================================

# Validate password strength (delegates to validation.sh's validate_password)
# Arguments:
#   $1 - Password to validate
# Returns:
#   0 if password is strong, 1 otherwise
# Note: validate_password (in validation.sh) is the canonical implementation.
# This wrapper exists for backward compatibility with callers that don't need
# the field_name / VALIDATION_ERRORS machinery.
validate_password_strength() {
    validate_password "$1" "password" 2>/dev/null
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
validate_config() {
    local errors=0

    # Validate TEMP_USER format (prevents command injection in useradd/userdel)
    if ! [[ "$TEMP_USER" =~ ^[a-z][a-z0-9_-]{1,31}$ ]]; then
        log "red" "TEMP_USER must start with a lowercase letter and contain only lowercase letters, digits, hyphens, and underscores (max 32 chars)."
        errors=$((errors + 1))
    fi

    # Validate TTYD_USERNAME format (used in sudo -u and user creation)
    if ! [[ "$TTYD_USERNAME" =~ ^[a-z][a-z0-9_-]{1,31}$ ]]; then
        log "red" "TTYD_USERNAME must start with a lowercase letter and contain only lowercase letters, digits, hyphens, and underscores (max 32 chars)."
        errors=$((errors + 1))
    fi

    # Validate password strength
    if ! validate_password_strength "$TTYD_PASSWD"; then
        log "red" "TTYD_PASSWD must be at least 8 characters and contain uppercase, lowercase, and digits. Cannot be a known weak/default password."
        errors=$((errors + 1))
    fi

    # Validate temporary user password (defaults to TTYD_PASSWD)
    if ! validate_password_strength "$TEMP_USER_PASS"; then
        log "red" "TEMP_USER_PASS must be at least 8 characters and contain uppercase, lowercase, and digits. Cannot be a known weak/default password."
        errors=$((errors + 1))
    fi

    # Validate VNC password
    if ! validate_password_strength "$VNC_PASSWORD"; then
        log "red" "VNC_PASSWORD must be at least 8 characters and contain uppercase, lowercase, and digits. Cannot be a known weak/default password."
        errors=$((errors + 1))
    fi

    # Validate User Management UI password only when the UI is enabled
    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        if ! validate_password_strength "$USER_UI_PASSWORD"; then
            log "red" "USER_UI_PASSWORD must be at least 8 characters and contain uppercase, lowercase, and digits. Cannot be a known weak/default password."
            errors=$((errors + 1))
        fi
    fi

    # Validate email (used for Let's Encrypt certificate registration)
    if [[ -n "$EMAIL" ]]; then
        if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log "red" "EMAIL must be a valid email address (used for Let's Encrypt)."
            errors=$((errors + 1))
        elif [[ "$EMAIL" == *"example.com" ]]; then
            log "red" "EMAIL cannot use the example.com placeholder domain; set a real address for Let's Encrypt."
            errors=$((errors + 1))
        fi
    fi

    # Validate ports (using validation.sh validate_port)
    if ! validate_port "$NOVNC_PORT" "NOVNC_PORT"; then
        log "red" "NOVNC_PORT must be a valid port number (1-65535)"
        errors=$((errors + 1))
    fi

    if ! validate_port "$TTYD_PORT" "TTYD_PORT"; then
        log "red" "TTYD_PORT must be a valid port number (1-65535)"
        errors=$((errors + 1))
    fi

    if ! validate_port "$VNC_PORT" "VNC_PORT"; then
        log "red" "VNC_PORT must be a valid port number (1-65535)"
        errors=$((errors + 1))
    fi

    # Validate domain (using validation.sh validate_domain)
    if ! validate_domain "$DUCK_DOMAIN" "DUCK_DOMAIN"; then
        log "red" "DUCK_DOMAIN must be a valid domain name"
        errors=$((errors + 1))
    fi

    # Check port availability
    if ! check_port_available "$NOVNC_PORT"; then
        log "red" "Port $NOVNC_PORT is already in use"
        errors=$((errors + 1))
    fi

    if ! check_port_available "$TTYD_PORT"; then
        log "red" "Port $TTYD_PORT is already in use"
        errors=$((errors + 1))
    fi

    if ! check_port_available "$VNC_PORT"; then
        log "red" "Port $VNC_PORT is already in use"
        errors=$((errors + 1))
    fi

    if (( errors > 0 )); then
        log "red" "Configuration validation failed with $errors error(s)"
        return 1
    fi

    return 0
}

# ============================================================================
# LOG VIEWING
# ============================================================================

show_logs() {
    if [[ "$SHOW_LOGS" != "true" ]]; then
        log "yellow" "Log viewing is disabled. Set SHOW_LOGS=true to enable."
        wait
        return
    fi

    log "blue" "Monitoring service logs (Press CTRL+C to stop)..."
    echo ""

    # Create a combined log viewer
    if command -v multitail &>/dev/null; then
        # Use multitail if available for better viewing
        multitail "$LOG_DIR/ttyd.log" "$LOG_DIR/novnc.log" "$LOG_DIR/vnc.log"
    elif command -v tail &>/dev/null; then
        # Use tail to follow all logs
        tail -f "$LOG_DIR"/*.log 2>/dev/null || {
            log "yellow" "No log files found yet. Waiting for logs..."
            sleep 5
            tail -f "$LOG_DIR"/*.log 2>/dev/null || wait
        }
    else
        # Fallback to just wait
        log "yellow" "tail command not available. Using wait..."
        wait
    fi
}
