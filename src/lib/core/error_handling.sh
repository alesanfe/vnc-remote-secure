#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# ADVANCED ERROR HANDLING AND RECOVERY SYSTEM
# ============================================================================

# Error tracking
declare -gA ERROR_COUNTS
declare -gA LAST_ERROR_TIME
declare -gA ERROR_RECOVERY_ACTIONS

# Maximum retry attempts
MAX_RETRY_ATTEMPTS=3
# Backoff multiplier for retries
RETRY_BACKOFF_MULTIPLIER=2
# Initial retry delay in seconds
INITIAL_RETRY_DELAY=1

# Error severity levels
declare -gA ERROR_SEVERITY=(
    ["LOW"]=1
    ["MEDIUM"]=2
    ["HIGH"]=3
    ["CRITICAL"]=4
)

# Initialize error handling system
init_error_handling() {
    # Set up error trap
    trap 'handle_error $? $LINENO $BASH_LINENO "$BASH_COMMAND" "${FUNCNAME[*]}"' ERR

    # Clear error tracking
    ERROR_COUNTS=()
    LAST_ERROR_TIME=()
    ERROR_RECOVERY_ACTIONS=()

    log_info "Error handling system initialized" "ERROR_HANDLING"
}

# Main error handler
handle_error() {
    local exit_code=$1
    local line_no=$2
    local bash_line_no=$3
    local last_command="$4"
    local function_stack="$5"

    # Don't handle errors in cleanup functions
    if [[ "$function_stack" == *"cleanup"* ]]; then
        return "$exit_code"
    fi

    local error_context="Exit: $exit_code, Line: $line_no, Command: $last_command"

    # Log the error with context
    log_error_context "Script failed with exit code $exit_code" "$line_no" "${function_stack%% *}" "ERROR_HANDLER"
    log_error "Failed command: $last_command" "ERROR_HANDLER"

    # Track error
    track_error "$last_command" "$exit_code"

    # Attempt recovery
    if attempt_recovery "$last_command" "$exit_code"; then
        log_info "Recovery successful for: $last_command" "RECOVERY"
        return 0
    else
        log_error "Recovery failed for: $last_command" "RECOVERY"
        return "$exit_code"
    fi
}

# Track errors for pattern detection
track_error() {
    local command="$1"
    local exit_code="$2"
    local timestamp
    timestamp=$(date +%s)

    # Increment error count
    ERROR_COUNTS["$command"]=$((${ERROR_COUNTS["$command"]:-0} + 1))
    LAST_ERROR_TIME["$command"]=$timestamp

    # Check for error patterns
    if [[ ${ERROR_COUNTS["$command"]} -gt 3 ]]; then
        log_warn "Repeated error detected: $command (${ERROR_COUNTS["$command"]} times)" "ERROR_TRACKING"
    fi
}

# Attempt automatic recovery
# SECURITY: ERROR_RECOVERY_ACTIONS must only be populated with trusted,
# hard-coded function names — never with user-supplied input.
attempt_recovery() {
    local command="$1"
    local exit_code="$2"
    local recovery_action="${ERROR_RECOVERY_ACTIONS[$command]}"

    if [[ -n "$recovery_action" ]]; then
        # Only allow recovery actions that are defined function names
        if ! declare -f "$recovery_action" &>/dev/null; then
            log_error "Recovery action '$recovery_action' is not a defined function, skipping" "RECOVERY"
            return 1
        fi
        log_info "Attempting recovery action: $recovery_action" "RECOVERY"

        # Execute recovery function directly in the current shell (where all
        # helper functions are available). No timeout wrapper because timeout
        # runs in a subprocess where shell functions are not accessible.
        if "$recovery_action" 2>/dev/null; then
            log_success "Recovery action completed" "RECOVERY"
            return 0
        else
            log_error "Recovery action failed or timed out" "RECOVERY"
            return 1
        fi
    else
        # Generic recovery attempts based on error type
        case "$command" in
            *"useradd"*|*"userdel"*)
                recover_user_management "$exit_code"
                ;;
            *"systemctl"*)
                recover_service_management "$exit_code"
                ;;
            *"certbot"*)
                recover_ssl_management "$exit_code"
                ;;
            *"nginx"*)
                recover_nginx_management "$exit_code"
                ;;
            *)
                log_warn "No specific recovery action for: $command" "RECOVERY"
                return 1
                ;;
        esac
    fi
}

# Recovery functions for specific error types
recover_user_management() {
    local exit_code="$1"

    log_info "Attempting user management recovery" "RECOVERY"

    # Clean up any stuck processes
    if [[ -n "$TEMP_USER" ]]; then
        kill_user_processes_gracefully "$TEMP_USER" 5 || true
    fi

    # Fix user database issues
    if command -v pwck &>/dev/null; then
        sudo pwck -r 2>/dev/null || true
    fi

    # Fix group database issues
    if command -v grpck &>/dev/null; then
        sudo grpck -r 2>/dev/null || true
    fi

    return 0
}

recover_service_management() {
    local exit_code="$1"

    log_info "Attempting service management recovery" "RECOVERY"

    # Reload systemd
    if command -v systemctl &>/dev/null; then
        sudo systemctl daemon-reload 2>/dev/null || true
    fi

    # Reset failed services
    if command -v systemctl &>/dev/null; then
        sudo systemctl reset-failed 2>/dev/null || true
    fi

    return 0
}

recover_ssl_management() {
    local exit_code="$1"

    log_info "Attempting SSL management recovery" "RECOVERY"

    # Check if port 80 is blocked
    if command -v lsof &>/dev/null && sudo lsof -ti:80 &>/dev/null; then
        log_warn "Port 80 is in use, attempting to free it" "RECOVERY"

        # Try to stop nginx gracefully first
        if command -v systemctl &>/dev/null; then
            sudo systemctl stop nginx 2>/dev/null || true
        fi

        # Only kill processes that are nginx-related on port 80
        # (avoid killing unrelated web servers or services)
        local port80_pids
        port80_pids=$(sudo lsof -ti:80 2>/dev/null || true)
        if [[ -n "$port80_pids" ]]; then
            local pid
            for pid in $port80_pids; do
                local proc_name
                proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                if [[ "$proc_name" == "nginx" || "$proc_name" == "nginx:"* ]]; then
                    log_info "Stopping nginx process $pid on port 80" "RECOVERY"
                    sudo kill -TERM "$pid" 2>/dev/null || true
                else
                    log_warn "Port 80 is held by '$proc_name' (PID $pid), not killing" "RECOVERY"
                fi
            done
            sleep 2

            # Force kill only nginx processes still on port 80
            port80_pids=$(sudo lsof -ti:80 2>/dev/null || true)
            for pid in $port80_pids; do
                local proc_name
                proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                if [[ "$proc_name" == "nginx" || "$proc_name" == "nginx:"* ]]; then
                    sudo kill -KILL "$pid" 2>/dev/null || true
                fi
            done
        fi
    fi

    return 0
}

recover_nginx_management() {
    local exit_code="$1"

    log_info "Attempting nginx management recovery" "RECOVERY"

    # Test nginx configuration
    if command -v nginx &>/dev/null; then
        if sudo nginx -t 2>/dev/null; then
            log_info "Nginx configuration is valid" "RECOVERY"
        else
            log_error "Nginx configuration has errors" "RECOVERY"
            return 1
        fi
    fi

    return 0
}

# Retry mechanism with exponential backoff
# SECURITY: $command must be a trusted, hard-coded string — never pass
# user-supplied input. All current callers use literal strings only.
retry_with_backoff() {
    local command="$1"
    local max_attempts="${2:-$MAX_RETRY_ATTEMPTS}"
    local initial_delay="${3:-$INITIAL_RETRY_DELAY}"
    local backoff_multiplier="${4:-$RETRY_BACKOFF_MULTIPLIER}"

    local attempt=1
    local delay=$initial_delay

    while [[ $attempt -le $max_attempts ]]; do
        log_info "Attempt $attempt/$max_attempts: $command" "RETRY"

        # shellcheck disable=SC2086  # command is a trusted hard-coded string
        if eval "$command"; then
            log_success "Command succeeded on attempt $attempt" "RETRY"
            return 0
        else
            local exit_code=$?

            if [[ $attempt -eq $max_attempts ]]; then
                log_error "Command failed after $max_attempts attempts" "RETRY"
                return $exit_code
            fi

            log_warn "Command failed (attempt $attempt/$max_attempts), retrying in ${delay}s" "RETRY"
            sleep "$delay"

            # Exponential backoff
            delay=$((delay * backoff_multiplier))
            attempt=$((attempt + 1))
        fi
    done
}

# Safe command execution with error handling
# SECURITY: $command must be a trusted, hard-coded string — never pass
# user-supplied input. All current callers use literal strings only.
safe_execute() {
    local command="$1"
    local description="${2:-command}"
    local error_action="${3:-continue}"

    log_info "Executing: $description" "SAFE_EXECUTE"

    # Execute with timeout and error handling
    # shellcheck disable=SC2086  # command is a trusted hard-coded string
    if timeout 300 eval "$command" 2>/dev/null; then
        log_success "$description completed successfully" "SAFE_EXECUTE"
        return 0
    else
        local exit_code=$?

        log_error "$description failed with exit code $exit_code" "SAFE_EXECUTE"

        case "$error_action" in
            "continue")
                return $exit_code
                ;;
            "retry")
                retry_with_backoff "$command"
                ;;
            "abort")
                die "$description failed, aborting"
                ;;
            *)
                log_warn "Unknown error action: $error_action" "SAFE_EXECUTE"
                return $exit_code
                ;;
        esac
    fi
}

# Resource cleanup with error handling
# SECURITY: $cleanup_function must be a trusted, hard-coded string — never
# pass user-supplied input. All current callers use literal strings only.
safe_cleanup() {
    local cleanup_function="$1"
    local resource_description="${2:-resource}"

    log_info "Cleaning up: $resource_description" "CLEANUP"

    # Execute cleanup with timeout and error suppression
    # shellcheck disable=SC2086  # cleanup_function is a trusted hard-coded string
    if timeout 60 eval "$cleanup_function" 2>/dev/null; then
        log_success "$resource_description cleaned up successfully" "CLEANUP"
        return 0
    else
        log_warn "$resource_description cleanup failed or timed out" "CLEANUP"
        return 1
    fi
}

# Get error statistics (manual debugging utility)
get_error_stats() {
    log_info "Error Statistics:" "ERROR_STATS"

    for command in "${!ERROR_COUNTS[@]}"; do
        local count="${ERROR_COUNTS[$command]}"
        local last_time="${LAST_ERROR_TIME[$command]}"
        local time_diff
        time_diff=$(($(date +%s) - last_time))

        echo "  $command: $count errors (last: ${time_diff}s ago)"
    done
}
