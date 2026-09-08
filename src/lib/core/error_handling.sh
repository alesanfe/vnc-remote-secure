#!/bin/bash
# shellcheck disable=SC2034
set -e
set -o pipefail
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
        return $exit_code
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
        return $exit_code
    fi
}

# Track errors for pattern detection
track_error() {
    local command="$1"
    local exit_code="$2"
    local timestamp=$(date +%s)
    
    # Increment error count
    ERROR_COUNTS["$command"]=$((${ERROR_COUNTS["$command"]:-0} + 1))
    LAST_ERROR_TIME["$command"]=$timestamp
    
    # Check for error patterns
    if [[ ${ERROR_COUNTS["$command"]} -gt 3 ]]; then
        log_warn "Repeated error detected: $command (${ERROR_COUNTS["$command"]} times)" "ERROR_TRACKING"
    fi
}

# Attempt automatic recovery
attempt_recovery() {
    local command="$1"
    local exit_code="$2"
    local recovery_action="${ERROR_RECOVERY_ACTIONS[$command]}"
    
    if [[ -n "$recovery_action" ]]; then
        log_info "Attempting recovery action: $recovery_action" "RECOVERY"
        
        # Execute recovery action with timeout
        if timeout 30 bash -c "$recovery_action" 2>/dev/null; then
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
    if sudo netstat -tulpn 2>/dev/null | grep -q ':80 '; then
        log_warn "Port 80 is in use, attempting to free it" "RECOVERY"
        
        # Try to stop nginx
        if command -v systemctl &>/dev/null; then
            sudo systemctl stop nginx 2>/dev/null || true
        fi
        
        # Kill processes on port 80
        sudo lsof -ti:80 | xargs -r sudo kill -TERM 2>/dev/null || true
        sleep 2
        
        # Force kill if still running
        sudo lsof -ti:80 | xargs -r sudo kill -KILL 2>/dev/null || true
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
retry_with_backoff() {
    local command="$1"
    local max_attempts="${2:-$MAX_RETRY_ATTEMPTS}"
    local initial_delay="${3:-$INITIAL_RETRY_DELAY}"
    local backoff_multiplier="${4:-$RETRY_BACKOFF_MULTIPLIER}"
    
    local attempt=1
    local delay=$initial_delay
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Attempt $attempt/$max_attempts: $command" "RETRY"
        
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
safe_execute() {
    local command="$1"
    local description="${2:-command}"
    local error_action="${3:-continue}"
    
    log_info "Executing: $description" "SAFE_EXECUTE"
    
    # Execute with timeout and error handling
    if timeout 300 bash -c "$command" 2>/dev/null; then
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
safe_cleanup() {
    local cleanup_function="$1"
    local resource_description="${2:-resource}"
    
    log_info "Cleaning up: $resource_description" "CLEANUP"
    
    # Execute cleanup with timeout and error suppression
    if timeout 60 bash -c "$cleanup_function" 2>/dev/null; then
        log_success "$resource_description cleaned up successfully" "CLEANUP"
        return 0
    else
        log_warn "$resource_description cleanup failed or timed out" "CLEANUP"
        return 1
    fi
}

# Health check with recovery
health_check_with_recovery() {
    local service="$1"
    local check_command="$2"
    local recovery_action="$3"
    
    log_info "Checking health of: $service" "HEALTH_CHECK"
    
    if eval "$check_command" 2>/dev/null; then
        log_success "$service is healthy" "HEALTH_CHECK"
        return 0
    else
        log_warn "$service health check failed" "HEALTH_CHECK"
        
        if [[ -n "$recovery_action" ]]; then
            log_info "Attempting recovery for: $service" "HEALTH_CHECK"
            
            if eval "$recovery_action" 2>/dev/null; then
                log_success "$service recovery successful" "HEALTH_CHECK"
                
                # Re-check after recovery
                sleep 5
                if eval "$check_command" 2>/dev/null; then
                    log_success "$service is healthy after recovery" "HEALTH_CHECK"
                    return 0
                else
                    log_error "$service still unhealthy after recovery" "HEALTH_CHECK"
                    return 1
                fi
            else
                log_error "$service recovery failed" "HEALTH_CHECK"
                return 1
            fi
        else
            return 1
        fi
    fi
}

# Register custom recovery action
register_recovery_action() {
    local command_pattern="$1"
    local recovery_action="$2"
    
    ERROR_RECOVERY_ACTIONS["$command_pattern"]="$recovery_action"
    log_info "Registered recovery action for: $command_pattern" "RECOVERY_REGISTRY"
}

# Get error statistics
get_error_stats() {
    log_info "Error Statistics:" "ERROR_STATS"
    
    for command in "${!ERROR_COUNTS[@]}"; do
        local count="${ERROR_COUNTS[$command]}"
        local last_time="${LAST_ERROR_TIME[$command]}"
        local time_diff=$(($(date +%s) - last_time))
        
        echo "  $command: $count errors (last: ${time_diff}s ago)"
    done
}

# Reset error tracking
reset_error_tracking() {
    ERROR_COUNTS=()
    LAST_ERROR_TIME=()
    log_info "Error tracking reset" "ERROR_TRACKING"
}

# Cleanup function for error handling
cleanup_error_handling() {
    log_info "Cleaning up error handling system" "ERROR_HANDLING"
    
    # Remove error trap
    trap - ERR
    
    # Log final statistics
    if [[ ${#ERROR_COUNTS[@]} -gt 0 ]]; then
        get_error_stats
    fi
}
