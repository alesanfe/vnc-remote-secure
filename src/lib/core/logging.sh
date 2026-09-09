#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# STRUCTURED LOGGING SYSTEM
# ============================================================================

# Log levels in order of severity
declare -gA LOG_LEVELS=(
    ["DEBUG"]=0
    ["INFO"]=1
    ["WARN"]=2
    ["ERROR"]=3
    ["FATAL"]=4
)

# Default log level (uppercase to match LOG_LEVELS keys, accepts lowercase input)
_log_level_key="${LOG_LEVEL:-INFO}"
CURRENT_LOG_LEVEL="${LOG_LEVELS[${_log_level_key^^}]}"
if [[ -z "$CURRENT_LOG_LEVEL" ]]; then
    CURRENT_LOG_LEVEL="${LOG_LEVELS[INFO]}"
fi
unset _log_level_key

# Color definitions
declare -gA LOG_COLORS=(
    ["DEBUG"]="\033[0;36m"
    ["INFO"]="\033[0;34m"
    ["WARN"]="\033[1;33m"
    ["ERROR"]="\033[0;31m"
    ["FATAL"]="\033[1;41m"
    ["SUCCESS"]="\033[0;32m"
    ["RESET"]="\033[0m"
)

# Check if we should log at this level
should_log() {
    local level="$1"
    local level_num="${LOG_LEVELS[$level]}"
    
    if [[ -z "$level_num" ]]; then
        level_num="${LOG_LEVELS[INFO]}"
    fi
    
    [[ $level_num -ge $CURRENT_LOG_LEVEL ]]
}

# Core logging function
# Arguments:
#   $1 - Log level (DEBUG, INFO, WARN, ERROR, FATAL, SUCCESS)
#   $2 - Message
#   $3 - Component/module name (optional)
#   $4 - Additional context (optional)
write_log() {
    local level="$1"
    local message="$2"
    local component="${3:-MAIN}"
    local context="${4:-}"
    
    if ! should_log "$level"; then
        return 0
    fi
    
    local color="${LOG_COLORS[$level]:-${LOG_COLORS[RESET]}}"
    local timestamp=""
    local pid=""
    
    # Add timestamp if verbose is enabled
    if [[ "$VERBOSE" == "true" ]]; then
        timestamp="[$(date '+%Y-%m-%d %H:%M:%S')] "
    fi
    
    # Add PID if in debug mode
    if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        pid="[PID:$$] "
    fi
    
    # Build the log entry
    local log_entry="${color}${timestamp}${pid}[${level}] [${component}] ${message}${LOG_COLORS[RESET]}"
    
    # Add context if provided
    if [[ -n "$context" ]]; then
        log_entry="${log_entry} | ${context}"
    fi
    
    echo -e "$log_entry"
    
    # Log to file if LOG_FILE is set
    if [[ -n "$LOG_FILE" ]]; then
        local file_entry="${timestamp}[${level}] [${component}] ${message}"
        if [[ -n "$context" ]]; then
            file_entry="${file_entry} | ${context}"
        fi
        echo "$file_entry" >> "$LOG_FILE"
    fi
}

# Convenience logging functions
log_debug() {
    write_log "DEBUG" "$1" "${2:-MAIN}" "${3:-}"
}

log_info() {
    write_log "INFO" "$1" "${2:-MAIN}" "${3:-}"
}

log_warn() {
    write_log "WARN" "$1" "${2:-MAIN}" "${3:-}"
}

log_error() {
    write_log "ERROR" "$1" "${2:-MAIN}" "${3:-}"
}

log_fatal() {
    write_log "FATAL" "$1" "${2:-MAIN}" "${3:-}"
}

log_success() {
    write_log "SUCCESS" "$1" "${2:-MAIN}" "${3:-}"
}

# Legacy compatibility functions
log() {
    local level="$1"
    local message="$2"
    
    # Convert old level names to new ones
    case "$level" in
        "red") log_error "$message" ;;
        "green") log_success "$message" ;;
        "yellow") log_warn "$message" ;;
        "blue") log_info "$message" ;;
        "purple"|"cyan") log_debug "$message" ;;
        "white"|"bright") log_info "$message" ;;
        *) log_info "$message" ;;
    esac
}

warn() {
    log_warn "$1" "${2:-MAIN}"
}

info() {
    log_info "$1" "${2:-MAIN}"
}

success() {
    log_success "$1" "${2:-MAIN}"
}

die() {
    log_fatal "$1" "${2:-MAIN}"
    echo ""
    exit 1
}

# Service-specific logging
log_service_start() {
    local service="$1"
    local component="${2:-SERVICE}"
    log_info "Starting service: $service" "$component"
}

log_service_stop() {
    local service="$1"
    local component="${2:-SERVICE}"
    log_info "Stopping service: $service" "$component"
}

log_service_status() {
    local service="$1"
    local status="$2"
    local component="${3:-SERVICE}"
    
    if [[ "$status" == "running" ]]; then
        log_success "Service $service is running" "$component"
    else
        log_error "Service $service is not running" "$component"
    fi
}

log_system_resources() {
    if [[ "$LOG_LEVEL" != "DEBUG" ]]; then
        return 0
    fi
    
    local cpu_usage mem_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    
    log_debug "System Resources" "SYSTEM" "CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}"
}

# Error context logging
log_error_context() {
    local error_message="$1"
    local line_number="${2:-}"
    local function_name="${3:-}"
    local component="${4:-ERROR}"
    
    local context="Line: ${line_number:-unknown}"
    if [[ -n "$function_name" ]]; then
        context="${context}, Function: $function_name"
    fi
    
    log_error "$error_message" "$component" "$context"
}

# Performance logging
log_performance() {
    local operation="$1"
    local duration="$2"
    local component="${3:-PERF}"
    
    log_debug "Performance: $operation took ${duration}s" "$component"
}

# Security event logging
log_security_event() {
    local event="$1"
    local source_ip="${2:-}"
    local user="${3:-}"
    local component="${4:-SECURITY}"
    
    local context=""
    if [[ -n "$source_ip" ]]; then
        context="IP: $source_ip"
    fi
    if [[ -n "$user" ]]; then
        if [[ -n "$context" ]]; then
            context="${context}, User: $user"
        else
            context="User: $user"
        fi
    fi
    
    log_warn "Security Event: $event" "$component" "$context"
}

# Initialize logging system
init_logging() {
    local log_dir="${LOG_DIR:-./logs}"
    local log_file="$log_dir/system.log"
    
    # Create log directory if it doesn't exist
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || true
    fi
    
    # Set log file if writable
    if [[ -w "$log_dir" ]]; then
        export LOG_FILE="$log_file"
    fi
    
    # Log initialization
    log_info "Logging system initialized" "LOGGING" "Level: ${LOG_LEVEL:-INFO}, File: ${LOG_FILE:-none}"
}

# Set log level dynamically
set_log_level() {
    local new_level="$1"
    
    if [[ -n "${LOG_LEVELS[$new_level]}" ]]; then
        export LOG_LEVEL="$new_level"
        export CURRENT_LOG_LEVEL="${LOG_LEVELS[$new_level]}"
        log_info "Log level changed to: $new_level" "LOGGING"
    else
        log_error "Invalid log level: $new_level" "LOGGING"
        return 1
    fi
}
