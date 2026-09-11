#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# PROCESS MANAGEMENT UTILITIES
# ============================================================================

# Graceful process termination with timeout
# Arguments:
#   $1 - PID or process name
#   $2 - Timeout in seconds (default: 10)
#   $3 - Signal to use (default: TERM)
# Returns:
#   0 if process terminated gracefully, 1 if force kill was needed, 2 if failed
terminate_process_gracefully() {
    local target="$1"
    local timeout="${2:-10}"
    local signal="${3:-TERM}"
    local force_signal="KILL"

    if [[ -z "$target" ]]; then
        log "red" "terminate_process_gracefully: No target specified"
        return 2
    fi

    # Get PID(s) if process name was provided
    local pids
    if [[ "$target" =~ ^[0-9]+$ ]]; then
        pids="$target"
    else
        pids=$(pgrep -f "$target" 2>/dev/null || true)
    fi

    if [[ -z "$pids" ]]; then
        log "yellow" "Process '$target' not found"
        return 0
    fi

    # Terminate all matching PIDs
    local overall_rc=0
    local pid
    for pid in $pids; do
        log "cyan" "Terminating process $pid (signal: $signal, timeout: ${timeout}s)..."

        # Send initial signal
        if ! kill -"$signal" "$pid" 2>/dev/null; then
            log "red" "Failed to send signal $signal to process $pid"
            overall_rc=2
            continue
        fi

        # Wait for graceful termination
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt $timeout ]]; do
            sleep 1
            count=$((count + 1))
        done

        # Check if process terminated
        if ! kill -0 "$pid" 2>/dev/null; then
            log "green" "Process $pid terminated gracefully"
            continue
        fi

        # Process still running, use force signal
        log "yellow" "Process $pid did not terminate gracefully, using force signal $force_signal..."
        if kill -"$force_signal" "$pid" 2>/dev/null; then
            sleep 2
            if ! kill -0 "$pid" 2>/dev/null; then
                log "green" "Process $pid terminated with force signal"
                [[ $overall_rc -eq 0 ]] && overall_rc=1
                continue
            fi
        fi

        log "red" "Failed to terminate process $pid"
        overall_rc=2
    done

    return $overall_rc
}

# Kill all processes matching pattern gracefully
# Arguments:
#   $1 - Process pattern
#   $2 - Timeout in seconds (default: 10)
# Returns:
#   0 if all processes terminated, 1 if some failed, 2 if all failed
kill_processes_by_pattern() {
    local pattern="$1"
    local timeout="${2:-10}"
    local failed_count=0
    local total_count=0

    if [[ -z "$pattern" ]]; then
        log "red" "kill_processes_by_pattern: No pattern specified"
        return 2
    fi

    log "cyan" "Terminating processes matching pattern: $pattern"

    # Get all matching PIDs
    local pids
    mapfile -t pids < <(pgrep -f "$pattern" 2>/dev/null || true)

    if [[ ${#pids[@]} -eq 0 ]]; then
        log "yellow" "No processes found matching pattern: $pattern"
        return 0
    fi

    total_count=${#pids[@]}

    # Terminate each process
    for pid in "${pids[@]}"; do
        if ! terminate_process_gracefully "$pid" "$timeout"; then
            failed_count=$((failed_count + 1))
        fi
    done

    if [[ $failed_count -eq 0 ]]; then
        log "green" "All $total_count processes terminated successfully"
        return 0
    elif [[ $failed_count -lt $total_count ]]; then
        log "yellow" "$failed_count of $total_count processes failed to terminate"
        return 1
    else
        log "red" "All $total_count processes failed to terminate"
        return 2
    fi
}

# Kill user processes gracefully
# Arguments:
#   $1 - Username
#   $2 - Timeout in seconds (default: 15)
# Returns:
#   0 if all processes terminated, 1 if some failed, 2 if all failed
kill_user_processes_gracefully() {
    local username="$1"
    local timeout="${2:-15}"

    if [[ -z "$username" ]]; then
        log "red" "kill_user_processes_gracefully: No username specified"
        return 2
    fi

    if ! id "$username" &>/dev/null; then
        log "yellow" "User '$username' does not exist"
        return 0
    fi

    log "cyan" "Terminating processes for user: $username"

    # Get all user processes
    local pids
    mapfile -t pids < <(ps -u "$username" -o pid= 2>/dev/null | tr -d ' ')

    if [[ ${#pids[@]} -eq 0 ]]; then
        log "yellow" "No processes found for user: $username"
        return 0
    fi

    # Terminate each process
    local failed_count=0
    for pid in "${pids[@]}"; do
        if ! terminate_process_gracefully "$pid" "$timeout"; then
            failed_count=$((failed_count + 1))
        fi
    done

    if [[ $failed_count -eq 0 ]]; then
        log "green" "All user processes terminated successfully"
        return 0
    else
        log "yellow" "$failed_count user processes failed to terminate"
        return 1
    fi
}

# Stop service gracefully with systemctl if available, fallback to process kill
# Arguments:
#   $1 - Service name
#   $2 - Timeout in seconds (default: 20)
# Returns:
#   0 if service stopped, 1 if fallback used, 2 if failed
stop_service_gracefully() {
    local service="$1"
    local timeout="${2:-20}"

    if [[ -z "$service" ]]; then
        log "red" "stop_service_gracefully: No service name specified"
        return 2
    fi

    log "cyan" "Stopping service: $service"

    # Try systemctl first
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "blue" "Using systemctl to stop $service..."
            if sudo systemctl stop "$service" 2>/dev/null; then
                # Wait for service to stop
                local count=0
                while systemctl is-active --quiet "$service" 2>/dev/null && [[ $count -lt $timeout ]]; do
                    sleep 1
                    count=$((count + 1))
                done

                if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                    log "green" "Service $service stopped via systemctl"
                    return 0
                else
                    log "yellow" "Service $service did not stop via systemctl, using fallback..."
                fi
            else
                log "yellow" "systemctl stop failed for $service, using fallback..."
            fi
        else
            log "yellow" "Service $service is not running"
            return 0
        fi
    else
        log "yellow" "systemctl not available, using process termination..."
    fi

    # Fallback to process termination
    if kill_processes_by_pattern "$service" "$timeout"; then
        return 1  # Indicate fallback was used
    else
        return 2
    fi
}
