#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# CLEANUP UTILITIES
# ============================================================================

kill_process_on_port() {
    local port="$1"
    local pid

    pid=$(lsof -t -i :"$port" 2>/dev/null || true)

    if [[ -n "$pid" ]]; then
        log_info "Stopping process on port $port (PID: $pid)" "CLEANUP"
        terminate_process_gracefully "$pid" 5 || true
    else
        log_debug "No process found on port $port" "CLEANUP"
    fi
}

kill_vnc_server() {
    if pgrep -x "Xtigervnc" > /dev/null; then
        log_info "Stopping TigerVNC server" "CLEANUP"

        # Try graceful shutdown first
        if [[ -n "$TEMP_USER" ]]; then
            sudo -u "$TEMP_USER" tigervncserver -kill "$VNC_DISPLAY" 2>/dev/null || true
        fi

        # Kill any remaining VNC processes
        kill_processes_by_pattern "tigervncserver" 5 || true
    else
        log_debug "No TigerVNC server running" "CLEANUP"
    fi
}

remove_temp_user() {
    if id "$TEMP_USER" &>/dev/null; then
        log_info "Removing temporary user $TEMP_USER" "CLEANUP"

        # Kill user processes gracefully
        kill_user_processes_gracefully "$TEMP_USER" 5 || true

        # Remove user and home directory
        if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
            log_success "Temporary user $TEMP_USER removed successfully" "CLEANUP"
        else
            log_warn "Failed to remove temporary user $TEMP_USER" "CLEANUP"
            return 1
        fi
    else
        log_debug "Temporary user $TEMP_USER does not exist" "CLEANUP"
    fi
}

cleanup_processes() {
    log_info "Cleaning up processes" "CLEANUP"

    # Stop services on specific ports
    kill_process_on_port "$NOVNC_PORT"
    kill_process_on_port "$TTYD_PORT"
    kill_process_on_port "$VNC_PORT"

    # Stop VNC server
    kill_vnc_server

    # Remove temporary user
    remove_temp_user

    log_success "Process cleanup completed" "CLEANUP"
}

# Force cleanup (emergency manual use — not called automatically).
# Use this when the normal cleanup fails or the system is in a bad state.
force_cleanup() {
    log_warn "Starting force cleanup (emergency mode)" "CLEANUP"

    # Kill all related processes forcefully
    local patterns=("tigervncserver" "ttyd" "novnc" "websockify")

    for pattern in "${patterns[@]}"; do
        log_info "Force killing processes matching: $pattern" "CLEANUP"
        sudo pkill -f "$pattern" 2>/dev/null || true
        sleep 1
        sudo pkill -9 -f "$pattern" 2>/dev/null || true
    done

    # Remove user forcefully
    if id "$TEMP_USER" &>/dev/null; then
        log_info "Force removing user: $TEMP_USER" "CLEANUP"
        sudo pkill -u "$TEMP_USER" 2>/dev/null || true
        sleep 2
        sudo pkill -9 -u "$TEMP_USER" 2>/dev/null || true
        sudo userdel -r "$TEMP_USER" 2>/dev/null || true
    fi

    log_success "Force cleanup completed" "CLEANUP"
}
