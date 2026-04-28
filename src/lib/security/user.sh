#!/bin/bash
# shellcheck disable=SC2155
set -e
set -o pipefail
# ============================================================================
# USER MANAGEMENT
# ============================================================================

get_next_uid() {
    local last_uid=$(getent passwd | cut -d: -f3 | sort -n | tail -n 1)
    local next_uid=$((last_uid + 1))
    
    # Ensure UID is within valid range (1000-60000)
    if (( next_uid < 1000 )); then
        echo 1000
    elif (( next_uid > 60000 )); then
        echo 60000
    else
        echo "$next_uid"
    fi
}

copy_user_config() {
    local source_user="$1"
    local target_user="$2"
    local source_gid=$(id -g "$source_user")

    # Copy .Xauthority
    if [[ -f "/home/$source_user/.Xauthority" ]]; then
        log "yellow" "Copying .Xauthority file for $target_user..."
        sudo cp "/home/$source_user/.Xauthority" "/home/$target_user/.Xauthority"
        sudo chown "$target_user:$source_gid" "/home/$target_user/.Xauthority"
    fi

    # Create .vnc directory but don't copy password files (will be set via VNC_PASSWORD)
    sudo mkdir -p "/home/$target_user/.vnc"
    sudo chown "$target_user:$source_gid" "/home/$target_user/.vnc"
    sudo chmod 700 "/home/$target_user/.vnc"
}

create_temp_user() {
    # Remove existing user and home directory if exists
    if id "$TEMP_USER" &>/dev/null; then
        log "yellow" "Removing existing user $TEMP_USER..."
        
        # Kill all processes belonging to the user first
        log "yellow" "Stopping all processes for user $TEMP_USER..."
        sudo pkill -u "$TEMP_USER" 2>/dev/null || true
        
        # Wait a moment for processes to terminate
        sleep 2
        
        # Force kill any remaining processes
        sudo pkill -9 -u "$TEMP_USER" 2>/dev/null || true
        
        # Kill specific processes that might hold the user (ssh-agent, etc.)
        sudo pkill -f "ssh-agent.*$TEMP_USER" 2>/dev/null || true
        sudo pkill -f "/usr/bin/ssh-agent" 2>/dev/null || true
        
        # Wait again
        sleep 1
        
        # Now try to remove the user
        if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
            log "green" "Successfully removed existing user $TEMP_USER"
        else
            # If still failing, try more aggressive approach
            log "yellow" "Standard removal failed, trying force removal..."
            
            # Find and kill any remaining processes by PID
            local user_processes=$(ps -u "$TEMP_USER" -o pid= 2>/dev/null | tr -d ' ')
            if [[ -n "$user_processes" ]]; then
                for pid in $user_processes; do
                    sudo kill -9 "$pid" 2>/dev/null || true
                done
                sleep 1
            fi
            
            # Try userdel again
            if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
                log "green" "Successfully removed user $TEMP_USER (force)"
            else
                log "red" "Failed to remove user $TEMP_USER. Manual intervention required."
                log "yellow" "Try: sudo pkill -9 -u $TEMP_USER && sudo userdel -r $TEMP_USER"
                die "Cannot proceed with existing user $TEMP_USER blocking setup"
            fi
        fi
    fi

    # Remove home directory if it still exists
    if [[ -d "/home/$TEMP_USER" ]]; then
        log "yellow" "Removing existing home directory /home/$TEMP_USER..."
        sudo rm -rf "/home/$TEMP_USER"
    fi

    # Validate TTYD_USERNAME exists
    if ! id "$TTYD_USERNAME" &>/dev/null; then
        die "TTYD_USERNAME '$TTYD_USERNAME' does not exist. Please provide a valid username."
    fi

    log "cyan" "Creating temporary user: $TEMP_USER"

    export TTYD_UID=$(id -u "$TTYD_USERNAME")
    export TTYD_GID=$(id -g "$TTYD_USERNAME")
    local new_uid=$(get_next_uid)

    # Create user with bash shell
    sudo useradd -m -u "$new_uid" -g "$TTYD_GID" -s /bin/bash "$TEMP_USER"
    echo "$TEMP_USER:$TEMP_USER_PASS" | sudo chpasswd

    copy_user_config "$TTYD_USERNAME" "$TEMP_USER"

    # Verify bash is accessible for the user
    if ! sudo -u "$TEMP_USER" which bash &>/dev/null; then
        log "red" "User $TEMP_USER cannot access bash"
        die "Failed to verify bash access for $TEMP_USER"
    fi

    # Test that bash can be executed
    if ! sudo -u "$TEMP_USER" bash -c "echo 'test'" &>/dev/null; then
        log "red" "User $TEMP_USER cannot execute bash"
        die "Failed to execute bash as $TEMP_USER"
    fi

    success "Temporary user $TEMP_USER created (UID: $new_uid)"
}
