#!/bin/bash
# shellcheck disable=SC2155
# ============================================================================
# USER MANAGEMENT
# ============================================================================

get_next_uid() {
    # Find the first available UID in the standard non-system range (1000-60000)
    local used_uids
    used_uids=$(getent passwd | cut -d: -f3 | sort -n)
    local uid=1000
    while (( uid <= 60000 )); do
        if ! echo "$used_uids" | grep -qx "$uid"; then
            echo "$uid"
            return 0
        fi
        uid=$((uid + 1))
    done
    # Fallback: no free UID in range
    log "red" "No free UID available in range 1000-60000"
    return 1
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

# Remove an existing temporary user and its home directory.
# Tries graceful removal first, then force-removes if needed.
remove_existing_temp_user() {
    if ! id "$TEMP_USER" &>/dev/null; then
        return 0
    fi

    log "yellow" "Removing existing user $TEMP_USER..."

    # Kill all processes belonging to the user gracefully
    kill_user_processes_gracefully "$TEMP_USER" 10 || true

    # Kill specific processes that might hold the user (ssh-agent, etc.)
    kill_processes_by_pattern "ssh-agent.*$TEMP_USER" 5 || true
    kill_processes_by_pattern "/usr/bin/ssh-agent" 5 || true

    sleep 1

    # Now try to remove the user
    if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
        log "green" "Successfully removed existing user $TEMP_USER"
    else
        # If still failing, try more aggressive approach
        log "yellow" "Standard removal failed, trying force removal..."

        if ! kill_user_processes_gracefully "$TEMP_USER" 5; then
            log "yellow" "Some processes still running, attempting final cleanup..."
            kill_user_processes_gracefully "$TEMP_USER" 2 || true
        fi

        if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
            log "green" "Successfully removed user $TEMP_USER (force)"
        else
            log "red" "Failed to remove user $TEMP_USER. Manual intervention required."
            log "yellow" "Try: kill_user_processes_gracefully $TEMP_USER && sudo userdel -r $TEMP_USER"
            die "Cannot proceed with existing user $TEMP_USER blocking setup"
        fi
    fi

    # Remove home directory if it still exists
    if [[ -d "/home/$TEMP_USER" ]]; then
        log "yellow" "Removing existing home directory /home/$TEMP_USER..."
        sudo rm -rf "/home/$TEMP_USER"
    fi
}

create_temp_user() {
    # Remove any existing temp user first
    remove_existing_temp_user

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
    # Hash the password with SHA-512 + salt to avoid issues with : and \n in chpasswd
    local hashed_pass
    hashed_pass=$(openssl passwd -6 "$TEMP_USER_PASS")
    echo "$TEMP_USER:$hashed_pass" | sudo chpasswd -e

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
