#!/bin/bash
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
        log "yellow" "Copying .Xauthority file for $target_user..." "⚠️"
        sudo cp "/home/$source_user/.Xauthority" "/home/$target_user/.Xauthority"
        sudo chown "$target_user:$source_gid" "/home/$target_user/.Xauthority"
    fi
    
    # Copy VNC password files
    if [[ -d "/home/$source_user/.vnc" ]]; then
        log "yellow" "Copying VNC password files for $target_user..." "⚠️"
        sudo mkdir -p "/home/$target_user/.vnc"
        sudo cp -r "/home/$source_user/.vnc/"* "/home/$target_user/.vnc/" 2>/dev/null || true
        sudo chown -R "$target_user:$source_gid" "/home/$target_user/.vnc"
        sudo chmod -R 700 "/home/$target_user/.vnc"
    fi
}

create_temp_user() {
    id "$TEMP_USER" &>/dev/null && return
    
    log "cyan" "Creating temporary user $TEMP_USER..." "👤"
    
    export TTYD_UID=$(id -u "$TTYD_USERNAME")
    export TTYD_GID=$(id -g "$TTYD_USERNAME")
    local new_uid=$(get_next_uid)
    
    sudo useradd -m -u "$new_uid" -g "$TTYD_GID" -s /bin/bash "$TEMP_USER"
    echo "$TEMP_USER:$TEMP_USER_PASS" | sudo chpasswd
    
    sudo rm -rf "/home/$TEMP_USER" 2>/dev/null || true
    sudo mkdir -p "/home/$TEMP_USER"
    sudo chown "$TEMP_USER:$TTYD_GID" "/home/$TEMP_USER"
    
    copy_user_config "$TTYD_USERNAME" "$TEMP_USER"
    
    success "Temporary user $TEMP_USER created with UID $new_uid."
}
