#!/bin/bash
# shellcheck disable=SC2155,SC2034
# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

configure_vnc_password() {
    local user="$1"
    local password="$VNC_PASSWORD"

    log "cyan" "Setting VNC password for $user..."

    # Create .vnc directory if it doesn't exist
    sudo mkdir -p "/home/$user/.vnc"
    log "blue" "Created .vnc directory"

    # Check which vncpasswd command is available
    local vncpasswd_cmd=""
    if command -v tigervncpasswd &>/dev/null; then
        vncpasswd_cmd="tigervncpasswd"
        log "blue" "Using tigervncpasswd"
    elif command -v vncpasswd &>/dev/null; then
        vncpasswd_cmd="vncpasswd"
        log "blue" "Using vncpasswd"
    else
        log "red" "Neither tigervncpasswd nor vncpasswd found"
        die "VNC password utility not found. Please install tigervnc-common or vncpasswd"
    fi

    # Set VNC password using the available command
    log "blue" "Generating VNC password file..."
    if ! echo "$password" | sudo "$vncpasswd_cmd" -f | sudo tee "/home/$user/.vnc/passwd" > /dev/null; then
        log "red" "Failed to generate VNC password file"
        die "$vncpasswd_cmd command failed"
    fi

    # Fix ownership and permissions
    local user_group
    user_group=$(id -gn "$user")
    sudo chown -R "$user:$user_group" "/home/$user/.vnc"
    sudo chmod 700 "/home/$user/.vnc"
    sudo chmod 600 "/home/$user/.vnc/passwd"

    log "blue" "Fixed ownership and permissions for .vnc directory"
    success "VNC password configured for $user"
}

configure_novnc() {
    if [[ -f "/usr/share/novnc/vnc.html" && ! -f "/usr/share/novnc/index.html" ]]; then
        sudo cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
    fi
}

start_ttyd() {
    log "cyan" "Starting terminal service (ttyd)..."
    install_ttyd

    # Determine bind address based on nginx status and security profile.
    # In hardened profiles, always bind to localhost even if nginx is
    # disabled (defense in depth).
    local bind_address="0.0.0.0"
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        bind_address="127.0.0.1"
        log "blue" "Binding to localhost (nginx will handle external access)"
    fi
    # Harden: force localhost in non-development profiles.
    if [[ "$SECURITY_PROFILE" == "public-hardened" ]] || \
       [[ "$SECURITY_PROFILE" == "private-overlay" ]] || \
       [[ "$SECURITY_PROFILE" == "trusted-lan" ]]; then
        if [[ "$bind_address" != "127.0.0.1" ]]; then
            log "yellow" "Security profile $SECURITY_PROFILE requires localhost bind — overriding"
            bind_address="127.0.0.1"
        fi
    fi

    # Write credentials to a temp file with restricted permissions to avoid
    # exposing the password in the process list (ps aux).
    local cred_file
    cred_file=$(mktemp /tmp/.ttyd-cred.XXXXXX)
    chmod 600 "$cred_file"
    printf '%s:%s' "$TTYD_USERNAME" "$TTYD_PASSWD" > "$cred_file"

    # Wrapper script that reads credentials from file and execs ttyd
    local wrapper
    wrapper=$(mktemp /tmp/.ttyd-launch.XXXXXX)
    cat > "$wrapper" << 'TTYD_WRAPPER'
#!/bin/bash
cred_file="$1"; shift
cred=$(cat "$cred_file")
rm -f "$cred_file"
exec ttyd -c "$cred" "$@"
TTYD_WRAPPER
    chmod 700 "$wrapper"

    # Fix ownership so TEMP_USER can read cred_file and execute wrapper
    local user_group
    user_group=$(id -gn "$TEMP_USER")
    sudo chown "$TEMP_USER:$user_group" "$cred_file" "$wrapper"

    if [[ "$DISABLE_SSL" == true ]] || [[ "$NGINX_ENABLED" == "true" ]]; then
        log "yellow" "Starting ttyd WITHOUT SSL encryption (nginx handles SSL when enabled)"
        sudo -u "$TEMP_USER" "$wrapper" "$cred_file" -p "$TTYD_PORT" -a "$bind_address" bash >/dev/null 2>&1 &
    else
        log "green" "Starting ttyd WITH SSL encryption"
        # Validate SSL certificate files exist before attempting to start
        if [[ ! -f "$SSL_CERT" || ! -f "$SSL_KEY" ]]; then
            log "red" "SSL certificate or key not found: $SSL_CERT / $SSL_KEY"
            rm -f "$cred_file" "$wrapper" 2>/dev/null
            return 1
        fi
        # Ensure SSL certificates have correct permissions
        user_group=$(id -gn "$TEMP_USER")
        sudo chown "$TEMP_USER:$user_group" "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true
        sudo chmod 644 "$SSL_CERT" 2>/dev/null || true
        sudo chmod 600 "$SSL_KEY" 2>/dev/null || true
        sudo -u "$TEMP_USER" "$wrapper" "$cred_file" -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" \
            -p "$TTYD_PORT" -a "$bind_address" bash >/dev/null 2>&1 &
    fi
    # Clean up wrapper after a short delay (ttyd has already read credentials)
    ( sleep 5 && rm -f "$wrapper" 2>/dev/null ) &
    sleep 2
    # Verify ttyd is actually listening
    if lsof -i :"$TTYD_PORT" >/dev/null 2>&1; then
        success "Terminal service started on port $TTYD_PORT"
    else
        log "red" "ttyd failed to start on port $TTYD_PORT"
        rm -f "$cred_file" "$wrapper" 2>/dev/null
        return 1
    fi
}

start_vnc_server() {
    log "cyan" "Starting VNC server for $TEMP_USER..."

    # Configure VNC password
    configure_vnc_password "$TEMP_USER"

    # Kill existing VNC server if running
    if sudo -u "$TEMP_USER" vncserver -list 2>/dev/null | grep -q "$VNC_DISPLAY"; then
        log "yellow" "Removing existing VNC server on $VNC_DISPLAY"
        sudo -u "$TEMP_USER" vncserver -kill "$VNC_DISPLAY" 2>/dev/null || true
        sleep 1
    fi

    log "blue" "Display: $VNC_DISPLAY | Resolution: $VNC_GEOMETRY | Depth: $VNC_DEPTH"

    # Bind VNC to localhost when nginx is enabled (nginx proxies external access).
    # When nginx is disabled (development mode), bind to all interfaces for direct access.
    local vnc_localhost="yes"
    if [[ "$NGINX_ENABLED" != "true" ]]; then
        vnc_localhost="no"
        log "yellow" "VNC binding to all interfaces (nginx disabled, development mode)"
    else
        log "blue" "VNC binding to localhost (nginx will handle external access)"
    fi

    if sudo -u "$TEMP_USER" tigervncserver "$VNC_DISPLAY" -geometry "$VNC_GEOMETRY" \
        -depth "$VNC_DEPTH" -rfbport "$VNC_PORT" -SecurityTypes VncAuth -localhost "$vnc_localhost" >/dev/null 2>&1; then
        success "VNC server started successfully on display $VNC_DISPLAY"
    else
        die "Failed to start VNC server."
    fi
}

start_novnc() {
    log "cyan" "Starting web VNC interface (noVNC)..."
    configure_novnc

    # Determine bind address based on nginx status and security profile.
    # In hardened profiles, always bind to localhost even if nginx is
    # disabled (defense in depth).
    local bind_address="0.0.0.0"
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        bind_address="127.0.0.1"
        log "blue" "Binding to localhost (nginx will handle external access)"
    fi
    # Harden: force localhost in non-development profiles.
    if [[ "$SECURITY_PROFILE" == "public-hardened" ]] || \
       [[ "$SECURITY_PROFILE" == "private-overlay" ]] || \
       [[ "$SECURITY_PROFILE" == "trusted-lan" ]]; then
        if [[ "$bind_address" != "127.0.0.1" ]]; then
            log "yellow" "Security profile $SECURITY_PROFILE requires localhost bind — overriding"
            bind_address="127.0.0.1"
        fi
    fi

    if [[ "$DISABLE_SSL" == true ]] || [[ "$NGINX_ENABLED" == "true" ]]; then
        log "yellow" "Starting noVNC WITHOUT SSL encryption (nginx handles SSL when enabled)"
        sudo -u "$TEMP_USER" /usr/share/novnc/utils/novnc_proxy \
            --vnc "127.0.0.1:$VNC_PORT" --listen "$bind_address:$NOVNC_PORT" >/dev/null 2>&1 &
    else
        log "green" "Starting noVNC WITH SSL encryption"
        # Ensure SSL certificates have correct permissions
        if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
            local user_group
            user_group=$(id -gn "$TEMP_USER")
            sudo chown "$TEMP_USER:$user_group" "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true
            sudo chmod 644 "$SSL_CERT" 2>/dev/null || true
            sudo chmod 600 "$SSL_KEY" 2>/dev/null || true
        fi
        sudo -u "$TEMP_USER" SSL_CERT="$SSL_CERT" SSL_KEY="$SSL_KEY" \
            /usr/share/novnc/utils/novnc_proxy \
            --vnc "127.0.0.1:$VNC_PORT" --listen "$bind_address:$NOVNC_PORT" \
            --cert "$SSL_CERT" --key "$SSL_KEY" --ssl-only >/dev/null 2>&1 &
    fi
    sleep 2
    # Verify noVNC is actually listening
    if lsof -i :"$NOVNC_PORT" >/dev/null 2>&1; then
        success "Web VNC interface started on port $NOVNC_PORT"
    else
        log "red" "noVNC failed to start on port $NOVNC_PORT"
        return 1
    fi
}

