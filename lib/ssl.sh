#!/bin/bash
# ============================================================================
# SSL MANAGEMENT
# ============================================================================

check_ssl_expiry() {
    if [[ ! -f "$SSL_CERT" ]]; then
        return 1
    fi
    
    local expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
    [[ -z "$expire_date" ]] && return 1
    
    local expire_sec=$(date --date="$expire_date" +%s 2>/dev/null || echo 0)
    local now_sec=$(date +%s)
    local days_left=$(( (expire_sec - now_sec) / 86400 ))
    
    if (( days_left > SSL_RENEW_DAYS )); then
        success "SSL certificate is still valid for $days_left days. Skipping renewal."
        return 0
    else
        warn "SSL certificate expires in $days_left days. Attempting renewal..."
        return 1
    fi
}

generate_ssl_certificates() {
    log "yellow" "Removing old SSL certificates..." "🧨"
    sudo rm -rf ./ssl 2>/dev/null || true
    sudo rm -f "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true
    
    log "yellow" "Attempting to generate new SSL certificates..." "🔐"
    install_dependencies
    
    mkdir -p ./ssl
    
    if sudo certbot certonly --standalone --preferred-challenges http \
        -d "$DUCK_DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email \
        --non-interactive --quiet --rsa-key-size 4096 --must-staple 2>&1; then
        success "SSL certificate generated successfully."
        return 0
    else
        die "Failed to generate SSL certificate."
    fi
}

copy_ssl_certificates() {
    if [[ -f "$DUCK_DIR/fullchain.pem" && -f "$DUCK_DIR/privkey.pem" ]]; then
        log "yellow" "Using existing SSL certificates from Let's Encrypt..." "📂"
        sudo cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT"
        sudo cp "$DUCK_DIR/privkey.pem" "$SSL_KEY"
        return 0
    fi
    return 1
}

setup_ssl() {
    [[ -z "$DUCK_DOMAIN" ]] && {
        warn "No domain provided. Running without SSL."
        export DISABLE_SSL=true
        return
    }
    
    if check_ssl_expiry; then
        export DISABLE_SSL=false
        return
    fi
    
    if generate_ssl_certificates; then
        sudo cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT"
        sudo cp "$DUCK_DIR/privkey.pem" "$SSL_KEY"
        export DISABLE_SSL=false
    elif copy_ssl_certificates; then
        export DISABLE_SSL=false
    else
        warn "No valid SSL certificates found. Disabling SSL."
        export DISABLE_SSL=true
        return
    fi
    
    success "SSL certificates are ready."
}
