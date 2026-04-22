#!/bin/bash
# shellcheck disable=SC2155
set -o pipefail
# ============================================================================
# SSL MANAGEMENT
# ============================================================================

check_ssl_expiry() {
    if [[ ! -f "$SSL_CERT" ]]; then
        return 1
    fi

    # Use openssl -checkend for portable date validation
    # Check if certificate expires within SSL_RENEW_DAYS days
    local check_end_seconds=$((SSL_RENEW_DAYS * 86400))

    if openssl x509 -checkend "$check_end_seconds" -noout -in "$SSL_CERT" 2>/dev/null; then
        # Certificate is still valid for more than SSL_RENEW_DAYS
        local expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        log "green" "✓ SSL certificate is valid (expires: $expire_date)"
        return 0
    else
        # Certificate expires within SSL_RENEW_DAYS or is already expired
        local expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        log "yellow" "⚠️  SSL certificate expires soon or is expired (expires: $expire_date)"
        log "cyan" "🔄 Attempting certificate renewal..."
        return 1
    fi
}

generate_ssl_certificates() {
    log "yellow" "🧨 Cleaning up old SSL certificates..."
    sudo rm -rf ./ssl 2>/dev/null || true
    sudo rm -f "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true

    log "cyan" "🔐 Generating new SSL certificates for $DUCK_DOMAIN"
    install_dependencies

    mkdir -p ./ssl

    # Check if port 80 is available
    if sudo netstat -tulpn 2>/dev/null | grep -q ':80 '; then
        log "red" "❌ Port 80 is already in use"
        log "yellow" "💡 To use SSL, stop the service using port 80 or configure DNS challenge"
        return 1
    fi

    log "blue" "📡 Requesting certificate from Let's Encrypt..."
    if sudo certbot certonly --standalone --preferred-challenges http \
        -d "$DUCK_DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email \
        --non-interactive --quiet --rsa-key-size 4096 --must-staple 2>&1; then
        success "✓ SSL certificate generated successfully"
        fix_ssl_permissions
        return 0
    else
        log "red" "❌ Failed to generate SSL certificate"
        log "yellow" "⚠️  Continuing without SSL encryption"
        return 1
    fi
}

fix_ssl_permissions() {
    log "yellow" "🔧 Fixing SSL certificate permissions for $TEMP_USER..."

    # Check if user exists first
    if ! id "$TEMP_USER" &>/dev/null; then
        log "yellow" "⚠️  User $TEMP_USER does not exist yet, skipping permission fix"
        return 0
    fi

    if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
        # Get the user's primary group
        local user_group=$(id -gn "$TEMP_USER")

        # Ensure the SSL directory exists and has correct permissions
        sudo mkdir -p "$(dirname "$SSL_CERT")"
        sudo chown "$TEMP_USER:$user_group" "$(dirname "$SSL_CERT")"
        sudo chmod 755 "$(dirname "$SSL_CERT")"

        # Set ownership and permissions for certificate files
        sudo chown "$TEMP_USER:$user_group" "$SSL_CERT" "$SSL_KEY"
        sudo chmod 644 "$SSL_CERT"
        sudo chmod 600 "$SSL_KEY"

        # Verify permissions
        if sudo -u "$TEMP_USER" test -r "$SSL_CERT" && sudo -u "$TEMP_USER" test -r "$SSL_KEY"; then
            success "✓ SSL certificate permissions fixed and verified"
            return 0
        else
            log "red" "❌ Failed to verify SSL certificate permissions for $TEMP_USER"
            return 1
        fi
    else
        log "red" "❌ SSL certificate files not found at $SSL_CERT and $SSL_KEY"
        return 1
    fi
}

copy_ssl_certificates() {
    if [[ -f "$DUCK_DIR/fullchain.pem" && -f "$DUCK_DIR/privkey.pem" ]]; then
        log "yellow" "Using existing SSL certificates from Let's Encrypt..." "📂"
        sudo cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT"
        sudo cp "$DUCK_DIR/privkey.pem" "$SSL_KEY"
        fix_ssl_permissions
        return 0
    fi
    return 1
}

setup_ssl() {
    [[ -z "$DUCK_DOMAIN" ]] && {
        log "yellow" "⚠️  No domain provided. Running without SSL."
        export DISABLE_SSL=true
        return
    }

    if check_ssl_expiry; then
        # Certificate is valid, but still need to verify permissions
        log "cyan" "🔐 SSL certificate is valid, verifying permissions..."
        if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
            fix_ssl_permissions
        else
            log "yellow" "⚠️  SSL certificate files not found, attempting to copy from Let's Encrypt..."
            if copy_ssl_certificates; then
                export DISABLE_SSL=false
                success "✓ SSL certificates copied and permissions fixed"
            else
                log "yellow" "⚠️  No valid SSL certificates found. Running without SSL."
                export DISABLE_SSL=true
                return
            fi
        fi
        export DISABLE_SSL=false
        return
    fi

    if generate_ssl_certificates; then
        sudo cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT"
        sudo cp "$DUCK_DIR/privkey.pem" "$SSL_KEY"
        fix_ssl_permissions
        export DISABLE_SSL=false
        success "✓ SSL certificates configured successfully"
    elif copy_ssl_certificates; then
        export DISABLE_SSL=false
        success "✓ SSL certificates copied from existing installation"
    else
        log "yellow" "⚠️  No valid SSL certificates found. Running without SSL."
        export DISABLE_SSL=true
        return
    fi
}
