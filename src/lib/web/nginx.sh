#!/bin/bash
# shellcheck disable=SC2155,SC2034
set -e
set -o pipefail
# ============================================================================
# NGINX REVERSE PROXY CONFIGURATION
# ============================================================================

install_nginx() {
    if command -v nginx &>/dev/null; then
        success "nginx is already installed."
        return
    fi
    
    log "yellow" "Installing nginx..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx > /dev/null 2>&1
    success "nginx installed successfully."
}

configure_nginx() {
    log "cyan" "Configuring nginx reverse proxy..."
    
    local nginx_conf="/etc/nginx/sites-available/rpi-vnc"
    local nginx_enabled="/etc/nginx/sites-enabled/rpi-vnc"
    
    # Remove default site if it exists
    if [[ -f "/etc/nginx/sites-enabled/default" ]]; then
        sudo rm -f /etc/nginx/sites-enabled/default
        log "blue" "Removed default nginx site"
    fi
    
    # Create nginx configuration from template
    local template_file="$PROJECT_DIR/src/config/nginx.conf"
    
    if [[ -f "$template_file" ]]; then
        # Load .env file if it exists
        if [[ -f "$PROJECT_DIR/.env" ]]; then
            source "$PROJECT_DIR/.env"
        fi
        
        # Set default values for environment variables
        export DUCK_DOMAIN="${DUCK_DOMAIN:-localhost}"
        
        # Convert SSL paths to absolute paths
        if [[ -n "$SSL_CERT" && ! "$SSL_CERT" = /* ]]; then
            # Remove leading ./ if present
            SSL_CERT_CLEAN="${SSL_CERT#./}"
            export SSL_CERT="$PROJECT_DIR/$SSL_CERT_CLEAN"
        fi
        if [[ -z "$SSL_CERT" ]]; then
            export SSL_CERT="$PROJECT_DIR/data/ssl/fullchain.pem"
        fi
        
        if [[ -n "$SSL_KEY" && ! "$SSL_KEY" = /* ]]; then
            # Remove leading ./ if present
            SSL_KEY_CLEAN="${SSL_KEY#./}"
            export SSL_KEY="$PROJECT_DIR/$SSL_KEY_CLEAN"
        fi
        if [[ -z "$SSL_KEY" ]]; then
            export SSL_KEY="$PROJECT_DIR/data/ssl/privkey.pem"
        fi
        
        # Process template with environment variables (only substitute specific vars)
        envsubst '\$DUCK_DOMAIN|\$SSL_CERT|\$SSL_KEY' < "$template_file" | sudo tee "$nginx_conf" > /dev/null
        log "blue" "Nginx configuration created from template"
    else
        log "red" "Nginx template not found at $template_file"
        return 1
    fi
    
    # Enable the site
    sudo ln -sf "$nginx_conf" "$nginx_enabled"
    
    # Test nginx configuration
    if sudo nginx -t 2>/dev/null; then
        success "nginx configuration is valid."
    else
        sudo nginx -t
        die "nginx configuration test failed."
    fi
}

start_nginx() {
    log "cyan" "Starting nginx..."
    sudo systemctl enable nginx > /dev/null 2>&1
    sudo systemctl restart nginx
    success "nginx started successfully."
}

stop_nginx() {
    log "yellow" "Stopping nginx..."
    sudo systemctl stop nginx 2>/dev/null || true
    success "nginx stopped."
}

restart_nginx() {
    log "cyan" "Restarting nginx..."
    sudo systemctl restart nginx
    success "nginx restarted successfully."
}

reload_nginx() {
    log "cyan" "Reloading nginx configuration..."
    sudo systemctl reload nginx 2>/dev/null || sudo systemctl restart nginx
    success "nginx reloaded successfully."
}

nginx_status() {
    if sudo systemctl is-active --quiet nginx; then
        log "green" "nginx is running"
        sudo systemctl status nginx --no-pager -l
    else
        log "red" "nginx is not running"
    fi
}
