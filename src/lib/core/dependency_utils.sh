#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# DEPENDENCY MANAGEMENT UTILITIES
# ============================================================================

install_dependencies() {
    log_info "Installing required packages" "DEPENDENCIES"

    if ! safe_execute "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq" "Package database update" "retry"; then
        log_error "Failed to update package database" "DEPENDENCIES"
        return 1
    fi

    local packages=(
        "wget"
        "iproute2"
        "lsof"
        "tigervnc-standalone-server"
        "novnc"
        "xfce4"
        "xfce4-goodies"
        "x11-xserver-utils"
        "certbot"
        "python3-certbot-dns-standalone"
        "acl"
    )

    for package in "${packages[@]}"; do
        if ! safe_execute "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $package" "Install $package" "retry"; then
            log_warn "Failed to install $package, continuing..." "DEPENDENCIES"
        fi
    done

    log_success "Dependencies installation completed" "DEPENDENCIES"
}

detect_ttyd_arch() {
    local arch
    arch=$(uname -m)

    case "$arch" in
        armv7l|armhf) echo "armhf" ;;
        aarch64|arm64) echo "arm64" ;;
        x86_64) echo "amd64" ;;
        *)
            log_error "Unsupported architecture: $arch" "DEPENDENCIES"
            return 1
            ;;
    esac
}

install_ttyd() {
    if command -v ttyd &>/dev/null; then
        log_success "ttyd is already installed" "DEPENDENCIES"
        return 0
    fi

    log_info "Installing ttyd" "DEPENDENCIES"

    # Clean up any existing downloads
    safe_cleanup "rm -f ttyd.armhf* 2>/dev/null || true" "ttyd cleanup files"

    local ttyd_arch
    ttyd_arch=$(detect_ttyd_arch) || return 1

    log_info "Downloading ttyd for $(uname -m)" "DEPENDENCIES"

    # Try primary download
    if safe_execute "wget -q 'https://github.com/tsl0922/ttyd/releases/download/1.7.4/ttyd.linux-$ttyd_arch' -O ttyd" "ttyd download (1.7.4)" "continue"; then
        # Verify download by checking the file is a valid ELF binary
        if file ttyd | grep -q 'ELF'; then
            log_success "ttyd downloaded and verified as ELF binary" "DEPENDENCIES"
        else
            log_warn "Downloaded ttyd is not a valid ELF binary" "DEPENDENCIES"
            return 1
        fi
    else
        log_warn "Primary download failed, trying fallback version" "DEPENDENCIES"

        # Try fallback version
        if ! safe_execute "wget -q 'https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.$ttyd_arch' -O ttyd" "ttyd download (1.6.3)" "continue"; then
            log_error "Failed to download ttyd from all sources" "DEPENDENCIES"
            return 1
        fi
        # Verify fallback download is a valid ELF binary
        if ! file ttyd | grep -q 'ELF'; then
            log_warn "Downloaded ttyd (fallback) is not a valid ELF binary" "DEPENDENCIES"
            return 1
        fi
    fi

    # Install ttyd
    if safe_execute "sudo cp ttyd /usr/local/bin/ttyd && sudo chmod +x /usr/local/bin/ttyd" "ttyd installation" "continue"; then
        safe_cleanup "rm -f ttyd 2>/dev/null || true" "ttyd temporary file"
        log_success "ttyd installed successfully" "DEPENDENCIES"
        return 0
    else
        log_error "Failed to install ttyd" "DEPENDENCIES"
        return 1
    fi
}

check_package_installed() {
    local package="$1"

    if dpkg -l | grep -q "^ii  $package "; then
        return 0
    else
        return 1
    fi
}

install_package_if_missing() {
    local package="$1"

    if check_package_installed "$package"; then
        log_debug "Package $package is already installed" "DEPENDENCIES"
        return 0
    else
        log_info "Installing package: $package" "DEPENDENCIES"

        if safe_execute "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $package" "Install $package" "retry"; then
            log_success "Package $package installed successfully" "DEPENDENCIES"
            return 0
        else
            log_error "Failed to install package: $package" "DEPENDENCIES"
            return 1
        fi
    fi
}

validate_dependencies() {
    local missing_deps=()
    local required_commands=("wget" "lsof" "tigervncserver" "certbot")

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}" "DEPENDENCIES"
        return 1
    else
        log_success "All required dependencies are available" "DEPENDENCIES"
        return 0
    fi
}

update_system_packages() {
    log_info "Updating system packages" "DEPENDENCIES"

    if safe_execute "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq" "Package list update" "retry"; then
        if safe_execute "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq" "System upgrade" "retry"; then
            log_success "System packages updated successfully" "DEPENDENCIES"
            return 0
        else
            log_warn "System upgrade completed with some issues" "DEPENDENCIES"
            return 1
        fi
    else
        log_error "Failed to update package list" "DEPENDENCIES"
        return 1
    fi
}
