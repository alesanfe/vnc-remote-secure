#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# INPUT VALIDATION SYSTEM
# ============================================================================

# Validation result structure (global so it survives across function scopes)
declare -gA VALIDATION_ERRORS

# Core validation function
# Arguments:
#   $1 - Value to validate
#   $2 - Validation type
#   $3 - Field name (for error messages)
#   $4 - Additional parameters (optional)
# Returns:
#   0 if valid, 1 if invalid
validate_input() {
    local value="$1"
    local validation_type="$2"
    local field_name="$3"
    local params="$4"

    case "$validation_type" in
        "password") validate_password "$value" "$field_name" "$params" ;;
        "port") validate_port "$value" "$field_name" ;;
        "domain") validate_domain "$value" "$field_name" ;;
        "email") validate_email "$value" "$field_name" ;;
        "username") validate_username "$value" "$field_name" ;;
        "path") validate_path "$value" "$field_name" ;;
        "url") validate_url "$value" "$field_name" ;;
        "number") validate_number "$value" "$field_name" "$params" ;;
        "boolean") validate_boolean "$value" "$field_name" ;;
        "required") validate_required "$value" "$field_name" ;;
        *)
            log_error "Unknown validation type: $validation_type" "VALIDATION"
            return 1
            ;;
    esac
}

# Enhanced password validation
validate_password() {
    local password="$1"
    local field_name="${2:-password}"
    local params="$3"

    # Parse parameters
    local min_length="${params:-8}"
    local require_special="true"
    local require_upper="true"
    local require_lower="true"
    local require_digit="true"

    # Check minimum length
    if [[ ${#password} -lt $min_length ]]; then
        VALIDATION_ERRORS["$field_name"]="Password must be at least $min_length characters"
        return 1
    fi

    # Check for common weak passwords
    local weak_patterns=("password" "123456" "qwerty" "changeme" "admin" "root" "user" "yourstrongpassword" "letmein" "welcome")
    for pattern in "${weak_patterns[@]}"; do
        if [[ "${password,,}" == *"$pattern"* ]]; then
            VALIDATION_ERRORS["$field_name"]="Password is too common and weak"
            return 1
        fi
    done

    # Check character requirements
    if [[ "$require_upper" == "true" ]] && ! [[ "$password" =~ [A-Z] ]]; then
        VALIDATION_ERRORS["$field_name"]="Password must contain at least one uppercase letter"
        return 1
    fi

    if [[ "$require_lower" == "true" ]] && ! [[ "$password" =~ [a-z] ]]; then
        VALIDATION_ERRORS["$field_name"]="Password must contain at least one lowercase letter"
        return 1
    fi

    if [[ "$require_digit" == "true" ]] && ! [[ "$password" =~ [0-9] ]]; then
        VALIDATION_ERRORS["$field_name"]="Password must contain at least one digit"
        return 1
    fi

    if [[ "$require_special" == "true" ]]; then
        # Check for any non-alphanumeric character (simpler and more reliable
        # than enumerating special chars in a regex character class, which
        # breaks on escaped brackets in bash ERE).
        if ! [[ "$password" =~ [^a-zA-Z0-9] ]]; then
            VALIDATION_ERRORS["$field_name"]="Password must contain at least one special character"
            return 1
        fi
    fi

    return 0
}

# Enhanced port validation
validate_port() {
    local port="$1"
    local field_name="${2:-port}"

    # Check if numeric
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Port must be a number"
        return 1
    fi

    # Check if in valid range
    if (( port < 1 || port > 65535 )); then
        VALIDATION_ERRORS["$field_name"]="Port must be between 1 and 65535"
        return 1
    fi

    # Check for privileged ports
    if (( port < 1024 )); then
        log_warn "Port $port is privileged and may require root permissions" "VALIDATION"
    fi

    # Check for well-known ports that might conflict
    local well_known_ports=(22 80 443 3389 5900 5901)
    for well_known in "${well_known_ports[@]}"; do
        if [[ "$port" == "$well_known" ]]; then
            log_warn "Port $port is well-known and may conflict with system services" "VALIDATION"
            break
        fi
    done

    return 0
}

# Enhanced domain validation
validate_domain() {
    local domain="$1"
    local field_name="${2:-domain}"

    # Allow empty domain (SSL disabled)
    if [[ -z "$domain" ]]; then
        return 0
    fi

    # Basic domain validation
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])+$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Invalid domain name format"
        return 1
    fi

    # Check domain length
    if [[ ${#domain} -gt 253 ]]; then
        VALIDATION_ERRORS["$field_name"]="Domain name too long (max 253 characters)"
        return 1
    fi

    # Check for localhost variations
    if [[ "$domain" =~ ^(localhost|127\.0\.0\.1|::1)$ ]]; then
        log_warn "Using localhost domain may cause SSL certificate issues" "VALIDATION"
    fi

    return 0
}

# Email validation
validate_email() {
    local email="$1"
    local field_name="${2:-email}"

    # Basic email validation
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Invalid email format"
        return 1
    fi

    # Check email length
    if [[ ${#email} -gt 254 ]]; then
        VALIDATION_ERRORS["$field_name"]="Email address too long"
        return 1
    fi

    # Check for common invalid domains
    local invalid_domains=("example.com" "test.com" "invalid.com")
    for invalid in "${invalid_domains[@]}"; do
        if [[ "$email" == *"$invalid" ]]; then
            VALIDATION_ERRORS["$field_name"]="Email domain $invalid is not valid for production"
            return 1
        fi
    done

    return 0
}

# Username validation
validate_username() {
    local username="$1"
    local field_name="${2:-username}"

    # Check if empty
    if [[ -z "$username" ]]; then
        VALIDATION_ERRORS["$field_name"]="Username cannot be empty"
        return 1
    fi

    # Check username format
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Username can only contain letters, numbers, underscores, and hyphens"
        return 1
    fi

    # Check username length
    if [[ ${#username} -lt 3 ]]; then
        VALIDATION_ERRORS["$field_name"]="Username must be at least 3 characters"
        return 1
    fi

    if [[ ${#username} -gt 32 ]]; then
        VALIDATION_ERRORS["$field_name"]="Username too long (max 32 characters)"
        return 1
    fi

    # Check for reserved usernames
    local reserved=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "pulse" "speech-dispatcher" "avahi" "saned" "colord" "hplip" "geoclue" "gnome-initial-setup" "gdm")
    for reserved_user in "${reserved[@]}"; do
        if [[ "$username" == "$reserved_user" ]]; then
            VALIDATION_ERRORS["$field_name"]="Username '$username' is reserved by the system"
            return 1
        fi
    done

    # Check if username starts with number or hyphen
    if [[ "$username" =~ ^[0-9-] ]]; then
        VALIDATION_ERRORS["$field_name"]="Username cannot start with a number or hyphen"
        return 1
    fi

    return 0
}

# Path validation
validate_path() {
    local path="$1"
    local field_name="${2:-path}"

    # Check if empty
    if [[ -z "$path" ]]; then
        VALIDATION_ERRORS["$field_name"]="Path cannot be empty"
        return 1
    fi

    # Check for dangerous path components
    if [[ "$path" =~ \.\./|\.\. ]]; then
        VALIDATION_ERRORS["$field_name"]="Path contains potentially dangerous components"
        return 1
    fi

    # Check path length
    if [[ ${#path} -gt 4096 ]]; then
        VALIDATION_ERRORS["$field_name"]="Path too long"
        return 1
    fi

    # If path should exist, check it
    if [[ "$path" =~ ^/ ]] && [[ ! -e "$path" ]]; then
        log_warn "Path '$path' does not exist" "VALIDATION"
    fi

    return 0
}

# URL validation
validate_url() {
    local url="$1"
    local field_name="${2:-url}"

    # Basic URL validation
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9.-]+[a-zA-Z0-9._/-]*$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Invalid URL format"
        return 1
    fi

    # Check for localhost URLs (may be insecure)
    if [[ "$url" =~ (localhost|127\.0\.0\.1|::1) ]]; then
        log_warn "Localhost URL may not be accessible remotely" "VALIDATION"
    fi

    return 0
}

# Number validation
validate_number() {
    local number="$1"
    local field_name="${2:-number}"
    local params="$3"

    # Parse parameters
    local min="${params%%,*}"
    local max="${params##*,}"

    # Check if numeric
    if ! [[ "$number" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
        VALIDATION_ERRORS["$field_name"]="Must be a number"
        return 1
    fi

    # Check range if specified (use bash arithmetic, no external bc dependency)
    if [[ -n "$min" ]] && [[ "$min" != "$params" ]]; then
        local num_int min_int
        num_int="${number%.*}"
        min_int="${min%.*}"
        if (( num_int < min_int )); then
            VALIDATION_ERRORS["$field_name"]="Number must be at least $min"
            return 1
        fi
    fi

    if [[ -n "$max" ]] && [[ "$max" != "$params" ]]; then
        local num_int max_int
        num_int="${number%.*}"
        max_int="${max%.*}"
        if (( num_int > max_int )); then
            VALIDATION_ERRORS["$field_name"]="Number must be at most $max"
            return 1
        fi
    fi

    return 0
}

# Boolean validation
validate_boolean() {
    local value="$1"
    local field_name="${2:-boolean}"

    # Check valid boolean values
    case "${value,,}" in
        "true"|"false"|"yes"|"no"|"1"|"0"|"on"|"off")
            return 0
            ;;
        *)
            VALIDATION_ERRORS["$field_name"]="Must be a boolean value (true/false, yes/no, 1/0, on/off)"
            return 1
            ;;
    esac
}

# Required field validation
validate_required() {
    local value="$1"
    local field_name="${2:-field}"

    if [[ -z "$value" ]]; then
        VALIDATION_ERRORS["$field_name"]="This field is required"
        return 1
    fi

    return 0
}

# Get validation errors
get_validation_errors() {
    for field in "${!VALIDATION_ERRORS[@]}"; do
        echo "$field: ${VALIDATION_ERRORS[$field]}"
    done
}

# Check if there are validation errors
has_validation_errors() {
    [[ ${#VALIDATION_ERRORS[@]} -gt 0 ]]
}

# Clear validation errors
clear_validation_errors() {
    VALIDATION_ERRORS=()
}

# Sanitize input (basic XSS prevention)
sanitize_input() {
    local input="$1"

    # Escape dangerous characters to HTML entities using sed.
    # In sed replacement, \& means literal & (escaped to avoid meaning "matched text").
    printf '%s' "$input" | sed -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

# Validate and sanitize user input
validate_and_sanitize() {
    local input="$1"
    local validation_type="$2"
    local field_name="$3"
    local params="$4"

    # First validate
    if ! validate_input "$input" "$validation_type" "$field_name" "$params"; then
        return 1
    fi

    # Then sanitize
    sanitize_input "$input"
}
