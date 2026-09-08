#!/bin/bash
# ============================================================================
# UNIT TESTS: Security modules (ssl.sh, user.sh, fail2ban.sh)
# ============================================================================
# Tests functions that can run without root: get_next_uid, check_ssl_expiry
# with non-existent cert, and function existence checks.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../../lib/test_framework.sh"

begin_suite "Security Modules (ssl.sh, user.sh, fail2ban.sh)"

setup() {
    source_module_safe "src/lib/core/config.sh"
    source_module_safe "src/lib/core/logging.sh"
    source_module_safe "src/lib/core/validation.sh"
    source_module_safe "src/lib/core/error_handling.sh"
    source_module_safe "src/lib/core/utils.sh"
    source_module_safe "src/lib/security/ssl.sh"
    source_module_safe "src/lib/security/user.sh"
    source_module_safe "src/lib/security/fail2ban.sh"
}

# --- Function existence ---

test_ssl_functions_exist() {
    setup
    assert_function_exists check_ssl_expiry
    assert_function_exists generate_ssl_certificates
    assert_function_exists fix_ssl_permissions
    assert_function_exists setup_ssl
}

test_user_functions_exist() {
    setup
    assert_function_exists get_next_uid
    assert_function_exists create_temp_user
}

test_fail2ban_functions_exist() {
    setup
    assert_function_exists install_fail2ban
    assert_function_exists configure_fail2ban
    assert_function_exists start_fail2ban
    assert_function_exists check_fail2ban_status
}

# --- get_next_uid ---

test_get_next_uid_returns_number() {
    setup
    local uid
    uid=$(get_next_uid 2>/dev/null)
    # Should be a numeric value
    if [[ "$uid" =~ ^[0-9]+$ ]]; then
        return 0
    else
        echo "    get_next_uid returned non-numeric: '$uid'"
        return 1
    fi
}

test_get_next_uid_in_valid_range() {
    setup
    local uid
    uid=$(get_next_uid 2>/dev/null)
    if (( uid >= 1000 && uid <= 60000 )); then
        return 0
    else
        echo "    get_next_uid out of range [1000-60000]: $uid"
        return 1
    fi
}

# --- check_ssl_expiry ---

test_check_ssl_expiry_no_cert() {
    setup
    # Point SSL_CERT to a non-existent file
    SSL_CERT="/tmp/nonexistent-cert-$$ .pem"
    assert_failure check_ssl_expiry
}

# --- config defaults for fail2ban ---

test_fail2ban_config_defaults() {
    setup
    assert_eq "false" "$FAIL2BAN_ENABLED" "FAIL2BAN_ENABLED should default to false"
    assert_eq "5" "$FAIL2BAN_MAX_RETRY" "FAIL2BAN_MAX_RETRY should default to 5"
    assert_eq "600" "$FAIL2BAN_FINDTIME" "FAIL2BAN_FINDTIME should default to 600"
    assert_eq "3600" "$FAIL2BAN_BANTIME" "FAIL2BAN_BANTIME should default to 3600"
}

run_test "SSL functions are defined" test_ssl_functions_exist
run_test "User functions are defined" test_user_functions_exist
run_test "Fail2ban functions are defined" test_fail2ban_functions_exist
run_test "get_next_uid returns a number" test_get_next_uid_returns_number
run_test "get_next_uid is in valid range [1000-60000]" test_get_next_uid_in_valid_range
run_test "check_ssl_expiry fails when cert missing" test_check_ssl_expiry_no_cert
run_test "Fail2ban config defaults are correct" test_fail2ban_config_defaults

end_suite
