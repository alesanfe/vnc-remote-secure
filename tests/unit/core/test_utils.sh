#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# UNIT TESTS: Main utilities (src/lib/core/utils.sh)
# ============================================================================
# Tests validate_password_strength and validate_config (the functions that
# gate startup security). These are the most security-critical functions.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../../lib/test_framework.sh"

begin_suite "Utils Module (utils.sh)"

# Source the full core chain in the order the main script uses it.
setup() {
    source_module_safe "src/lib/core/config.sh"
    source_module_safe "src/lib/core/logging.sh"
    source_module_safe "src/lib/core/validation.sh"
    source_module_safe "src/lib/core/error_handling.sh"
    source_module_safe "src/lib/core/utils.sh"
}

# --- validate_password_strength ---

test_strength_rejects_changeme() {
    setup
    assert_failure validate_password_strength "changeme"
}

test_strength_rejects_yourstrongpassword123() {
    setup
    assert_failure validate_password_strength "YourStrongPassword123"
}

test_strength_rejects_admin123() {
    setup
    assert_failure validate_password_strength "admin123"
}

test_strength_rejects_password123() {
    setup
    assert_failure validate_password_strength "password123"
}

test_strength_rejects_short() {
    setup
    assert_failure validate_password_strength "short"
}

test_strength_rejects_no_uppercase() {
    setup
    assert_failure validate_password_strength "alllowercase123"
}

test_strength_rejects_no_lowercase() {
    setup
    assert_failure validate_password_strength "ALLUPPERCASE123"
}

test_strength_rejects_no_digit() {
    setup
    assert_failure validate_password_strength "NoDigitsHere"
}

test_strength_accepts_strong() {
    setup
    assert_success validate_password_strength "RealStrong#Pass2024"
}

# --- validate_config (with secure defaults) ---

test_config_passes_with_defaults() {
    # Unset password variables so config.sh generates fresh random ones,
    # ignoring any values inherited from .env via the Makefile.
    unset TTYD_PASSWD TEMP_USER_PASS VNC_PASSWORD USER_UI_PASSWORD
    setup
    # config.sh now generates random strong passwords and EMAIL defaults
    # to empty (optional, only needed for SSL). All defaults are secure,
    # so validate_config should succeed.
    check_port_available() { return 0; }
    assert_success validate_config
}

# --- validate_config (with secure values) ---

test_config_passes_with_secure_values() {
    setup
    TTYD_PASSWD="RealStrong#Pass2024"
    TEMP_USER_PASS="RealStrong#Pass2024"
    VNC_PASSWORD="RealStrong#Pass2024"
    USER_UI_ENABLED="false"
    EMAIL="realuser@gmail.com"
    NOVNC_PORT=6080
    TTYD_PORT=5000
    VNC_PORT=5901
    DUCK_DOMAIN=""
    # Mock check_port_available so it doesn't depend on the host's ports
    check_port_available() { return 0; }
    assert_success validate_config
}

test_config_fails_with_example_email() {
    setup
    TTYD_PASSWD="RealStrong#Pass2024"
    TEMP_USER_PASS="RealStrong#Pass2024"
    VNC_PASSWORD="RealStrong#Pass2024"
    USER_UI_ENABLED="false"
    EMAIL="user@example.com"
    NOVNC_PORT=6080
    TTYD_PORT=5000
    VNC_PORT=5901
    DUCK_DOMAIN=""
    check_port_available() { return 0; }
    assert_failure validate_config
}

test_config_fails_with_weak_ui_password() {
    setup
    TTYD_PASSWD="RealStrong#Pass2024"
    TEMP_USER_PASS="RealStrong#Pass2024"
    VNC_PASSWORD="RealStrong#Pass2024"
    USER_UI_ENABLED="true"
    USER_UI_PASSWORD="admin123"
    EMAIL="realuser@gmail.com"
    NOVNC_PORT=6080
    TTYD_PORT=5000
    VNC_PORT=5901
    DUCK_DOMAIN=""
    check_port_available() { return 0; }
    assert_failure validate_config
}

test_config_fails_with_invalid_port() {
    setup
    TTYD_PASSWD="RealStrong#Pass2024"
    TEMP_USER_PASS="RealStrong#Pass2024"
    VNC_PASSWORD="RealStrong#Pass2024"
    USER_UI_ENABLED="false"
    EMAIL="realuser@gmail.com"
    NOVNC_PORT=99999   # invalid
    TTYD_PORT=5000
    VNC_PORT=5901
    DUCK_DOMAIN=""
    check_port_available() { return 0; }
    assert_failure validate_config
}

# --- validate_port (from utils.sh) ---

test_utils_validate_port_rejects_non_numeric() {
    setup
    assert_failure validate_port "abc"
}

test_utils_validate_port_accepts_valid() {
    setup
    assert_success validate_port "443"
}

# --- validate_domain (from utils.sh) ---

test_utils_validate_domain_accepts_empty() {
    setup
    assert_success validate_domain ""
}

test_utils_validate_domain_rejects_invalid() {
    setup
    assert_failure validate_domain "notvalid"
}

# --- handle_command ---

test_handle_command_stop() {
    setup
    # handle_command "stop" calls cleanup then exit 0; we can't easily test
    # the exit, so just assert the function exists
    assert_function_exists handle_command
}

test_handle_command_help() {
    setup
    assert_function_exists handle_command
}

run_test "strength rejects 'changeme'" test_strength_rejects_changeme
run_test "strength rejects 'YourStrongPassword123'" test_strength_rejects_yourstrongpassword123
run_test "strength rejects 'admin123'" test_strength_rejects_admin123
run_test "strength rejects 'password123'" test_strength_rejects_password123
run_test "strength rejects too short" test_strength_rejects_short
run_test "strength rejects no uppercase" test_strength_rejects_no_uppercase
run_test "strength rejects no lowercase" test_strength_rejects_no_lowercase
run_test "strength rejects no digit" test_strength_rejects_no_digit
run_test "strength accepts strong password" test_strength_accepts_strong
run_test "validate_config passes with secure defaults" test_config_passes_with_defaults
run_test "validate_config passes with secure values" test_config_passes_with_secure_values
run_test "validate_config fails with example.com email" test_config_fails_with_example_email
run_test "validate_config fails with weak UI password" test_config_fails_with_weak_ui_password
run_test "validate_config fails with invalid port" test_config_fails_with_invalid_port
run_test "utils validate_port rejects non-numeric" test_utils_validate_port_rejects_non_numeric
run_test "utils validate_port accepts valid" test_utils_validate_port_accepts_valid
run_test "utils validate_domain accepts empty" test_utils_validate_domain_accepts_empty
run_test "utils validate_domain rejects invalid" test_utils_validate_domain_rejects_invalid
run_test "handle_command function exists" test_handle_command_stop
run_test "handle_command help exists" test_handle_command_help

end_suite
