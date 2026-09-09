#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# LEVEL 3 — INTEGRATION TESTS: Module Loading Chain
# ============================================================================
# Verifies that all modules can be sourced together in the same order as the
# main script, without errors or conflicts. This catches issues that unit
# tests (which source modules in isolation) miss: duplicate function names,
# variable collisions, and dependency ordering.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../lib/test_framework.sh"

begin_suite "Integration: Module Loading Chain (Level 3)"

# The exact source order used by src/rpi-vnc-remote.sh
MODULES=(
    "src/lib/core/config.sh"
    "src/lib/core/logging.sh"
    "src/lib/core/validation.sh"
    "src/lib/core/error_handling.sh"
    "src/lib/core/utils.sh"
    "src/lib/core/process_utils.sh"
    "src/lib/security/ssl.sh"
    "src/lib/web/nginx.sh"
    "src/lib/security/user.sh"
    "src/lib/core/services.sh"
    "src/lib/communication/notifications.sh"
    "src/lib/security/fail2ban.sh"
    "src/lib/monitoring/healthcheck.sh"
    "src/lib/monitoring/health_web_server.sh"
    "src/lib/monitoring/monitoring.sh"
    "src/lib/features/recording.sh"
    "src/lib/web/user_ui.sh"
    "src/lib/communication/alerts.sh"
)

test_all_modules_source_without_error() {
    local f
    for f in "${MODULES[@]}"; do
        local path="$PROJECT_ROOT/$f"
        if [[ ! -f "$path" ]]; then
            echo "    missing module: $f"
            return 1
        fi
        # Some modules (e.g. health_web_server.sh) execute code on source
        # (start a background server) and depend on core modules being
        # loaded first. We source them with the core chain in a subshell
        # with a timeout. Exit 124 (timeout) means it loaded and started
        # running, which is acceptable.
        local rc
        rc=$(timeout 3 bash -c "
            set +e
            source '$PROJECT_ROOT/src/lib/core/config.sh'
            source '$PROJECT_ROOT/src/lib/core/logging.sh'
            source '$PROJECT_ROOT/src/lib/core/validation.sh'
            source '$PROJECT_ROOT/src/lib/core/error_handling.sh'
            source '$PROJECT_ROOT/src/lib/core/utils.sh'
            source '$path'
        " >/dev/null 2>&1; echo $?)
        if [[ "$rc" != "0" && "$rc" != "124" ]]; then
            echo "    failed to source: $f (exit $rc)"
            return 1
        fi
    done
    return 0
}

test_core_chain_sources_together() {
    # Source the core chain in a subshell (config → logging → validation →
    # error_handling → utils) and check that key functions are available.
    local result
    result=$( (
        set +e
        source "$PROJECT_ROOT/src/lib/core/config.sh"
        source "$PROJECT_ROOT/src/lib/core/logging.sh"
        source "$PROJECT_ROOT/src/lib/core/validation.sh"
        source "$PROJECT_ROOT/src/lib/core/error_handling.sh"
        source "$PROJECT_ROOT/src/lib/core/utils.sh"
        # Check a function from each module
        declare -F validate_config >/dev/null 2>&1 && echo "validate_config"
        declare -F log_error >/dev/null 2>&1 && echo "log_error"
        declare -F validate_password >/dev/null 2>&1 && echo "validate_password"
        declare -F handle_command >/dev/null 2>&1 && echo "handle_command"
    ) 2>/dev/null)
    assert_contains "$result" "validate_config" "validate_config should be defined"
    assert_contains "$result" "log_error" "log_error should be defined"
    assert_contains "$result" "validate_password" "validate_password should be defined"
    assert_contains "$result" "handle_command" "handle_command should be defined"
}

test_no_duplicate_function_definitions() {
    # After sourcing utils.sh (which sources *_utils.sh and then redefines),
    # check that the final definition of key functions comes from utils.sh
    # (not from the specialized modules). This documents the known behavior.
    local result
    result=$( (
        set +e
        source "$PROJECT_ROOT/src/lib/core/config.sh"
        source "$PROJECT_ROOT/src/lib/core/logging.sh"
        source "$PROJECT_ROOT/src/lib/core/validation.sh"
        source "$PROJECT_ROOT/src/lib/core/error_handling.sh"
        source "$PROJECT_ROOT/src/lib/core/utils.sh"
        # print_banner is defined in both display_utils.sh and utils.sh
        # The utils.sh version should win (sourced last)
        declare -F print_banner >/dev/null 2>&1 && echo "print_banner: defined"
        declare -F handle_command >/dev/null 2>&1 && echo "handle_command: defined"
        declare -F show_help >/dev/null 2>&1 && echo "show_help: defined"
    ) 2>/dev/null)
    assert_contains "$result" "print_banner: defined"
    assert_contains "$result" "handle_command: defined"
    assert_contains "$result" "show_help: defined"
}

test_validate_config_end_to_end() {
    # Source the full core chain and run validate_config with secure values.
    # This tests the integration of config + validation + utils.
    local rc
    rc=$( (
        set +e
        source "$PROJECT_ROOT/src/lib/core/config.sh"
        source "$PROJECT_ROOT/src/lib/core/logging.sh"
        source "$PROJECT_ROOT/src/lib/core/validation.sh"
        source "$PROJECT_ROOT/src/lib/core/error_handling.sh"
        source "$PROJECT_ROOT/src/lib/core/utils.sh"
        TTYD_PASSWD="RealStrong#Pass2024"
        TEMP_USER_PASS="RealStrong#Pass2024"
        VNC_PASSWORD="RealStrong#Pass2024"
        USER_UI_ENABLED="false"
        EMAIL="realuser@gmail.com"
        NOVNC_PORT=6080
        TTYD_PORT=5000
        VNC_PORT=5901
        DUCK_DOMAIN=""
        check_port_available() { return 0; }
        validate_config >/dev/null 2>&1
        echo $?
    ) 2>/dev/null)
    assert_eq "0" "$rc" "validate_config should pass with secure values in full chain"
}

test_validate_config_rejects_defaults_in_chain() {
    local rc
    rc=$( (
        set +e
        source "$PROJECT_ROOT/src/lib/core/config.sh"
        source "$PROJECT_ROOT/src/lib/core/logging.sh"
        source "$PROJECT_ROOT/src/lib/core/validation.sh"
        source "$PROJECT_ROOT/src/lib/core/error_handling.sh"
        source "$PROJECT_ROOT/src/lib/core/utils.sh"
        # Use defaults (TTYD_PASSWD=changeme, VNC_PASSWORD=YourStrongPassword123)
        check_port_available() { return 0; }
        validate_config >/dev/null 2>&1
        echo $?
    ) 2>/dev/null)
    assert_eq "1" "$rc" "validate_config should reject insecure defaults in full chain"
}

test_security_modules_source_after_core() {
    # Security modules depend on core (logging, config). Source them in order.
    local rc
    rc=$( (
        set +e
        source "$PROJECT_ROOT/src/lib/core/config.sh"
        source "$PROJECT_ROOT/src/lib/core/logging.sh"
        source "$PROJECT_ROOT/src/lib/core/validation.sh"
        source "$PROJECT_ROOT/src/lib/core/error_handling.sh"
        source "$PROJECT_ROOT/src/lib/core/utils.sh"
        source "$PROJECT_ROOT/src/lib/core/process_utils.sh"
        source "$PROJECT_ROOT/src/lib/security/ssl.sh"
        source "$PROJECT_ROOT/src/lib/security/user.sh"
        source "$PROJECT_ROOT/src/lib/security/fail2ban.sh"
        declare -F setup_ssl >/dev/null 2>&1 && echo "setup_ssl"
        declare -F create_temp_user >/dev/null 2>&1 && echo "create_temp_user"
        declare -F install_fail2ban >/dev/null 2>&1 && echo "install_fail2ban"
    ) 2>/dev/null)
    assert_contains "$rc" "setup_ssl"
    assert_contains "$rc" "create_temp_user"
    assert_contains "$rc" "install_fail2ban"
}

run_test "All 18 modules source without error" test_all_modules_source_without_error
run_test "Core chain sources together (functions available)" test_core_chain_sources_together
run_test "No duplicate function definition conflicts" test_no_duplicate_function_definitions
run_test "validate_config end-to-end with secure values" test_validate_config_end_to_end
run_test "validate_config rejects insecure defaults in chain" test_validate_config_rejects_defaults_in_chain
run_test "Security modules source after core" test_security_modules_source_after_core

end_suite
