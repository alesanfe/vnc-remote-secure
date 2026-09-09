#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# LEVEL 7 — SECURITY TESTS
# ============================================================================
# Tests security-critical behavior: password policy enforcement, input
# sanitization (XSS prevention), config hardening, and access control
# defaults. These go beyond "does it work?" to "does it block what it should?"
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../lib/test_framework.sh"

begin_suite "Security Tests (Level 7)"

setup() {
    source_module_safe "src/lib/core/config.sh"
    source_module_safe "src/lib/core/logging.sh"
    source_module_safe "src/lib/core/validation.sh"
    source_module_safe "src/lib/core/error_handling.sh"
    source_module_safe "src/lib/core/utils.sh"
}

# ============================================================================
# Password Policy Enforcement
# ============================================================================

test_rejects_empty_password() {
    setup
    assert_failure validate_password_strength ""
}

test_rejects_known_weak_passwords() {
    setup
    local weak
    for weak in "changeme" "password" "123456" "qwerty" "admin" "root" \
                "letmein" "welcome" "YourStrongPassword123" "admin123" \
                "password123" "root1234"; do
        if validate_password_strength "$weak" 2>/dev/null; then
            echo "    weak password accepted: '$weak'"
            return 1
        fi
    done
    return 0
}

test_accepts_strong_passwords() {
    setup
    local strong
    for strong in "RealStrong#Pass2024" "MySecure!Pass9" "Abcdef123!xyz"; do
        if ! validate_password_strength "$strong" 2>/dev/null; then
            echo "    strong password rejected: '$strong'"
            return 1
        fi
    done
    return 0
}

test_password_requires_minimum_length() {
    setup
    # 7 chars should fail, 8+ should pass (with other requirements met)
    assert_failure validate_password_strength "Short1!"
    assert_success validate_password_strength "Longer123!"
}

test_password_requires_complexity() {
    setup
    # Missing uppercase
    assert_failure validate_password_strength "alllowercase123!"
    # Missing lowercase
    assert_failure validate_password_strength "ALLUPPERCASE123!"
    # Missing digit
    assert_failure validate_password_strength "NoDigitsHere!"
}

# ============================================================================
# Input Sanitization (XSS Prevention)
# ============================================================================

test_sanitize_escapes_angle_brackets() {
    setup
    local result
    result=$(sanitize_input '<div>test</div>')
    # Raw < should NOT appear in output
    if [[ "$result" == *"<"* ]]; then
        echo "    raw < in output: '$result'"
        return 1
    fi
    # Raw > should NOT appear in output
    if [[ "$result" == *">"* ]]; then
        echo "    raw > in output: '$result'"
        return 1
    fi
    return 0
}

test_sanitize_escapes_quotes() {
    setup
    local result
    result=$(sanitize_input 'say "hello" and '"'"'world'"'"'')
    # Raw " should NOT appear in output
    if [[ "$result" == *'"'* ]]; then
        echo "    raw double-quote in output: '$result'"
        return 1
    fi
    return 0
}

test_sanitize_handles_script_injection() {
    setup
    local result
    result=$(sanitize_input '<script>alert("XSS")</script>')
    # The word "script" can appear, but <script> as raw HTML must not
    if [[ "$result" == *"<script>"* ]]; then
        echo "    unescaped <script> tag in output: '$result'"
        return 1
    fi
    return 0
}

test_sanitize_preserves_safe_text() {
    setup
    local result
    result=$(sanitize_input 'Hello World 123')
    assert_eq "Hello World 123" "$result" "safe text should pass through unchanged"
}

# ============================================================================
# Config Hardening
# ============================================================================

test_defaults_are_secure() {
    # Unset password variables so config.sh generates fresh random ones,
    # ignoring any values inherited from .env via the Makefile.
    unset TTYD_PASSWD TEMP_USER_PASS VNC_PASSWORD USER_UI_PASSWORD
    setup
    # With default values, validate_config should succeed because:
    # - Passwords are randomly generated (strong)
    # - EMAIL defaults to empty (optional, only needed for SSL)
    # - DUCK_DOMAIN defaults to empty (optional)
    check_port_available() { return 0; }
    assert_success validate_config
}

test_temp_user_removed_by_default() {
    setup
    assert_eq "false" "$KEEP_TEMP_USER" "temp user must be removed on exit by default"
}

test_optional_features_disabled_by_default() {
    setup
    # Security-relevant features should be opt-in, not opt-out
    assert_eq "false" "$FAIL2BAN_ENABLED" "fail2ban should be opt-in"
    assert_eq "false" "$BEEF_ENABLED" "BeEF should be opt-in"
    assert_eq "false" "$DISCORD_ENABLED" "Discord webhook should be opt-in"
}

test_ssl_enabled_by_default() {
    setup
    assert_eq "false" "$DISABLE_SSL" "SSL should be enabled by default"
}

test_example_email_rejected() {
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
    assert_failure validate_config "example.com email must be rejected"
}

test_ui_password_required_when_ui_enabled() {
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
    assert_failure validate_config "weak UI password must be rejected when UI enabled"
}

# ============================================================================
# Username Validation (Injection Prevention)
# ============================================================================

test_rejects_command_injection_in_username() {
    setup
    assert_failure validate_username "user;rm -rf /" "username"
    assert_failure validate_username "user\$(whoami)" "username"
    assert_failure validate_username "user|cat /etc/passwd" "username"
}

test_rejects_reserved_system_users() {
    setup
    local reserved
    for reserved in root daemon bin sys nobody www-data; do
        if validate_username "$reserved" "username" 2>/dev/null; then
            echo "    reserved username accepted: '$reserved'"
            return 1
        fi
    done
    return 0
}

# ============================================================================
# Path Validation (Directory Traversal Prevention)
# ============================================================================

test_rejects_directory_traversal() {
    setup
    assert_failure validate_path "../../../etc/passwd" "path"
    assert_failure validate_path "..%2f..%2fetc" "path"
}

run_test "Rejects empty password" test_rejects_empty_password
run_test "Rejects all known weak passwords" test_rejects_known_weak_passwords
run_test "Accepts strong passwords" test_accepts_strong_passwords
run_test "Password requires minimum length (8)" test_password_requires_minimum_length
run_test "Password requires complexity (upper/lower/digit)" test_password_requires_complexity
run_test "Sanitize escapes < and >" test_sanitize_escapes_angle_brackets
run_test "Sanitize escapes quotes" test_sanitize_escapes_quotes
run_test "Sanitize blocks <script> injection" test_sanitize_handles_script_injection
run_test "Sanitize preserves safe text" test_sanitize_preserves_safe_text
run_test "Defaults are secure (validate_config passes)" test_defaults_are_secure
run_test "Temp user removed by default" test_temp_user_removed_by_default
run_test "Optional security features disabled by default" test_optional_features_disabled_by_default
run_test "SSL enabled by default" test_ssl_enabled_by_default
run_test "example.com email rejected" test_example_email_rejected
run_test "Weak UI password rejected when UI enabled" test_ui_password_required_when_ui_enabled
run_test "Rejects command injection in username" test_rejects_command_injection_in_username
run_test "Rejects reserved system usernames" test_rejects_reserved_system_users
run_test "Rejects directory traversal in paths" test_rejects_directory_traversal

end_suite
