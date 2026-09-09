#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# UNIT TESTS: Validation module (src/lib/core/validation.sh)
# ============================================================================
# Tests input validation functions: password, port, domain, email, username.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../../lib/test_framework.sh"

begin_suite "Validation Module (validation.sh)"

# Source config first (validation uses logging which may need config), then validation
setup() {
    source_module_safe "src/lib/core/config.sh"
    source_module_safe "src/lib/core/logging.sh"
    source_module_safe "src/lib/core/validation.sh"
}

# --- validate_password ---

test_password_rejects_short() {
    setup
    assert_failure validate_password "Ab1" "password"
}

test_password_rejects_common_weak() {
    setup
    assert_failure validate_password "changeme" "password"
    assert_failure validate_password "password123" "password"
    assert_failure validate_password "admin1234" "password"
}

test_password_requires_uppercase() {
    setup
    assert_failure validate_password "alllowercase1" "password"
}

test_password_requires_lowercase() {
    setup
    assert_failure validate_password "ALLUPPERCASE1" "password"
}

test_password_requires_digit() {
    setup
    assert_failure validate_password "NoDigitsHere" "password"
}

test_password_accepts_strong() {
    setup
    assert_success validate_password "RealStrong#Pass2024" "password"
}

# --- validate_port ---

test_port_rejects_non_numeric() {
    setup
    assert_failure validate_port "abc" "port"
}

test_port_rejects_out_of_range() {
    setup
    assert_failure validate_port "0" "port"
    assert_failure validate_port "65536" "port"
    assert_failure validate_port "-1" "port"
}

test_port_accepts_valid() {
    setup
    assert_success validate_port "1" "port"
    assert_success validate_port "80" "port"
    assert_success validate_port "443" "port"
    assert_success validate_port "65535" "port"
}

# --- validate_domain ---

test_domain_accepts_empty() {
    setup
    assert_success validate_domain "" "domain"
}

test_domain_rejects_invalid_format() {
    setup
    assert_failure validate_domain "notvalid" "domain"
    assert_failure validate_domain "-invalid.com" "domain"
}

test_domain_accepts_valid() {
    setup
    assert_success validate_domain "example.duckdns.org" "domain"
    assert_success validate_domain "sub.domain.com" "domain"
}

# --- validate_email ---

test_email_rejects_invalid() {
    setup
    assert_failure validate_email "notanemail" "email"
    assert_failure validate_email "user@" "email"
    assert_failure validate_email "@domain.com" "email"
}

test_email_rejects_example_com() {
    setup
    assert_failure validate_email "user@example.com" "email"
}

test_email_accepts_valid() {
    setup
    assert_success validate_email "user@gmail.com" "email"
    assert_success validate_email "real.user@duckdns.org" "email"
}

# --- validate_username ---

test_username_rejects_empty() {
    setup
    assert_failure validate_username "" "username"
}

test_username_rejects_reserved() {
    setup
    assert_failure validate_username "root" "username"
    assert_failure validate_username "daemon" "username"
}

test_username_rejects_short() {
    setup
    assert_failure validate_username "ab" "username"
}

test_username_rejects_invalid_chars() {
    setup
    assert_failure validate_username "user name" "username"
    assert_failure validate_username "user;rm" "username"
}

test_username_accepts_valid() {
    setup
    assert_success validate_username "remote" "username"
    assert_success validate_username "user-123" "username"
}

# --- sanitize_input ---

test_sanitize_escapes_html() {
    setup
    local result
    result=$(sanitize_input '<script>alert(1)</script>')
    # sanitize_input replaces < with &lt; and > with &gt;
    assert_contains "$result" "&lt;script&gt;" "sanitize should escape < to &lt; and > to &gt;"
    assert_contains "$result" "&lt;/script&gt;" "sanitize should escape closing tag too"
    # Original raw < should NOT appear
    if [[ "$result" == *"<"* ]]; then
        echo "    raw < still present in sanitized output: '$result'"
        return 1
    fi
    return 0
}

run_test "Password rejects too short" test_password_rejects_short
run_test "Password rejects common weak patterns" test_password_rejects_common_weak
run_test "Password requires uppercase" test_password_requires_uppercase
run_test "Password requires lowercase" test_password_requires_lowercase
run_test "Password requires digit" test_password_requires_digit
run_test "Password accepts strong password" test_password_accepts_strong
run_test "Port rejects non-numeric" test_port_rejects_non_numeric
run_test "Port rejects out of range (0, 65536, -1)" test_port_rejects_out_of_range
run_test "Port accepts valid range (1-65535)" test_port_accepts_valid
run_test "Domain accepts empty (SSL disabled)" test_domain_accepts_empty
run_test "Domain rejects invalid format" test_domain_rejects_invalid_format
run_test "Domain accepts valid domains" test_domain_accepts_valid
run_test "Email rejects invalid format" test_email_rejects_invalid
run_test "Email rejects example.com placeholder" test_email_rejects_example_com
run_test "Email accepts valid addresses" test_email_accepts_valid
run_test "Username rejects empty" test_username_rejects_empty
run_test "Username rejects reserved names" test_username_rejects_reserved
run_test "Username rejects too short (<3 chars)" test_username_rejects_short
run_test "Username rejects invalid characters" test_username_rejects_invalid_chars
run_test "Username accepts valid names" test_username_accepts_valid
run_test "sanitize_input escapes HTML characters" test_sanitize_escapes_html

end_suite
