#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# UNIT TESTS: Configuration module (src/lib/core/config.sh)
# ============================================================================
# Verifies that all configuration variables are defined with correct defaults
# and that environment overrides work as expected.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../../lib/test_framework.sh"

begin_suite "Configuration Module (config.sh)"

# Source the module under test (in a clean subshell per test where needed)
# We must unset env vars that .env or the Makefile may have set, so we
# test the DEFAULTS defined in config.sh, not overridden values.
setup() {
    unset TTYD_USERNAME TTYD_PASSWD TEMP_USER TEMP_USER_PASS \
          NOVNC_PORT TTYD_PORT VNC_PORT \
          SSL_CERT SSL_KEY SSL_RENEW_DAYS \
          FAIL2BAN_ENABLED MONITORING_ENABLED \
          RECORDING_ENABLED USER_UI_ENABLED ALERTS_ENABLED DISCORD_ENABLED \
          HEALTHCHECK_ENABLED HEALTHCHECK_INTERVAL AUTO_RESTART \
          KEEP_TEMP_USER VNC_DISPLAY VNC_GEOMETRY VNC_DEPTH VNC_PASSWORD \
          USER_UI_PASSWORD USER_UI_PORT DUCK_DOMAIN EMAIL DISABLE_SSL \
          SHOW_LOGS LOG_DIR 2>/dev/null
    source_module_safe "src/lib/core/config.sh"
}

test_default_ttyd_username() {
    setup
    # TTYD_USERNAME defaults to whoami; just check it is non-empty
    assert_not_empty TTYD_USERNAME "TTYD_USERNAME should default to current user"
}

test_default_ttyd_passwd() {
    setup
    # TTYD_PASSWD now defaults to a random 20-char string (not "changeme")
    assert_not_empty TTYD_PASSWD "TTYD_PASSWD should have a generated default"
    # Should NOT be a known weak password
    if [[ "$TTYD_PASSWD" == "changeme" ]]; then
        echo "    TTYD_PASSWD should not default to 'changeme'"
        return 1
    fi
    # Should be at least 8 characters (generated random passwords are 20)
    if (( ${#TTYD_PASSWD} < 8 )); then
        echo "    TTYD_PASSWD too short: '$TTYD_PASSWD' (${#TTYD_PASSWD} chars)"
        return 1
    fi
}

test_default_temp_user() {
    setup
    assert_eq "remote" "$TEMP_USER" "TEMP_USER default should be remote"
}

test_default_ports() {
    setup
    assert_eq "6080" "$NOVNC_PORT" "NOVNC_PORT default should be 6080"
    assert_eq "5000" "$TTYD_PORT" "TTYD_PORT default should be 5000"
    assert_eq "5901" "$VNC_PORT" "VNC_PORT default should be 5901"
}

test_default_ssl_paths() {
    setup
    assert_contains "$SSL_CERT" "fullchain.pem" "SSL_CERT should point to fullchain.pem"
    assert_contains "$SSL_KEY" "privkey.pem" "SSL_KEY should point to privkey.pem"
}

test_default_ssl_renew_days() {
    setup
    assert_eq "30" "$SSL_RENEW_DAYS" "SSL_RENEW_DAYS default should be 30"
}

test_default_feature_flags_disabled() {
    setup
    assert_eq "false" "$FAIL2BAN_ENABLED" "FAIL2BAN_ENABLED should default to false"
    assert_eq "false" "$MONITORING_ENABLED" "MONITORING_ENABLED should default to false"
    assert_eq "false" "$RECORDING_ENABLED" "RECORDING_ENABLED should default to false"
    assert_eq "false" "$USER_UI_ENABLED" "USER_UI_ENABLED should default to false"
    assert_eq "false" "$ALERTS_ENABLED" "ALERTS_ENABLED should default to false"
    assert_eq "false" "$DISCORD_ENABLED" "DISCORD_ENABLED should default to false"
}

test_default_healthcheck_enabled() {
    setup
    assert_eq "true" "$HEALTHCHECK_ENABLED" "HEALTHCHECK_ENABLED should default to true"
    assert_eq "30" "$HEALTHCHECK_INTERVAL" "HEALTHCHECK_INTERVAL should default to 30"
}

test_keep_temp_user_default() {
    setup
    assert_eq "false" "$KEEP_TEMP_USER" "KEEP_TEMP_USER must default to false (security: remove temp user on exit)"
}

test_vnc_defaults() {
    setup
    assert_eq ":2" "$VNC_DISPLAY" "VNC_DISPLAY default should be :2"
    assert_eq "1920x1080" "$VNC_GEOMETRY" "VNC_GEOMETRY default should be 1920x1080"
    assert_eq "24" "$VNC_DEPTH" "VNC_DEPTH default should be 24"
}

test_env_override() {
    # Override via environment before sourcing
    unset TTYD_PASSWD NOVNC_PORT KEEP_TEMP_USER 2>/dev/null
    TTYD_PASSWD="MyCustom#Pass1"
    NOVNC_PORT=7080
    KEEP_TEMP_USER="true"
    source_module_safe "src/lib/core/config.sh"
    assert_eq "MyCustom#Pass1" "$TTYD_PASSWD" "TTYD_PASSWD should pick up env override"
    assert_eq "7080" "$NOVNC_PORT" "NOVNC_PORT should pick up env override"
    assert_eq "true" "$KEEP_TEMP_USER" "KEEP_TEMP_USER should pick up env override"
}

test_runtime_state() {
    setup
    assert_eq "false" "$DISABLE_SSL" "DISABLE_SSL should be false by default"
    assert_eq "true" "$SHOW_LOGS" "SHOW_LOGS should default to true"
}

run_test "TTYD_USERNAME has default" test_default_ttyd_username
run_test "TTYD_PASSWD has generated default (not changeme)" test_default_ttyd_passwd
run_test "TEMP_USER defaults to remote" test_default_temp_user
run_test "Default ports are 6080/5000/5901" test_default_ports
run_test "SSL paths point to fullchain/privkey" test_default_ssl_paths
run_test "SSL_RENEW_DAYS defaults to 30" test_default_ssl_renew_days
run_test "Optional feature flags default to false" test_default_feature_flags_disabled
run_test "Healthcheck enabled by default" test_default_healthcheck_enabled
run_test "KEEP_TEMP_USER defaults to false (security)" test_keep_temp_user_default
run_test "VNC defaults (display, geometry, depth)" test_vnc_defaults
run_test "Environment variables override defaults" test_env_override
run_test "Runtime state defaults" test_runtime_state

end_suite
