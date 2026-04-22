#!/bin/bash
# ============================================================================
# SECURITY IMPROVEMENTS TESTS
# Tests for security improvements made to the codebase
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        fail_count=$((fail_count + 1))
        return 1
    fi
}

echo "=== Security Improvements Tests ==="
echo ""

# Source config
source "$SCRIPT_DIR/src/lib/config.sh"

# ============================================================================
# USER UI SECURITY TESTS
# ============================================================================

echo "--- User UI Security Tests ---"

# Test Flask secret key is not hardcoded
run_test "Flask secret key uses environment variable or secrets module" "grep -q 'secrets.token_hex\|FLASK_SECRET_KEY' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test input sanitization functions exist
run_test "sanitize_username function exists" "grep -q 'sanitize_username' '$SCRIPT_DIR/src/lib/user_ui.sh'"
run_test "sanitize_string function exists" "grep -q 'sanitize_string' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test username sanitization regex is present
run_test "Username sanitization regex prevents injection" "grep -q 're.match.*a-zA-Z0-9_.-' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test string sanitization removes dangerous characters
run_test "String sanitization removes dangerous chars" "grep -q 're.sub.*[;&|\\$()]' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test chpasswd is fixed (no shell syntax error)
run_test "chpasswd uses Popen instead of shell" "grep -q 'Popen.*stdin.*PIPE' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test username validation before user creation
run_test "Username validation before creation" "grep -q 'if not username' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test password validation exists
run_test "Password validation exists" "grep -q 'len(password) < 8' '$SCRIPT_DIR/src/lib/user_ui.sh'"

# Test system user protection
run_test "System users protected from deletion" "grep -q 'root.*pi.*admin' '$SCRIPT_DIR/src/lib/user_ui.sh'"

echo ""

# ============================================================================
# USER VALIDATION TESTS
# ============================================================================

echo "--- User Validation Tests ---"

# Test TTYD_USERNAME validation exists
run_test "TTYD_USERNAME validation exists" "grep -q 'id.*TTYD_USERNAME' '$SCRIPT_DIR/src/lib/user.sh'"

# Test error message for invalid user
run_test "Error message for invalid TTYD_USERNAME" "grep -q 'does not exist' '$SCRIPT_DIR/src/lib/user.sh'"

# Test validation happens before user creation
run_test "Validation before temp user creation" "grep -A 5 'create_temp_user' '$SCRIPT_DIR/src/lib/user.sh' | grep -q 'id.*TTYD_USERNAME'"

echo ""

# ============================================================================
# CONFIG VALIDATION TESTS
# ============================================================================

echo "--- Config Validation Tests ---"

# Test DUCK_DIR uses conditional expansion
run_test "DUCK_DIR uses conditional expansion" "grep -q 'DUCK_DIR.*:+.*DUCK_DOMAIN' '$SCRIPT_DIR/src/lib/config.sh'"

# Test DUCK_DIR is not constructed when domain is empty
run_test "DUCK_DIR handles empty domain correctly" "[ -z '$DUCK_DIR' ] || [ '$DUCK_DIR' = '/etc/letsencrypt/live/' ]"

echo ""

# ============================================================================
# PORT KNOCKING TESTS
# ============================================================================

echo "--- Port Knocking Tests ---"

# Test PORT_KNOCK_INTERFACE variable exists
run_test "PORT_KNOCK_INTERFACE variable exists" "grep -q 'PORT_KNOCK_INTERFACE' '$SCRIPT_DIR/src/lib/config.sh'"

# Test PORT_KNOCK_INTERFACE has default value
run_test "PORT_KNOCK_INTERFACE has default" "grep -q 'PORT_KNOCK_INTERFACE.*eth0' '$SCRIPT_DIR/src/lib/config.sh'"

# Test knockd configuration uses variable
run_test "knockd uses PORT_KNOCK_INTERFACE variable" "grep -q '\$PORT_KNOCK_INTERFACE' '$SCRIPT_DIR/src/lib/portknock.sh'"

# Test interface is not hardcoded in knockd config
run_test "Interface not hardcoded in knockd" "! grep -q 'Interface = eth0' '$SCRIPT_DIR/src/lib/portknock.sh'"

echo ""

# ============================================================================
# SSL VALIDATION TESTS
# ============================================================================

echo "--- SSL Validation Tests ---"

# Test SSL uses openssl -checkend for portability
run_test "SSL uses openssl -checkend" "grep -q 'openssl.*checkend' '$SCRIPT_DIR/src/lib/ssl.sh'"

# Test SSL validation is more portable
run_test "SSL validation avoids date parsing" "! grep -q 'date --date=' '$SCRIPT_DIR/src/lib/ssl.sh'"

echo ""

# ============================================================================
# HEALTHCHECK SECURITY TESTS
# ============================================================================

echo "--- Healthcheck Security Tests ---"

# Test eval has been removed from auto_restart_service
run_test "eval removed from auto_restart_service" "! grep -q 'eval.*start_cmd' '$SCRIPT_DIR/src/lib/healthcheck.sh'"

# Test case statement used instead
run_test "case statement used for restart" "grep -q 'case.*\$service' '$SCRIPT_DIR/src/lib/healthcheck.sh'"

# Test specific restart functions exist
run_test "Specific restart functions exist" "grep -q 'start_novnc\|start_ttyd\|start_vnc_server' '$SCRIPT_DIR/src/lib/healthcheck.sh'"

echo ""

# ============================================================================
# BEEF BACKUP TESTS
# ============================================================================

echo "--- BeEF Backup Tests ---"

# Test backup is created before BeEF injection
run_test "Backup created before BeEF injection" "grep -q 'backup_file' '$SCRIPT_DIR/src/lib/services.sh'"

# Test backup includes timestamp
run_test "Backup includes timestamp" "grep -q 'backup.*date' '$SCRIPT_DIR/src/lib/services.sh'"

# Test original file is copied before modification
run_test "Original file copied before modification" "grep -q 'cp.*backup' '$SCRIPT_DIR/src/lib/services.sh'"

echo ""

# ============================================================================
# NEW VARIABLES TESTS
# ============================================================================

echo "--- New Configuration Variables Tests ---"

# Test FLASK_SECRET_KEY in config
run_test "FLASK_SECRET_KEY documented in .env.example" "grep -q 'FLASK_SECRET_KEY' '$SCRIPT_DIR/.env.example'"

# Test PORT_KNOCK_INTERFACE in config
run_test "PORT_KNOCK_INTERFACE documented in .env.example" "grep -q 'PORT_KNOCK_INTERFACE' '$SCRIPT_DIR/.env.example'"

# Test INDEX_FILE in config
run_test "INDEX_FILE documented in .env.example" "grep -q 'INDEX_FILE' '$SCRIPT_DIR/.env.example'"

# Test VNC_FILE in config
run_test "VNC_FILE documented in .env.example" "grep -q 'VNC_FILE' '$SCRIPT_DIR/.env.example'"

# Test advanced configuration variables exist
run_test "LOG_LEVEL variable documented" "grep -q 'LOG_LEVEL' '$SCRIPT_DIR/.env.example'"
run_test "CONNECTION_TIMEOUT variable documented" "grep -q 'CONNECTION_TIMEOUT' '$SCRIPT_DIR/.env.example'"
run_test "MAX_CONNECTIONS variable documented" "grep -q 'MAX_CONNECTIONS' '$SCRIPT_DIR/.env.example'"

echo ""

# ============================================================================
# SUMMARY
# ============================================================================

echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All security improvement tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some security improvement tests failed.${NC}"
    exit 1
fi
