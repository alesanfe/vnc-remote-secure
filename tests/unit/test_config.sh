#!/bin/bash
# ============================================================================
# CONFIG VALIDATION TESTS
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

echo "=== Config Validation Tests ==="
echo ""

# Source config module
source "$SCRIPT_DIR/src/lib/config.sh"

# Test default values
run_test "TTYD_USERNAME has default value" "[ -n '$TTYD_USERNAME' ]"
run_test "TTYD_PASSWD has default value" "[ '$TTYD_PASSWD' = 'changeme' ]"
run_test "TEMP_USER has default value" "[ '$TEMP_USER' = 'remote' ]"
run_test "EMAIL has default value" "[ '$EMAIL' = 'user@example.com' ]"

# Test port defaults
run_test "NOVNC_PORT has default value" "[ '$NOVNC_PORT' = '6080' ]"
run_test "TTYD_PORT has default value" "[ '$TTYD_PORT' = '5000' ]"
run_test "VNC_PORT has default value" "[ '$VNC_PORT' = '5901' ]"

# Test SSL config defaults
run_test "SSL_DIR has default value" "[ -n '$SSL_DIR' ]"
run_test "DUCK_DOMAIN is empty by default" "[ -z '$DUCK_DOMAIN' ]"
run_test "SSL_RENEW_DAYS has default value" "[ '$SSL_RENEW_DAYS' = '30' ]"

# Test VNC config defaults
run_test "VNC_DISPLAY has default value" "[ '$VNC_DISPLAY' = ':2' ]"
run_test "VNC_GEOMETRY has default value" "[ '$VNC_GEOMETRY' = '1920x1080' ]"
run_test "VNC_DEPTH has default value" "[ '$VNC_DEPTH' = '24' ]"

# Test BeEF defaults
run_test "BEEF_ENABLED is false by default" "[ '$BEEF_ENABLED' = 'false' ]"
run_test "BEEF_HOOK_URL is empty by default" "[ -z '$BEEF_HOOK_URL' ]"

# Test DISABLE_SSL initial state
run_test "DISABLE_SSL is false by default" "[ '$DISABLE_SSL' = 'false' ]"

# Test environment variable override
export TTYD_PASSWD="testpassword"
source "$SCRIPT_DIR/src/lib/config.sh"
run_test "TTYD_PASSWD can be overridden" "[ '$TTYD_PASSWD' = 'testpassword' ]"
unset TTYD_PASSWD

# Test port number validity (numeric)
export NOVNC_PORT="8080"
source "$SCRIPT_DIR/src/lib/config.sh"
run_test "Port can be set to valid number" "[ '$NOVNC_PORT' = '8080' ]"
unset NOVNC_PORT

# Test SSL paths are constructed correctly
source "$SCRIPT_DIR/src/lib/config.sh"
run_test "SSL_CERT path is constructed" "[ -n '$SSL_CERT' ]"
run_test "SSL_KEY path is constructed" "[ -n '$SSL_KEY' ]"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All config tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some config tests failed.${NC}"
    exit 1
fi
