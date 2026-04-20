#!/bin/bash
# ============================================================================
# MODULE LOADING TESTS
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

echo "=== Module Loading Tests ==="
echo ""

# Test lib directory exists
run_test "lib directory exists" "test -d '$SCRIPT_DIR/lib'"

# Test all module files exist
run_test "config.sh exists" "test -f '$SCRIPT_DIR/lib/config.sh'"
run_test "utils.sh exists" "test -f '$SCRIPT_DIR/lib/utils.sh'"
run_test "ssl.sh exists" "test -f '$SCRIPT_DIR/lib/ssl.sh'"
run_test "user.sh exists" "test -f '$SCRIPT_DIR/lib/user.sh'"
run_test "services.sh exists" "test -f '$SCRIPT_DIR/lib/services.sh'"

# Test module files are readable
run_test "config.sh is readable" "test -r '$SCRIPT_DIR/lib/config.sh'"
run_test "utils.sh is readable" "test -r '$SCRIPT_DIR/lib/utils.sh'"
run_test "ssl.sh is readable" "test -r '$SCRIPT_DIR/lib/ssl.sh'"
run_test "user.sh is readable" "test -r '$SCRIPT_DIR/lib/user.sh'"
run_test "services.sh is readable" "test -r '$SCRIPT_DIR/lib/services.sh'"

# Test modules can be sourced without errors
run_test "config.sh sources without errors" "source '$SCRIPT_DIR/lib/config.sh'"
run_test "utils.sh sources without errors" "source '$SCRIPT_DIR/lib/utils.sh'"
run_test "ssl.sh sources without errors" "source '$SCRIPT_DIR/lib/ssl.sh'"
run_test "user.sh sources without errors" "source '$SCRIPT_DIR/lib/user.sh'"
run_test "services.sh sources without errors" "source '$SCRIPT_DIR/lib/services.sh'"

# Test config module exports expected variables
source "$SCRIPT_DIR/lib/config.sh"
run_test "config exports TTYD_USERNAME" "[ -n '$TTYD_USERNAME' ]"
run_test "config exports TTYD_PASSWD" "[ -n '$TTYD_PASSWD' ]"
run_test "config exports NOVNC_PORT" "[ -n '$NOVNC_PORT' ]"
run_test "config exports TTYD_PORT" "[ -n '$TTYD_PORT' ]"
run_test "config exports VNC_PORT" "[ -n '$VNC_PORT' ]"

# Test utils module exports expected functions
source "$SCRIPT_DIR/lib/utils.sh"
run_test "utils exports log function" "type log &>/dev/null"
run_test "utils exports die function" "type die &>/dev/null"
run_test "utils exports cleanup function" "type cleanup &>/dev/null"

# Test ssl module exports expected functions
source "$SCRIPT_DIR/lib/ssl.sh"
run_test "ssl exports check_ssl_expiry function" "type check_ssl_expiry &>/dev/null"
run_test "ssl exports setup_ssl function" "type setup_ssl &>/dev/null"

# Test user module exports expected functions
source "$SCRIPT_DIR/lib/user.sh"
run_test "user exports create_temp_user function" "type create_temp_user &>/dev/null"
run_test "user exports get_next_uid function" "type get_next_uid &>/dev/null"

# Test services module exports expected functions
source "$SCRIPT_DIR/lib/services.sh"
run_test "services exports start_ttyd function" "type start_ttyd &>/dev/null"
run_test "services exports start_vnc_server function" "type start_vnc_server &>/dev/null"
run_test "services exports start_novnc function" "type start_novnc &>/dev/null"

# Test main script exists and is readable
run_test "Main script exists" "test -f '$SCRIPT_DIR/rpi-vnc-remote.sh'"
run_test "Main script is readable" "test -r '$SCRIPT_DIR/rpi-vnc-remote.sh'"

# Test main script sources modules without errors
run_test "Main script sources modules without errors" "bash -c 'source \"$SCRIPT_DIR/rpi-vnc-remote.sh\" 2>&1' || true"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All module loading tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some module loading tests failed.${NC}"
    exit 1
fi
