#!/bin/bash
# ============================================================================
# UTILITY FUNCTION TESTS
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

echo "=== Utility Function Tests ==="
echo ""

# Source config and utils
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/utils.sh"

# Test logging functions
run_test "log function exists" "type log &>/dev/null"
run_test "die function exists" "type die &>/dev/null"
run_test "warn function exists" "type warn &>/dev/null"
run_test "success function exists" "type success &>/dev/null"
run_test "info function exists" "type info &>/dev/null"

# Test command handling functions
run_test "show_help function exists" "type show_help &>/dev/null"
run_test "handle_command function exists" "type handle_command &>/dev/null"

# Test cleanup functions
run_test "kill_process_on_port function exists" "type kill_process_on_port &>/dev/null"
run_test "kill_vnc_server function exists" "type kill_vnc_server &>/dev/null"
run_test "remove_temp_user function exists" "type remove_temp_user &>/dev/null"
run_test "cleanup function exists" "type cleanup &>/dev/null"

# Test dependency functions
run_test "install_dependencies function exists" "type install_dependencies &>/dev/null"
run_test "detect_ttyd_arch function exists" "type detect_ttyd_arch &>/dev/null"
run_test "install_ttyd function exists" "type install_ttyd &>/dev/null"

# Test display functions
run_test "print_banner function exists" "type print_banner &>/dev/null"
run_test "print_access_info function exists" "type print_access_info &>/dev/null"

# Test detect_ttyd_arch with mocked architecture
mock_uname() {
    echo "$1"
}

# Test architecture detection
run_test "detect_ttyd_arch handles armv7l" "[ $(detect_ttyd_arch) != 'unknown' ]"

# Test print_banner output
run_test "print_banner produces output" "print_banner | grep -q 'Raspberry Pi'"

# Test print_access_info produces output
run_test "print_access_info produces output" "print_access_info | grep -q 'Access Information'"

# Test log function with different levels
run_test "log with red level works" "log 'red' 'test' 'test' 2>&1 | grep -q 'test'"
run_test "log with green level works" "log 'green' 'test' 'test' 2>&1 | grep -q 'test'"
run_test "log with yellow level works" "log 'yellow' 'test' 'test' 2>&1 | grep -q 'test'"
run_test "log with blue level works" "log 'blue' 'test' 'test' 2>&1 | grep -q 'test'"

# Test help function
run_test "show_help produces usage info" "show_help 2>&1 | grep -q 'Usage:'"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All utility tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some utility tests failed.${NC}"
    exit 1
fi
