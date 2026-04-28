#!/bin/bash
# ============================================================================
# ENHANCED UTILITY FUNCTION TESTS
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

echo "=== Enhanced Utility Function Tests ==="
echo ""

# Source config and utils
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"

# Test basic logging functions
run_test "log function exists" "type log &>/dev/null"
run_test "die function exists" "type die &>/dev/null"
run_test "warn function exists" "type warn &>/dev/null"
run_test "success function exists" "type success &>/dev/null"
run_test "info function exists" "type info &>/dev/null"

# Test enhanced debug functions
run_test "debug_log function exists" "type debug_log &>/dev/null"
run_test "log_service_status function exists" "type log_service_status &>/dev/null"
run_test "log_system_resources function exists" "type log_system_resources &>/dev/null"

# Test debug_log with VERBOSE=true
VERBOSE=true
run_test "debug_log works with VERBOSE=true" "debug_log 'test' 'action' 'success' '1.0'"

# Test log_system_resources with VERBOSE=true
run_test "log_system_resources works with VERBOSE=true" "log_system_resources"

# Test print functions
run_test "print_header function exists" "type print_header &>/dev/null"
run_test "print_section function exists" "type print_section &>/dev/null"
run_test "print_separator function exists" "type print_separator &>/dev/null"

# Test print functions
run_test "print_header works" "print_header 'Test Header'"
run_test "print_section works" "print_section 'Test Section'"
run_test "print_separator works" "print_separator"

echo ""
echo "=== Test Summary ==="
echo "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
