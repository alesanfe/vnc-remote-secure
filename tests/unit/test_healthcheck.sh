#!/bin/bash
# ============================================================================
# HEALTHCHECK FUNCTION TESTS
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

echo "=== Healthcheck Function Tests ==="
echo ""

# Source required modules
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"
source "$SCRIPT_DIR/src/lib/healthcheck.sh"

# Test basic healthcheck functions
run_test "check_service_port function exists" "type check_service_port &>/dev/null"
run_test "check_process function exists" "type check_process &>/dev/null"
run_test "check_novnc function exists" "type check_novnc &>/dev/null"
run_test "check_ttyd function exists" "type check_ttyd &>/dev/null"
run_test "check_vnc function exists" "type check_vnc &>/dev/null"
run_test "check_temp_user function exists" "type check_temp_user &>/dev/null"
run_test "check_ssl_cert function exists" "type check_ssl_cert &>/dev/null"

# Test new resource monitoring functions
run_test "check_memory function exists" "type check_memory &>/dev/null"
run_test "check_cpu function exists" "type check_cpu &>/dev/null"
run_test "check_disk function exists" "type check_disk &>/dev/null"

# Test main healthcheck function
run_test "run_healthcheck function exists" "type run_healthcheck &>/dev/null"

# Test resource monitoring functions work
run_test "check_memory works" "check_memory"
run_test "check_cpu works" "check_cpu"
run_test "check_disk works" "check_disk"

# Test SSL certificate check (may fail if no cert, but function should exist)
run_test "check_ssl_cert handles missing cert gracefully" "check_ssl_cert"

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
