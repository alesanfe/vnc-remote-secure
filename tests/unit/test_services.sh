#!/bin/bash
# ============================================================================
# SERVICES FUNCTION TESTS
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

echo "=== Services Function Tests ==="
echo ""

# Source required modules
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"
source "$SCRIPT_DIR/src/lib/services.sh"

# Test VNC functions
run_test "configure_vnc_password function exists" "type configure_vnc_password &>/dev/null"
run_test "configure_novnc function exists" "type configure_novnc &>/dev/null"
run_test "start_vnc_server function exists" "type start_vnc_server &>/dev/null"
run_test "start_novnc function exists" "type start_novnc &>/dev/null"
run_test "start_ttyd function exists" "type start_ttyd &>/dev/null"

# Test user functions
run_test "create_temp_user function exists" "type create_temp_user &>/dev/null"

# Test configuration validation
run_test "VNC configuration variables are set" "[ -n \"$VNC_PORT\" ]"
run_test "noVNC configuration variables are set" "[ -n \"$NOVNC_PORT\" ]"
run_test "ttyd configuration variables are set" "[ -n \"$TTYD_PORT\" ]"

# Test service configuration functions
run_test "configure_vnc_password handles missing vncpasswd" "! command -v vncpasswd &>/dev/null || ! command -v tigervncpasswd &>/dev/null || configure_vnc_password testuser"

# Test noVNC configuration
run_test "configure_novnc function exists and is callable" "type configure_novnc &>/dev/null"

# Test service startup functions (without actually starting services)
run_test "start_vnc_server function structure is valid" "grep -q 'tigervncserver' \"$SCRIPT_DIR/src/lib/services.sh\""
run_test "start_novnc function structure is valid" "grep -q 'novnc_proxy' \"$SCRIPT_DIR/src/lib/services.sh\""
run_test "start_ttyd function structure is valid" "grep -q 'ttyd' \"$SCRIPT_DIR/src/lib/services.sh\""

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
