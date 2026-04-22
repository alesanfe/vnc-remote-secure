#!/bin/bash
# ============================================================================
# DEPENDENCY INTEGRATION TESTS
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

echo "=== Dependency Integration Tests ==="
echo ""

# Source config and utils
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"

# Test dependency check functions exist
run_test "install_dependencies function exists" "type install_dependencies &>/dev/null"
run_test "install_ttyd function exists" "type install_ttyd &>/dev/null"
run_test "detect_ttyd_arch function exists" "type detect_ttyd_arch &>/dev/null"

# Test architecture detection returns known values
arch=$(detect_ttyd_arch)
run_test "Architecture detection returns valid value" "[ '$arch' = 'armhf' ] || [ '$arch' = 'arm64' ] || [ '$arch' = 'amd64' ]"

# Test config has dependency-related variables
run_test "SSL_DIR variable defined" "[ -n '$SSL_DIR' ]"

# Test SSL certificate paths are constructed
run_test "SSL_CERT path constructed" "[ -n '$SSL_CERT' ]"
run_test "SSL_KEY path constructed" "[ -n '$SSL_KEY' ]"

# Test BeEF configuration
run_test "BEEF_ENABLED variable defined" "[ -n '$BEEF_ENABLED' ]"
run_test "BEEF_HOOK_URL variable exists" "[ -v 'BEEF_HOOK_URL' ]"

# Test VNC configuration
run_test "VNC_DISPLAY variable defined" "[ -n '$VNC_DISPLAY' ]"
run_test "VNC_GEOMETRY variable defined" "[ -n '$VNC_GEOMETRY' ]"
run_test "VNC_DEPTH variable defined" "[ -n '$VNC_DEPTH' ]"

# Test network configuration
run_test "NOVNC_PORT variable defined" "[ -n '$NOVNC_PORT' ]"
run_test "TTYD_PORT variable defined" "[ -n '$TTYD_PORT' ]"
run_test "VNC_PORT variable defined" "[ -n '$VNC_PORT' ]"

# Test user configuration
run_test "TTYD_USERNAME variable defined" "[ -n '$TTYD_USERNAME' ]"
run_test "TTYD_PASSWD variable defined" "[ -n '$TTYD_PASSWD' ]"
run_test "TEMP_USER variable defined" "[ -n '$TEMP_USER' ]"
run_test "TEMP_USER_PASS variable defined" "[ -n '$TEMP_USER_PASS' ]"

# Test email configuration
run_test "EMAIL variable defined" "[ -n '$EMAIL' ]"

# Test SSL renewal configuration
run_test "SSL_RENEW_DAYS variable defined" "[ -n '$SSL_RENEW_DAYS' ]"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All dependency integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some dependency integration tests failed.${NC}"
    exit 1
fi
