#!/bin/bash
# ============================================================================
# NGINX FUNCTION TESTS
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

echo "=== Nginx Function Tests ==="
echo ""

# Source required modules
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"
source "$SCRIPT_DIR/src/lib/nginx.sh"

# Test nginx functions
run_test "install_nginx function exists" "type install_nginx &>/dev/null"
run_test "configure_nginx function exists" "type configure_nginx &>/dev/null"
run_test "start_nginx function exists" "type start_nginx &>/dev/null"
run_test "stop_nginx function exists" "type stop_nginx &>/dev/null"

# Test nginx configuration generation
run_test "nginx configuration template contains rate limiting" "grep -q 'limit_req_zone' \"$SCRIPT_DIR/src/lib/nginx.sh\""
run_test "nginx configuration contains vnc rate limiting" "grep -q 'vnc_limit' \"$SCRIPT_DIR/src/lib/nginx.sh\""
run_test "nginx configuration contains terminal rate limiting" "grep -q 'terminal_limit' \"$SCRIPT_DIR/src/lib/nginx.sh\""

# Test SSL configuration
run_test "nginx configuration contains SSL settings" "grep -q 'ssl_certificate' \"$SCRIPT_DIR/src/lib/nginx.sh\""
run_test "nginx configuration contains SSL protocols" "grep -q 'ssl_protocols' \"$SCRIPT_DIR/src/lib/nginx.sh\""

# Test proxy configurations
run_test "nginx configuration contains noVNC proxy" "grep -q 'location /vnc/' \"$SCRIPT_DIR/src/lib/nginx.sh\""
run_test "nginx configuration contains ttyd proxy" "grep -q 'location /terminal/' \"$SCRIPT_DIR/src/lib/nginx.sh\""
run_test "nginx configuration contains health check" "grep -q 'location /health' \"$SCRIPT_DIR/src/lib/nginx.sh\""

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
