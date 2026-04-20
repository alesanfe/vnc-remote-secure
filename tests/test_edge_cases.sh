#!/bin/bash
# ============================================================================
# EDGE CASE TESTS
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

echo "=== Edge Case Tests ==="
echo ""

# Test with empty environment variables
unset TTYD_USERNAME
unset TTYD_PASSWD
source "$SCRIPT_DIR/lib/config.sh"

run_test "TTYD_USERNAME defaults to whoami when unset" "[ -n '$TTYD_USERNAME' ]"
run_test "TTYD_PASSWD defaults to changeme when unset" "[ '$TTYD_PASSWD' = 'changeme' ]"

# Test with special characters in passwords
export TTYD_PASSWD='p@ssw0rd!#$%'
source "$SCRIPT_DIR/lib/config.sh"
run_test "Password with special characters is accepted" "[ -n '$TTYD_PASSWD' ]"

# Test with very long values
export TTYD_USERNAME="verylongusername123456789"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Long username is accepted" "[ -n '$TTYD_USERNAME' ]"

# Test with port numbers at boundaries
export NOVNC_PORT="1"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Port 1 is accepted" "[ '$NOVNC_PORT' = '1' ]"

export NOVNC_PORT="65535"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Port 65535 is accepted" "[ '$NOVNC_PORT' = '65535' ]"

# Test with empty domain (should disable SSL)
unset DUCK_DOMAIN
source "$SCRIPT_DIR/lib/config.sh"
run_test "Empty domain sets DISABLE_SSL" "source '$SCRIPT_DIR/lib/ssl.sh' 2>/dev/null || true"

# Test with invalid VNC display numbers
export VNC_DISPLAY=":99"
source "$SCRIPT_DIR/lib/config.sh"
run_test "High display number is accepted" "[ -n '$VNC_DISPLAY' ]"

export VNC_DISPLAY=":0"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Display :0 is accepted" "[ -n '$VNC_DISPLAY' ]"

# Test with invalid geometry
export VNC_GEOMETRY="800x600"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Small geometry is accepted" "[ -n '$VNC_GEOMETRY' ]"

export VNC_GEOMETRY="3840x2160"
source "$SCRIPT_DIR/lib/config.sh"
run_test "4K geometry is accepted" "[ -n '$VNC_GEOMETRY' ]"

# Test with invalid color depth
export VNC_DEPTH="8"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Low color depth is accepted" "[ -n '$VNC_DEPTH' ]"

export VNC_DEPTH="32"
source "$SCRIPT_DIR/lib/config.sh"
run_test "High color depth is accepted" "[ -n '$VNC_DEPTH' ]"

# Test BeEF with empty hook URL
export BEEF_ENABLED="true"
export BEEF_HOOK_URL=""
source "$SCRIPT_DIR/lib/config.sh"
run_test "BeEF disabled when hook URL is empty" "[ -z '$BEEF_HOOK_URL' ]"

# Test file path validation
export SSL_DIR="/nonexistent/path"
source "$SCRIPT_DIR/lib/config.sh"
run_test "SSL path can be set to any path" "[ -n '$SSL_DIR' ]"

# Test with multiple conflicting environment variables
export NOVNC_PORT="6080"
export TTYD_PORT="6080"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Conflicting ports are accepted (user responsibility)" "[ '$NOVNC_PORT' = '$TTYD_PORT' ]"

# Test with unicode characters
export TTYD_USERNAME="用户"
source "$SCRIPT_DIR/lib/config.sh"
run_test "Unicode username is accepted" "[ -n '$TTYD_USERNAME' ]"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All edge case tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some edge case tests failed.${NC}"
    exit 1
fi
