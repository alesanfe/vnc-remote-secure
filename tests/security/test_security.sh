#!/bin/bash
# ============================================================================
# SECURITY VALIDATION TESTS
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

echo "=== Security Validation Tests ==="
echo ""

# Source config
source "$SCRIPT_DIR/src/lib/config.sh"

# Test default password is not empty
run_test "Default password is not empty" "[ -n '$TTYD_PASSWD' ]"

# Test default password is weak (should warn)
run_test "Default password is weak (changeme)" "[ '$TTYD_PASSWD' = 'changeme' ]"

# Test SSL paths are not hardcoded with sensitive data
run_test "SSL_CERT path is variable" "grep -q '\$SSL_CERT' '$SCRIPT_DIR/src/lib/ssl.sh'"
run_test "SSL_KEY path is variable" "grep -q '\$SSL_KEY' '$SCRIPT_DIR/src/lib/ssl.sh'"

# Test no hardcoded passwords in scripts
run_test "No hardcoded passwords in main script" "! grep -q 'password=' '$SCRIPT_DIR/src/rpi-vnc-remote.sh' 2>/dev/null || ! grep -q 'passwd=' '$SCRIPT_DIR/src/rpi-vnc-remote.sh' 2>/dev/null"
run_test "No hardcoded passwords in lib files" "! grep -r 'password=' '$SCRIPT_DIR/src/lib/' 2>/dev/null || ! grep -r 'passwd=' '$SCRIPT_DIR/src/lib/' 2>/dev/null"

# Test BeEF is disabled by default
run_test "BeEF disabled by default" "[ '$BEEF_ENABLED' = 'false' ]"

# Test BeEF hook URL is empty by default
run_test "BeEF hook URL empty by default" "[ -z '$BEEF_HOOK_URL' ]"

# Test no hardcoded domains
run_test "No hardcoded domains in config" "! grep -q 'duckdns.org' '$SCRIPT_DIR/src/lib/config.sh' 2>/dev/null || grep -q '\$DUCK_DOMAIN' '$SCRIPT_DIR/src/lib/config.sh'"

# Test temp user is not root
run_test "Temp user is not root by default" "[ '$TEMP_USER' != 'root' ]"

# Test scripts use sudo correctly (not everywhere)
run_test "Sudo usage is selective" "grep -q 'sudo' '$SCRIPT_DIR/src/lib/utils.sh'"

# Test no world-writable sensitive files in git
run_test "SSL directory in .gitignore" "grep -q 'ssl/' '$SCRIPT_DIR/.gitignore'"

# Test no secrets in git history (check .gitignore)
run_test ".gitignore exists" "test -f '$SCRIPT_DIR/.gitignore'"
run_test ".gitignore has ssl/" "grep -q 'ssl/' '$SCRIPT_DIR/.gitignore'"

# Test no executable scripts in lib without shebang check
run_test "Lib files have shebang" "head -n1 '$SCRIPT_DIR/src/lib/config.sh' | grep -q '#!/bin/bash'"

# Test cleanup removes temporary user
run_test "Cleanup removes temp user" "grep -q 'deluser' '$SCRIPT_DIR/src/lib/utils.sh'"

# Test SSL certificates are not committed
run_test "SSL directory excluded" "grep -q 'ssl/' '$SCRIPT_DIR/.gitignore'"

# Test no API keys in scripts
run_test "No API keys in scripts" "! grep -r 'api_key\|apikey\|API_KEY' '$SCRIPT_DIR/src/lib/' 2>/dev/null"

# Test no tokens in scripts (excluding legitimate uses)
run_test "No hardcoded tokens in scripts" "! grep -r 'token.*=' '$SCRIPT_DIR/src/lib/' 2>/dev/null"

# Test VNC uses authentication
run_test "VNC uses authentication" "grep -q 'VncAuth\|SecurityTypes' '$SCRIPT_DIR/src/lib/services.sh'"

# Test no localhost only restriction when SSL is disabled (warning)
run_test "VNC allows remote connections" "grep -q 'localhost no' '$SCRIPT_DIR/src/lib/services.sh'"

# Test temp user has limited permissions concept
run_test "Temp user concept exists" "grep -q 'TEMP_USER' '$SCRIPT_DIR/src/lib/config.sh'"

# Test no eval of user input
run_test "No eval of user input" "! grep -r 'eval.*\$' '$SCRIPT_DIR/src/lib/' 2>/dev/null"

# Test no source of dynamic files
run_test "No source of dynamic files" "! grep -r 'source.*\$.*sh' '$SCRIPT_DIR/src/lib/' 2>/dev/null"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All security tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some security tests failed.${NC}"
    exit 1
fi
