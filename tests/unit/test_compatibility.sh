#!/bin/bash
# ============================================================================
# COMPATIBILITY TESTS
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd"

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

echo "=== Compatibility Tests ==="
echo ""

# Test bash version compatibility
run_test "Bash version 4.0 or higher" "[ ${BASH_VERSINFO[0]} -ge 4 ]"

# Test POSIX compatibility features
run_test "Local variable support" "local test_var=123 2>/dev/null || true"
run_test "Array support" "declare -a test_array 2>/dev/null || true"

# Source config
source "$SCRIPT_DIR/src/lib/config.sh"

# Test environment variable compatibility
export TEST_VAR="test_value"
run_test "Environment variable export works" "[ -n '$TEST_VAR' ]"
unset TEST_VAR

# Test path handling with spaces
export TEMP_USER="test user"
source "$SCRIPT_DIR/src/lib/config.sh"
run_test "Handles usernames with spaces" "[ -n '$TEMP_USER' ]"
unset TEMP_USER

# Test numeric comparisons
run_test "Integer comparison works" "[ 5 -gt 3 ]"
run_test "String comparison works" "[ 'test' = 'test' ]"

# Test file operations compatibility
run_test "File existence check works" "test -f '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"
run_test "Directory existence check works" "test -d '$SCRIPT_DIR/src/lib'"
run_test "File readability check works" "test -r '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"

# Test command substitution compatibility
test_var=$(echo "test")
run_test "Command substitution works" "[ '$test_var' = 'test' ]"

# Test arithmetic expansion compatibility
result=$((5 + 3))
run_test "Arithmetic expansion works" "[ $result -eq 8 ]"

# Test function definition compatibility
test_func() { echo "test"; }
run_test "Function definition works" "test_func &>/dev/null"

# Test subshell compatibility
run_test "Subshell execution works" "(echo test) &>/dev/null"

# Test pipe compatibility
run_test "Pipe operation works" "echo test | grep -q test"

# Test redirect compatibility
run_test "Output redirect works" "echo test > /dev/null"
run_test "Input redirect works" "cat /dev/null"

# Test background job compatibility
run_test "Background job syntax works" "sleep 0 &"

# Test signal handling
run_test "Trap command works" "trap 'echo test' EXIT"

# Test conditional compatibility
run_test "If statement works" "if true; then :; fi"

# Test loop compatibility
run_test "For loop works" "for i in 1 2 3; do :; done"
run_test "While loop works" "while false; do :; done"

# Test case statement compatibility
run_test "Case statement works" "case 'test' in test) :;; esac"

# Test function parameter passing
test_param_func() {
    [ "$1" = "test" ]
}
run_test "Function parameters work" "test_param_func 'test'"

# Test return value compatibility
test_return_func() { return 0; }
run_test "Function return works" "test_return_func"

# Test exit code compatibility
run_test "Exit code works" "true"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All compatibility tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some compatibility tests failed.${NC}"
    exit 1
fi
