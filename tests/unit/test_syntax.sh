#!/bin/bash
# ============================================================================
# SYNTAX VALIDATION TESTS
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

echo "=== Syntax Validation Tests ==="
echo ""

# Check if shellcheck is installed
if ! command -v shellcheck &> /dev/null; then
    echo -e "${YELLOW}shellcheck not found. Installing...${NC}"
    sudo apt-get install -y shellcheck > /dev/null 2>&1 || {
        echo -e "${YELLOW}Failed to install shellcheck. Skipping shellcheck tests.${NC}"
        SKIP_SHELLCHECK=true
    }
fi

# Test main script
if [ -z "$SKIP_SHELLCHECK" ]; then
    run_test "Main script syntax" "shellcheck '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"
fi

# Test all library modules
if [ -z "$SKIP_SHELLCHECK" ]; then
    for module in config.sh utils.sh ssl.sh user.sh services.sh; do
        run_test "Module syntax: $module" "shellcheck '$SCRIPT_DIR/src/lib/$module'"
    done
fi

# Test shebang presence
run_test "Main script has shebang" "head -n1 '$SCRIPT_DIR/src/rpi-vnc-remote.sh' | grep -q '#!/bin/bash'"

for module in config.sh utils.sh ssl.sh user.sh services.sh; do
    run_test "Module has shebang: $module" "head -n1 '$SCRIPT_DIR/src/lib/$module' | grep -q '#!/bin/bash'"
done

# Test set -e presence
run_test "Main script has set -e" "grep -q 'set -e' '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"

# Test file permissions
run_test "Main script is readable" "test -r '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"
for module in config.sh utils.sh ssl.sh user.sh services.sh; do
    run_test "Module is readable: $module" "test -r '$SCRIPT_DIR/src/lib/$module'"
done

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All syntax tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some syntax tests failed.${NC}"
    exit 1
fi
