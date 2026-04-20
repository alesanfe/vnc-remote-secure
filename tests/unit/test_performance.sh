#!/bin/bash
# ============================================================================
# PERFORMANCE TESTS
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

echo "=== Performance Tests ==="
echo ""

# Source config
source "$SCRIPT_DIR/src/lib/config.sh"

# Test configuration loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/config.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "Config loading took ${duration}ms"

run_test "Config loads in under 100ms" "[ $duration -lt 100 ]"

# Test utils loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/utils.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "Utils loading took ${duration}ms"

run_test "Utils loads in under 100ms" "[ $duration -lt 100 ]"

# Test SSL module loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/ssl.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "SSL module loading took ${duration}ms"

run_test "SSL module loads in under 100ms" "[ $duration -lt 100 ]"

# Test user module loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/user.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "User module loading took ${duration}ms"

run_test "User module loads in under 100ms" "[ $duration -lt 100 ]"

# Test services module loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/services.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "Services module loading took ${duration}ms"

run_test "Services module loads in under 100ms" "[ $duration -lt 100 ]"

# Test total loading performance
start_time=$(date +%s%N)
source "$SCRIPT_DIR/src/lib/config.sh"
source "$SCRIPT_DIR/src/lib/utils.sh"
source "$SCRIPT_DIR/src/lib/ssl.sh"
source "$SCRIPT_DIR/src/lib/user.sh"
source "$SCRIPT_DIR/src/lib/services.sh"
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "Total module loading took ${duration}ms"

run_test "All modules load in under 500ms" "[ $duration -lt 500 ]"

# Test log function performance
start_time=$(date +%s%N)
for i in {1..100}; do
    log "test" "test message" "test" > /dev/null
done
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "100 log calls took ${duration}ms"

run_test "100 log calls complete in under 1s" "[ $duration -lt 1000 ]"

# Test architecture detection performance
start_time=$(date +%s%N)
detect_ttyd_arch > /dev/null
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))

echo "Architecture detection took ${duration}ms"

run_test "Architecture detection completes in under 50ms" "[ $duration -lt 50 ]"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All performance tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some performance tests failed.${NC}"
    exit 1
fi
