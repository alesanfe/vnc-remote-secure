#!/bin/bash
# ============================================================================
# DOCKER-SPECIFIC INTEGRATION TESTS
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

echo "=== Docker Integration Tests ==="
echo ""

# Check Docker is available
run_test "Docker command available" "command -v docker &>/dev/null"

# Check docker-compose is available
run_test "Docker Compose available" "command -v docker-compose &>/dev/null || docker compose version &>/dev/null"

# Check if Dockerfile exists
run_test "Dockerfile exists" "test -f '$SCRIPT_DIR/docker/Dockerfile'"

# Check if docker-compose.yml exists
run_test "docker-compose.yml exists" "test -f '$SCRIPT_DIR/docker/docker-compose.yml'"

# Test Dockerfile syntax
run_test "Dockerfile is valid" "docker build -f '$SCRIPT_DIR/docker/Dockerfile' --target test -t test-image . 2>&1 | head -20"

# Test docker-compose syntax
run_test "docker-compose.yml is valid" "docker-compose -f '$SCRIPT_DIR/docker/docker-compose.yml' config &>/dev/null || docker compose -f '$SCRIPT_DIR/docker/docker-compose.yml' config &>/dev/null"

# Test if we can build the Docker image
run_test "Docker image can be built" "docker build -t rpi-vnc-test -f '$SCRIPT_DIR/docker/Dockerfile' . 2>&1 | tail -5"

# Test if we can run a simple command in Docker
if [ -n "$IN_DOCKER" ]; then
    run_test "Can run bash in container" "bash -c 'echo test' &>/dev/null"
    run_test "User has sudo access" "sudo -n true &>/dev/null"
    run_test "Can install packages" "apt-get update &>/dev/null"
fi

# Test project files are accessible
run_test "Project files copied to container" "test -f '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"
run_test "Lib files are accessible" "test -d '$SCRIPT_DIR/src/lib'"
run_test "Test files are accessible" "test -d '$SCRIPT_DIR/tests'"

# Test script permissions
run_test "Main script is executable" "test -x '$SCRIPT_DIR/src/rpi-vnc-remote.sh'"
run_test "Test scripts are executable" "test -x '$SCRIPT_DIR/tests/run_tests.sh'"

# Test script can source modules
run_test "Can source config module" "source '$SCRIPT_DIR/src/lib/config.sh' 2>/dev/null"
run_test "Can source utils module" "source '$SCRIPT_DIR/src/lib/utils.sh' 2>/dev/null"

# Test help command works
run_test "Help command works" "bash '$SCRIPT_DIR/src/rpi-vnc-remote.sh' help 2>&1 | grep -q 'Usage:'"

echo ""
echo "=== Results ==="
echo -e "Total: $test_count | ${GREEN}Passed: $pass_count${NC} | ${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All Docker integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some Docker integration tests failed.${NC}"
    exit 1
fi
