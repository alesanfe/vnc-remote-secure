#!/bin/bash
# ============================================================================
# TEST RUNNER
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

total_tests=0
total_passed=0
total_failed=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Running Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root (needed for some tests)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Some tests may require sudo privileges${NC}"
    echo ""
fi

# Array of test files
test_files=(
    "test_syntax.sh"
    "test_config.sh"
    "test_utils.sh"
    "test_modules.sh"
    "test_docker.sh"
    "test_edge_cases.sh"
    "test_error_handling.sh"
    "test_security.sh"
)

# Run each test file
for test_file in "${test_files[@]}"; do
    test_path="$SCRIPT_DIR/$test_file"
    
    if [ ! -f "$test_path" ]; then
        echo -e "${RED}Test file not found: $test_file${NC}"
        continue
    fi
    
    echo -e "${BLUE}Running: $test_file${NC}"
    echo ""
    
    # Make test executable
    chmod +x "$test_path"
    
    # Run test and capture exit code
    if bash "$test_path"; then
        test_result=0
    else
        test_result=$?
    fi
    
    # Parse results from test output (last line contains summary)
    # We'll just count based on exit code for simplicity
    if [ $test_result -eq 0 ]; then
        echo -e "${GREEN}✓ $test_file passed${NC}"
        total_passed=$((total_passed + 1))
    else
        echo -e "${RED}✗ $test_file failed${NC}"
        total_failed=$((total_failed + 1))
    fi
    
    total_tests=$((total_tests + 1))
    echo ""
    echo "---"
    echo ""
done

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Total test suites: $total_tests"
echo -e "${GREEN}Passed: $total_passed${NC}"
echo -e "${RED}Failed: $total_failed${NC}"
echo ""

if [ $total_failed -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  All tests passed!${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Some tests failed${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
