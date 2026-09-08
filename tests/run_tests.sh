#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# TEST RUNNER (clean rewrite)
# ============================================================================
# Auto-discovers and runs all test files under tests/unit/ and tests/integration/.
# Each test file sources tests/lib/test_framework.sh and uses begin_suite/end_suite.
#
# Usage:
#   ./run_tests.sh                 # Run all tests
#   ./run_tests.sh unit/core/      # Run tests matching a path prefix
#   ./run_tests.sh -l              # List available tests
#   ./run_tests.sh -h              # Show help
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

total_passed=0
total_failed=0
total_suites=0

show_help() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Test Runner${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "Usage: $0 [options] [path_prefix]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -l, --list           List available tests"
    echo "  path_prefix          Run tests matching a path prefix"
    echo "                       (e.g. 'unit/core/' or 'unit/')"
    echo ""
    echo "Examples:"
    echo "  $0                        # Run all tests"
    echo "  $0 unit/core/             # Run only core unit tests"
    echo "  $0 unit/security/         # Run only security tests"
    echo "  $0 -l                     # List all tests"
    echo ""
}

list_tests() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Available Tests${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    local count=0
    while IFS= read -r test_file; do
        local rel="${test_file#$SCRIPT_DIR/}"
        echo -e "  ${GREEN}$rel${NC}"
        count=$((count + 1))
    done < <(find "$SCRIPT_DIR" -name "test_*.sh" -type f -not -path "*/lib/*" | sort)
    echo ""
    echo "Total: $count test files"
    echo ""
}

# Discover all test files (exclude lib/ which contains the framework)
discover_tests() {
    local filter="$1"
    find "$SCRIPT_DIR" -name "test_*.sh" -type f -not -path "*/lib/*" | sort | while read -r f; do
        local rel="${f#$SCRIPT_DIR/}"
        if [[ -z "$filter" ]] || [[ "$rel" == "$filter"* ]]; then
            echo "$f"
        fi
    done
}

# Parse arguments
if [ $# -eq 0 ]; then
    filter=""
elif [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    show_help
    exit 0
elif [ "$1" == "-l" ] || [ "$1" == "--list" ]; then
    list_tests
    exit 0
else
    filter="$1"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Running Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root (needed for some tests)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: Some tests may require sudo privileges${NC}"
    echo ""
fi

# Collect test files
test_files=()
while IFS= read -r f; do
    test_files+=("$f")
done < <(discover_tests "$filter")

if [ ${#test_files[@]} -eq 0 ]; then
    echo -e "${RED}No test files found matching '$filter'${NC}"
    exit 1
fi

# Run each test file
for test_path in "${test_files[@]}"; do
    rel="${test_path#$SCRIPT_DIR/}"
    echo -e "${BLUE}Running: $rel${NC}"
    echo ""

    if bash "$test_path"; then
        echo -e "${GREEN}PASS: $rel${NC}"
        total_passed=$((total_passed + 1))
    else
        echo -e "${RED}FAIL: $rel${NC}"
        total_failed=$((total_failed + 1))
    fi

    total_suites=$((total_suites + 1))
    echo ""
    echo "---"
    echo ""
done

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Total suites: $total_suites | ${GREEN}Passed: $total_passed${NC} | ${RED}Failed: $total_failed${NC}"
echo ""

if [ $total_failed -eq 0 ]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}Some test suites failed.${NC}"
    exit 1
fi
