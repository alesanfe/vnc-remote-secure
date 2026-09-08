#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# TEST FRAMEWORK LIBRARY (clean rewrite)
# ============================================================================
# Common testing utilities for all test files.
# Designed to be sourced by individual test files. Does NOT use set -e so
# that tests can capture and assert on exit codes.
#
# Usage in a test file:
#   #!/bin/bash
#   TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$TEST_DIR/../lib/test_framework.sh"
#   # source the module under test, then call run_test_suite
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters (reset per suite)
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
CURRENT_SUITE=""

# Resolve project root (parent of tests/)
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(dirname "$TESTS_DIR")"

# ----------------------------------------------------------------------------
# Print helpers
# ----------------------------------------------------------------------------

print_test_header() {
    local title="$1"
    echo ""
    echo -e "${BLUE}=== $title ===${NC}"
    echo ""
}

print_suite_summary() {
    echo ""
    echo -e "${BLUE}--- Results: $CURRENT_SUITE ---${NC}"
    if [[ "$FAIL_COUNT" -eq 0 ]]; then
        echo -e "${GREEN}Total: $TEST_COUNT | Passed: $PASS_COUNT | Failed: $FAIL_COUNT${NC}"
    else
        echo -e "${RED}Total: $TEST_COUNT | Passed: $PASS_COUNT | Failed: $FAIL_COUNT${NC}"
    fi
}

# ----------------------------------------------------------------------------
# Assertions (each returns 0 on success, 1 on failure; does NOT exit)
# ----------------------------------------------------------------------------

# Assert two strings are equal
assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-values should be equal}"
    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        echo "    ${RED}assert_eq failed:${NC} $msg"
        echo "    expected: '$expected'"
        echo "    actual:   '$actual'"
        return 1
    fi
}

# Assert two strings are NOT equal
assert_ne() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-values should differ}"
    if [[ "$expected" != "$actual" ]]; then
        return 0
    else
        echo "    ${RED}assert_ne failed:${NC} $msg"
        echo "    both were: '$expected'"
        return 1
    fi
}

# Assert a command exits with the expected code
# Usage: assert_exit_code <expected_code> <command...>
assert_exit_code() {
    local expected="$1"
    shift
    local actual
    "$@" >/dev/null 2>&1
    actual=$?
    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        echo "    ${RED}assert_exit_code failed:${NC} expected $expected, got $actual"
        echo "    command: $*"
        return 1
    fi
}

# Assert a command succeeds (exit 0)
assert_success() {
    local actual
    "$@" >/dev/null 2>&1
    actual=$?
    if [[ "$actual" -eq 0 ]]; then
        return 0
    else
        echo "    ${RED}assert_success failed:${NC} exit code $actual"
        echo "    command: $*"
        return 1
    fi
}

# Assert a command fails (non-zero exit)
assert_failure() {
    local actual
    "$@" >/dev/null 2>&1
    actual=$?
    if [[ "$actual" -ne 0 ]]; then
        return 0
    else
        echo "    ${RED}assert_failure failed:${NC} command unexpectedly succeeded"
        echo "    command: $*"
        return 1
    fi
}

# Assert a string contains a substring
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="${3:-string should contain substring}"
    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        echo "    ${RED}assert_contains failed:${NC} $msg"
        echo "    haystack: '$haystack'"
        echo "    needle:   '$needle'"
        return 1
    fi
}

# Assert a variable is set and non-empty
assert_not_empty() {
    local var_name="$1"
    local var_value="${!var_name}"
    local msg="${2:-variable should be non-empty}"
    if [[ -n "$var_value" ]]; then
        return 0
    else
        echo "    ${RED}assert_not_empty failed:${NC} $msg"
        echo "    variable: $var_name"
        return 1
    fi
}

# Assert a function exists (is defined)
assert_function_exists() {
    local fn="$1"
    if declare -F "$fn" >/dev/null 2>&1; then
        return 0
    else
        echo "    ${RED}assert_function_exists failed:${NC} function '$fn' is not defined"
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Test runner
# ----------------------------------------------------------------------------

# Run a single test case. Usage:
#   run_test "description" test_function_name
# The test function should use the assert_* helpers and return non-zero on failure.
run_test() {
    local description="$1"
    local fn="$2"
    TEST_COUNT=$((TEST_COUNT + 1))
    echo -n "  Test $TEST_COUNT: $description... "
    # Run the test function; capture its exit code
    if "$fn"; then
        echo -e "${GREEN}PASS${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# Begin a new suite (resets counters and sets the suite name)
begin_suite() {
    local name="$1"
    CURRENT_SUITE="$name"
    TEST_COUNT=0
    PASS_COUNT=0
    FAIL_COUNT=0
    print_test_header "$name"
}

# End the current suite and print its summary. Returns 1 if any test failed.
end_suite() {
    print_suite_summary
    [[ "$FAIL_COUNT" -eq 0 ]]
}

# ----------------------------------------------------------------------------
# Module sourcing helper
# ----------------------------------------------------------------------------

# Source a project module by relative path from PROJECT_ROOT.
# Usage: source_module "src/lib/core/config.sh"
source_module() {
    local rel="$1"
    local path="$PROJECT_ROOT/$rel"
    if [[ ! -f "$path" ]]; then
        echo "    ${RED}source_module: file not found: $path${NC}" >&2
        return 1
    fi
    # shellcheck disable=SC1090
    source "$path"
}

# Source a module and disable set -e (modules enable it on load).
# Usage: source_module_safe "src/lib/core/config.sh"
source_module_safe() {
    source_module "$1" || return 1
    set +e  # modules set -e on load; disable so tests can capture exit codes
}
