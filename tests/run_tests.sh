#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# TEST RUNNER — Pyramid Strategy
# ============================================================================
# Auto-discovers and runs all test files, organized by testing pyramid level:
#
#   static/       → Level 0: lint, syntax, CRLF, shellcheck
#   unit/         → Level 1: isolated function tests
#   integration/  → Level 3: multi-module interaction tests
#   e2e/          → Level 5: entry-point and full-flow tests
#   security/     → Level 7: password policy, sanitization, hardening
#   powershell/   → PowerShell module tests (Pester)
#   windows/      → Windows wrapper tests (Pester)
#
# Supports multiple test formats:
#   test_*.sh     → Bash tests (run with bash)
#   test_*.py     → Python tests (run with pytest)
#   *.Tests.ps1   → PowerShell tests (run with pwsh -c Invoke-Pester)
#
# Usage:
#   ./run_tests.sh                 # Run all levels in order
#   ./run_tests.sh static/         # Run only static tests
#   ./run_tests.sh unit/           # Run only unit tests
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

# Pyramid levels in execution order (fastest first)
LEVELS=(static unit integration e2e security powershell windows)

total_passed=0
total_failed=0
total_suites=0
declare -A level_results

show_help() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Test Runner (Pyramid Strategy)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "Usage: $0 [options] [level_prefix]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -l, --list           List available tests"
    echo "  level_prefix         Run tests for a specific level:"
    echo "                       static, unit, integration, e2e, security,"
    echo "                       powershell, windows"
    echo ""
    echo "Pyramid levels (run in order):"
    echo "  static/      Level 0: lint, syntax, CRLF, shellcheck"
    echo "  unit/        Level 1: isolated function tests"
    echo "  integration/  Level 3: multi-module interaction"
    echo "  e2e/         Level 5: entry-point and full-flow"
    echo "  security/    Level 7: password policy, sanitization"
    echo "  powershell/  PowerShell module tests (Pester)"
    echo "  windows/     Windows wrapper tests (Pester)"
    echo ""
    echo "Supported test formats:"
    echo "  test_*.sh    Bash tests"
    echo "  test_*.py    Python tests (pytest)"
    echo "  *.Tests.ps1  PowerShell tests (Pester)"
    echo ""
    echo "Examples:"
    echo "  $0                        # Run all levels"
    echo "  $0 static/                # Run only static tests"
    echo "  $0 unit/core/              # Run only core unit tests"
    echo "  $0 -l                     # List all tests"
    echo ""
}

list_tests() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Available Tests (by level)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    local count=0
    for level in "${LEVELS[@]}"; do
        local level_dir="$SCRIPT_DIR/$level"
        if [[ -d "$level_dir" ]]; then
            echo -e "${BLUE}[$level]${NC}"
            # Bash tests
            while IFS= read -r test_file; do
                local rel="${test_file#"$SCRIPT_DIR"/}"
                echo -e "  ${GREEN}$rel${NC}"
                count=$((count + 1))
            done < <(find "$level_dir" -name "test_*.sh" -type f 2>/dev/null | sort)
            # Python tests
            while IFS= read -r test_file; do
                local rel="${test_file#"$SCRIPT_DIR"/}"
                echo -e "  ${GREEN}$rel${NC}"
                count=$((count + 1))
            done < <(find "$level_dir" -name "test_*.py" -type f 2>/dev/null | sort)
            # PowerShell tests
            while IFS= read -r test_file; do
                local rel="${test_file#"$SCRIPT_DIR"/}"
                echo -e "  ${GREEN}$rel${NC}"
                count=$((count + 1))
            done < <(find "$level_dir" -name "*.Tests.ps1" -type f 2>/dev/null | sort)
            echo ""
        fi
    done
    echo "Total: $count test files"
    echo ""
}

# Discover test files for a given level (or all if empty)
discover_tests() {
    local filter="$1"
    for level in "${LEVELS[@]}"; do
        local level_dir="$SCRIPT_DIR/$level"
        if [[ ! -d "$level_dir" ]]; then
            continue
        fi
        # If filter starts with a level name, only run that level
        if [[ -n "$filter" ]] && [[ "$filter" != "$level"* ]]; then
            continue
        fi
        # Bash tests (test_*.sh)
        while IFS= read -r f; do
            local rel="${f#"$SCRIPT_DIR"/}"
            if [[ -z "$filter" ]] || [[ "$rel" == "$filter"* ]]; then
                echo "$f"
            fi
        done < <(find "$level_dir" -name "test_*.sh" -type f 2>/dev/null | sort)
        # Python tests (test_*.py)
        while IFS= read -r f; do
            local rel="${f#"$SCRIPT_DIR"/}"
            if [[ -z "$filter" ]] || [[ "$rel" == "$filter"* ]]; then
                echo "$f"
            fi
        done < <(find "$level_dir" -name "test_*.py" -type f 2>/dev/null | sort)
        # PowerShell tests (*.Tests.ps1)
        while IFS= read -r f; do
            local rel="${f#"$SCRIPT_DIR"/}"
            if [[ -z "$filter" ]] || [[ "$rel" == "$filter"* ]]; then
                echo "$f"
            fi
        done < <(find "$level_dir" -name "*.Tests.ps1" -type f 2>/dev/null | sort)
    done
}

# Run a single test file based on its extension
run_test_file() {
    local test_path="$1"
    local ext="${test_path##*.}"

    if [[ "$ext" == "sh" ]]; then
        bash "$test_path"
    elif [[ "$ext" == "py" ]]; then
        # Try pytest, then python3 -m pytest, then Windows Python (python.exe
        # or py.exe) for WSL environments where Linux Python may not have
        # pytest installed. When using Windows Python from WSL, convert paths
        # to Windows format via wslpath.
        if command -v pytest &>/dev/null; then
            pytest "$test_path" -q
        elif command -v python3 &>/dev/null && python3 -m pytest --version &>/dev/null; then
            python3 -m pytest "$test_path" -q
        elif command -v python.exe &>/dev/null; then
            local win_path="$test_path"
            local win_pythonpath="src"
            if command -v wslpath &>/dev/null; then
                win_path=$(wslpath -w "$test_path")
                win_pythonpath=$(wslpath -w "$PWD/src")
            fi
            PYTHONPATH="$win_pythonpath" python.exe -m pytest "$win_path" -q
        elif command -v py.exe &>/dev/null; then
            local win_path="$test_path"
            local win_pythonpath="src"
            if command -v wslpath &>/dev/null; then
                win_path=$(wslpath -w "$test_path")
                win_pythonpath=$(wslpath -w "$PWD/src")
            fi
            PYTHONPATH="$win_pythonpath" py.exe -3 -m pytest "$win_path" -q
        else
            echo -e "${YELLOW}[SKIP] pytest not installed, skipping $test_path${NC}"
            return 0
        fi
    elif [[ "$ext" == "ps1" ]]; then
        if command -v pwsh &>/dev/null; then
            pwsh -NoProfile -Command "Invoke-Pester '$test_path' -Output Detailed"
        elif command -v powershell &>/dev/null; then
            powershell -NoProfile -Command "Invoke-Pester '$test_path' -Output Detailed"
        else
            echo -e "${YELLOW}[SKIP] PowerShell not available, skipping $test_path${NC}"
            return 0
        fi
    else
        echo -e "${YELLOW}[SKIP] Unknown test type: $test_path${NC}"
        return 0
    fi
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
echo -e "${BLUE}  Running Test Suite (Pyramid)${NC}"
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
    rel="${test_path#"$SCRIPT_DIR"/}"
    echo -e "${BLUE}Running: $rel${NC}"
    echo ""

    if run_test_file "$test_path"; then
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
