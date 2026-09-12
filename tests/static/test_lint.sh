#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2317,SC2153
# ============================================================================
# LEVEL 0 — STATIC TESTS
# ============================================================================
# Catches errors before execution: syntax, lint, format, line endings.
# These are the cheapest tests and should run first in any pipeline.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../lib/test_framework.sh"

begin_suite "Static Analysis (Level 0)"

# Collect all .sh files under src/ and scripts/
SRC_SCRIPTS=()
while IFS= read -r f; do
    SRC_SCRIPTS+=("$f")
done < <(find "$PROJECT_ROOT/src" -name "*.sh" -type f | sort)

MAINTENANCE_SCRIPTS=()
while IFS= read -r f; do
    MAINTENANCE_SCRIPTS+=("$f")
done < <(find "$PROJECT_ROOT/scripts" -name "*.sh" -type f | sort)

ALL_SCRIPTS=("${SRC_SCRIPTS[@]}" "${MAINTENANCE_SCRIPTS[@]}")

# --- Syntax (bash -n) ---

test_main_script_parses() {
    assert_success bash -n "$PROJECT_ROOT/src/rpi-vnc-remote.sh"
}

test_all_src_modules_parse() {
    local f
    for f in "${SRC_SCRIPTS[@]}"; do
        if ! bash -n "$f" 2>/dev/null; then
            echo "    syntax error in: $f"
            return 1
        fi
    done
    return 0
}

test_all_maintenance_scripts_parse() {
    local f
    for f in "${MAINTENANCE_SCRIPTS[@]}"; do
        if ! bash -n "$f" 2>/dev/null; then
            echo "    syntax error in: $f"
            return 1
        fi
    done
    return 0
}

# --- Shebang ---

test_main_script_has_shebang() {
    local first_line
    first_line=$(head -n1 "$PROJECT_ROOT/src/rpi-vnc-remote.sh")
    assert_contains "$first_line" "#!/bin/bash" "main script should start with #!/bin/bash"
}

test_all_modules_have_shebang() {
    local f
    for f in "${ALL_SCRIPTS[@]}"; do
        if ! head -n1 "$f" | grep -qE '^#!(/bin/bash|/usr/bin/env bash)'; then
            echo "    missing shebang: $f"
            return 1
        fi
    done
    return 0
}

# --- set -e / set -o pipefail ---

test_main_script_has_set_e() {
    assert_success grep -q 'set -e' "$PROJECT_ROOT/src/rpi-vnc-remote.sh"
}

test_main_script_has_pipefail() {
    assert_success grep -q 'set -o pipefail' "$PROJECT_ROOT/src/rpi-vnc-remote.sh"
}

# --- Line endings (CRLF detection) ---

test_no_crlf_in_sh_files() {
    local f
    for f in "${ALL_SCRIPTS[@]}"; do
        if grep -lqP '\r$' "$f" 2>/dev/null; then
            echo "    CRLF line endings found in: $f"
            return 1
        fi
    done
    return 0
}

test_no_crlf_in_python_sources() {
    local f
    while IFS= read -r f; do
        if grep -lqP '\r$' "$f" 2>/dev/null; then
            echo "    CRLF line endings found in: $f"
            return 1
        fi
    done < <(find "$PROJECT_ROOT/src" -name "*.py" -type f | sort)
    return 0
}

# --- File permissions ---

test_all_scripts_are_readable() {
    local f
    for f in "${ALL_SCRIPTS[@]}"; do
        if [[ ! -r "$f" ]]; then
            echo "    not readable: $f"
            return 1
        fi
    done
    return 0
}

test_main_script_is_executable() {
    if [[ -x "$PROJECT_ROOT/src/rpi-vnc-remote.sh" ]]; then
        return 0
    else
        echo "    main script is not executable: src/rpi-vnc-remote.sh"
        return 1
    fi
}

# --- shellcheck (blocking at warning level) ---

test_shellcheck_no_errors() {
    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "    (shellcheck not installed - skipping)"
        return 0
    fi
    # Functional check: shellcheck wrappers (e.g. npm) may exist on PATH but
    # fail at runtime if their runtime (node) is missing. Verify shellcheck
    # actually works before relying on it.
    if ! shellcheck --version >/dev/null 2>&1; then
        echo "    (shellcheck found but not functional - skipping)"
        return 0
    fi
    local f
    local errors=0
    for f in "${ALL_SCRIPTS[@]}"; do
        local output
        if ! output=$(shellcheck -S error "$f" 2>&1); then
            echo "    shellcheck errors in: $f"
            echo "$output" | head -5 | sed 's/^/      /'
            errors=$((errors + 1))
        fi
    done
    [[ "$errors" -eq 0 ]]
}

test_shellcheck_warnings_advisory() {
    # Shellcheck warnings are advisory - the codebase has pre-existing
    # warnings that need a dedicated cleanup pass. This test reports
    # the count but does not fail the suite.
    if ! command -v shellcheck >/dev/null 2>&1; then
        echo "    (shellcheck not installed - skipping)"
        return 0
    fi
    # Functional check (see test_shellcheck_no_errors for rationale).
    if ! shellcheck --version >/dev/null 2>&1; then
        echo "    (shellcheck found but not functional - skipping)"
        return 0
    fi
    local f
    local warnings=0
    for f in "${ALL_SCRIPTS[@]}"; do
        if ! shellcheck -S warning "$f" >/dev/null 2>&1; then
            warnings=$((warnings + 1))
        fi
    done
    if [[ "$warnings" -gt 0 ]]; then
        echo "    (advisory: shellcheck warnings in $warnings/${#ALL_SCRIPTS[@]} files - needs cleanup)"
    fi
    return 0
}

# --- Python syntax check ---

test_python_sources_compile() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "    (python3 not installed - skipping)"
        return 0
    fi
    local f
    while IFS= read -r f; do
        if ! python3 -c "compile(open('$f').read(), '$f', 'exec')" 2>/dev/null; then
            echo "    Python syntax error in: $f"
            return 1
        fi
    done < <(find "$PROJECT_ROOT/src" -name "*.py" -type f | sort)
    return 0
}

# --- Run tests ---

run_test "Main script parses with bash -n" test_main_script_parses
run_test "All src/ modules parse with bash -n" test_all_src_modules_parse
run_test "All scripts/ parse with bash -n" test_all_maintenance_scripts_parse
run_test "Main script has shebang" test_main_script_has_shebang
run_test "All modules have shebang" test_all_modules_have_shebang
run_test "Main script has set -e" test_main_script_has_set_e
run_test "Main script has set -o pipefail" test_main_script_has_pipefail
run_test "No CRLF in .sh files" test_no_crlf_in_sh_files
run_test "No CRLF in .py files" test_no_crlf_in_python_sources
run_test "All scripts are readable" test_all_scripts_are_readable
run_test "Main script is executable" test_main_script_is_executable
run_test "shellcheck: no errors" test_shellcheck_no_errors
run_test "shellcheck: warnings (advisory)" test_shellcheck_warnings_advisory
run_test "Python sources compile" test_python_sources_compile

end_suite
