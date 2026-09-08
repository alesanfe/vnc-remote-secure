#!/bin/bash
# ============================================================================
# SYNTAX VALIDATION TESTS (clean rewrite)
# ============================================================================
# Verifies that every shell script in src/ parses without syntax errors using
# `bash -n`. If shellcheck is available, runs it as a non-blocking warning.
# ============================================================================

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TEST_DIR/../../lib/test_framework.sh"

begin_suite "Syntax Validation"

# Collect all .sh files under src/
SCRIPTS_DIR="$PROJECT_ROOT/src"
ALL_SCRIPTS=()
while IFS= read -r f; do
    ALL_SCRIPTS+=("$f")
done < <(find "$SCRIPTS_DIR" -name "*.sh" -type f | sort)

test_main_script_has_shebang() {
    local first_line
    first_line=$(head -n1 "$PROJECT_ROOT/src/rpi-vnc-remote.sh")
    assert_contains "$first_line" "#!/bin/bash" "main script should start with #!/bin/bash"
}

test_main_script_has_set_e() {
    assert_success grep -q 'set -e' "$PROJECT_ROOT/src/rpi-vnc-remote.sh"
}

test_all_modules_have_shebang() {
    local f
    for f in "${ALL_SCRIPTS[@]}"; do
        if ! head -n1 "$f" | grep -q '#!/bin/bash'; then
            echo "    missing shebang: $f"
            return 1
        fi
    done
    return 0
}

test_all_modules_parse_with_bash_n() {
    local f
    for f in "${ALL_SCRIPTS[@]}"; do
        if ! bash -n "$f" 2>/dev/null; then
            echo "    syntax error in: $f"
            return 1
        fi
    done
    return 0
}

test_main_script_parses() {
    assert_success bash -n "$PROJECT_ROOT/src/rpi-vnc-remote.sh"
}

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

test_no_crlf_line_endings_in_src() {
    # CRLF (\r\n) breaks bash scripts; detect any .sh under src/ with \r
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
    done < <(find "$SCRIPTS_DIR" -name "*.py" -type f | sort)
    return 0
}

run_test "Main script has shebang" test_main_script_has_shebang
run_test "Main script has set -e" test_main_script_has_set_e
run_test "All modules have shebang" test_all_modules_have_shebang
run_test "All modules parse with bash -n" test_all_modules_parse_with_bash_n
run_test "Main script parses with bash -n" test_main_script_parses
run_test "All scripts are readable" test_all_scripts_are_readable
run_test "No CRLF line endings in src .sh files" test_no_crlf_line_endings_in_src
run_test "No CRLF line endings in src .py files" test_no_crlf_in_python_sources

# Non-blocking shellcheck advisory
if command -v shellcheck >/dev/null 2>&1; then
    echo ""
    echo -e "${YELLOW}(shellcheck available - advisory only, not counted)${NC}"
    sc_errors=0
    for f in "${ALL_SCRIPTS[@]}"; do
        if ! shellcheck -S warning "$f" >/dev/null 2>&1; then
            sc_errors=$((sc_errors + 1))
        fi
    done
    echo -e "${YELLOW}shellcheck warnings in $sc_errors/${#ALL_SCRIPTS[@]} files (advisory)${NC}"
else
    echo ""
    echo -e "${YELLOW}shellcheck not installed - skipping advisory checks${NC}"
fi

end_suite
