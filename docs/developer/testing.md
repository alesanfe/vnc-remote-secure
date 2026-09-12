# Testing Guide

This project uses a **testing pyramid** strategy with 5 levels, from cheapest
to most expensive. Tests are organized by level under `tests/`.

## Pyramid Structure

```
                    security/  (18 tests)     ← Level 7
                        e2e/  (15 tests)     ← Level 5
                integration/  (6 tests)      ← Level 3
                      unit/  (63 tests)      ← Level 1
                   static/  (14 tests)       ← Level 0
```

**Total: 8 suites, 116 tests.**

## Directory Layout

```
tests/
├── lib/
│   └── test_framework.sh      # Shared assertions and helpers
├── static/
│   └── test_lint.sh            # Level 0: bash -n, shellcheck, CRLF, shebang
├── unit/
│   └── core/
│       ├── test_config.sh     # Level 1: config defaults and env overrides
│       ├── test_logging.sh    # Level 1: log functions and levels
│       ├── test_utils.sh      # Level 1: validate_config, password strength
│       └── test_validation.sh # Level 1: password, port, domain, email, username
├── integration/
│   └── test_module_loading.sh # Level 3: 18-module load chain, validate_config
├── e2e/
│   └── test_script_load.sh    # Level 5: main() structure, cleanup, commands
├── security/
│   └── test_security.sh       # Level 7: password policy, XSS, injection
└── run_tests.sh               # Runner with auto-discovery by level
```

## Running Tests

```bash
# Run the full pyramid (all levels in order)
bash tests/run_tests.sh
make test-all

# Run a single level
bash tests/run_tests.sh static/       # Level 0
bash tests/run_tests.sh unit/          # Level 1
bash tests/run_tests.sh integration/  # Level 3
bash tests/run_tests.sh e2e/           # Level 5
bash tests/run_tests.sh security/     # Level 7

# Or via Makefile
make test-static
make test-unit
make test-integration
make test-e2e
make test-security

# List available tests
bash tests/run_tests.sh -l
make test-list
```

## Test Framework

The framework (`tests/lib/test_framework.sh`) provides:

- **Assertions**: `assert_eq`, `assert_ne`, `assert_success`, `assert_failure`,
  `assert_contains`, `assert_not_empty`, `assert_function_exists`
- **Suite helpers**: `begin_suite`, `run_test`, `end_suite`
- **Module loading**: `source_module`, `source_module_safe` (resets `set +e`)

The framework intentionally does NOT enable `set -e`, so tests can assert
expected non-zero return codes without terminating the test process.

## What Each Level Tests

### Level 0 — Static (`tests/static/`)

Catches errors before execution:
- `bash -n` syntax check on all `.sh` files in `src/` and `scripts/`
- `shellcheck` (errors are blocking, warnings are advisory)
- CRLF line ending detection (`.sh` and `.py`)
- Shebang and `set -e` / `set -o pipefail` verification
- File permission checks
- Python source compilation (`python3 -c compile`)

### Level 1 — Unit (`tests/unit/`)

Isolated function tests:
- Config defaults and environment variable overrides
- Password validation (length, complexity, weak pattern rejection)
- Port, domain, email, and username validation
- `sanitize_input` HTML escaping
- Logging function output and delegation
- `validate_config` with secure and insecure values

### Level 3 — Integration (`tests/integration/`)

Multi-module interaction:
- All 18 modules source without error (in load order)
- Core chain (config → logging → validation → error_handling → utils) works together
- `validate_config` end-to-end with secure values (passes) and defaults (fails)
- Security modules source correctly after core
- Duplicate function definition detection

### Level 5 — E2E (`tests/e2e/`)

Entry-point and full-flow:
- `main()` function exists and has cleanup trap
- Script sources all 18 modules
- `help` command exits without hanging
- No-args execution does not hang (timeout-protected)
- Cleanup references `userdel`, `tigervncserver`, `novnc_proxy`, `ttyd`
- Main calls `validate_config`, `install_dependencies`, `setup_ssl`,
  `create_temp_user`, `start_vnc_server`, `start_novnc`, `start_ttyd`

### Level 7 — Security (`tests/security/`)

Security-critical behavior:
- Password policy: rejects empty, weak patterns, short, and non-complex
- XSS prevention: `sanitize_input` escapes `<`, `>`, `"`, `'`
- Config hardening: defaults block startup (insecure email rejected)
- `KEEP_TEMP_USER=false` by default (temp user removed on exit)
- Optional features (fail2ban, Discord) disabled by default
- SSL enabled by default (`DISABLE_SSL=false`)
- Command injection prevention in usernames
- Reserved system usernames rejected
- Directory traversal prevention in paths

## CI/CD Pipeline

The recommended CI pipeline runs levels in order (fastest first):

```
static → unit → integration → e2e → security
```

Each level gates the next: if static fails, don't run unit; if unit fails,
don't run integration; etc. This gives the fastest feedback on errors.

## Adding New Tests

1. Create a `test_*.sh` file in the appropriate level directory
2. Source the framework: `source "$TEST_DIR/../lib/test_framework.sh"`
3. Use `begin_suite` / `end_suite` and `run_test` helpers
4. For unit tests, use `source_module_safe` to load modules
5. The runner auto-discovers `test_*.sh` files — no registration needed
