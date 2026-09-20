# Contributing to VNC Remote Secure

Thank you for your interest in contributing! This document covers the development
setup, coding standards, and pull request process.

## Development Setup

### Prerequisites

- Bash 4+ (Linux/macOS) or Git Bash (Windows)
- Python 3.11+
- `shellcheck` (for linting)
- `pre-commit` (optional, recommended)

### Initial setup

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Create .env from template
make setup-env
# Edit .env with test credentials (DO NOT commit)

# Install Python dependencies
make setup-deps

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Verify your environment

```bash
make check    # Run lint + fast tests
make test-all # Run full test suite
```

## Coding Standards

### Shell scripts (Bash)

- Use `#!/bin/bash` shebang
- Start scripts with `set -e` and `set -o pipefail`
- Use `[[ ]]` for tests (not `[ ]`)
- Quote all variable expansions: `"$var"`, `"${var}"`
- Use `local` for function-local variables
- Avoid `eval` — find alternatives
- Functions use `snake_case`
- Add `##` comment headers for major sections
- Run `make lint` before committing

### Python

- Follow PEP 8 (enforced by `black` if installed)
- Use type hints for public functions
- Functions use `snake_case`
- Classes use `PascalCase`
- Run `make lint-python` before committing
- Run `make format` to auto-format

### Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description
```

Types:
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation only
- `refactor` — Code restructuring without behavior change
- `test` — Adding or fixing tests
- `chore` — Maintenance, deps, tooling
- `style` — Formatting only

Scopes: `security`, `config`, `web`, `monitoring`, `platform`, `core`, `tests`, `docs`

Examples:
```
feat(security): validate VNC_PASSWORD in validate_config
fix(config): default KEEP_TEMP_USER to false so temp users are cleaned up
docs(architecture): correct module paths to reflect subfolder layout
test(unit): add password strength edge case tests
```

## Testing

### Test pyramid

| Level | Directory | What it covers |
|-------|-----------|----------------|
| 0 | `tests/static/` | bash -n, shellcheck, CRLF, shebang, permissions |
| 1 | `tests/unit/` | Config defaults, validation logic, utils, logging |
| 3 | `tests/integration/` | Module loading chain, validate_config end-to-end |
| 5 | `tests/e2e/` | Main() structure, cleanup trap, command dispatch |
| 7 | `tests/security/` | Password policy, XSS, injection, config hardening |

**Always run `make test-all` before committing changes to `src/` or `tests/`.**

### Writing tests

The canonical test framework is Python `pytest`:

```python
"""Tests for my feature."""
import pytest

from vnc_remote_secure.my_module import my_function


class TestMyFeature:
    def test_my_feature_works(self):
        assert my_function() == "expected"
```

Place test files under `tests/unit/`, `tests/integration/`, or
`tests/e2e/` depending on scope. The runner auto-discovers them.

## Pull Request Process

1. **Create a branch**: `feat/my-feature` or `fix/my-bugfix`
2. **Make changes** following the coding standards above
3. **Run quality checks**:
   ```bash
   make check
   make test-all
   ```
4. **Commit** with conventional commit messages
5. **Push** and open a PR with a clear description
6. **Address review feedback**

### PR checklist

- [ ] Code follows style guidelines
- [ ] `make lint` passes
- [ ] `make test-all` passes
- [ ] New tests added for new functionality
- [ ] Documentation updated if needed
- [ ] No secrets or `.env` committed
- [ ] Commit messages follow Conventional Commits

## Security Considerations

- **Never commit `.env`, `*.pem`, `*.key`** — these are gitignored
- **Never hardcode credentials** — use environment variables
- **Never log secrets** — redact passwords in logs
- **Report vulnerabilities** — see `SECURITY.md`

## Project Structure

See the [Architecture section in README.md](README.md#architecture) for the
project layout and module organization.

## Questions?

Open an issue on GitHub or see [`docs/`](docs/) for detailed documentation.
