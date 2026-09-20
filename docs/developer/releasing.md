# Release Process

This document describes how to cut a release of VNC Remote Secure.

## Prerequisites

- Python 3.11+
- `pip install -e ".[dev]"` (includes `build`, `wheel`, `ruff`, `pytest`)
- Git

## Version management

The project follows [Semantic Versioning](https://semver.org/):
- `MAJOR`: breaking changes
- `MINOR`: new features (backward-compatible)
- `PATCH`: bug fixes (backward-compatible)

The version is defined in **`pyproject.toml`** (single source of truth).
All other locations read it dynamically at build or run time:

- `src/vnc_remote_secure/__init__.py` — `importlib.metadata.version("vnc-remote-secure")`
- `src/vnc_remote_secure/core/constants.py` — imports `__version__` from the package
- `VncRemote.ps1` / `src/vnc_remote_secure/native/windows/VncRemote.psm1` — invoke Python to read `__version__`
- `scripts/release/build.ps1` — invokes Python to read `__version__`
- `packaging/windows/build-installer.ps1` — invokes Python to read `__version__`

A few locations still carry a static copy that must be bumped manually
when releasing (format-required duplicates — never add more):

- `src/vnc_remote_secure/native/windows/VncRemote.psd1` (`ModuleVersion`)
- `docs/api/openapi.yaml` (`info.version`)
- `tests/powershell/VncRemote.Tests.ps1` and `tests/windows/VncRemote.Tests.ps1` (version assertions)

`package.json` carries no `version` field (it is optional for npm
manifests and nothing consumed it), so it is deliberately omitted.

The `CHANGELOG.md` must be updated under `## [Unreleased]` and a new
version header added.

## Release checklist

1. **Update version** in all the files listed above.
2. **Update CHANGELOG.md**: move `## [Unreleased]` entries to a new
   `## [X.Y.Z] - YYYY-MM-DD` section.
3. **Run full verification**:
   ```bash
   bash tests/run_tests.sh
   pytest tests/unit tests/security
   ruff check .
   vnc-remote doctor
   ```
4. **Commit** the version bump:
   ```bash
   git commit -m "chore(release): vX.Y.Z"
   ```
5. **Tag** the release:
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --tags
   ```

## CI/CD

The `.github/workflows/release.yml` workflow triggers on `v*` tags and:
1. Builds the Python package (`python -m build`) on Ubuntu and Windows.
2. Generates SBOMs (SPDX and CycloneDX).
3. Generates SHA-256 checksums.
4. Verifies release artifacts (`scripts/release/verify-release.py`).
5. Creates a GitHub Release with the built artifacts and checksums.

## Manual build (optional)

For local builds without CI:

```bash
# Linux/macOS
bash scripts/release/build.sh

# Windows
powershell -File scripts/release/build.ps1
```

These wrappers run `python -m build` and generate `dist/SHA256SUMS.txt`.

## Verifying artifacts

After a build, verify artifacts with:

```bash
python scripts/release/verify-release.py
```

This checks:
- `dist/` exists and contains artifacts.
- `SHA256SUMS.txt` checksums match (if present).
- No secret files (`.env`, `*.pem`, `*.key`) are in `dist/`.
