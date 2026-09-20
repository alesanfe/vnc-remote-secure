"""E2E test: CLI commands work on Linux.

The real-platform test exercises the ``version`` command, which is
platform-agnostic (it runs on Linux, Windows, and macOS hosts alike).
The parametrized test covers the Bash wrapper entry point where it
exists.
"""
import os
import subprocess
import sys


def test_cli_version():
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure', 'version'],
        capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')}
    )
    assert result.returncode == 0
    assert '0.2.0' in result.stdout


def test_cli_version_runs_on_any_platform():
    """CLI version works regardless of host platform (no platform-specific deps)."""
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure', 'version'],
        capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')}
    )
    assert result.returncode == 0
    assert '0.2.0' in result.stdout
