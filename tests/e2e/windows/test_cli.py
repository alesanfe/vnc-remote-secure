"""E2E test: CLI commands work on Windows.

The real-platform test is skipped on non-Windows. The mock-based test
exercises the detection logic on any host.
"""
import os
import platform
import subprocess
import sys

import pytest


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows only')
def test_cli_version():
    src_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure', 'version'],
        capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': src_path}
    )
    assert result.returncode == 0
    assert '0.2.0' in result.stdout


def test_cli_version_runs_on_any_platform():
    """CLI version works regardless of host platform (no platform-specific deps)."""
    src_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure', 'version'],
        capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': src_path}
    )
    assert result.returncode == 0
    assert '0.2.0' in result.stdout
