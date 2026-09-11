"""E2E test: CLI commands work on Linux."""
import os
import sys
import subprocess
import platform
import pytest

@pytest.mark.skipif(platform.system() != 'Linux', reason='Linux only')
def test_cli_version():
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure', 'version'],
        capture_output=True, text=True,
        env={**os.environ, 'PYTHONPATH': os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')}
    )
    assert result.returncode == 0
    assert '0.2.0' in result.stdout
