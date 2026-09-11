"""Security test: verify no secrets are exposed in the repository."""
import os
import subprocess
import pytest

def test_no_env_file_committed():
    """Verify .env is not tracked by git."""
    result = subprocess.run(
        ['git', 'ls-files', '.env'],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    )
    assert result.stdout.strip() == '', '.env should not be tracked by git'

def test_no_pem_files_committed():
    """Verify no .pem files are tracked."""
    result = subprocess.run(
        ['git', 'ls-files', '*.pem', 'data/ssl/'],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    )
    assert result.stdout.strip() == '', 'No .pem files should be tracked'
