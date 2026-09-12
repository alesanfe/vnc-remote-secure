"""Security test: verify no secrets are exposed in the repository."""
import os
import subprocess
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def _git_ls_files(*patterns):
    """Return tracked files matching the given patterns."""
    result = subprocess.run(
        ['git', 'ls-files', *patterns],
        capture_output=True, text=True,
        cwd=REPO_ROOT
    )
    return result.stdout.strip()


def test_no_env_file_committed():
    """Verify .env is not tracked by git."""
    assert _git_ls_files('.env') == '', '.env should not be tracked by git'


def test_no_pem_files_committed():
    """Verify no .pem files are tracked."""
    assert _git_ls_files('*.pem', 'data/ssl/') == '', 'No .pem files should be tracked'


def test_no_runtime_credentials_committed():
    """Verify .runtime_credentials.json is not tracked by git."""
    result = _git_ls_files('.runtime_credentials.json', '*.runtime_credentials.json')
    assert result == '', '.runtime_credentials.json should not be tracked by git'


def test_runtime_credentials_in_gitignore():
    """Verify .runtime_credentials.json is listed in .gitignore."""
    gitignore_path = os.path.join(REPO_ROOT, '.gitignore')
    with open(gitignore_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert '.runtime_credentials.json' in content, \
        '.runtime_credentials.json should be in .gitignore'


def test_no_key_files_committed():
    """Verify no .key files are tracked."""
    assert _git_ls_files('*.key') == '', 'No .key files should be tracked'


def test_no_pfx_p12_files_committed():
    """Verify no .pfx/.p12 files are tracked."""
    assert _git_ls_files('*.pfx', '*.p12') == '', 'No .pfx/.p12 files should be tracked'
