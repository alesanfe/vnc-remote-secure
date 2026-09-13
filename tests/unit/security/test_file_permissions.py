"""Tests for secret file permissions validation."""
import os
import sys
import stat

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


@pytest.fixture
def secret_files(tmp_path):
    """Create test secret files with various permissions."""
    # World-readable .env (insecure).
    env_file = tmp_path / '.env'
    env_file.write_text('SECRET=leaked\n')
    os.chmod(env_file, 0o644)

    # Restricted .key (secure).
    key_file = tmp_path / 'private.key'
    key_file.write_text('PRIVATE KEY DATA\n')
    os.chmod(key_file, 0o600)

    return tmp_path


class TestFilePermissions:
    def test_detects_world_readable(self, secret_files):
        if os.name == 'nt':
            pytest.skip('Unix permissions test')
        from vnc_remote_secure.security.file_permissions import validate_secret_files
        findings = validate_secret_files(str(secret_files))
        criticals = [f for f in findings if f['severity'] == 'critical']
        # .env is world-readable.
        assert any('.env' in f['file'] for f in criticals)

    def test_secure_file_no_findings(self, secret_files):
        if os.name == 'nt':
            pytest.skip('Unix permissions test')
        from vnc_remote_secure.security.file_permissions import validate_secret_files
        findings = validate_secret_files(str(secret_files))
        # private.key should not appear in critical findings.
        criticals = [f for f in findings if f['severity'] == 'critical']
        assert not any('private.key' in f['file'] for f in criticals)

    def test_fix_permissions(self, tmp_path):
        if os.name == 'nt':
            pytest.skip('Unix permissions test')
        from vnc_remote_secure.security.file_permissions import fix_secret_file_permissions
        test_file = tmp_path / 'test.key'
        test_file.write_text('data')
        os.chmod(test_file, 0o644)
        assert fix_secret_file_permissions(str(test_file))
        mode = os.stat(test_file).st_mode & 0o777
        assert mode == 0o600
