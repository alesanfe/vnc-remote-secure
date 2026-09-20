"""Tests for secret file permissions validation."""
import os
import sys

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


def _grant_everyone_read(path):
    """Grant Everyone read access on Windows (creates a critical finding).

    Uses the universal SID ``*S-1-1-0`` rather than the localized name
    ("Everyone" on en-US, "Todos" on es-ES) so it works on any locale.
    """
    import subprocess
    subprocess.run(
        ['icacls', str(path), '/grant', '*S-1-1-0:R'],
        check=True, capture_output=True,
    )


def _restrict_fixture_acl(path):
    """Restrict a file to SYSTEM+Admins+current user on Windows."""
    from vnc_remote_secure.security.certificates import (
        _restrict_key_permissions,
    )
    _restrict_key_permissions(str(path), writable=True)


class TestFilePermissions:
    def test_detects_world_readable(self, secret_files):
        from vnc_remote_secure.security.file_permissions import validate_secret_files
        if os.name == 'nt':
            # Windows equivalent of a world-readable file: an ACE for
            # Everyone. The default ACL (Users read) is only a warning.
            _grant_everyone_read(secret_files / '.env')
        findings = validate_secret_files(str(secret_files))
        criticals = [f for f in findings if f['severity'] == 'critical']
        # .env is world-readable.
        assert any('.env' in f['file'] for f in criticals)

    def test_secure_file_no_findings(self, secret_files):
        from vnc_remote_secure.security.file_permissions import (
            _check_windows_permissions,
            validate_secret_files,
        )
        if os.name == 'nt':
            # Restrict private.key to owner-only so it produces no
            # findings at all on Windows (Users-group read is only a
            # warning anyway, but an explicit lockdown mirrors the
            # Unix 0o600 intent).
            _restrict_fixture_acl(secret_files / 'private.key')
            assert not _check_windows_permissions(
                str(secret_files / 'private.key'))
        findings = validate_secret_files(str(secret_files))
        # private.key should not appear in critical findings.
        criticals = [f for f in findings if f['severity'] == 'critical']
        assert not any('private.key' in f['file'] for f in criticals)

    def test_fix_permissions(self, tmp_path):
        from vnc_remote_secure.security.file_permissions import (
            fix_secret_file_permissions,
        )
        test_file = tmp_path / 'test.key'
        test_file.write_text('data')
        if os.name == 'nt':
            from vnc_remote_secure.security.file_permissions import (
                _check_windows_permissions,
            )
            _grant_everyone_read(test_file)
            assert any(f['severity'] == 'critical'
                       for f in _check_windows_permissions(str(test_file)))
            assert fix_secret_file_permissions(str(test_file))
            assert not any(f['severity'] == 'critical'
                           for f in _check_windows_permissions(str(test_file)))
            return
        os.chmod(test_file, 0o644)
        assert fix_secret_file_permissions(str(test_file))
        mode = os.stat(test_file).st_mode & 0o777
        assert mode == 0o600
