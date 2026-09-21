"""Tests for backup archive link handling.

Two properties pin down the fix in create/restore:
1. create_backup dereferences symlinks — a symlinked SSL cert (the
   Let's Encrypt layout) is stored as file CONTENT, so restore under
   filter='data' no longer rejects the archive.
2. restore rejects link members whose targets escape the extraction
   dir — the manual validation now covers linkname, not just member
   names, for interpreters without extractall(filter=...).
"""
import os
import tarfile

import pytest


def _tar_with_symlink(path, link_name, link_target):
    """Archive containing a symlink member (like an LE cert link)."""
    with tarfile.open(path, 'w:gz') as tar:
        info = tarfile.TarInfo(name=link_name)
        info.type = tarfile.SYMTYPE
        info.linkname = link_target
        tar.addfile(info)


class TestBackupDereferencesLinks:
    def test_symlinked_ssl_file_stored_as_content(self, tmp_path,
                                                monkeypatch):
        """A symlink inside the SSL dir must land in the archive as a
        regular file with the target's bytes — not a SYMTYPE member
        that restore's filter='data' rejects."""
        from vnc_remote_secure.core import backup as backup_mod
        # conftest isolates runtime dirs under tmp_path ('ssl' may
        # already exist) — use a distinct staging dir name.
        ssl_dir = tmp_path / 'staging_ssl'
        ssl_dir.mkdir()
        real_cert = tmp_path / 'real_cert.pem'
        real_cert.write_text('CERTDATA')
        link = ssl_dir / 'fullchain.pem'
        try:
            os.symlink(str(real_cert), link)
        except (OSError, NotImplementedError):
            pytest.skip('symlinks unavailable on this platform/user')

        # Point the backup at a minimal tree containing the link.
        monkeypatch.setattr(
            backup_mod, '_collect_paths',
            lambda: [(str(ssl_dir), 'ssl')])
        out = tmp_path / 'out.tar.gz'
        result = backup_mod.create_backup(str(out))
        assert os.path.isfile(result)
        with tarfile.open(str(out), 'r:gz') as tar:
            member = tar.getmember('ssl/fullchain.pem')
            assert not member.issym(), 'link stored as link, not content'
            content = tar.extractfile(member).read().decode()
            assert content == 'CERTDATA'


class TestRestoreRejectsEscapingLinks:
    def test_absolute_symlink_target_rejected(self, tmp_path):
        f = tmp_path / 'evil.tar.gz'
        _tar_with_symlink(str(f), 'link', '/etc/passwd')
        # verify_backup only checks format; use the restore validator.
        from vnc_remote_secure.core.backup import restore_backup
        with pytest.raises(RuntimeError, match='Unsafe link target'):
            restore_backup(str(f), dry_run=True)

    def test_relative_symlink_escape_rejected(self, tmp_path):
        from vnc_remote_secure.core.backup import restore_backup
        f = tmp_path / 'evil2.tar.gz'
        _tar_with_symlink(str(f), 'sub/link', '../../outside')
        with pytest.raises(RuntimeError, match='Unsafe link target'):
            restore_backup(str(f), dry_run=True)


class TestSanitizedChildEnv:
    def test_strips_secret_vars(self, monkeypatch):
        from vnc_remote_secure.security.redaction import SECRET_VARS, sanitized_child_env
        for var in list(SECRET_VARS)[:4]:
            monkeypatch.setenv(var, 'leakme')
        env = sanitized_child_env()
        assert env is not None
        for var in SECRET_VARS:
            assert var not in env

    def test_fail_closed_not_none(self, monkeypatch):
        """If SECRET_VARS lookup itself blows up, the helper returns a
        minimal env — never None (env=None inherits everything)."""
        import vnc_remote_secure.security.redaction as red
        monkeypatch.setitem(red.__dict__, 'SECRET_VARS', None)
        env = red.sanitized_child_env()
        assert isinstance(env, dict)
