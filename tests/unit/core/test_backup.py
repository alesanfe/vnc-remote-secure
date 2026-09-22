"""Tests for core.backup — create, list, verify."""
import os
import tarfile

import pytest


def _make_tar(path, members=('a.txt', 'b.txt')):
    """Create a minimal valid .tar.gz at ``path``."""
    import io
    with tarfile.open(path, 'w:gz') as tar:
        for name in members:
            data = f'data:{name}'.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class TestVerifyBackup:
    def test_missing_file(self, tmp_path):
        from vnc_remote_secure.core.backup import verify_backup
        ok, msg, count = verify_backup(str(tmp_path / 'nope.tar.gz'))
        assert not ok
        assert count == -1
        assert 'not found' in msg.lower()

    def test_valid_archive(self, tmp_path):
        from vnc_remote_secure.core.backup import verify_backup
        f = tmp_path / 'backup_x.tar.gz'
        _make_tar(str(f))
        ok, msg, count = verify_backup(str(f))
        assert ok
        assert count == 2
        assert 'intact' in msg.lower()

    def test_corrupt_archive(self, tmp_path):
        from vnc_remote_secure.core.backup import verify_backup
        f = tmp_path / 'backup_bad.tar.gz'
        f.write_bytes(b'not a real tarball' * 4)
        ok, msg, count = verify_backup(str(f))
        assert not ok
        assert count == -1
        assert 'corrupt' in msg.lower()

    def test_encrypted_backup(self, tmp_path, monkeypatch):
        """An .enc.tar.gz must be decrypted before CRC checking."""
        import cryptography.fernet  # noqa: F401 - skip if absent

        from vnc_remote_secure.core import backup as backup_mod

        plain = tmp_path / 'plain.tar.gz'
        _make_tar(str(plain))

        monkeypatch.setenv('BACKUP_PASSWORD', 'test-pw-123')
        enc = tmp_path / 'backup_enc.enc.tar.gz'
        backup_mod._encrypt_file(str(plain), str(enc))

        ok, msg, count = backup_mod.verify_backup(str(enc))
        assert ok
        assert count == 2

    def test_encrypted_wrong_password(self, tmp_path, monkeypatch):
        pytest.importorskip('cryptography.fernet')
        from vnc_remote_secure.core import backup as backup_mod

        plain = tmp_path / 'plain2.tar.gz'
        _make_tar(str(plain))
        monkeypatch.setenv('BACKUP_PASSWORD', 'right-pw')
        enc = tmp_path / 'backup_enc2.enc.tar.gz'
        backup_mod._encrypt_file(str(plain), str(enc))

        monkeypatch.setenv('BACKUP_PASSWORD', 'wrong-pw')
        ok, msg, _count = backup_mod.verify_backup(str(enc))
        assert not ok
        assert 'decrypt' in msg.lower()


class TestListBackups:
    def test_newest_first(self, tmp_path, monkeypatch):
        from vnc_remote_secure.core import backup as backup_mod
        monkeypatch.setattr(backup_mod, '_backup_dir',
                            lambda: str(tmp_path))
        import time
        for i in range(3):
            f = tmp_path / f'backup_{i}.tar.gz'
            _make_tar(str(f))
            os.utime(f, (time.time() + i, time.time() + i))
        backups = backup_mod.list_backups()
        assert len(backups) == 3
        assert backups[0].endswith('backup_2.tar.gz')

    def test_ignores_non_backups(self, tmp_path, monkeypatch):
        from vnc_remote_secure.core import backup as backup_mod
        monkeypatch.setattr(backup_mod, '_backup_dir',
                            lambda: str(tmp_path))
        (tmp_path / 'random.txt').write_text('x')
        _make_tar(str(tmp_path / 'backup_ok.tar.gz'))
        backups = backup_mod.list_backups()
        assert len(backups) == 1


class TestArchiveLimits:
    """Tar-bomb guards: member count, per-file size, total size."""

    def _tar_with_many_members(self, path, count):
        import io
        with tarfile.open(path, 'w:gz') as tar:
            for i in range(count):
                info = tarfile.TarInfo(name=f'f{i}.txt')
                data = b'x'
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    def test_member_count_cap_rejects(self, tmp_path, monkeypatch):
        """More members than _MAX_BACKUP_MEMBERS must abort extraction."""
        from vnc_remote_secure.core import backup
        monkeypatch.setattr(backup, '_MAX_BACKUP_MEMBERS', 5)
        f = tmp_path / 'bomb.tar.gz'
        self._tar_with_many_members(str(f), 10)
        monkeypatch.setattr(backup, 'get_run_dir',
                            lambda: str(tmp_path / 'run'))
        with pytest.raises(RuntimeError, match='too many entries'):
            backup.restore_backup(str(f))

    def test_oversize_member_rejected(self, tmp_path, monkeypatch):
        from vnc_remote_secure.core import backup
        monkeypatch.setattr(backup, '_MAX_BACKUP_FILE_SIZE', 4)
        f = tmp_path / 'big.tar.gz'
        _make_tar(str(f))  # members carry >4 bytes of data each
        monkeypatch.setattr(backup, 'get_run_dir',
                            lambda: str(tmp_path / 'run'))
        with pytest.raises(RuntimeError, match='too large'):
            backup.restore_backup(str(f))

    def test_total_size_cap_rejects(self, tmp_path, monkeypatch):
        from vnc_remote_secure.core import backup
        monkeypatch.setattr(backup, '_MAX_BACKUP_TOTAL_SIZE', 8)
        f = tmp_path / 'total.tar.gz'
        _make_tar(str(f), members=('a.txt', 'b.txt', 'c.txt', 'd.txt'))
        monkeypatch.setattr(backup, 'get_run_dir',
                            lambda: str(tmp_path / 'run'))
        with pytest.raises(RuntimeError, match='uncompressed size'):
            backup.restore_backup(str(f))


class TestBackupEdgeCases:
    def test_empty_collect_paths_raises(self, monkeypatch, tmp_path):
        """create_backup must fail loudly — returning a path to a file
        never written makes the CLI report a phantom success."""
        from vnc_remote_secure.core import backup
        monkeypatch.setattr(backup, '_collect_paths', list)
        monkeypatch.setattr(backup, 'find_project_root',
                            lambda: str(tmp_path))
        monkeypatch.setattr(backup, '_backup_dir',
                            lambda: str(tmp_path / 'backups'))
        monkeypatch.setattr('vnc_remote_secure.core.service_manager.save_state',
                            lambda: {'pids': {}, 'timestamp': 0},
                            raising=False)
        with pytest.raises(RuntimeError, match='No files'):
            backup.create_backup()

    def test_traversal_member_name_rejected(self, tmp_path, monkeypatch):
        """A member literally named ../evil must be rejected (link
        targets are tested elsewhere; member names were not)."""
        import io
        from vnc_remote_secure.core import backup
        f = tmp_path / 'evil.tar.gz'
        with tarfile.open(str(f), 'w:gz') as tar:
            info = tarfile.TarInfo(name='../evil.txt')
            data = b'x'
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        monkeypatch.setattr(backup, 'find_project_root',
                            lambda: str(tmp_path / 'proj'))
        with pytest.raises(RuntimeError):
            backup.restore_backup(str(f), dry_run=True)

    def test_absolute_member_name_rejected(self, tmp_path, monkeypatch):
        import io
        from vnc_remote_secure.core import backup
        f = tmp_path / 'abs.tar.gz'
        with tarfile.open(str(f), 'w:gz') as tar:
            info = tarfile.TarInfo(name='/etc/cron.d/x')
            data = b'x'
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        monkeypatch.setattr(backup, 'find_project_root',
                            lambda: str(tmp_path / 'proj'))
        with pytest.raises(RuntimeError):
            backup.restore_backup(str(f), dry_run=True)

    def test_member_at_exact_size_limit_accepted(self, tmp_path,
                                                 monkeypatch):
        """size == _MAX_BACKUP_FILE_SIZE is INCLUSIVE-allowed (check
        uses >) — pin the boundary so an off-by-one cannot shrink it."""
        import io
        from vnc_remote_secure.core import backup
        monkeypatch.setattr(backup, '_MAX_BACKUP_FILE_SIZE', 5)
        monkeypatch.setattr(backup, '_MAX_BACKUP_TOTAL_SIZE', 10**9)
        f = tmp_path / 'exact.tar.gz'
        with tarfile.open(str(f), 'w:gz') as tar:
            info = tarfile.TarInfo(name='ok.txt')
            data = b'12345'  # exactly at the cap
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        monkeypatch.setattr(backup, 'find_project_root',
                            lambda: str(tmp_path / 'proj'))
        # dry_run validates + extracts but skips copy — must not raise.
        assert backup.restore_backup(str(f), dry_run=True) is True
