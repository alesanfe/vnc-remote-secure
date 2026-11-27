"""Tests for secret file permissions validation."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))


@pytest.fixture
def secret_files(tmp_path):
    """Create test secret files with various permissions."""
    # World-readable .env (insecure).
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=leaked\n")
    os.chmod(env_file, 0o644)

    # Restricted .key (secure).
    key_file = tmp_path / "private.key"
    key_file.write_text("PRIVATE KEY DATA\n")
    os.chmod(key_file, 0o600)

    return tmp_path


def _grant_everyone_read(path):
    """Grant Everyone read access on Windows (creates a critical finding).

    Uses the universal SID ``*S-1-1-0`` rather than the localized name
    ("Everyone" on en-US, "Todos" on es-ES) so it works on any locale.
    """
    import subprocess

    subprocess.run(
        ["icacls", str(path), "/grant", "*S-1-1-0:R"],
        check=True,
        capture_output=True,
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

        if os.name == "nt":
            # Windows equivalent of a world-readable file: an ACE for
            # Everyone. The default ACL (Users read) is only a warning.
            _grant_everyone_read(secret_files / ".env")
        findings = validate_secret_files(str(secret_files))
        criticals = [f for f in findings if f["severity"] == "critical"]
        # .env is world-readable.
        assert any(".env" in f["file"] for f in criticals)

    def test_secure_file_no_findings(self, secret_files):
        from vnc_remote_secure.security.file_permissions import (
            _check_windows_permissions,
            validate_secret_files,
        )

        if os.name == "nt":
            # Restrict private.key to owner-only so it produces no
            # findings at all on Windows (Users-group read is only a
            # warning anyway, but an explicit lockdown mirrors the
            # Unix 0o600 intent).
            _restrict_fixture_acl(secret_files / "private.key")
            assert not _check_windows_permissions(str(secret_files / "private.key"))
        findings = validate_secret_files(str(secret_files))
        # private.key should not appear in critical findings.
        criticals = [f for f in findings if f["severity"] == "critical"]
        assert not any("private.key" in f["file"] for f in criticals)

    def test_fix_permissions(self, tmp_path):
        from vnc_remote_secure.security.file_permissions import (
            fix_secret_file_permissions,
        )

        test_file = tmp_path / "test.key"
        test_file.write_text("data")
        if os.name == "nt":
            from vnc_remote_secure.security.file_permissions import (
                _check_windows_permissions,
            )

            _grant_everyone_read(test_file)
            assert any(
                f["severity"] == "critical" for f in _check_windows_permissions(str(test_file))
            )
            assert fix_secret_file_permissions(str(test_file))
            assert not any(
                f["severity"] == "critical" for f in _check_windows_permissions(str(test_file))
            )
            return
        os.chmod(test_file, 0o644)
        assert fix_secret_file_permissions(str(test_file))
        mode = os.stat(test_file).st_mode & 0o777
        assert mode == 0o600


class TestOperatorUsersStore:
    """operator_users.json holds PBKDF2 password + recovery-code
    hashes — it must be validated like the signing secret."""

    def test_store_checked_for_permissions(self, tmp_path, monkeypatch):
        import os

        from vnc_remote_secure.security import file_permissions

        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        store = data_dir / "operator_users.json"
        store.write_text('{"op": {"password_hash": "x"}}')
        run_dir = tmp_path / "run"
        run_dir.mkdir(exist_ok=True)
        log_dir = tmp_path / "log"
        log_dir.mkdir(exist_ok=True)
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_data_dir", lambda: str(data_dir))
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_run_dir", lambda: str(run_dir))
        monkeypatch.setattr("vnc_remote_secure.core.paths.get_log_dir", lambda: str(log_dir))
        if os.name != "nt":
            os.chmod(store, 0o644)  # world-readable = critical
        else:
            _grant_everyone_read(store)
        findings = file_permissions.validate_secret_files(str(tmp_path))
        hits = [f for f in findings if "operator_users.json" in f["file"]]
        assert hits, "operator store must be permission-checked"
        assert hits[0]["severity"] in ("critical", "warning")


class TestWindowsAclParser:
    """The icacls ACE parser is pure logic — exercise it via a mocked
    run_cmd so the Windows-only branches are covered on POSIX."""

    def _icacls(self, monkeypatch, stdout):
        import types

        monkeypatch.setattr(
            "vnc_remote_secure.core.processes.run_cmd",
            lambda *a, **kw: types.SimpleNamespace(stdout=stdout),
            raising=False,
        )

    def test_everyone_is_critical(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        self._icacls(
            monkeypatch,
            "C:\\secret.key NT AUTHORITY\\SYSTEM:(F)\n"
            "             Everyone:(R)\n"
            "Successfully processed 1 files\n",
        )
        findings = fp._check_windows_permissions("C:\\secret.key")
        assert [f["severity"] for f in findings] == ["critical"]

    def test_builtin_users_is_warning(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        self._icacls(
            monkeypatch,
            "C:\\secret.key NT AUTHORITY\\SYSTEM:(F)\n" "              BUILTIN\\Users:(RX)\n",
        )
        findings = fp._check_windows_permissions("C:\\secret.key")
        assert [f["severity"] for f in findings] == ["warning"]

    def test_spanish_todos_is_critical(self, monkeypatch):
        """Localized Windows (es-ES) names the Everyone group 'Todos'."""
        from vnc_remote_secure.security import file_permissions as fp

        self._icacls(monkeypatch, "C:\\secret.key Todos:(F)\n")
        findings = fp._check_windows_permissions("C:\\secret.key")
        assert [f["severity"] for f in findings] == ["critical"]

    def test_path_in_header_no_false_positive(self, monkeypatch):
        """The icacls header echoes the file path — a file under
        C:\\Users\\ must NOT flag 'users' unless a Users ACE exists."""
        from vnc_remote_secure.security import file_permissions as fp

        self._icacls(
            monkeypatch,
            "C:\\Users\\admin\\secret.key NT AUTHORITY\\SYSTEM:(F)\n",
        )
        findings = fp._check_windows_permissions("C:\\Users\\admin\\secret.key")
        assert findings == []

    def test_icacls_failure_is_empty(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        def _boom(*a, **kw):
            raise OSError("icacls missing")

        monkeypatch.setattr("vnc_remote_secure.core.processes.run_cmd", _boom, raising=False)
        assert fp._check_windows_permissions("C:\\x.key") == []

    def test_check_permissions_dispatches_windows(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        monkeypatch.setattr(fp, "_is_windows", lambda: True)
        self._icacls(monkeypatch, "C:\\x.key Everyone:(F)\n")
        findings = fp._check_permissions("C:\\x.key")
        assert findings and findings[0]["severity"] == "critical"


class TestSecretFileEnumeration:
    def test_glob_finds_pems_in_all_dirs(self, tmp_path, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        for d in (tmp_path, tmp_path / "data" / "ssl", tmp_path / "ssl", tmp_path / "secrets"):
            d.mkdir(parents=True, exist_ok=True)
            (d / "cert.pem").write_text("x")
        canonical = tmp_path / "canonical-ssl"
        canonical.mkdir()
        (canonical / "k.pem").write_text("x")
        monkeypatch.setattr(
            "vnc_remote_secure.core.paths.get_ssl_dir",
            lambda: str(canonical),
            raising=False,
        )
        matches = fp._glob_secret_pattern(str(tmp_path), "*.pem")
        assert len(matches) == 5

    def test_glob_survives_ssl_dir_failure(self, tmp_path, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        def _boom():
            raise RuntimeError("no paths")

        monkeypatch.setattr("vnc_remote_secure.core.paths.get_ssl_dir", _boom, raising=False)
        (tmp_path / "a.pem").write_text("x")
        assert fp._glob_secret_pattern(str(tmp_path), "*.pem") == [str(tmp_path / "a.pem")]

    def test_backup_archives_enumerated(self, tmp_path):
        from vnc_remote_secure.security import file_permissions as fp

        bdir = tmp_path / "backups"
        bdir.mkdir()
        (bdir / "vrs-1.enc.tar.zst").write_text("x")
        (bdir / "vrs-2.tar.gz").write_text("x")
        (bdir / "readme.txt").write_text("x")
        extras = fp._extra_secret_files(str(tmp_path))
        backup_hits = [e for e in extras if "backups" in e]
        assert len(backup_hits) == 2
        assert not any(e.endswith("readme.txt") for e in backup_hits)

    def test_fix_nonexistent_file_returns_false(self, tmp_path):
        from vnc_remote_secure.security import file_permissions as fp

        monkeypatch_file = tmp_path / "missing.key"
        if os.name == "nt":
            return  # POSIX branch only — Windows covered by icacls mock
        assert fp.fix_secret_file_permissions(str(monkeypatch_file)) is False

    def test_world_writable_is_critical(self, tmp_path):
        from vnc_remote_secure.security import file_permissions as fp

        if os.name == "nt":
            return
        f = tmp_path / "leak.key"
        f.write_text("x")
        os.chmod(f, 0o606)  # owner rw + group/other rw, not readable flag? yes readable too
        findings = fp._check_unix_permissions(str(f))
        severities = {x["severity"] for x in findings}
        assert "critical" in severities
        assert any("world-writable" in x["message"] for x in findings)

    def test_stat_failure_returns_empty(self, tmp_path):
        from vnc_remote_secure.security import file_permissions as fp

        if os.name == "nt":
            return
        assert fp._check_unix_permissions(str(tmp_path / "missing")) == []

    def test_default_root_uses_find_project_root(self, tmp_path, monkeypatch):
        """project_root=None resolves via find_project_root — the
        doctor runs it with no argument."""
        from vnc_remote_secure.security import file_permissions as fp

        monkeypatch.setattr(
            "vnc_remote_secure.core.paths.find_project_root",
            lambda: str(tmp_path),
            raising=False,
        )
        f = tmp_path / ".env"
        f.write_text("SECRET=x")
        if os.name != "nt":
            os.chmod(f, 0o644)
            findings = fp.validate_secret_files()
            assert any(x["severity"] == "critical" for x in findings)

    def test_fix_windows_branch_delegates(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        calls = []
        monkeypatch.setattr(fp, "_is_windows", lambda: True)
        monkeypatch.setattr(
            "vnc_remote_secure.security.certificates._restrict_key_permissions",
            lambda p, writable=True: calls.append((p, writable)),
            raising=False,
        )
        assert fp.fix_secret_file_permissions("C:\\x.key") is True
        assert calls == [("C:\\x.key", True)]

    def test_fix_windows_failure_returns_false(self, monkeypatch):
        from vnc_remote_secure.security import file_permissions as fp

        def _boom(p, writable=True):
            raise RuntimeError("acl fail")

        monkeypatch.setattr(fp, "_is_windows", lambda: True)
        monkeypatch.setattr(
            "vnc_remote_secure.security.certificates._restrict_key_permissions",
            _boom,
            raising=False,
        )
        assert fp.fix_secret_file_permissions("C:\\x.key") is False
