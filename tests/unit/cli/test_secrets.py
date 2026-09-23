"""Unit tests for cli.commands.secrets — rotate/redact/check."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.cli.commands import secrets as sec  # noqa: E402


class TestRotate:
    def test_rotate_rejects_unknown_name(self, capsys, ns):
        assert sec._secrets_rotate(ns(secret_name='ROOT_PASSWORD', json=False, fix=False)) == 1
        assert 'cannot rotate' in capsys.readouterr().out

    def test_rotate_requires_name(self, capsys, ns):
        assert sec._secrets_rotate(ns(secret_name=None, json=False, fix=False)) == 1

    def test_rotate_writes_persistent_not_stdout(self, monkeypatch,
                                                 tmp_path, capsys, ns):
        """The new secret must land in .env — printing it would leak
        into scrollback; stdout may only show a fingerprint."""
        env = tmp_path / '.env'
        monkeypatch.setattr(
            'vnc_remote_secure.core.config.set_env_persistent',
            lambda k, v: env.write_text(f'{k}={v}\n') or True)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._system_env_path',
            lambda: None, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.cli.commands.secrets._find_project_root',
            lambda: str(tmp_path))
        monkeypatch.setattr(
            'vnc_remote_secure.cli.commands.secrets._audit_cli',
            lambda *a, **k: None)
        assert sec._secrets_rotate(
            ns(secret_name='TTYD_PASSWD', json=False, fix=False)) == 0
        written = env.read_text()
        val = written.split('=', 1)[1].strip()
        out = capsys.readouterr().out
        assert val not in out  # fingerprint only
        assert 'Fingerprint' in out

    def test_rotate_vnc_password_capped_8(self, monkeypatch, tmp_path, ns):
        """VNC DES truncates at 8 bytes — rotating a longer value would
        silently desync .env from the effective credential."""
        captured = {}
        monkeypatch.setattr(
            'vnc_remote_secure.core.config.set_env_persistent',
            lambda k, v: captured.update({k: v}) or True)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._system_env_path',
            lambda: None, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.cli.commands.secrets._find_project_root',
            lambda: str(tmp_path))
        monkeypatch.setattr(
            'vnc_remote_secure.cli.commands.secrets._audit_cli',
            lambda *a, **k: None)
        assert sec._secrets_rotate(
            ns(secret_name='VNC_PASSWORD', json=False, fix=False)) == 0
        assert len(captured['VNC_PASSWORD']) == 8

    def test_rotate_persist_failure_returns_1(self, monkeypatch, capsys, ns):
        monkeypatch.setattr(
            'vnc_remote_secure.core.config.set_env_persistent',
            lambda k, v: False)
        assert sec._secrets_rotate(ns(secret_name='TTYD_PASSWD', json=False, fix=False)) == 1
        assert 'could not write' in capsys.readouterr().err


class TestCheck:
    def test_check_critical_returns_1(self, monkeypatch, ns):
        monkeypatch.setattr(
            'vnc_remote_secure.security.tls_validation.validate_tls_config',
            lambda: [{'severity': 'critical', 'message': 'x'}],
            raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.file_permissions.validate_secret_files',
            list, raising=False)
        assert sec._secrets_check(ns(secret_name=None, json=False, fix=False)) == 1

    def test_check_clean_returns_0(self, monkeypatch, capsys, ns):
        monkeypatch.setattr(
            'vnc_remote_secure.security.tls_validation.validate_tls_config',
            list, raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.file_permissions.validate_secret_files',
            list, raising=False)
        assert sec._secrets_check(ns(secret_name=None, json=False, fix=False)) == 0
        assert 'All checks passed' in capsys.readouterr().out

    def test_check_validation_error_is_critical(self, monkeypatch, ns):
        """A validator crash is a critical finding, not silent pass."""
        monkeypatch.setattr(
            'vnc_remote_secure.security.tls_validation.validate_tls_config',
            lambda: (_ for _ in ()).throw(ValueError('bad cert')),
            raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.file_permissions.validate_secret_files',
            list, raising=False)
        assert sec._secrets_check(ns(secret_name=None, json=False, fix=False)) == 1


class TestGenerateSecretValue:
    def test_value_has_all_char_classes(self):
        for _ in range(10):
            v = sec._generate_secret_value('TTYD_PASSWD')
            assert len(v) == 24
            assert any(c.isupper() for c in v)
            assert any(c.islower() for c in v)
            assert any(c.isdigit() for c in v)
            assert any(c in '!@%^&*' for c in v)
