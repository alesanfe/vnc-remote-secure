"""Unit tests for core.config module."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import _safe_int, generate_random_password, get_config


def test_safe_int_returns_default_when_unset(monkeypatch):
    """_safe_int returns the default when the env var is unset."""
    monkeypatch.delenv('TEST_INT_VAR', raising=False)
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_returns_default_when_empty(monkeypatch):
    """_safe_int returns the default when the env var is empty."""
    monkeypatch.setenv('TEST_INT_VAR', '')
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_returns_value_when_valid(monkeypatch):
    """_safe_int returns the parsed value when it is a valid integer."""
    monkeypatch.setenv('TEST_INT_VAR', '100')
    assert _safe_int('TEST_INT_VAR', 42) == 100


def test_safe_int_returns_default_when_invalid(monkeypatch):
    """_safe_int returns the default when the value is not an integer."""
    monkeypatch.setenv('TEST_INT_VAR', 'abc')
    assert _safe_int('TEST_INT_VAR', 42) == 42


def test_safe_int_enforces_minimum(monkeypatch):
    """_safe_int returns the default when the value is below the minimum."""
    monkeypatch.setenv('TEST_INT_VAR', '0')
    assert _safe_int('TEST_INT_VAR', 42, minimum=1) == 42


def test_safe_int_enforces_maximum(monkeypatch):
    """_safe_int returns the default when the value is above the maximum."""
    monkeypatch.setenv('TEST_INT_VAR', '99999')
    assert _safe_int('TEST_INT_VAR', 42, maximum=65535) == 42


def test_get_config_returns_dict():
    """get_config should return a dictionary."""
    config = get_config()
    assert isinstance(config, dict)


def test_get_config_has_required_keys():
    """Config should contain all required keys."""
    config = get_config()
    required_keys = [
        'vnc_port', 'novnc_port', 'ttyd_port', 'health_port', 'landing_port',
        'vnc_http_port', 'vnc_password', 'ttyd_username', 'ttyd_password',
        'ssl_cert', 'ssl_key', 'health_host', 'landing_host', 'webterm_shell',
    ]
    for key in required_keys:
        assert key in config, f"Missing required config key: {key}"


def test_get_config_ports_are_integers():
    """All port values should be integers."""
    config = get_config()
    port_keys = ['vnc_port', 'novnc_port', 'ttyd_port', 'health_port', 'landing_port', 'vnc_http_port']
    for key in port_keys:
        assert isinstance(config[key], int), f"{key} should be int, got {type(config[key])}"
        assert config[key] > 0


def test_generate_random_password_length():
    """generate_random_password should return a string of the specified length."""
    pw = generate_random_password(16)
    assert isinstance(pw, str)
    assert len(pw) == 16


def test_generate_random_password_default_length():
    """Default password length should be 16."""
    pw = generate_random_password()
    assert len(pw) == 16


def test_generate_random_password_uniqueness():
    """Two generated passwords should be different."""
    pw1 = generate_random_password()
    pw2 = generate_random_password()
    assert pw1 != pw2


def test_get_config_hosts_are_strings():
    """Host values should be strings."""
    config = get_config()
    assert isinstance(config['health_host'], str)
    assert isinstance(config['landing_host'], str)


from vnc_remote_secure.core import config as _cfg


class TestSetEnvPersistent:
    """set_env_persistent: atomic env-file rewrite + process env."""

    def _setup(self, tmp_path, monkeypatch, content):
        env = tmp_path / '.env'
        env.write_text(content, encoding='utf-8')
        monkeypatch.setattr(_cfg, '_find_project_root',
                            lambda: str(tmp_path))
        monkeypatch.setattr(_cfg, '_system_env_path',
                            lambda: str(tmp_path / 'nope.env'))
        # set_env_persistent writes os.environ directly (not via
        # monkeypatch) — pre-mark the keys so teardown restores them.
        for k in ('VNC_PASSWORD', 'NEW_KEY', 'PERSISTED_X', 'ROT'):
            monkeypatch.delenv(k, raising=False)
        return env

    def test_rewrites_existing_key(self, tmp_path, monkeypatch):
        env = self._setup(tmp_path, monkeypatch,
                          'A=1\nVNC_PASSWORD=old\n# comment\n')
        monkeypatch.delenv('ROTATE_ME', raising=False)
        assert _cfg.set_env_persistent('VNC_PASSWORD', 'new') is True
        text = env.read_text(encoding='utf-8')
        assert 'VNC_PASSWORD=new' in text
        assert 'VNC_PASSWORD=old' not in text
        assert '# comment' in text
        assert 'A=1' in text

    def test_appends_missing_key(self, tmp_path, monkeypatch):
        env = self._setup(tmp_path, monkeypatch, 'A=1\n')
        assert _cfg.set_env_persistent('NEW_KEY', 'v') is True
        assert 'NEW_KEY=v' in env.read_text(encoding='utf-8')

    def test_rejects_crlf_value(self, tmp_path, monkeypatch):
        env = self._setup(tmp_path, monkeypatch, 'A=1\n')
        assert _cfg.set_env_persistent('A', 'x\r\nEVIL=1') is False
        assert 'EVIL' not in env.read_text(encoding='utf-8')

    def test_rejects_bad_name(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch, 'A=1\n')
        assert _cfg.set_env_persistent('BAD=NAME', 'v') is False
        assert _cfg.set_env_persistent('', 'v') is False

    def test_updates_process_env(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch, 'A=1\n')
        monkeypatch.delenv('PERSISTED_X', raising=False)
        assert _cfg.set_env_persistent('PERSISTED_X', 'yes') is True
        assert os.environ.get('PERSISTED_X') == 'yes'

    def test_prefers_file_holding_key(self, tmp_path, monkeypatch):
        """When the system env file already holds the key, it wins."""
        proj = tmp_path / 'proj'
        sysd = tmp_path / 'sys'
        proj.mkdir()
        sysd.mkdir()
        (proj / '.env').write_text('A=1\n', encoding='utf-8')
        sysenv = sysd / 'config.env'
        sysenv.write_text('ROT=old\n', encoding='utf-8')
        monkeypatch.setattr(_cfg, '_find_project_root',
                            lambda: str(proj))
        monkeypatch.setattr(_cfg, '_system_env_path',
                            lambda: str(sysenv))
        assert _cfg.set_env_persistent('ROT', 'new') is True
        assert 'ROT=new' in sysenv.read_text(encoding='utf-8')
        assert 'ROT' not in (proj / '.env').read_text(encoding='utf-8')


class TestValidateUserPasswords:
    """_validate_user_passwords: user-set creds validated, generated
    ones must NEVER raise (random draw can contain weak substrings)."""

    def _v(self, **kw):
        from vnc_remote_secure.core.config import _validate_user_passwords
        defaults = {
            'vnc_password': 'Str0ng!Pass', 'vnc_user_set': True,
            'ttyd_password': 'Str0ng!Pass', 'ttyd_user_set': True,
            'user_ui_password': 'Str0ng!Pass',
            'landing_password': 'Str0ng!Pass',
            'landing_user_set': True,
        }
        defaults.update(kw)
        return _validate_user_passwords(**defaults)

    def test_weak_user_vnc_password_rejected(self):
        import pytest
        from vnc_remote_secure.core.validation import ValidationError
        with pytest.raises(ValidationError):
            self._v(vnc_password='changeme')

    def test_weak_user_landing_password_rejected(self):
        import pytest
        from vnc_remote_secure.core.validation import ValidationError
        with pytest.raises(ValidationError):
            self._v(landing_password='changeme')

    def test_generated_weak_substring_not_rejected(self):
        """A generated LANDING_PASSWORD containing a weak substring
        must not crash get_config() — the draw is random."""
        # user_set=False -> skipped even if the value is weak.
        self._v(landing_password='changeme', landing_user_set=False)

    def test_generated_vnc_password_not_validated(self):
        """Generated VNC password (vnc_user_set=False) skips validation —
        it is a random strong draw, not operator input."""
        self._v(vnc_password='changeme', vnc_user_set=False)
