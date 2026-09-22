"""Idempotency tests for VNC Remote Secure.

Verifies that running setup/configuration twice produces the same
result as running it once — no duplicate users, services, or config
entries.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.security.profiles import apply_profile, get_profile_config


class TestConfigIdempotency:
    """Config loading and profile application should be idempotent."""

    def test_load_env_file_twice_same_result(self, monkeypatch, tmp_path):
        """Loading .env twice should not change existing env vars."""
        env_file = tmp_path / '.env'
        env_file.write_text('TEST_VAR=idempotent_value\n')

        # First load.
        monkeypatch.delenv('TEST_VAR', raising=False)
        load_env_file(str(env_file))
        assert os.environ.get('TEST_VAR') == 'idempotent_value'

        # Modify env var to a different value.
        os.environ['TEST_VAR'] = 'overridden'

        # Second load should NOT override the existing value.
        load_env_file(str(env_file))
        assert os.environ.get('TEST_VAR') == 'overridden'

    def test_real_env_wins_over_env_file_even_for_defaulted_keys(
            self, monkeypatch, tmp_path):
        """A real env var must beat .env even when the key also exists in
        the platform defaults (regression: USER_UI_ENABLED in common.env
        was misclassified as a default and .env could override it)."""
        # USER_UI_ENABLED is defined in config/defaults/common.env.
        monkeypatch.setenv('USER_UI_ENABLED', 'true')
        env_file = tmp_path / '.env'
        env_file.write_text('USER_UI_ENABLED=false\n')

        load_env_file(str(env_file))
        assert os.environ.get('USER_UI_ENABLED') == 'true'

        # Without a real env var, .env's value applies.
        monkeypatch.delenv('USER_UI_ENABLED')
        load_env_file(str(env_file))
        assert os.environ.get('USER_UI_ENABLED') == 'false'

    def test_apply_profile_twice_same_config(self, monkeypatch):
        """Applying a profile twice should produce the same config."""
        monkeypatch.setenv('SECURITY_PROFILE', 'development')

        apply_profile('development', overwrite=True)
        config1 = get_profile_config('development')

        apply_profile('development', overwrite=True)
        config2 = get_profile_config('development')

        # Remove description for comparison.
        config1.pop('description', None)
        config2.pop('description', None)

        assert config1 == config2

    def test_apply_profile_preserves_user_overrides(self, monkeypatch):
        """User-set env vars should survive profile application."""
        monkeypatch.setenv('SECURITY_PROFILE', 'development')
        monkeypatch.setenv('BIND_HOST', '192.168.1.100')

        apply_profile('development', overwrite=False)

        # User override should be preserved.
        assert os.environ.get('BIND_HOST') == '192.168.1.100'


class TestProfileIdempotency:
    """Profile switching should be idempotent."""

    @pytest.mark.parametrize('profile', ['development', 'trusted-lan', 'private-overlay', 'public-hardened'])
    def test_profile_apply_idempotent(self, monkeypatch, profile):
        """Applying any profile twice should produce identical env state."""
        monkeypatch.setenv('SECURITY_PROFILE', profile)

        apply_profile(profile, overwrite=True)
        env1 = dict(os.environ)

        apply_profile(profile, overwrite=True)
        env2 = dict(os.environ)

        # The env should be identical after the second application.
        assert env1 == env2


class TestAliasIdempotency:
    """Legacy profile aliases should resolve consistently."""

    @pytest.mark.parametrize(('alias', 'target'), [
        ('home-lan', 'trusted-lan'),
        ('private-vpn', 'private-overlay'),
        ('internet-hardened', 'public-hardened'),
        ('local-only', 'development'),
    ])
    def test_alias_resolves_to_same_config(self, alias, target):
        """An alias should resolve to the same config as its target."""
        from vnc_remote_secure.security.profiles import _PROFILE_ALIASES, get_profile_config

        resolved = _PROFILE_ALIASES.get(alias, alias)
        assert resolved == target

        config_alias = get_profile_config(alias)
        config_target = get_profile_config(target)

        # Remove description for comparison.
        config_alias.pop('description', None)
        config_target.pop('description', None)

        assert config_alias == config_target
