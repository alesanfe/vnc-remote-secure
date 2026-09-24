"""Tests for the optional-service plugin registry."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.plugins import (  # noqa: E402
    attack_surface,
    enabled_plugins,
    iter_plugins,
    plugin_for,
)


class TestRegistry:
    def test_declared_plugins(self):
        names = [p.name for p in iter_plugins()]
        assert names == ['health', 'user_ui', 'audio', 'gamepad',
                         'nginx']

    def test_every_plugin_declares_a_config_key(self):
        for p in iter_plugins():
            assert p.config_key
            assert p.description

    def test_core_services_are_not_plugins(self):
        for core in ('vnc', 'terminal', 'novnc', 'landing',
                     'websockify'):
            assert plugin_for(core) is None

    def test_plugin_lookup(self):
        assert plugin_for('gamepad').permission == 'gamepad:attach'
        assert plugin_for('nope') is None


class TestEnablement:
    def test_defaults_off_except_health(self):
        cfg = {}
        assert enabled_plugins(cfg, is_windows=False) == ['health']
        # nginx needs an explicit opt-in AND Linux.
        assert 'nginx' not in enabled_plugins(cfg, is_windows=False)

    def test_opt_in_flags(self):
        cfg = {'audio_stream_enabled': True,
               'gamepad_enabled': True,
               'user_ui_enabled': True,
               'nginx_enabled': True}
        assert enabled_plugins(cfg, is_windows=False) == [
            'health', 'user_ui', 'audio', 'gamepad', 'nginx']

    def test_linux_only_skipped_on_windows(self):
        cfg = {'nginx_enabled': True}
        assert 'nginx' not in enabled_plugins(cfg, is_windows=True)
        assert 'nginx' in enabled_plugins(cfg, is_windows=False)

    def test_health_can_be_disabled(self):
        cfg = {'health_web_enabled': False}
        assert 'health' not in enabled_plugins(cfg, is_windows=False)

    def test_attack_surface_maps_capability(self):
        cfg = {'audio_stream_enabled': True}
        surface = attack_surface(cfg, is_windows=False)
        assert surface == {'health': 'metrics:read',
                           'audio': 'audio:listen'}


class TestServiceManagerWiring:
    def test_enabled_services_matches_plugin_contract(self):
        """_enabled_services output must equal the old hardcoded
        ordering: core + health + websockify + opted-in plugins."""
        from vnc_remote_secure.core.service_manager import _enabled_services
        cfg = {'health_web_enabled': True,
               'user_ui_enabled': True,
               'audio_stream_enabled': True,
               'gamepad_enabled': True,
               'nginx_enabled': True}
        got = _enabled_services(cfg)
        import sys as _sys
        expected = ['vnc', 'terminal', 'novnc', 'landing',
                    'health', 'websockify', 'user_ui', 'audio',
                    'gamepad']
        if _sys.platform != 'win32':
            expected.append('nginx')
        assert got == expected

    def test_minimal_config_is_core_only(self):
        from vnc_remote_secure.core.service_manager import _enabled_services
        got = _enabled_services({})
        assert got == ['vnc', 'terminal', 'novnc', 'landing',
                       'health', 'websockify']
