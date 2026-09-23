"""Windows terminal sandbox mode resolution.

``TERMINAL_WINDOWS_SANDBOX=auto`` falls back to an unsandboxed spawn
when AppContainer setup fails — under a hardened security profile
that silently widens the blast radius of a terminal escape, so
``auto`` is promoted to ``strict``. An explicit ``off`` is always
honoured.
"""
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != 'win32',
    reason='sandbox.py imports msvcrt/wintypes — Windows only')


@pytest.fixture
def sandbox():
    from vnc_remote_secure.platform.windows import sandbox as sb
    return sb


class TestSandboxModeResolution:
    def test_explicit_modes_pass_through(self, sandbox, monkeypatch):
        for mode in ('auto', 'strict', 'off'):
            monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', mode)
            monkeypatch.setattr(
                'vnc_remote_secure.security.profiles.resolve_profile',
                lambda: 'development', raising=False)
            assert sandbox.sandbox_mode() == mode

    def test_invalid_mode_defaults_auto(self, sandbox, monkeypatch):
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'bogus')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            lambda: 'development', raising=False)
        assert sandbox.sandbox_mode() == 'auto'

    def test_auto_promoted_under_hardened(self, sandbox, monkeypatch):
        """public-hardened: an unsandboxed fallback child can read the
        service account's secrets — auto must behave as strict."""
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'auto')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            lambda: 'public-hardened', raising=False)
        assert sandbox.sandbox_mode() == 'strict'

    def test_auto_promoted_under_overlay(self, sandbox, monkeypatch):
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'auto')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            lambda: 'private-overlay', raising=False)
        assert sandbox.sandbox_mode() == 'strict'

    def test_off_not_promoted(self, sandbox, monkeypatch):
        """An explicit off is the operator's call — never overridden."""
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'off')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            lambda: 'public-hardened', raising=False)
        assert sandbox.sandbox_mode() == 'off'

    def test_auto_stays_auto_on_dev(self, sandbox, monkeypatch):
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'auto')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            lambda: 'development', raising=False)
        assert sandbox.sandbox_mode() == 'auto'

    def test_missing_profiles_module_keeps_auto(
            self, sandbox, monkeypatch):
        """profiles unresolvable → auto stays auto (do not break
        development machines)."""
        monkeypatch.setenv('TERMINAL_WINDOWS_SANDBOX', 'auto')

        def _boom():
            raise ImportError('no profiles')
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.resolve_profile',
            _boom, raising=False)
        assert sandbox.sandbox_mode() == 'auto'
