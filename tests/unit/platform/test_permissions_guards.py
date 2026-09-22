"""Regression tests for the platform permission-adapter guards.

- linux/permissions: usernames starting with '-' would be parsed as
  flags by useradd/userdel/chpasswd; the adapter must reject them.
- windows/permissions.remove_user: must refuse reserved/builtin names
  even when called directly (not via the adapter's guarded wrapper).
"""
from unittest.mock import patch

from vnc_remote_secure.platform.linux import permissions as linux_perms
from vnc_remote_secure.platform.windows import permissions as win_perms


class _FakeResult:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestLinuxUsernameGuard:
    def test_create_user_rejects_flag_injection(self):
        calls = []
        with patch.object(linux_perms, 'run_cmd',
                          side_effect=lambda *a, **kw: calls.append(a) or _FakeResult()):
            with patch.object(linux_perms, 'user_exists', return_value=False):
                assert linux_perms.create_user('-f') is False
                assert linux_perms.create_user('--system') is False
        assert calls == []

    def test_remove_user_rejects_flag_injection(self):
        calls = []
        with patch.object(linux_perms, 'run_cmd',
                          side_effect=lambda *a, **kw: calls.append(a) or _FakeResult()):
            assert linux_perms.remove_user('-rf') is False
            assert linux_perms.remove_user('root') is False
        assert calls == []

    def test_remove_user_allows_normal_name(self):
        seen = []
        with patch.object(linux_perms, 'run_cmd',
                          side_effect=lambda cmd, **kw: seen.append(cmd) or _FakeResult()):
            assert linux_perms.remove_user('remote') is True
        assert seen
        assert '--' in seen[0]
        assert 'remote' in seen[0]

    def test_set_user_password_rejects_flag_injection(self):
        calls = []
        with patch.object(linux_perms, 'run_cmd',
                          side_effect=lambda *a, **kw: calls.append(a) or _FakeResult()):
            assert linux_perms.set_user_password('-e', 'Passw0rd!') is False
        assert calls == []


class TestWindowsBuiltinGuard:
    def test_remove_user_refuses_builtin(self):
        with patch.object(win_perms, 'run_powershell') as ps:
            assert win_perms.remove_user('Administrator') is False
            assert win_perms.remove_user('Guest') is False
            ps.assert_not_called()

    def test_remove_user_refuses_reserved_case_insensitive(self):
        with patch.object(win_perms, 'run_powershell') as ps:
            assert win_perms.remove_user('ROOT') is False
            ps.assert_not_called()

    def test_remove_user_allows_normal_name(self):
        with patch.object(win_perms, 'run_powershell',
                          return_value=_FakeResult()) as ps:
            assert win_perms.remove_user('remote') is True
            ps.assert_called_once()
