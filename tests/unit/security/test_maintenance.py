"""Tests for maintenance mode."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security import maintenance  # noqa: E402


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.delenv('MAINTENANCE_MODE', raising=False)
    monkeypatch.setenv('VRS_RUN_DIR', str(tmp_path / 'run'))
    # Point the flag file at tmp regardless of platform resolution.
    monkeypatch.setattr(
        maintenance, '_flag_path',
        lambda: str(tmp_path / 'run' / 'maintenance.json'))
    yield


class TestFlag:
    def test_inactive_by_default(self):
        assert maintenance.maintenance_active() is False
        assert maintenance.maintenance_info() is None

    def test_env_flag(self, monkeypatch):
        monkeypatch.setenv('MAINTENANCE_MODE', 'true')
        assert maintenance.maintenance_active() is True
        assert maintenance.maintenance_info()['source'] == 'env'

    def test_flag_file_roundtrip(self, tmp_path):
        maintenance.set_maintenance(True, by='test', reason='upgrade')
        assert maintenance.maintenance_active() is True
        info = maintenance.maintenance_info()
        assert info['by'] == 'test'
        assert info['reason'] == 'upgrade'
        maintenance.set_maintenance(False)
        assert maintenance.maintenance_active() is False

    def test_corrupt_flag_still_blocks(self, tmp_path):
        # A present-but-unreadable flag must still mean "active" —
        # existence is the signal, contents are informational.
        (tmp_path / 'run').mkdir(parents=True, exist_ok=True)
        (tmp_path / 'run' / 'maintenance.json').write_text('{bad')
        assert maintenance.maintenance_active() is True
        assert maintenance.maintenance_info() is None


class TestLoginGate:
    def test_open_when_inactive(self):
        assert maintenance.maintenance_login_allowed('anyone') is True

    def test_regular_user_blocked(self, monkeypatch, tmp_path):
        maintenance.set_maintenance(True)
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.get_permissions',
            lambda u: set())
        monkeypatch.delenv('USER_UI_USERNAME', raising=False)
        monkeypatch.delenv('TTYD_USERNAME', raising=False)
        assert maintenance.maintenance_login_allowed('guest') is False

    def test_operator_allowed(self, monkeypatch):
        maintenance.set_maintenance(True)
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.get_permissions',
            lambda u: {'desktop:view'} if u == 'ops' else set())
        assert maintenance.maintenance_login_allowed('ops') is True

    def test_env_admin_allowed(self, monkeypatch):
        maintenance.set_maintenance(True)
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.get_permissions',
            lambda u: set())
        monkeypatch.setenv('USER_UI_USERNAME', 'admin')
        assert maintenance.maintenance_login_allowed('admin') is True


class TestEnforcement:
    def test_ephemeral_activate_denied(self, monkeypatch):
        maintenance.set_maintenance(True)
        from vnc_remote_secure.security import ephemeral_sessions
        # A syntactically valid token still fails before touching the
        # store — the maintenance check runs first.
        monkeypatch.setattr(
            ephemeral_sessions, 'verify_ephemeral_token',
            lambda t: {'session_token': 'tok'})
        assert ephemeral_sessions.activate_ephemeral_session(
            'signed', client_ip='127.0.0.1') is None
        assert ephemeral_sessions.consume_ephemeral_session(
            'signed') is False

    def test_login_denied_for_non_admin(self, monkeypatch):
        maintenance.set_maintenance(True)
        from vnc_remote_secure.security import auth_gateway
        monkeypatch.setattr(
            auth_gateway, 'authenticate', lambda u, p: True)
        monkeypatch.setattr(
            auth_gateway, 'mfa_required_for_login', lambda: False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.operator_users.get_permissions',
            lambda u: set())
        monkeypatch.delenv('USER_UI_USERNAME', raising=False)
        monkeypatch.delenv('TTYD_USERNAME', raising=False)
        ok, msg, session = auth_gateway.attempt_login(
            'alice', 'pw', client_ip='127.0.0.1')
        assert ok is False
        assert 'maintenance' in msg.lower()
        assert session is None
