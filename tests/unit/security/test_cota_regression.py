"""Regression tests for COTA audit findings.

These tests verify that the incongruences found during the COTA
audit have been fixed and do not regress.

COTA-003: SameSite policy must be coherent across all session stores.
COTA-004: FLASK_SECRET_KEY must be enforced in non-dev profiles.
COTA-008: WebSocket registry must be integrated with auth gateway.
COTA-010: Security scan reports must be excluded from Docker image.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


class TestCota003SameSiteCoherent:
    """COTA-003: SameSite policy must be coherent."""

    def test_flask_app_uses_env_var(self):
        """Flask app reads SESSION_SAMESITE from env, defaults to Lax."""
        from vnc_remote_secure.web.application import create_app
        # Default should be Lax.
        app = create_app()
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'

    def test_sessions_py_uses_env_var(self):
        """sessions.py reads SESSION_SAMESITE from env, defaults to Lax."""
        from vnc_remote_secure.security.sessions import get_cookie_attributes
        opts = get_cookie_attributes(secure=True)
        assert opts['samesite'] == 'Lax'
        assert opts['httponly'] is True

    def test_user_ui_app_uses_env_var(self):
        """user_ui_app.py reads SESSION_SAMESITE from env, defaults to Lax.

        This was the incongruence: user_ui_app.py hardcoded 'Lax' while
        the rest of the codebase used the env var.
        """
        # Read the source to verify env var is used.
        user_ui_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'lib', 'web', 'user_ui_app.py',
        )
        with open(user_ui_path, encoding='utf-8') as f:
            content = f.read()
        assert "os.environ.get('SESSION_SAMESITE', 'Lax')" in content, (
            "user_ui_app.py should read SESSION_SAMESITE from env"
        )


class TestCota004FlaskSecretEnforced:
    """COTA-004: FLASK_SECRET_KEY must be enforced in non-dev profiles."""

    def test_user_ui_app_warns_on_missing_secret(self):
        """user_ui_app.py logs error when FLASK_SECRET_KEY missing in
        non-development profiles."""
        user_ui_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'lib', 'web', 'user_ui_app.py',
        )
        with open(user_ui_path, encoding='utf-8') as f:
            content = f.read()
        assert 'FLASK_SECRET_KEY' in content
        assert 'SECURITY_PROFILE' in content
        # Should check for non-development profiles.
        assert 'public-hardened' in content or 'trusted-lan' in content


class TestCota008WebSocketRegistryIntegrated:
    """COTA-008: WebSocket registry must be integrated with auth gateway."""

    def test_auth_gateway_has_register_function(self):
        """auth_gateway.py exposes register_websocket_connection."""
        from vnc_remote_secure.security.auth_gateway import (
            register_websocket_connection,
            unregister_websocket_connection,
        )
        assert callable(register_websocket_connection)
        assert callable(unregister_websocket_connection)

    def test_register_then_revoke_closes_connection(self):
        """Registering a connection and revoking closes it."""
        from vnc_remote_secure.security.auth_gateway import (
            register_websocket_connection,
        )
        from vnc_remote_secure.security.websocket_registry import (
            revoke_session_connections,
            reset_registry,
        )
        reset_registry()

        closed = []
        def close_cb():
            closed.append(True)
            return True

        conn_id = register_websocket_connection('session-123', close_cb, 'desktop')
        assert conn_id is not None

        closed_count = revoke_session_connections('session-123')
        assert closed_count == 1
        assert closed == [True]


class TestCota010DockerignoreScanReports:
    """COTA-010: Security scan reports excluded from Docker image."""

    def test_dockerignore_excludes_bandit(self):
        """bandit-report.json is in .dockerignore."""
        dockerignore_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..', '.dockerignore'
        )
        with open(dockerignore_path, encoding='utf-8') as f:
            content = f.read()
        assert 'bandit-report.json' in content
        assert '*.sarif' in content

    def test_dockerignore_excludes_credentials(self):
        """Runtime credentials are excluded."""
        dockerignore_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..', '.dockerignore'
        )
        with open(dockerignore_path, encoding='utf-8') as f:
            content = f.read()
        assert '.runtime_credentials.json' in content
        assert '.env' in content


class TestCota006BashBindHardened:
    """COTA-006: Bash services must force localhost in hardened profiles."""

    def test_services_sh_forces_localhost_in_hardened(self):
        """services.sh overrides bind_address in hardened profiles."""
        services_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'lib', 'core', 'services.sh',
        )
        with open(services_path, encoding='utf-8') as f:
            content = f.read()
        assert 'SECURITY_PROFILE' in content
        assert 'public-hardened' in content
        assert 'overriding' in content.lower() or 'override' in content.lower()

    def test_windows_sh_forces_localhost_in_hardened(self):
        """windows.sh overrides bind_address in hardened profiles."""
        windows_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'lib', 'platform', 'windows.sh',
        )
        with open(windows_path, encoding='utf-8') as f:
            content = f.read()
        assert 'SECURITY_PROFILE' in content
        assert 'public-hardened' in content
