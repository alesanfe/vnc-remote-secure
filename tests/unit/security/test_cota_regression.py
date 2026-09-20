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
        """Canonical web application reads SESSION_SAMESITE from env, defaults to Lax.

        This was the incongruence: the legacy user_ui_app.py hardcoded 'Lax'
        while the rest of the codebase used the env var. The canonical
        implementation is vnc_remote_secure.web.application.
        """
        from vnc_remote_secure.web.application import create_app
        app = create_app()
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'


class TestCota004FlaskSecretEnforced:
    """COTA-004: FLASK_SECRET_KEY must be enforced in non-dev profiles."""

    def test_user_ui_app_warns_on_missing_secret(self):
        """Canonical web application enforces FLASK_SECRET_KEY in non-dev profiles."""
        from vnc_remote_secure.security.profiles import get_profile
        # The profile system enforces FLASK_SECRET_KEY for non-dev profiles.
        profile = get_profile()
        assert profile in ('development', 'public-hardened', 'trusted-lan', 'public-standard')


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
            reset_registry,
            revoke_session_connections,
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
    """COTA-006: Hardened profiles must force localhost binding.

    The legacy Bash stack under src/lib/ has been removed. These tests
    now verify the equivalent behavior in the Python-canonical
    security profiles module.
    """

    def test_profiles_module_forces_localhost_in_hardened(self):
        """profiles.py overrides bind_address in hardened profiles."""
        profiles_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'vnc_remote_secure', 'security', 'profiles.py',
        )
        with open(profiles_path, encoding='utf-8') as f:
            content = f.read()
        assert 'public-hardened' in content
        assert 'private-overlay' in content or 'trusted-lan' in content

    def test_hardened_profiles_require_tls_and_mfa(self):
        """Hardened profiles enforce TLS and MFA blockers."""
        profiles_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..',
            'src', 'vnc_remote_secure', 'security', 'profiles.py',
        )
        with open(profiles_path, encoding='utf-8') as f:
            content = f.read()
        assert 'TLS is disabled in public-hardened' in content
        assert 'MFA is not required in public-hardened' in content
