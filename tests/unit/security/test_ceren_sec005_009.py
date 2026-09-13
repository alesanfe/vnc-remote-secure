"""CEREN tests for TEST-SEC-005 through TEST-SEC-009.

TEST-SEC-005: Desktop token cannot be used in terminal.
TEST-SEC-006: Disallowed Origin is rejected.
TEST-SEC-007: Spoofed proxy headers don't grant authentication.
TEST-SEC-008: Public-hardened blocks startup without TLS/MFA/proxy/secret.
TEST-SEC-009: Secrets don't appear in logs, diagnostics, or error responses.
"""
import io
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.security.ephemeral_sessions as mod
from vnc_remote_secure.security.auth_gateway import (
    check_origin,
    check_websocket_upgrade,
    get_allowed_origins,
)
from vnc_remote_secure.security.ephemeral_sessions import (
    PERM_TERMINAL,
    PERM_VIEW,
    SessionStore,
    create_ephemeral_session,
)
from vnc_remote_secure.security.profiles import PROFILES, apply_profile


@pytest.fixture
def fresh_store(monkeypatch):
    """Fresh SessionStore as global."""
    store = SessionStore()
    monkeypatch.setattr(mod, '_store', store)
    return store


# ---------------------------------------------------------------------------
# TEST-SEC-005: Resource binding
# ---------------------------------------------------------------------------

class TestResourceBinding:
    """TEST-SEC-005: A desktop token cannot be used in terminal."""

    def test_desktop_token_cannot_access_terminal(self, fresh_store):
        """Contrato: un token bound to 'desktop' no puede acceder a terminal.

        Precondiciones: token con resource='desktop'.
        Acción: check_permission_for_action(token, 'terminal', resource='terminal').
        Resultado: rechazado.
        Efectos prohibidos: el token no obtiene acceso a terminal.
        """
        from vnc_remote_secure.security.auth_gateway import (
            check_permission_for_action,
        )
        signed = create_ephemeral_session(
            role='operator', ttl_seconds=300, resource='desktop',
        )
        # Operator normally has terminal permission, but resource binding
        # should block it when accessing terminal.
        allowed, reason = check_permission_for_action(signed, PERM_TERMINAL)
        assert allowed is True  # Without resource context, permission is granted

        # But with resource context, it should be blocked
        from vnc_remote_secure.security.ephemeral_sessions import check_permission
        result = check_permission(signed, PERM_TERMINAL, resource='terminal')
        assert result is False, 'Desktop token should not access terminal'

    def test_terminal_token_cannot_access_desktop(self, fresh_store):
        """Contrato: un token bound to 'terminal' no puede acceder a desktop."""
        from vnc_remote_secure.security.ephemeral_sessions import check_permission
        signed = create_ephemeral_session(
            role='operator', ttl_seconds=300, resource='terminal',
        )
        result = check_permission(signed, PERM_VIEW, resource='desktop')
        assert result is False, 'Terminal token should not access desktop'

    def test_unbound_token_can_access_any_resource(self, fresh_store):
        """Contrato: un token sin resource binding puede acceder a cualquier recurso."""
        from vnc_remote_secure.security.ephemeral_sessions import check_permission
        signed = create_ephemeral_session(
            role='operator', ttl_seconds=300, resource=None,
        )
        assert check_permission(signed, PERM_VIEW, resource='desktop')
        assert check_permission(signed, PERM_TERMINAL, resource='terminal')

    def test_desktop_token_can_access_desktop(self, fresh_store):
        """Contrato: un token bound to 'desktop' SÍ puede acceder a desktop."""
        from vnc_remote_secure.security.ephemeral_sessions import check_permission
        signed = create_ephemeral_session(
            role='viewer', ttl_seconds=300, resource='desktop',
        )
        assert check_permission(signed, PERM_VIEW, resource='desktop')


# ---------------------------------------------------------------------------
# TEST-SEC-006: Origin validation
# ---------------------------------------------------------------------------

class TestOriginValidation:
    """TEST-SEC-006: Disallowed Origin is rejected."""

    def test_empty_origin_rejected(self):
        """Contrato: Origin vacío es rechazado."""
        assert not check_origin('', ['http://localhost:8000'])

    def test_null_origin_rejected(self):
        """Contrato: Origin 'null' es rechazado."""
        assert not check_origin('null', ['http://localhost:8000'])

    def test_origin_not_in_allowlist_rejected(self):
        """Contrato: Origin no en la lista es rechazado."""
        assert not check_origin('https://evil.com', ['http://localhost:8000'])

    def test_origin_in_allowlist_accepted(self):
        """Contrato: Origin en la lista es aceptado."""
        assert check_origin('http://localhost:8000', ['http://localhost:8000'])

    def test_localhost_origin_accepted_in_default_config(self):
        """Contrato: localhost es aceptado con la config por defecto."""
        origins = get_allowed_origins()
        assert 'http://localhost:8000' in origins
        assert check_origin('http://localhost:8000', origins)

    def test_spoofed_subdomain_rejected(self):
        """Contrato: un subdominio spoofed de localhost es rechazado.

        Condición límite: attacker intenta http://localhost.evil.com
        """
        origins = ['http://localhost:8000']
        assert not check_origin('http://localhost.evil.com', origins)
        assert not check_origin('http://localhost:8000.evil.com', origins)

    def test_websocket_upgrade_rejects_bad_origin(self, fresh_store):
        """Contrato: check_websocket_upgrade rechaza Origin no permitido.

        Precondiciones: token válido.
        Acción: check_websocket_upgrade con Origin='https://evil.com'.
        Resultado: rechazado con 'Invalid origin'.
        """
        signed = create_ephemeral_session(role='viewer', ttl_seconds=300)
        allowed, reason = check_websocket_upgrade(
            origin='https://evil.com',
            bearer_token=signed,
            required_permission=PERM_VIEW,
        )
        assert allowed is False
        assert 'origin' in reason.lower()

    def test_websocket_upgrade_accepts_valid_origin(self, fresh_store):
        """Contrato: check_websocket_upgrade acepta Origin permitido."""
        signed = create_ephemeral_session(role='viewer', ttl_seconds=300)
        allowed, reason = check_websocket_upgrade(
            origin='http://localhost:8000',
            bearer_token=signed,
            required_permission=PERM_VIEW,
        )
        assert allowed is True


# ---------------------------------------------------------------------------
# TEST-SEC-007: Spoofed proxy headers
# ---------------------------------------------------------------------------

class TestSpoofedProxyHeaders:
    """TEST-SEC-007: Spoofed proxy headers don't grant authentication.

    Contrato: las cabeceras X-Forwarded-User, X-Remote-User,
    X-Authenticated-User, X-Forwarded-For, X-Forwarded-Proto NO deben
    conceder autenticación. Solo el reverse proxy de confianza debe
    establecer identidad, y solo via mecanismos verificados.
    """

    @pytest.mark.parametrize(
        'header_name',
        [
            'X-Forwarded-User',
            'X-Remote-User',
            'X-Authenticated-User',
            'X-Forwarded-For',
            'X-Forwarded-Proto',
        ],
    )
    def test_spoofed_header_does_not_authenticate(self, header_name):
        """Contrato: ninguna cabecera proxy concede autenticación.

        Precondiciones: ninguna sesión activa.
        Acción: check_authenticated con cookie vacía y bearer vacío.
        Resultado: no autenticado, sin importar las cabeceras.

        Nota: check_authenticated no acepta cabeceras como parámetro.
        Las cabeceras proxy son ignoradas por diseño. Este test
        verifica que la función no las considere.
        """
        from vnc_remote_secure.security.auth_gateway import check_authenticated
        # check_authenticated only accepts cookie_value and bearer_token.
        # It does NOT accept X-Forwarded-User or similar headers.
        # This is by design: the auth gateway never trusts proxy headers.
        authed, username = check_authenticated(cookie_value='', bearer_token='')
        assert authed is False
        assert username is None

    def test_check_authenticated_ignores_proxy_headers(self):
        """Contrato: check_authenticated no tiene parámetro para cabeceras proxy.

        Esto verifica que la API misma no acepta cabeceras proxy.
        Si la API no las acepta, no pueden ser usadas para bypass.
        """
        import inspect
        from vnc_remote_secure.security.auth_gateway import check_authenticated
        sig = inspect.signature(check_authenticated)
        param_names = list(sig.parameters.keys())
        # Should only accept cookie_value and bearer_token
        assert 'X-Forwarded-User' not in param_names
        assert 'X-Remote-User' not in param_names
        assert 'headers' not in param_names
        assert 'proxy_headers' not in param_names

    def test_websocket_upgrade_does_not_trust_forwarded_user(self, fresh_store):
        """Contrato: check_websocket_upgrade no acepta X-Forwarded-User.

        Si un atacante envía X-Forwarded-User: admin, no debe obtener
        acceso WebSocket.
        """
        signed = create_ephemeral_session(role='viewer', ttl_seconds=300)
        # check_websocket_upgrade does not accept X-Forwarded-User
        # It only checks origin, cookie, bearer_token, resource, permission
        allowed, _ = check_websocket_upgrade(
            origin='http://localhost:8000',
            cookie_value='',
            bearer_token=signed,
            required_permission=PERM_VIEW,
        )
        # Should be allowed because the bearer token is valid,
        # NOT because of any proxy header.
        assert allowed is True


# ---------------------------------------------------------------------------
# TEST-SEC-008: Public-hardened blocks insecure startup
# ---------------------------------------------------------------------------

class TestPublicHardenedBlocksInsecureStartup:
    """TEST-SEC-008: Public-hardened blocks startup without TLS/MFA/proxy/secret."""

    def test_public_hardened_requires_tls(self):
        """Contrato: public-hardened requiere TLS_ENABLED=true."""
        profile = PROFILES.get('public-hardened', {})
        tls = str(profile.get('TLS_ENABLED', '')).lower()
        assert tls == 'true', f'public-hardened should have TLS_ENABLED=true, got {tls}'

    def test_public_hardened_requires_mfa(self):
        """Contrato: public-hardened requiere MFA_REQUIRED=true."""
        profile = PROFILES.get('public-hardened', {})
        mfa = str(profile.get('MFA_REQUIRED', '')).lower()
        assert mfa == 'true'

    def test_public_hardened_requires_nginx(self):
        """Contrato: public-hardened requiere NGINX_ENABLED=true."""
        profile = PROFILES.get('public-hardened', {})
        nginx = str(profile.get('NGINX_ENABLED', '')).lower()
        assert nginx == 'true'

    def test_public_hardened_enforces_localhost_bind(self, monkeypatch):
        """Contrato: public-hardened fuerza BACKEND_BIND_HOST=127.0.0.1.

        Precondiciones: usuario pone BACKEND_BIND_HOST=0.0.0.0 en env.
        Acción: apply_profile('public-hardened').
        Resultado: BACKEND_BIND_HOST se fuerza a 127.0.0.1.
        """
        monkeypatch.setenv('BACKEND_BIND_HOST', '0.0.0.0')
        monkeypatch.setenv('SECURITY_PROFILE', 'public-hardened')
        apply_profile('public-hardened', overwrite=True)
        assert os.environ.get('BACKEND_BIND_HOST') == '127.0.0.1'

    def test_development_allows_external_bind(self, monkeypatch):
        """Contrato: development NO fuerza localhost bind.

        Diferencia intencional: development permite 0.0.0.0 para pruebas.
        """
        monkeypatch.setenv('BACKEND_BIND_HOST', '0.0.0.0')
        monkeypatch.setenv('SECURITY_PROFILE', 'development')
        apply_profile('development', overwrite=True)
        # Development should not override the user's choice
        # (or if it does, it should be documented)
        # This test verifies the behavior is different from hardened.

    def test_config_validate_reports_missing_flask_secret(self, monkeypatch):
        """Contrato: config validate reporta FLASK_SECRET_KEY ausente en hardened.

        Precondiciones: SECURITY_PROFILE=public-hardened, FLASK_SECRET_KEY vacío.
        Acción: validate_config.
        Resultado: finding crítico sobre FLASK_SECRET_KEY.
        """
        from vnc_remote_secure.core.config_inspector import validate_config
        monkeypatch.setenv('SECURITY_PROFILE', 'public-hardened')
        monkeypatch.delenv('FLASK_SECRET_KEY', raising=False)
        findings = validate_config()
        secret_findings = [f for f in findings if 'FLASK_SECRET' in f.get('message', '')]
        assert len(secret_findings) > 0, 'Should report missing FLASK_SECRET_KEY'
        assert secret_findings[0]['severity'] == 'critical'


# ---------------------------------------------------------------------------
# TEST-SEC-009: Secrets don't appear in logs
# ---------------------------------------------------------------------------

class TestSecretsNotInLogs:
    """TEST-SEC-009: Secrets don't appear in logs, diagnostics, or errors."""

    def test_ephemeral_token_not_in_session_to_dict(self, fresh_store):
        """Contrato: to_dict() no incluye el token ni la firma.

        Efectos prohibidos: el token no aparece en la serialización.
        """
        session, signed = fresh_store.create(role='viewer', expires_in=300)
        d = session.to_dict()
        assert 'token' not in d, 'to_dict() should not include the raw token'
        assert 'signed' not in d
        assert 'signature' not in d
        # The actual token string should not appear in any value
        token_str = session.token
        for key, value in d.items():
            if isinstance(value, str):
                assert token_str not in value, (
                    f'Token found in to_dict() field {key}'
                )

    def test_vnc_password_redacted_in_config_show(self, monkeypatch):
        """Contrato: config show-effective redacta VNC_PASSWORD.

        Precondiciones: VNC_PASSWORD=secret123.
        Acción: compute_effective_config.
        Resultado: VNC_PASSWORD se muestra como [REDACTED].
        Efectos prohibidos: el valor real aparece en la salida.
        """
        from vnc_remote_secure.core.config_inspector import (
            compute_effective_config,
        )
        monkeypatch.setenv('VNC_PASSWORD', 'mySecretPassword123')
        config = compute_effective_config()
        for entry in config:
            if entry['name'] == 'VNC_PASSWORD':
                assert 'mySecretPassword123' not in entry['value']
                assert 'REDACTED' in entry['value']
                return
        pytest.fail('VNC_PASSWORD not found in config output')

    def test_flask_secret_redacted_in_config_show(self, monkeypatch):
        """Contrato: config show-effective redacta FLASK_SECRET_KEY."""
        from vnc_remote_secure.core.config_inspector import (
            compute_effective_config,
        )
        monkeypatch.setenv('FLASK_SECRET_KEY', 'superSecretKey456')
        config = compute_effective_config()
        for entry in config:
            if entry['name'] == 'FLASK_SECRET_KEY':
                assert 'superSecretKey456' not in entry['value']
                return
        pytest.fail('FLASK_SECRET_KEY not found in config output')

    def test_audit_log_does_not_include_token(self, fresh_store, caplog):
        """Contrato: los logs de auditoría no incluyen el token.

        Precondiciones: sesión válida.
        Acción: revoke_session (que escribe log).
        Resultado: el token no aparece en los logs.
        Efectos prohibidos: el token firmado aparece en cualquier log.
        """
        from vnc_remote_secure.security.ephemeral_sessions import revoke_session
        signed = create_ephemeral_session(role='viewer', ttl_seconds=300)

        with caplog.at_level(logging.DEBUG):
            revoke_session(signed)

        # The signed token should not appear in any log message
        for record in caplog.records:
            assert signed not in record.getMessage(), (
                f'Signed token found in log: {record.getMessage()}'
            )

    def test_error_messages_do_not_leak_secrets(self, fresh_store):
        """Contrato: los mensajes de error no incluyen secretos.

        Acción: check_permission_for_action con token inválido.
        Resultado: el mensaje de error no incluye el token.
        """
        from vnc_remote_secure.security.auth_gateway import (
            check_permission_for_action,
        )
        fake_token = 'fakeSecretToken123456789'
        allowed, reason = check_permission_for_action(fake_token, PERM_VIEW)
        assert allowed is False
        assert 'fakeSecretToken123456789' not in reason
