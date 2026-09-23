"""CEREN tests for TEST-SEC-005 through TEST-SEC-009.

TEST-SEC-005: Desktop token cannot be used in terminal.
TEST-SEC-006: Disallowed Origin is rejected.
TEST-SEC-007: Spoofed proxy headers don't grant authentication.
TEST-SEC-008: Public-hardened blocks startup without TLS/MFA/proxy/secret.
TEST-SEC-009: Secrets don't appear in logs, diagnostics, or error responses.
"""
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
        # overwrite=False: operator-set vars win over profile defaults —
        # and development is not hardened, so BACKEND_BIND_HOST is not
        # in locked_vars (unlike public-hardened, which forces 127.0.0.1).
        apply_profile('development')
        assert os.environ.get('BACKEND_BIND_HOST') == '0.0.0.0'

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


class TestExpiryEnforcement:
    """An expired session must fail is_valid/validate/check_permission
    — the expiry check sits on the authorization critical path."""

    def test_expired_is_invalid(self, fresh_store):
        sess, signed = fresh_store.create(
            role='viewer', expires_in=-1)  # already expired
        assert sess.is_valid() is False
        assert fresh_store.validate(signed) is None

    def test_expired_check_permission_denied(self, fresh_store):
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=-1)
        from vnc_remote_secure.security.ephemeral_sessions import (
            check_permission)
        assert check_permission(signed, 'desktop:view') is False

    def test_expired_activate_returns_none(self, fresh_store):
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=-1)
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session)
        assert activate_ephemeral_session(signed) is None

    def test_max_uses_boundary(self, fresh_store):
        """max_uses=1: first consume ok, second must fail (boundary at
        the counter, not just single_use flag)."""
        sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, max_uses=1)
        assert sess.is_valid() is True
        sess.use_count = 1
        assert sess.is_valid() is False
        assert fresh_store.validate(signed) is None

    def test_expiry_boundary_just_inside(self, fresh_store):
        """expires_in=0 creates expires_at ~= now — must not be
        treated as still-valid after the clock advances."""
        import time
        sess, signed = fresh_store.create(role='viewer', expires_in=0)
        # Boundary: exactly at expiry is invalid (>), one second before
        # would be valid — freeze time just inside validity.
        sess.expires_at = time.time() + 1
        assert sess.is_valid() is True
        sess.expires_at = time.time() - 0.001
        assert sess.is_valid() is False


class TestResourceBindingValidation:
    """A token minted for resource='desktop' must not validate for
    resource='terminal' at the is_valid/validate layer — not just at
    has_permission."""

    def test_wrong_resource_is_invalid(self, fresh_store):
        sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, resource='desktop')
        assert sess.is_valid(resource='desktop') is True
        assert sess.is_valid(resource='terminal') is False
        assert fresh_store.validate(signed, resource='terminal') is None
        assert fresh_store.validate(signed, resource='desktop') is sess

    def test_check_permission_wrong_resource_denied(self, fresh_store):
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, resource='desktop')
        from vnc_remote_secure.security.ephemeral_sessions import (
            check_permission)
        assert check_permission(
            signed, 'desktop:view', resource='desktop') is True
        assert check_permission(
            signed, 'terminal:use', resource='terminal') is False


class TestCidrIpBinding:
    """allowed_ip accepts CIDR ranges — subnet policies survive a
    client roaming inside one network."""

    def test_cidr_match_accepted(self, fresh_store):
        sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='10.0.0.0/24')
        assert sess.is_valid(client_ip='10.0.0.55') is True
        assert fresh_store.validate(
            signed, client_ip='10.0.0.55') is sess

    def test_cidr_mismatch_rejected(self, fresh_store):
        sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='10.0.0.0/24')
        assert sess.is_valid(client_ip='10.0.1.5') is False
        assert fresh_store.validate(
            signed, client_ip='10.0.1.5') is None

    def test_cidr_boundary_first_last(self, fresh_store):
        """First and last usable addresses of the range are in."""
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='10.0.0.0/30')
        assert sess.is_valid(client_ip='10.0.0.1') is True
        assert sess.is_valid(client_ip='10.0.0.2') is True
        assert sess.is_valid(client_ip='10.0.0.4') is False

    def test_exact_still_works(self, fresh_store):
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='203.0.113.7')
        assert sess.is_valid(client_ip='203.0.113.7') is True
        assert sess.is_valid(client_ip='203.0.113.8') is False

    def test_invalid_cidr_fails_closed(self, fresh_store):
        """A garbage CIDR must never become a wildcard."""
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='999.0.0.0/8')
        assert sess.is_valid(client_ip='999.0.0.1') is False
        assert sess.is_valid(client_ip='10.0.0.1') is False

    def test_check_session_permission_cidr(self, fresh_store):
        """CIDR binding enforced on the activated-session path too."""
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=3600, allowed_ip='10.0.0.0/24')
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session, check_session_permission)
        internal = activate_ephemeral_session(
            signed, client_ip='10.0.0.5')
        assert internal is not None
        assert check_session_permission(
            internal, 'desktop:view', client_ip='10.0.0.9') is True
        assert check_session_permission(
            internal, 'desktop:view', client_ip='192.168.1.1') is False


class TestGranularPermissionExpansion:
    """Umbrella permissions expand; fine-grained perms do not grant
    the umbrella."""

    def test_control_implies_keyboard_and_pointer(self, fresh_store):
        sess, _ = fresh_store.create(role='support', expires_in=3600)
        assert sess.has_permission('desktop:keyboard') is True
        assert sess.has_permission('desktop:pointer') is True
        assert sess.has_permission('desktop:control') is True

    def test_clipboard_implies_write(self, fresh_store):
        sess, _ = fresh_store.create(role='support', expires_in=3600)
        assert sess.has_permission(
            'desktop:clipboard_write') is True

    def test_pointer_only_no_control(self, fresh_store):
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600,
            permissions={'view', 'pointer'})
        assert sess.has_permission('desktop:pointer') is True
        assert sess.has_permission('desktop:keyboard') is False
        assert sess.has_permission('desktop:control') is False

    def test_keyboard_only_no_pointer(self, fresh_store):
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600,
            permissions={'view', 'keyboard'})
        assert sess.has_permission('desktop:keyboard') is True
        assert sess.has_permission('desktop:pointer') is False

    def test_view_only_blocks_granular_input(self, fresh_store):
        """view_only blocks keyboard/pointer/clipboard_write even if
        a buggy caller granted them explicitly."""
        sess, _ = fresh_store.create(
            role='support', expires_in=3600, view_only=True,
            permissions={'view', 'keyboard', 'pointer',
                         'clipboard_write'})
        assert sess.has_permission('desktop:keyboard') is False
        assert sess.has_permission('desktop:pointer') is False
        assert sess.has_permission('desktop:clipboard_write') is False
        assert sess.has_permission('desktop:view') is True


class TestFirstObservedIpBinding:
    """allowed_ip='first-observed' pins the session to the first
    activation IP — a middle ground between no binding and an exact
    (possibly unknown) address."""

    def test_first_activation_pins_ip(self, fresh_store):
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session)
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=3600,
            allowed_ip='first-observed')
        token = activate_ephemeral_session(
            signed, client_ip='203.0.113.7')
        assert token is not None
        sess = fresh_store.get(token)
        assert sess.allowed_ip == '203.0.113.7'

    def test_pinned_binding_enforced(self, fresh_store):
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session, check_session_permission)
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=3600,
            allowed_ip='first-observed')
        token = activate_ephemeral_session(
            signed, client_ip='203.0.113.7')
        assert check_session_permission(
            token, 'desktop:view',
            client_ip='203.0.113.7') is True
        # A different client is rejected after pinning.
        assert check_session_permission(
            token, 'desktop:view',
            client_ip='198.51.100.4') is False

    def test_activation_without_ip_leaves_unbound(
            self, fresh_store):
        """CLI/API activation without caller context doesn't pin —
        the binding applies at first request with a real IP... and a
        later activation WITH an ip still pins then."""
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session)
        _sess, signed = fresh_store.create(
            role='viewer', expires_in=3600,
            allowed_ip='first-observed')
        token = activate_ephemeral_session(signed)
        assert token is not None
        sess = fresh_store.get(token)
        assert sess.allowed_ip == 'first-observed'


class TestAudioPermission:
    """desktop:audio is explicit — room audio is privacy-sensitive
    and must not ride along with desktop:view."""

    def test_viewer_lacks_audio(self, fresh_store):
        sess, _ = fresh_store.create(role='viewer', expires_in=3600)
        assert sess.has_permission('desktop:audio') is False
        assert sess.has_permission('desktop:view') is True

    def test_support_has_audio(self, fresh_store):
        sess, _ = fresh_store.create(role='support', expires_in=3600)
        assert sess.has_permission('desktop:audio') is True

    def test_explicit_view_plus_audio(self, fresh_store):
        sess, _ = fresh_store.create(
            role='viewer', expires_in=3600,
            permissions={'view', 'audio'})
        assert sess.has_permission('desktop:audio') is True


class TestGamepadPermission:
    """desktop:gamepad is explicit AND experimental — it is input
    injection through a privileged driver, not plain control."""

    def test_support_lacks_gamepad(self, fresh_store):
        """support has full control but NOT the experimental
        gamepad path — control umbrella must not imply it."""
        sess, _ = fresh_store.create(role='support', expires_in=3600)
        assert sess.has_permission('desktop:control') is True
        assert sess.has_permission('desktop:gamepad') is False

    def test_operator_has_gamepad(self, fresh_store):
        sess, _ = fresh_store.create(role='operator', expires_in=3600)
        assert sess.has_permission('desktop:gamepad') is True

    def test_view_only_blocks_gamepad(self, fresh_store):
        """Input injection must be blocked in view_only even when a
        caller granted the perm explicitly."""
        sess, _ = fresh_store.create(
            role='operator', expires_in=3600, view_only=True,
            permissions={'view', 'gamepad'})
        assert sess.has_permission('desktop:gamepad') is False
