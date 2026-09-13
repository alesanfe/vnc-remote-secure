"""CEREN tests for TEST-SEC-002: Viewer cannot control the desktop.

CONTRATO:
    Dado un usuario con rol viewer y una sesión válida,
    cuando intenta enviar eventos de teclado, ratón o portapapeles,
    entonces la petición es rechazada con 403/permission denied,
    y el evento no llega al sistema remoto,
    y no se elevan sus privilegios.

Estos tests verifican la autorización por acción (no solo por ruta),
que es el control crítico: ocultar un botón en la UI no es autorización.
El backend debe rechazar la petición directa.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.security.ephemeral_sessions as mod
from vnc_remote_secure.security.auth_gateway import check_permission_for_action
from vnc_remote_secure.security.ephemeral_sessions import (
    PERM_CLIPBOARD,
    PERM_CONTROL,
    PERM_FILE_TRANSFER,
    PERM_TERMINAL,
    PERM_VIEW,
    ROLES,
    SessionStore,
)


@pytest.fixture
def fresh_store(monkeypatch):
    """Provide a fresh SessionStore patched as the global store."""
    store = SessionStore()
    monkeypatch.setattr(mod, '_store', store)
    return store


# ---------------------------------------------------------------------------
# Camino correcto: viewer puede ver
# ---------------------------------------------------------------------------

class TestViewerCanView:
    """TEST-SEC-002: Un viewer SÍ puede recibir la imagen del desktop."""

    def test_viewer_can_view_desktop(self, fresh_store):
        """Contrato: viewer con sesión válida puede ver el desktop.

        Precondiciones: sesión viewer válida.
        Acción: check_permission_for_action(token, 'view').
        Resultado: permitido.
        Efectos prohibidos: no se conceden permisos extra.
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=300,
        )
        allowed, reason = check_permission_for_action(signed, PERM_VIEW)
        assert allowed is True
        assert reason == 'OK'

    def test_viewer_session_has_only_view_permission(self, fresh_store):
        """Contrato: el rol viewer tiene exactamente {view}.

        Resultado: permissions == {PERM_VIEW}.
        Efectos prohibidos: no contiene control, clipboard, terminal.
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=300,
        )
        assert session.permissions == {PERM_VIEW}
        assert PERM_CONTROL not in session.permissions
        assert PERM_CLIPBOARD not in session.permissions
        assert PERM_TERMINAL not in session.permissions


# ---------------------------------------------------------------------------
# Negativos: viewer NO puede controlar
# ---------------------------------------------------------------------------

class TestViewerCannotControl:
    """TEST-SEC-002: Un viewer NO puede enviar teclado, ratón ni portapapeles.

    Estos tests simulan peticiones directas al backend (no a través de
    la UI). Si el backend acepta porque la UI ocultaba el botón, hay
    una vulnerabilidad.
    """

    @pytest.mark.parametrize(
        ('permission', 'action_name'),
        [
            (PERM_CONTROL, 'keyboard.input'),
            (PERM_CONTROL, 'mouse.click'),
            (PERM_CONTROL, 'mouse.move'),
            (PERM_CLIPBOARD, 'clipboard.paste'),
            (PERM_CLIPBOARD, 'clipboard.copy'),
            (PERM_FILE_TRANSFER, 'file.upload'),
            (PERM_FILE_TRANSFER, 'file.download'),
            (PERM_TERMINAL, 'terminal.open'),
            (PERM_TERMINAL, 'terminal.exec'),
        ],
    )
    def test_viewer_cannot_perform_sensitive_action(
        self, fresh_store, permission, action_name,
    ):
        """Contrato: viewer no puede realizar acciones sensibles.

        Precondiciones: sesión viewer válida.
        Acción: check_permission_for_action(token, permission).
        Resultado: rechazado con 'Permission denied'.
        Efectos prohibidos: el permiso no se concede bajo ninguna
        circunstancia, incluso si el atacante construye la petición
        directamente sin usar la UI.
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=300,
        )
        allowed, reason = check_permission_for_action(signed, permission)
        assert allowed is False, (
            f'Viewer should not be able to perform {action_name} '
            f'(permission={permission})'
        )
        assert 'denied' in reason.lower() or 'Permission' in reason

    def test_viewer_with_view_only_flag_cannot_control(self, fresh_store):
        """Contrato: view_only=True bloquea control incluso si el rol
        tuviera el permiso.

        Precondiciones: sesión support con view_only=True.
        Acción: check_permission_for_action(token, 'control').
        Resultado: rechazado.
        """
        session, signed = fresh_store.create(
            role='support', expires_in=300, view_only=True,
        )
        # support normally has control, but view_only should block it
        assert not session.has_permission(PERM_CONTROL)
        allowed, reason = check_permission_for_action(signed, PERM_CONTROL)
        assert allowed is False

    def test_viewer_with_no_terminal_flag_cannot_open_terminal(self, fresh_store):
        """Contrato: no_terminal=True bloquea terminal incluso para
        roles que normalmente lo tienen.

        Precondiciones: sesión operator con no_terminal=True.
        Acción: check_permission_for_action(token, 'terminal').
        Resultado: rechazado.
        """
        session, signed = fresh_store.create(
            role='operator', expires_in=300, no_terminal=True,
        )
        assert not session.has_permission(PERM_TERMINAL)
        allowed, reason = check_permission_for_action(signed, PERM_TERMINAL)
        assert allowed is False


# ---------------------------------------------------------------------------
# Estado incorrecto: sesión revocada o expirada
# ---------------------------------------------------------------------------

class TestViewerInvalidState:
    """TEST-SEC-002: Sesiones revocadas/expiradas no conceden ningún permiso."""

    def test_revoked_viewer_session_rejected(self, fresh_store):
        """Contrato: una sesión revocada no puede ver ni controlar.

        Precondiciones: sesión viewer válida, luego revocada.
        Acción: check_permission_for_action(token, 'view').
        Resultado: rechazado con 'Session revoked'.
        Efectos prohibidos: no se concede ningún permiso.
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=300,
        )
        from vnc_remote_secure.security.ephemeral_sessions import revoke_session
        revoke_session(signed)

        allowed, reason = check_permission_for_action(signed, PERM_VIEW)
        assert allowed is False
        assert 'revoked' in reason.lower()

    def test_expired_viewer_session_rejected(self, fresh_store):
        """Contrato: una sesión expirada no puede ver ni controlar.

        Precondiciones: sesión viewer con expires_in=0 (ya expirada).
        Acción: check_permission_for_action(token, 'view').
        Resultado: rechazado con 'Session expired'.
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=-1,  # Already expired
        )
        allowed, reason = check_permission_for_action(signed, PERM_VIEW)
        assert allowed is False
        assert 'expired' in reason.lower()


# ---------------------------------------------------------------------------
# Entrada inválida: token malformado o vacío
# ---------------------------------------------------------------------------

class TestViewerInvalidInput:
    """TEST-SEC-002: Entradas inválidas no conceden permisos."""

    def test_empty_token_rejected(self, fresh_store):
        """Contrato: token vacío no concede ningún permiso.

        Acción: check_permission_for_action('', 'view').
        Resultado: rechazado con 'No token provided'.
        """
        allowed, reason = check_permission_for_action('', PERM_VIEW)
        assert allowed is False
        assert 'no token' in reason.lower()

    def test_malformed_token_rejected(self, fresh_store):
        """Contrato: token malformado no concede ningún permiso.

        Acción: check_permission_for_action('invalid-token', 'view').
        Resultado: rechazado.
        """
        allowed, reason = check_permission_for_action('invalid-token', PERM_VIEW)
        assert allowed is False

    def test_tampered_token_rejected(self, fresh_store):
        """Contrato: un token modificado (firma inválida) es rechazado.

        Precondiciones: sesión viewer válida.
        Acción: modificar un carácter del token y verificar.
        Resultado: rechazado (firma inválida).
        """
        session, signed = fresh_store.create(
            role='viewer', expires_in=300,
        )
        # Tamper: flip last character
        tampered = signed[:-1] + ('a' if signed[-1] != 'a' else 'b')
        allowed, reason = check_permission_for_action(tampered, PERM_VIEW)
        assert allowed is False


# ---------------------------------------------------------------------------
# Roles autorizados: support, operator, administrator SÍ pueden controlar
# ---------------------------------------------------------------------------

class TestAuthorizedRolesCanControl:
    """TEST-SEC-002: Los roles autorizados SÍ pueden controlar.

    Esto verifica que el bloqueo es por rol, no un bloqueo global.
    """

    @pytest.mark.parametrize(
        ('role', 'permission', 'expected'),
        [
            ('viewer', PERM_CONTROL, False),
            ('support', PERM_CONTROL, True),
            ('operator', PERM_CONTROL, True),
            ('administrator', PERM_CONTROL, True),
            ('viewer', PERM_CLIPBOARD, False),
            ('support', PERM_CLIPBOARD, True),
            ('operator', PERM_CLIPBOARD, True),
            ('administrator', PERM_CLIPBOARD, True),
            ('viewer', PERM_TERMINAL, False),
            ('support', PERM_TERMINAL, False),
            ('operator', PERM_TERMINAL, True),
            ('administrator', PERM_TERMINAL, True),
            ('viewer', PERM_FILE_TRANSFER, False),
            ('support', PERM_FILE_TRANSFER, False),
            ('operator', PERM_FILE_TRANSFER, True),
            ('administrator', PERM_FILE_TRANSFER, True),
        ],
    )
    def test_role_permission_matrix(
        self, fresh_store, role, permission, expected,
    ):
        """Contrato: la matriz de permisos por rol es correcta.

        Resultado: cada combinación rol/permiso debe dar el resultado
        esperado. Esto es un test parametrizado que cubre todos los
        roles y permisos.
        """
        session, signed = fresh_store.create(
            role=role, expires_in=300,
        )
        allowed, _ = check_permission_for_action(signed, permission)
        assert allowed is expected, (
            f'Role {role} should {"be able" if expected else "not be able"} '
            f'to {permission}'
        )
