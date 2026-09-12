"""Tests for per-action authorization and live session revocation.

Verifies that:
- A viewer cannot send keyboard input (control permission).
- A viewer cannot use the terminal.
- A support user can control but cannot open terminal.
- An operator can use terminal but cannot admin.
- A revoked session is immediately rejected on all checks.
- An expired session is rejected.
- Per-action checks work after initial WebSocket upgrade.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.ephemeral_sessions import (
    get_session_store,
    check_permission,
    is_session_revoked,
    is_session_expired,
    revoke_session,
    PERM_VIEW,
    PERM_CONTROL,
    PERM_CLIPBOARD,
    PERM_FILE_TRANSFER,
    PERM_TERMINAL,
    PERM_ADMIN,
)
from vnc_remote_secure.security.auth_gateway import (
    check_permission_for_action,
    check_websocket_upgrade,
    revoke_session_live,
)


@pytest.fixture(autouse=True)
def reset_store():
    """Reset the session store before each test."""
    import vnc_remote_secure.security.ephemeral_sessions as es
    es._store = None
    yield
    es._store = None


class TestPerActionAuthorization:
    """Verify that permissions are enforced per action, not just at login."""

    def test_viewer_can_view(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert check_permission(token, PERM_VIEW)

    def test_viewer_cannot_control(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not check_permission(token, PERM_CONTROL)

    def test_viewer_cannot_use_clipboard(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not check_permission(token, PERM_CLIPBOARD)

    def test_viewer_cannot_use_terminal(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not check_permission(token, PERM_TERMINAL)

    def test_viewer_cannot_transfer_files(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not check_permission(token, PERM_FILE_TRANSFER)

    def test_support_can_control(self):
        store = get_session_store()
        _, token = store.create(role='support', expires_in=3600)
        assert check_permission(token, PERM_CONTROL)
        assert check_permission(token, PERM_CLIPBOARD)

    def test_support_cannot_use_terminal(self):
        store = get_session_store()
        _, token = store.create(role='support', expires_in=3600)
        assert not check_permission(token, PERM_TERMINAL)

    def test_operator_can_use_terminal(self):
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        assert check_permission(token, PERM_TERMINAL)
        assert check_permission(token, PERM_FILE_TRANSFER)

    def test_operator_cannot_admin(self):
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        assert not check_permission(token, PERM_ADMIN)

    def test_administrator_has_all(self):
        store = get_session_store()
        _, token = store.create(role='administrator', expires_in=3600)
        for perm in [PERM_VIEW, PERM_CONTROL, PERM_CLIPBOARD,
                     PERM_FILE_TRANSFER, PERM_TERMINAL, PERM_ADMIN]:
            assert check_permission(token, perm), f"admin should have {perm}"

    def test_view_only_blocks_control_even_for_operator(self):
        store = get_session_store()
        _, token = store.create(role='operator', view_only=True, expires_in=3600)
        # view_only overrides: even operator cannot control
        assert not check_permission(token, PERM_CONTROL)
        assert not check_permission(token, PERM_CLIPBOARD)

    def test_no_terminal_blocks_terminal_even_for_operator(self):
        store = get_session_store()
        _, token = store.create(role='operator', no_terminal=True, expires_in=3600)
        assert not check_permission(token, PERM_TERMINAL)


class TestCheckPermissionForAction:
    """Test the gateway-level per-action check."""

    def test_valid_token_with_permission_allowed(self):
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        ok, reason = check_permission_for_action(token, PERM_TERMINAL)
        assert ok
        assert reason == 'OK'

    def test_valid_token_without_permission_denied(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        ok, reason = check_permission_for_action(token, PERM_CONTROL)
        assert not ok
        assert 'Permission denied' in reason

    def test_no_token_denied(self):
        ok, reason = check_permission_for_action('', PERM_VIEW)
        assert not ok
        assert 'No token' in reason

    def test_revoked_token_denied(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        revoke_session(token)
        ok, reason = check_permission_for_action(token, PERM_VIEW)
        assert not ok
        assert 'revoked' in reason.lower()

    def test_expired_token_denied(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=-1)  # already expired
        ok, reason = check_permission_for_action(token, PERM_VIEW)
        assert not ok
        assert 'expired' in reason.lower()


class TestLiveRevocation:
    """Verify that revocation propagates immediately to all checks."""

    def test_revoked_session_rejected_on_websocket_upgrade(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        # Revoke
        assert revoke_session(token)
        # WebSocket upgrade must now fail
        ok, reason = check_websocket_upgrade(
            origin='http://localhost:8000',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert not ok
        assert 'revoked' in reason.lower()

    def test_revoked_session_rejected_on_action_check(self):
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        # Before revocation: can use terminal
        ok, _ = check_permission_for_action(token, PERM_TERMINAL)
        assert ok
        # Revoke
        revoke_session_live(token)
        # After revocation: cannot use terminal
        ok, reason = check_permission_for_action(token, PERM_TERMINAL)
        assert not ok
        assert 'revoked' in reason.lower()

    def test_is_session_revoked_true_after_revoke(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not is_session_revoked(token)
        revoke_session(token)
        assert is_session_revoked(token)

    def test_invalid_token_treated_as_revoked(self):
        assert is_session_revoked('invalid-token-string')

    def test_revoked_token_cannot_reconnect(self):
        """Simulate: open WebSocket, revoke, try to reconnect with same token."""
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        # Initial check passes
        ok, _ = check_websocket_upgrade(
            origin='http://localhost:8000',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert ok
        # Revoke
        revoke_session(token)
        # Reconnect attempt fails
        ok, reason = check_websocket_upgrade(
            origin='http://localhost:8000',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert not ok
        assert 'revoked' in reason.lower()

    def test_other_sessions_still_work_after_revocation(self):
        """Revoking one session doesn't affect others."""
        store = get_session_store()
        _, token1 = store.create(role='viewer', expires_in=3600)
        _, token2 = store.create(role='viewer', expires_in=3600)
        revoke_session(token1)
        assert is_session_revoked(token1)
        assert not is_session_revoked(token2)
        ok, _ = check_permission_for_action(token2, PERM_VIEW)
        assert ok


class TestExpiredSessions:
    """Verify that expired sessions are rejected."""

    def test_expired_session_rejected(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=-1)
        assert is_session_expired(token)

    def test_valid_session_not_expired(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        assert not is_session_expired(token)
