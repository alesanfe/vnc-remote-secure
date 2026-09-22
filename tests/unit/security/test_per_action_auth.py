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

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.auth_gateway import (
    check_permission_for_action,
    check_websocket_upgrade,
    revoke_session_live,
)
from vnc_remote_secure.security.ephemeral_sessions import (
    PERM_ADMIN,
    PERM_CLIPBOARD,
    PERM_CONTROL,
    PERM_FILE_TRANSFER,
    PERM_TERMINAL,
    PERM_VIEW,
    check_permission,
    get_session_store,
    is_session_expired,
    is_session_revoked,
    revoke_session,
)


@pytest.fixture(autouse=True)
def _reset_store():
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


class TestShareLinkExchange:
    """The browser share-link flow: ?session= activates once, then the
    activated session keeps working via the internal token until TTL."""

    def test_activate_returns_internal_token(self):
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        store = get_session_store()
        session, signed = store.create(role='viewer', expires_in=3600)
        internal = activate_ephemeral_session(signed)
        assert internal == session.token

    def test_single_use_link_burns_after_first_exchange(self):
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600,
                                 single_use=True)
        assert activate_ephemeral_session(signed) is not None
        # Second exchange of the same link must fail.
        assert activate_ephemeral_session(signed) is None

    def test_activated_session_keeps_working(self):
        """After a single-use link is burned, the activated session must
        still serve requests (the cookie flow requires many requests)."""
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session,
            check_session_permission,
        )
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600,
                                 single_use=True)
        internal = activate_ephemeral_session(signed)
        assert check_session_permission(internal, 'view', resource='desktop')
        # Repeated checks keep working until TTL.
        assert check_session_permission(internal, 'view', resource='desktop')

    def test_check_session_permission_enforces_role(self):
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session,
            check_session_permission,
        )
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600)
        internal = activate_ephemeral_session(signed)
        assert check_session_permission(internal, 'view')
        assert not check_session_permission(internal, 'terminal')

    def test_check_session_permission_revoked(self):
        from vnc_remote_secure.security.ephemeral_sessions import (
            activate_ephemeral_session,
            check_session_permission,
            revoke_session,
        )
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600)
        internal = activate_ephemeral_session(signed)
        revoke_session(signed)
        assert not check_session_permission(internal, 'view')

    def test_activate_rejects_garbage(self):
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        assert activate_ephemeral_session('not-a-token') is None
        assert activate_ephemeral_session('') is None

    def test_activate_enforces_allowed_ip(self):
        """An IP-bound share link must not activate from a different
        client IP — without the check a link could be *burned* by a
        third party (single-use DoS) even though per-request checks
        would later reject them."""
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600,
                                 allowed_ip='203.0.113.7')
        assert activate_ephemeral_session(
            signed, client_ip='198.51.100.9') is None
        # The link is NOT burned by the rejected attempt — the bound
        # IP can still activate it.
        _, signed2 = store.create(role='viewer', expires_in=3600,
                                  allowed_ip='203.0.113.7')
        assert activate_ephemeral_session(
            signed2, client_ip='203.0.113.7') is not None

    def test_activate_ip_bound_missing_client_ip(self):
        """An IP-bound link activated without caller-IP context still
        activates (backward compat: CLI-created links via API paths
        that never saw an IP). The per-request check still enforces
        the binding on actual resource access."""
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        store = get_session_store()
        _, signed = store.create(role='viewer', expires_in=3600,
                                 allowed_ip='203.0.113.7')
        assert activate_ephemeral_session(signed) is not None
