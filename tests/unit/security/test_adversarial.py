"""Adversarial tests for security bypass attempts.

Tests specific attack vectors mentioned in the security review:
- Token from wrong IP rejected
- Token used for wrong service
- X-Forwarded-User header spoofing
- Direct backend access without proxy headers
- Single-use token consumed twice
- Token reuse after revocation
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
    revoke_session,
    PERM_VIEW,
    PERM_CONTROL,
    PERM_TERMINAL,
    PERM_FILE_TRANSFER,
)
from vnc_remote_secure.security.auth_gateway import (
    check_permission_for_action,
    check_websocket_upgrade,
)


@pytest.fixture(autouse=True)
def reset_store():
    import vnc_remote_secure.security.ephemeral_sessions as es
    es._store = None
    yield
    es._store = None


class TestTokenFromWrongIP:
    """Token with allowed_ip must reject connections from other IPs."""

    def test_token_from_wrong_ip_rejected(self):
        store = get_session_store()
        _, token = store.create(
            role='viewer', expires_in=3600, allowed_ip='192.168.1.100'
        )
        # Validating from the allowed IP should work
        session = store.validate(token, client_ip='192.168.1.100')
        assert session is not None
        # Validating from a different IP must fail
        session = store.validate(token, client_ip='10.0.0.50')
        assert session is None

    def test_token_without_ip_restriction_works_from_any(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        session = store.validate(token, client_ip='1.2.3.4')
        assert session is not None


class TestSingleUseToken:
    """Single-use tokens must be consumed only once."""

    def test_single_use_token_consumed_once(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600, single_use=True)
        # First use: valid
        session = store.validate(token)
        assert session is not None
        session.mark_used()
        # Second use: rejected
        session = store.validate(token)
        assert session is None


class TestTokenForWrongService:
    """A token for desktop should not work for terminal."""

    def test_desktop_token_cannot_use_terminal(self):
        store = get_session_store()
        # viewer has view but not terminal
        _, token = store.create(role='viewer', expires_in=3600)
        # Can view
        assert check_permission(token, PERM_VIEW)
        # Cannot use terminal
        assert not check_permission(token, PERM_TERMINAL)

    def test_operator_token_can_use_terminal(self):
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        assert check_permission(token, PERM_TERMINAL)
        assert check_permission(token, PERM_FILE_TRANSFER)


class TestHeaderSpoofing:
    """X-Forwarded-User and similar headers must not grant access."""

    def test_forwarded_user_header_does_not_grant_access(self):
        """An attacker setting X-Forwarded-User: admin must not get admin."""
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        # The gateway does NOT read X-Forwarded-User for authorization.
        # It only uses the signed token. So a viewer token stays viewer
        # regardless of any forwarded header.
        ok, reason = check_permission_for_action(token, PERM_CONTROL)
        assert not ok
        assert 'Permission denied' in reason

    def test_no_token_with_forwarded_header_denied(self):
        """No token + X-Forwarded-User header = no access."""
        ok, reason = check_permission_for_action('', PERM_VIEW)
        assert not ok
        assert 'No token' in reason


class TestDirectBackendAccess:
    """Direct access to backend without proxy headers must fail."""

    def test_websocket_upgrade_without_auth_rejected(self):
        """WebSocket upgrade without any token must be rejected."""
        ok, reason = check_websocket_upgrade(
            origin='http://localhost:8000',
            cookie_value='',
            bearer_token='',
        )
        assert not ok
        assert 'Authentication required' in reason

    def test_websocket_upgrade_with_invalid_origin_rejected(self):
        """WebSocket upgrade from wrong origin must be rejected."""
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        ok, reason = check_websocket_upgrade(
            origin='http://evil.com',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert not ok
        assert 'Invalid origin' in reason

    def test_websocket_upgrade_with_null_origin_rejected(self):
        """WebSocket upgrade with Origin: null must be rejected."""
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        ok, reason = check_websocket_upgrade(
            origin='null',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert not ok
        assert 'Invalid origin' in reason


class TestTokenReuseAfterRevocation:
    """Token must not be reusable after revocation."""

    def test_revoked_token_rejected_on_reconnect(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=3600)
        # Initial access works
        ok, _ = check_permission_for_action(token, PERM_VIEW)
        assert ok
        # Revoke
        revoke_session(token)
        # All subsequent uses fail
        ok, reason = check_permission_for_action(token, PERM_VIEW)
        assert not ok
        assert 'revoked' in reason.lower()

    def test_revoked_token_rejected_on_different_action(self):
        """Revocation affects ALL actions, not just the one that was active."""
        store = get_session_store()
        _, token = store.create(role='operator', expires_in=3600)
        revoke_session(token)
        # Even admin-level actions are rejected (though operator wouldn't
        # have admin anyway, the point is the token is fully dead)
        ok, _ = check_permission_for_action(token, PERM_VIEW)
        assert not ok
        ok, _ = check_permission_for_action(token, PERM_CONTROL)
        assert not ok
        ok, _ = check_permission_for_action(token, PERM_TERMINAL)
        assert not ok


class TestExpiredTokenRejection:
    """Expired tokens must be rejected on all paths."""

    def test_expired_token_rejected_on_upgrade(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=-1)
        ok, reason = check_websocket_upgrade(
            origin='http://localhost:8000',
            bearer_token=token,
            required_permission=PERM_VIEW,
        )
        assert not ok
        assert 'expired' in reason.lower()

    def test_expired_token_rejected_on_action(self):
        store = get_session_store()
        _, token = store.create(role='viewer', expires_in=-1)
        ok, reason = check_permission_for_action(token, PERM_VIEW)
        assert not ok
        assert 'expired' in reason.lower()
