"""Tests for strong token binding (resource, instance, max_uses)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.security.ephemeral_sessions as mod
from vnc_remote_secure.security.ephemeral_sessions import (
    EphemeralSession,
    SessionStore,
    check_permission,
    create_ephemeral_session,
)


@pytest.fixture
def fresh_store(monkeypatch):
    """Provide a fresh SessionStore patched as the global store."""
    store = SessionStore()
    monkeypatch.setattr(mod, '_store', store)
    return store


class TestResourceBinding:
    """A token bound to a resource can only access that resource."""

    def test_desktop_token_cannot_access_terminal(self, fresh_store):
        """A token for 'desktop' cannot be used for 'terminal'."""
        session, signed = fresh_store.create(
            role='operator',
            expires_in=300,
            resource='desktop',
        )

        # Can access desktop with view permission.
        assert check_permission(signed, 'view', resource='desktop')
        # Cannot access terminal.
        assert not check_permission(signed, 'terminal', resource='terminal')
        # Cannot access terminal even with view permission.
        assert not check_permission(signed, 'view', resource='terminal')

    def test_terminal_token_cannot_access_desktop(self, fresh_store):
        """A token for 'terminal' cannot be used for 'desktop'."""
        session, signed = fresh_store.create(
            role='operator',
            expires_in=300,
            resource='terminal',
        )

        # Can access terminal.
        assert check_permission(signed, 'terminal', resource='terminal')
        # Cannot access desktop.
        assert not check_permission(signed, 'view', resource='desktop')

    def test_unbound_token_can_access_any_resource(self, fresh_store):
        """A token without resource binding can access any resource."""
        session, signed = fresh_store.create(
            role='operator',
            expires_in=300,
            resource=None,  # No binding
        )

        assert check_permission(signed, 'view', resource='desktop')
        assert check_permission(signed, 'terminal', resource='terminal')


class TestMaxUses:
    """Tokens with max_uses are limited."""

    def test_max_uses_limits_consumption(self, fresh_store):
        """A token with max_uses=3 can be used 3 times."""
        session, signed = fresh_store.create(
            role='viewer',
            expires_in=300,
            max_uses=3,
        )

        # First 3 uses should be valid.
        assert session.is_valid()
        session.mark_used()
        assert session.is_valid()
        session.mark_used()
        assert session.is_valid()
        session.mark_used()
        # 4th use should be invalid.
        assert not session.is_valid()

    def test_single_use_implies_max_uses_1(self, fresh_store):
        """Single-use tokens have max_uses=1."""
        session, signed = fresh_store.create(
            role='viewer',
            expires_in=300,
            single_use=True,
        )
        assert session.max_uses == 1


class TestInstanceId:
    """Tokens are bound to a server instance."""

    def test_session_has_instance_id(self, fresh_store):
        """Every session has an instance_id."""
        session, signed = fresh_store.create(role='viewer', expires_in=300)
        assert session.instance_id is not None
        assert session.instance_id.startswith('srv_')

    def test_two_sessions_same_instance(self, fresh_store):
        """Sessions created in the same process share instance_id."""
        s1, _ = fresh_store.create(role='viewer', expires_in=300)
        s2, _ = fresh_store.create(role='viewer', expires_in=300)
        assert s1.instance_id == s2.instance_id

    def test_session_has_nonce(self, fresh_store):
        """Every session has a unique nonce."""
        s1, _ = fresh_store.create(role='viewer', expires_in=300)
        s2, _ = fresh_store.create(role='viewer', expires_in=300)
        assert s1.nonce is not None
        assert s2.nonce is not None
        assert s1.nonce != s2.nonce  # Different nonces


class TestToDictIncludesBinding:
    """to_dict() includes the new binding fields."""

    def test_to_dict_has_resource_and_instance(self, fresh_store):
        """to_dict() includes resource, instance_id, max_uses, use_count."""
        session, signed = fresh_store.create(
            role='viewer',
            expires_in=300,
            resource='desktop',
            max_uses=5,
        )
        d = session.to_dict()
        assert 'resource' in d
        assert 'instance_id' in d
        assert 'max_uses' in d
        assert 'use_count' in d
        assert d['resource'] == 'desktop'
        assert d['max_uses'] == 5
        assert d['use_count'] == 0
