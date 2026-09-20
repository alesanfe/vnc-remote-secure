"""Tests for step-up authentication."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.step_up_auth import (
    SENSITIVE_ACTIONS,
    StepUpAuthManager,
    record_auth_time,
    require_step_up,
)


class TestStepUpAuth:
    """Tests for step-up authentication."""

    def test_never_authenticated_needs_step_up(self):
        """A user who never authenticated needs step-up."""
        mgr = StepUpAuthManager()
        assert mgr.needs_step_up('newuser')

    def test_recent_auth_no_step_up(self):
        """A user who authenticated recently does not need step-up."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user')
        assert not mgr.needs_step_up('user', max_age=300)

    def test_old_auth_needs_step_up(self):
        """A user who authenticated long ago needs step-up."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user', auth_time=time.time() - 600)
        assert mgr.needs_step_up('user', max_age=300)

    def test_record_auth_updates_time(self):
        """Recording auth time updates the timestamp."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user', auth_time=time.time() - 600)
        assert mgr.needs_step_up('user', max_age=300)
        mgr.record_auth_time('user')  # Update to now
        assert not mgr.needs_step_up('user', max_age=300)

    def test_get_auth_age(self):
        """get_auth_age returns the age of the last authentication."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user', auth_time=time.time() - 100)
        age = mgr.get_auth_age('user')
        assert age is not None
        assert 99 <= age <= 101

    def test_get_auth_age_never_authenticated(self):
        """get_auth_age returns None for never-authenticated users."""
        mgr = StepUpAuthManager()
        assert mgr.get_auth_age('newuser') is None

    def test_clear_user(self):
        """Clearing a user removes their auth record."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user')
        mgr.clear('user')
        assert mgr.needs_step_up('user')

    def test_clear_all(self):
        """Clearing all users removes all auth records."""
        mgr = StepUpAuthManager()
        mgr.record_auth_time('user1')
        mgr.record_auth_time('user2')
        mgr.clear()
        assert mgr.needs_step_up('user1')
        assert mgr.needs_step_up('user2')


class TestRequireStepUp:
    """Tests for the require_step_up function."""

    def test_non_sensitive_action_allowed(self):
        """Non-sensitive actions don't require step-up."""
        # 'view' is not in SENSITIVE_ACTIONS
        result = require_step_up('user', 'view')
        assert result is None

    def test_sensitive_action_requires_recent_auth(self):
        """Sensitive actions require recent auth."""
        # Don't record auth time.
        result = require_step_up('user', 'open_terminal')
        assert result is not None
        assert 'Re-authentication required' in result

    def test_sensitive_action_with_recent_auth_allowed(self):
        """Sensitive actions with recent auth are allowed."""
        record_auth_time('user')
        result = require_step_up('user', 'open_terminal', max_age=300)
        assert result is None

    def test_all_sensitive_actions_enforced(self):
        """All actions in SENSITIVE_ACTIONS are enforced."""
        for action in SENSITIVE_ACTIONS:
            # Without recent auth, all should require step-up.
            result = require_step_up('newuser', action)
            assert result is not None, f'Action {action} not enforced'


class TestSensitiveActionsList:
    """Verify the list of sensitive actions is correct.

    The set intentionally contains ONLY actions with a runtime
    enforcement point (a require_step_up call site). CLI-only
    operations (rotate_secrets, modify_firewall, disable_tls,
    change_profile, view_audit_log, session creation) have no web
    session to step up against — the operator already holds a local
    shell — and ``file_transfer`` has no implementation.
    """

    def test_terminal_is_sensitive(self):
        assert 'open_terminal' in SENSITIVE_ACTIONS

    def test_create_admin_is_sensitive(self):
        assert 'create_admin' in SENSITIVE_ACTIONS

    def test_delete_admin_is_sensitive(self):
        assert 'delete_admin' in SENSITIVE_ACTIONS

    def test_no_unenforced_actions_listed(self):
        """Every declared action must have a call site — the set must
        not drift back into a declaration-only list."""
        assert SENSITIVE_ACTIONS == {
            'open_terminal', 'create_admin', 'delete_admin'}
