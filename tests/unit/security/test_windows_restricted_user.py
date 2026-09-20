"""Tests for Windows restricted user management.

Verifies that the restricted user API exists and is callable.
Actual PowerShell execution is mocked since we're not on Windows
or don't have admin rights in CI.
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.platform.windows.permissions import (
    create_restricted_user,
    restrict_user,
)
from vnc_remote_secure.platform.windows.users import (
    create_restricted_runtime_user,
)


class TestRestrictedUserAPI:
    """Verify the restricted user API is available and callable."""

    def test_create_restricted_user_exists(self):
        assert callable(create_restricted_user)

    def test_restrict_user_exists(self):
        assert callable(restrict_user)

    def test_create_restricted_runtime_user_exists(self):
        assert callable(create_restricted_runtime_user)


class TestRestrictedUserBehavior:
    """Test behavior with mocked PowerShell."""

    @patch('vnc_remote_secure.platform.windows.permissions.run_powershell')
    @patch('vnc_remote_secure.platform.windows.permissions.user_exists')
    def test_create_restricted_user_calls_create_and_restrict(self, mock_exists, mock_ps):
        # user_exists returns True (simulating user was created)
        mock_exists.return_value = True
        mock_ps.return_value = MagicMock(returncode=0)
        result = create_restricted_user('vnc-service')
        assert result is True
        # Should have called PowerShell at least once (create + restrict)
        assert mock_ps.call_count >= 1

    @patch('vnc_remote_secure.platform.windows.permissions.user_exists')
    def test_restrict_user_returns_false_if_not_exists(self, mock_exists):
        mock_exists.return_value = False
        result = restrict_user('nonexistent')
        assert result is False

    @patch('vnc_remote_secure.platform.windows.permissions.run_powershell')
    @patch('vnc_remote_secure.platform.windows.permissions.user_exists')
    def test_restrict_user_returns_true_if_exists(self, mock_exists, mock_ps):
        mock_exists.return_value = True
        mock_ps.return_value = MagicMock(returncode=0)
        result = restrict_user('vnc-service')
        assert result is True
