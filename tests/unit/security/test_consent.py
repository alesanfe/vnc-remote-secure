"""Tests for local consent mechanism."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.consent import (
    ConsentManager,
    approve_consent,
    check_consent,
    reject_consent,
    request_consent,
)


class TestConsentRequest:
    """Tests for the consent request flow."""

    def test_request_creates_pending_consent(self):
        """A new consent request starts as pending."""
        mgr = ConsentManager()
        req_id = mgr.request_consent(
            requester='support-alex',
            permissions=['view', 'control'],
            duration_minutes=30,
        )
        assert req_id is not None
        req = mgr.get_request(req_id)
        assert req['status'] == 'pending'
        assert req['requester'] == 'support-alex'
        assert 'view' in req['permissions']
        assert 'control' in req['permissions']

    def test_check_consent_pending_returns_false(self):
        """A pending consent request returns False from check_consent."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        assert not mgr.check_consent(req_id)

    def test_approve_consent(self):
        """An approved consent request returns True from check_consent."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        assert mgr.approve_consent(req_id)
        assert mgr.check_consent(req_id)

    def test_reject_consent(self):
        """A rejected consent request returns False from check_consent."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        assert mgr.reject_consent(req_id)
        assert not mgr.check_consent(req_id)

    def test_consent_request_expires(self):
        """A pending consent request expires after 60 seconds."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        req = mgr._requests[req_id]
        # Simulate expiration.
        req.expires_at = time.time() - 1
        assert not mgr.check_consent(req_id)
        assert mgr.get_request(req_id)['status'] == 'expired'

    def test_cannot_approve_expired_consent(self):
        """An expired consent request cannot be approved."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        req = mgr._requests[req_id]
        req.expires_at = time.time() - 1
        assert not mgr.approve_consent(req_id)

    def test_cannot_approve_already_approved(self):
        """An already approved consent cannot be approved again."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        assert mgr.approve_consent(req_id)
        assert not mgr.approve_consent(req_id)  # Already approved

    def test_cannot_reject_already_rejected(self):
        """An already rejected consent cannot be rejected again."""
        mgr = ConsentManager()
        req_id = mgr.request_consent('user', ['view'], 30)
        assert mgr.reject_consent(req_id)
        assert not mgr.reject_consent(req_id)  # Already rejected

    def test_get_pending_returns_only_pending(self):
        """get_pending returns only pending requests."""
        mgr = ConsentManager()
        req1 = mgr.request_consent('user1', ['view'], 30)
        req2 = mgr.request_consent('user2', ['view'], 30)
        mgr.approve_consent(req1)
        pending = mgr.get_pending()
        assert len(pending) == 1
        assert pending[0]['requester'] == 'user2'

    def test_consent_with_resource(self):
        """Consent requests can include a resource binding."""
        mgr = ConsentManager()
        req_id = mgr.request_consent(
            'user', ['view'], 30, resource='desktop'
        )
        req = mgr.get_request(req_id)
        assert req['resource'] == 'desktop'


class TestConsentGlobalFunctions:
    """Test the convenience functions."""

    def test_request_and_approve_flow(self):
        """The convenience functions work end-to-end."""
        req_id = request_consent('user', ['view'], 30)
        assert not check_consent(req_id)
        assert approve_consent(req_id)
        assert check_consent(req_id)

    def test_request_and_reject_flow(self):
        """The convenience functions work for rejection."""
        req_id = request_consent('user', ['view'], 30)
        assert reject_consent(req_id)
        assert not check_consent(req_id)
