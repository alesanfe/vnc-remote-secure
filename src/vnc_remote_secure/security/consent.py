"""Local consent for remote support sessions.

When someone requests remote access, the local machine should display
a consent dialog showing:
- Who is requesting access.
- What permissions they are requesting.
- How long the session will last.
- Buttons to Allow or Reject.

This module provides the consent state machine and request tracking.
The actual UI (dialog/notification) is platform-specific and should
be implemented by the caller.

Usage:
    from vnc_remote_secure.security.consent import (
        request_consent,
        check_consent,
        approve_consent,
        reject_consent,
    )

    # When a support session is requested:
    request_id = request_consent(
        requester='support-alejandro',
        permissions=['view', 'control'],
        duration_minutes=30,
    )

    # Display dialog to local user...
    # User clicks "Allow":
    approve_consent(request_id)

    # Check if consent was given:
    if check_consent(request_id):
        # Proceed with session
        ...
"""
import logging
import secrets
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ConsentRequest:
    """A pending consent request for remote access."""

    def __init__(
        self,
        requester: str,
        permissions: List[str],
        duration_minutes: int,
        resource: Optional[str] = None,
    ):
        self.request_id = secrets.token_hex(8)
        self.requester = requester
        self.permissions = permissions
        self.duration_minutes = duration_minutes
        self.resource = resource
        self.created_at = time.time()
        self.expires_at = self.created_at + 60  # 60s to respond
        self.status = 'pending'  # pending, approved, rejected, expired
        self.responded_at: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if this consent request has expired."""
        return time.time() > self.expires_at and self.status == 'pending'

    def approve(self):
        """Mark this consent request as approved."""
        self.status = 'approved'
        self.responded_at = time.time()

    def reject(self):
        """Mark this consent request as rejected."""
        self.status = 'rejected'
        self.responded_at = time.time()

    def to_dict(self) -> dict:
        """Serialize for API/logging."""
        return {
            'request_id': self.request_id,
            'requester': self.requester,
            'permissions': self.permissions,
            'duration_minutes': self.duration_minutes,
            'resource': self.resource,
            'status': self.status,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
        }


class ConsentManager:
    """Manages consent requests for remote support sessions."""

    def __init__(self):
        self._requests: Dict[str, ConsentRequest] = {}
        self._lock = threading.Lock()

    def request_consent(
        self,
        requester: str,
        permissions: List[str],
        duration_minutes: int = 30,
        resource: Optional[str] = None,
    ) -> str:
        """Create a new consent request.

        Args:
            requester: Username of the person requesting access.
            permissions: List of requested permissions.
            duration_minutes: How long the session will last.
            resource: Optional resource being accessed.

        Returns:
            The request ID (used to check/approve/reject).
        """
        with self._lock:
            req = ConsentRequest(requester, permissions, duration_minutes, resource)
            self._requests[req.request_id] = req
            logger.info(
                'Consent request created: %s (requester=%s, permissions=%s, duration=%dm)',
                req.request_id, requester, permissions, duration_minutes,
            )
            return req.request_id

    def check_consent(self, request_id: str) -> bool:
        """Check if consent was given for a request.

        Returns True only if the request exists and was approved.
        Expired or rejected requests return False.
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return False
            if req.is_expired() and req.status == 'pending':
                req.status = 'expired'
                return False
            return req.status == 'approved'

    def approve_consent(self, request_id: str) -> bool:
        """Approve a consent request.

        Returns True if the request was found and approved.
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req or req.status != 'pending':
                return False
            if req.is_expired():
                req.status = 'expired'
                return False
            req.approve()
            logger.info('Consent approved: %s', request_id)
            return True

    def reject_consent(self, request_id: str) -> bool:
        """Reject a consent request.

        Returns True if the request was found and rejected.
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req or req.status != 'pending':
                return False
            req.reject()
            logger.info('Consent rejected: %s', request_id)
            return True

    def get_pending(self) -> List[dict]:
        """Return all pending consent requests (for UI display)."""
        with self._lock:
            result = []
            for req in self._requests.values():
                if req.status == 'pending' and not req.is_expired():
                    result.append(req.to_dict())
                elif req.is_expired() and req.status == 'pending':
                    req.status = 'expired'
            return result

    def get_request(self, request_id: str) -> Optional[dict]:
        """Get a specific consent request by ID."""
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return None
            if req.is_expired() and req.status == 'pending':
                req.status = 'expired'
            return req.to_dict()

    def cleanup(self):
        """Remove expired and resolved requests."""
        with self._lock:
            expired = [
                rid for rid, req in self._requests.items()
                if req.status in ('expired', 'approved', 'rejected')
                and time.time() - (req.responded_at or req.expires_at) > 300
            ]
            for rid in expired:
                del self._requests[rid]


# Global singleton.
_manager: Optional[ConsentManager] = None


def get_consent_manager() -> ConsentManager:
    """Return the process-wide consent manager."""
    global _manager
    if _manager is None:
        _manager = ConsentManager()
    return _manager


def request_consent(requester: str, permissions: List[str],
                    duration_minutes: int = 30,
                    resource: Optional[str] = None) -> str:
    """Create a consent request (convenience function)."""
    return get_consent_manager().request_consent(
        requester, permissions, duration_minutes, resource
    )


def check_consent(request_id: str) -> bool:
    """Check if consent was given (convenience function)."""
    return get_consent_manager().check_consent(request_id)


def approve_consent(request_id: str) -> bool:
    """Approve a consent request (convenience function)."""
    return get_consent_manager().approve_consent(request_id)


def reject_consent(request_id: str) -> bool:
    """Reject a consent request (convenience function)."""
    return get_consent_manager().reject_consent(request_id)
