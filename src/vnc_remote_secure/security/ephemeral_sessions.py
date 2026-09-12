"""Ephemeral remote sessions for VNC Remote Secure.

Provides shareable, time-limited access sessions with granular
permissions. Useful for temporary support, demos, or granting
view-only access without sharing permanent credentials.

Usage:
    vnc-remote session create --expires 30m --view-only --no-terminal --single-use

The command returns a URL with an ephemeral token that grants
access according to the specified permissions.
"""
import hashlib
import hmac
import logging
import secrets
import time
from typing import Optional

logger = logging.getLogger(__name__)


# Permissions
PERM_VIEW = 'view'
PERM_CONTROL = 'control'
PERM_CLIPBOARD = 'clipboard'
PERM_FILE_TRANSFER = 'file_transfer'
PERM_TERMINAL = 'terminal'
PERM_ADMIN = 'admin'

ALL_PERMISSIONS = {
    PERM_VIEW, PERM_CONTROL, PERM_CLIPBOARD,
    PERM_FILE_TRANSFER, PERM_TERMINAL, PERM_ADMIN,
}

# Roles (collections of permissions)
ROLES = {
    'viewer': {PERM_VIEW},
    'support': {PERM_VIEW, PERM_CONTROL, PERM_CLIPBOARD},
    'operator': {PERM_VIEW, PERM_CONTROL, PERM_CLIPBOARD, PERM_FILE_TRANSFER, PERM_TERMINAL},
    'administrator': ALL_PERMISSIONS,
}


class EphemeralSession:
    """A time-limited, optionally single-use access session."""

    def __init__(
        self,
        token: str,
        role: str = 'viewer',
        permissions: Optional[set] = None,
        expires_at: float = 0,
        single_use: bool = False,
        view_only: bool = False,
        no_terminal: bool = False,
        allowed_ip: Optional[str] = None,
        created_by: str = 'admin',
    ):
        self.token = token
        self.role = role
        self.permissions = permissions or ROLES.get(role, {PERM_VIEW})
        self.expires_at = expires_at
        self.single_use = single_use
        self.view_only = view_only
        self.no_terminal = no_terminal
        self.allowed_ip = allowed_ip
        self.created_by = created_by
        self.created_at = time.time()
        self.used = False
        self.revoked = False

    def is_valid(self, client_ip: Optional[str] = None) -> bool:
        """Check if this session is still valid."""
        if self.revoked:
            return False
        if self.single_use and self.used:
            return False
        if time.time() > self.expires_at:
            return False
        if self.allowed_ip and client_ip and client_ip != self.allowed_ip:
            return False
        return True

    def has_permission(self, perm: str) -> bool:
        """Check if this session grants a specific permission."""
        if self.view_only and perm in (PERM_CONTROL, PERM_CLIPBOARD, PERM_FILE_TRANSFER):
            return False
        if self.no_terminal and perm == PERM_TERMINAL:
            return False
        return perm in self.permissions

    def mark_used(self):
        """Mark this session as used (for single-use sessions)."""
        self.used = True

    def revoke(self):
        """Revoke this session immediately."""
        self.revoked = True

    def to_dict(self) -> dict:
        """Serialize to dict (for logging/API, no secrets)."""
        return {
            'role': self.role,
            'permissions': sorted(self.permissions),
            'expires_at': self.expires_at,
            'single_use': self.single_use,
            'view_only': self.view_only,
            'no_terminal': self.no_terminal,
            'allowed_ip': self.allowed_ip,
            'created_by': self.created_by,
            'created_at': self.created_at,
            'used': self.used,
            'revoked': self.revoked,
        }


def _get_signing_secret() -> bytes:
    """Return the signing secret for ephemeral tokens."""
    from vnc_remote_secure.security.authentication import _get_secret
    return _get_secret()


def create_ephemeral_token(session: EphemeralSession) -> str:
    """Create a signed token for an ephemeral session.

    Format: <payload>.<signature>
    payload: hex(session_token:expires_at:single_use)
    """
    payload = f"{session.token}:{session.expires_at}:{int(session.single_use)}"
    secret = _get_signing_secret()
    sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_ephemeral_token(token: str) -> Optional[dict]:
    """Verify an ephemeral token signature.

    Returns the parsed payload if valid, None otherwise.
    Does NOT check expiry or usage — caller must do that via
    the session store.
    """
    if not token or '.' not in token:
        return None
    payload, sig = token.rsplit('.', 1)
    secret = _get_signing_secret()
    expected_sig = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    parts = payload.split(':')
    if len(parts) != 3:
        return None
    try:
        return {
            'session_token': parts[0],
            'expires_at': float(parts[1]),
            'single_use': bool(int(parts[2])),
        }
    except (ValueError, TypeError):
        return None


class SessionStore:
    """In-memory store for ephemeral sessions.

    For production use, this should be backed by Redis or a database
    to survive restarts and share state across processes.
    """

    def __init__(self):
        self._sessions: dict = {}  # token -> EphemeralSession
        self._cleanup_interval = 300  # 5 min

    def create(
        self,
        expires_in: int = 1800,
        role: str = 'viewer',
        single_use: bool = False,
        view_only: bool = False,
        no_terminal: bool = False,
        allowed_ip: Optional[str] = None,
        created_by: str = 'admin',
    ) -> tuple:
        """Create a new ephemeral session.

        Returns:
            Tuple of (EphemeralSession, signed_token_string).
        """
        token = secrets.token_urlsafe(32)
        session = EphemeralSession(
            token=token,
            role=role,
            expires_at=time.time() + expires_in,
            single_use=single_use,
            view_only=view_only,
            no_terminal=no_terminal,
            allowed_ip=allowed_ip,
            created_by=created_by,
        )
        self._sessions[token] = session
        signed = create_ephemeral_token(session)
        return session, signed

    def get(self, token: str) -> Optional[EphemeralSession]:
        """Retrieve a session by its token."""
        return self._sessions.get(token)

    def validate(self, signed_token: str, client_ip: Optional[str] = None) -> Optional[EphemeralSession]:
        """Validate a signed token and return the session if valid."""
        payload = verify_ephemeral_token(signed_token)
        if not payload:
            return None
        session = self.get(payload['session_token'])
        if not session:
            return None
        if not session.is_valid(client_ip):
            return None
        return session

    def revoke(self, token: str) -> bool:
        """Revoke a session by token."""
        session = self._sessions.get(token)
        if session:
            session.revoke()
            return True
        return False

    def list_active(self) -> list:
        """List all active (non-expired, non-revoked) sessions."""
        now = time.time()
        return [
            s.to_dict() for s in self._sessions.values()
            if not s.revoked and now < s.expires_at
        ]

    def cleanup(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [t for t, s in self._sessions.items() if now >= s.expires_at]
        for t in expired:
            del self._sessions[t]


# Global session store
_store: Optional[SessionStore] = None


def get_session_store() -> SessionStore:
    """Return the global ephemeral session store."""
    global _store
    if _store is None:
        _store = SessionStore()
    return _store


# ---------------------------------------------------------------------------
# Convenience functions for per-action authorization and live revocation
# ---------------------------------------------------------------------------

def check_permission(signed_token: str, permission: str) -> bool:
    """Check if a signed token's session has the given permission.

    This is the per-action authorization check. It verifies:
    - Token signature is valid
    - Session exists and is not revoked/expired
    - Role includes the requested permission
    - view_only and no_terminal restrictions are enforced
    """
    store = get_session_store()
    session = store.validate(signed_token)
    if not session:
        return False
    return session.has_permission(permission)


def is_session_revoked(signed_token: str) -> bool:
    """Check if a session has been revoked (live revocation check)."""
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return True  # Invalid token = treat as revoked
    store = get_session_store()
    session = store.get(payload['session_token'])
    if not session:
        return True  # Session doesn't exist = revoked
    return session.revoked


def is_session_expired(signed_token: str) -> bool:
    """Check if a session has expired."""
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return True
    store = get_session_store()
    session = store.get(payload['session_token'])
    if not session:
        return True
    return time.time() >= session.expires_at


def revoke_session(signed_token: str) -> bool:
    """Revoke a session by its signed token.

    This propagates immediately: any subsequent check_permission,
    is_session_revoked, or check_websocket_upgrade call will reject
    the token.
    """
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return False
    store = get_session_store()
    return store.revoke(payload['session_token'])
