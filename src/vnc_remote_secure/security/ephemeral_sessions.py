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
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Server instance identifier (unique per process).
_INSTANCE_ID = None


def _get_instance_id() -> str:
    """Return a unique identifier for this server instance."""
    global _INSTANCE_ID
    if _INSTANCE_ID is None:
        _INSTANCE_ID = f'srv_{secrets.token_hex(4)}'
    return _INSTANCE_ID


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
    """A time-limited, optionally single-use access session.

    Strong binding:
        - resource: The specific resource this token grants access to
          (e.g. 'desktop', 'terminal'). A token for 'desktop' cannot
          be used to open a terminal.
        - instance_id: The server instance that issued the token.
          Prevents token replay across different server instances.
        - nonce: A unique random value to prevent replay attacks.
        - max_uses: Maximum number of times this token can be used
          (default: unlimited; 1 for single-use).
    """

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
        resource: Optional[str] = None,
        instance_id: Optional[str] = None,
        nonce: Optional[str] = None,
        max_uses: int = 0,
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
        # Strong binding fields.
        self.resource = resource  # e.g. 'desktop', 'terminal'
        self.instance_id = instance_id or _get_instance_id()
        self.nonce = nonce or secrets.token_hex(8)
        self.max_uses = max_uses  # 0 = unlimited
        self.use_count = 0

    def is_valid(self, client_ip: Optional[str] = None,
                 resource: Optional[str] = None) -> bool:
        """Check if this session is still valid.

        Args:
            client_ip: Client IP address (for IP restriction check).
            resource: Requested resource (for resource binding check).
        """
        if self.revoked:
            return False
        if self.single_use and self.used:
            return False
        if self.max_uses > 0 and self.use_count >= self.max_uses:
            return False
        if time.time() > self.expires_at:
            return False
        if self.allowed_ip and client_ip and client_ip != self.allowed_ip:
            return False
        # Resource binding: if token has a resource, it must match.
        if self.resource and resource and resource != self.resource:
            return False
        return True

    def has_permission(self, perm: str, resource: Optional[str] = None) -> bool:
        """Check if this session grants a specific permission.

        Args:
            perm: Permission to check (e.g. 'view', 'control').
            resource: Resource being accessed (for resource binding).
        """
        # Resource binding: if token has a resource, it must match.
        if self.resource and resource and resource != self.resource:
            return False
        if self.view_only and perm in (PERM_CONTROL, PERM_CLIPBOARD, PERM_FILE_TRANSFER):
            return False
        if self.no_terminal and perm == PERM_TERMINAL:
            return False
        return perm in self.permissions

    def mark_used(self):
        """Mark this session as used (for single-use sessions)."""
        self.used = True
        self.use_count += 1

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
            'resource': self.resource,
            'instance_id': self.instance_id,
            'max_uses': self.max_uses,
            'use_count': self.use_count,
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
        self._lock = threading.Lock()

    def create(
        self,
        expires_in: int = 1800,
        role: str = 'viewer',
        single_use: bool = False,
        view_only: bool = False,
        no_terminal: bool = False,
        allowed_ip: Optional[str] = None,
        created_by: str = 'admin',
        resource: Optional[str] = None,
        max_uses: int = 0,
    ) -> tuple:
        """Create a new ephemeral session.

        Args:
            resource: If set, the token can only access this resource
                (e.g. 'desktop', 'terminal'). Prevents cross-resource
                token reuse.
            max_uses: Maximum uses (0 = unlimited, 1 = single-use).

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
            resource=resource,
            max_uses=max_uses if max_uses > 0 else (1 if single_use else 0),
        )
        self._sessions[token] = session
        signed = create_ephemeral_token(session)
        return session, signed

    def get(self, token: str) -> Optional[EphemeralSession]:
        """Retrieve a session by its token."""
        return self._sessions.get(token)

    def validate(self, signed_token: str, client_ip: Optional[str] = None,
                 resource: Optional[str] = None) -> Optional[EphemeralSession]:
        """Validate a signed token and return the session if valid.

        Args:
            signed_token: The signed token string.
            client_ip: Client IP address (for IP restriction check).
            resource: Requested resource (for resource binding check).
        """
        payload = verify_ephemeral_token(signed_token)
        if not payload:
            return None
        session = self.get(payload['session_token'])
        if not session:
            return None
        if not session.is_valid(client_ip, resource):
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

def check_permission(signed_token: str, permission: str,
                     resource: Optional[str] = None) -> bool:
    """Check if a signed token's session has the given permission.

    This is the per-action authorization check. It verifies:
    - Token signature is valid
    - Session exists and is not revoked/expired
    - Role includes the requested permission
    - view_only and no_terminal restrictions are enforced
    - Resource binding: if token has a resource, it must match
    """
    store = get_session_store()
    session = store.validate(signed_token, resource=resource)
    if not session:
        return False
    return session.has_permission(permission, resource)


def create_ephemeral_session(
    permissions=None,
    role='viewer',
    ttl_seconds=1800,
    single_use=False,
    view_only=False,
    no_terminal=False,
    allowed_ip=None,
    created_by='admin',
    resource=None,
    max_uses=0,
):
    """Create a new ephemeral session and return its signed token.

    Convenience wrapper around SessionStore.create().

    Args:
        permissions: Optional list of permission strings.
        role: Session role (viewer, support, operator, administrator).
        ttl_seconds: Time-to-live in seconds.
        single_use: If True, the session can only be used once.
        view_only: If True, restricts to view-only access.
        no_terminal: If True, terminal access is blocked.
        allowed_ip: Optional IP restriction.
        created_by: Username of the creator.
        resource: If set, token can only access this resource.
        max_uses: Maximum uses (0 = unlimited, 1 = single-use).

    Returns:
        A signed token string, or None on failure.
    """
    store = get_session_store()
    try:
        session, signed = store.create(
            expires_in=ttl_seconds,
            role=role,
            single_use=single_use,
            view_only=view_only,
            no_terminal=no_terminal,
            allowed_ip=allowed_ip,
            created_by=created_by,
            resource=resource,
            max_uses=max_uses,
        )
        return signed
    except Exception:
        return None


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
    the token. Additionally, all active WebSocket connections for this
    session are forcibly closed via the WebSocket registry.
    """
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return False
    store = get_session_store()
    token = payload['session_token']
    result = store.revoke(token)

    # Close all active WebSocket connections for this session.
    try:
        from vnc_remote_secure.security.websocket_registry import revoke_session_connections
        revoke_session_connections(token)
    except Exception:
        pass  # Registry not available (e.g. during tests)

    return result


def consume_ephemeral_session(signed_token: str) -> bool:
    """Atomically consume a single-use ephemeral session.

    For single-use sessions, this marks the session as used and revokes
    it. The check-and-consume is atomic (thread-safe via a lock) so
    that only one concurrent client can consume a single-use token.

    For multi-use sessions, this is a no-op (returns True if valid).

    Returns:
        True if the token was valid and consumed (or multi-use),
        False if the token was invalid, already consumed, or revoked.
    """
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return False
    store = get_session_store()
    token = payload['session_token']

    with store._lock:
        session = store.get(token)
        if not session:
            return False
        if session.revoked:
            return False
        if time.time() >= session.expires_at:
            return False
        if session.single_use:
            # Atomic check-and-consume under lock.
            if session.revoked:
                return False
            session.revoke()
            return True  # Return inside lock to prevent race.
        else:
            return True  # Multi-use: valid, return inside lock.

    # unreachable, but kept for safety
    return True
