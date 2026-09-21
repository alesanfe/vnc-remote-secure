"""Ephemeral remote sessions for VNC Remote Secure.

Provides shareable, time-limited access sessions with granular
permissions. Useful for temporary support, demos, or granting
view-only access without sharing permanent credentials.

Usage:
    vnc-remote session create --expires 30m --view-only --no-terminal --single-use

The command returns a URL with an ephemeral token that grants
access according to the specified permissions.

Token signing is delegated to ``security.token_signing`` so that
ephemeral tokens and persistent session cookies share a single
signing mechanism while remaining type-separated.
"""
import logging
import secrets
import threading
import time
from typing import Optional

from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_EPHEMERAL,
    sign_token,
    verify_token,
)

logger = logging.getLogger(__name__)

# Server instance identifier (unique per process).
_INSTANCE_ID = None


def _get_instance_id() -> str:
    """Return the deployment-wide instance identifier.

    The id is generated once and persisted to ``<run_dir>/instance.id``
    so every process of this deployment (CLI, services) shares it —
    the docstring-level claim that it binds tokens to the issuing
    deployment only holds if validation can compare against the same
    value everywhere. A purely per-process id would make CLI-created
    share links invalid in the long-running services.
    """
    global _INSTANCE_ID
    if _INSTANCE_ID is not None:
        return _INSTANCE_ID
    import os
    try:
        from vnc_remote_secure.core.paths import get_run_dir
        path = os.path.join(get_run_dir(), 'instance.id')
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                saved = f.read().strip()
            if saved:
                _INSTANCE_ID = saved
                return _INSTANCE_ID
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _INSTANCE_ID = f'srv_{secrets.token_hex(4)}'
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(path), suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(_INSTANCE_ID)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            from vnc_remote_secure.security.certificates import (
                _restrict_key_permissions,
            )
            _restrict_key_permissions(path, writable=True)
        except Exception:  # noqa: BLE001 - ACL hardening is best-effort
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except Exception:  # noqa: BLE001 - fall back to process-local id
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
        # IP binding is fail-closed: a missing client_ip must not
        # silently skip an operator-configured restriction.
        if self.allowed_ip and client_ip != self.allowed_ip:
            return False
        # Resource binding restricts WHERE a permission may be used —
        # enforced only when the caller names a resource (action-level
        # checks without resource context assert the permission exists;
        # see TestResourceBinding contract).
        if self.resource and resource and resource != self.resource:
            return False
        # Deployment binding: a token issued by a different deployment
        # (different persisted instance.id) must not authenticate here.
        if self.instance_id and self.instance_id != _get_instance_id():
            return False
        return True

    def has_permission(self, perm: str, resource: Optional[str] = None) -> bool:
        """Check if this session grants a specific permission.

        Args:
            perm: Permission to check (e.g. 'view', 'control', 'terminal',
                or 'terminal:use', 'desktop:view', 'desktop:control').
                The ``resource:action`` form is normalized to the
                canonical permission name.
            resource: Resource being accessed (for resource binding).
        """
        # Normalize 'resource:action' to canonical permission names.
        # e.g. 'terminal:use' -> 'terminal', 'desktop:view' -> 'view',
        # 'desktop:control' -> 'control'.
        if ':' in perm:
            res, action = perm.split(':', 1)
            perm = action if action in ALL_PERMISSIONS else res
        # Resource binding: if token has a resource, it must match —
        # enforced only when the caller names the resource.
        if self.resource and resource and resource != self.resource:
            return False
        # view_only also blocks the terminal: a shell is full control,
        # so a "view-only" session that can open one is not view-only.
        # (Documented in docs/user-guide/sessions.md.)
        if self.view_only and perm in (PERM_CONTROL, PERM_CLIPBOARD,
                                       PERM_FILE_TRANSFER, PERM_TERMINAL):
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
        import hashlib
        return {
            # Public identifier: sha256 of the internal token. Lets an
            # operator reference a session (revoke by id) without the
            # token itself appearing in list output.
            'token_id': hashlib.sha256(self.token.encode()).hexdigest()[:12],
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

    def to_persist_dict(self) -> dict:
        """Serialize to dict for persistence (includes token)."""
        d = self.to_dict()
        d['token'] = self.token
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'EphemeralSession':
        """Deserialize from dict (for persistence)."""
        session = cls(
            token=data['token'],
            role=data.get('role', 'viewer'),
            permissions=set(data.get('permissions', [])),
            expires_at=float(data.get('expires_at', 0)),
            single_use=bool(data.get('single_use', False)),
            view_only=bool(data.get('view_only', False)),
            no_terminal=bool(data.get('no_terminal', False)),
            allowed_ip=data.get('allowed_ip'),
            created_by=data.get('created_by', 'admin'),
            resource=data.get('resource'),
            instance_id=data.get('instance_id'),
            max_uses=int(data.get('max_uses', 0)),
        )
        session.created_at = float(data.get('created_at', time.time()))
        session.used = bool(data.get('used', False))
        session.revoked = bool(data.get('revoked', False))
        session.use_count = int(data.get('use_count', 0))
        return session


def create_ephemeral_token(session: EphemeralSession) -> str:
    """Create a signed token for an ephemeral session.

    Format: <type>:<payload>.<signature>
    payload: session_token:expires_at:single_use
    """
    payload = f"{session.token}:{session.expires_at}:{int(session.single_use)}"
    return sign_token(TOKEN_TYPE_EPHEMERAL, payload)


def verify_ephemeral_token(token: str) -> Optional[dict]:
    """Verify an ephemeral token signature.

    Returns the parsed payload if valid, None otherwise.
    Does NOT check expiry or usage — caller must do that via
    the session store.
    """
    payload = verify_token(TOKEN_TYPE_EPHEMERAL, token)
    if payload is None:
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
    """Persistent store for ephemeral sessions.

    Sessions are persisted to a JSON file in the runtime directory so
    they survive across CLI invocations and process restarts. The
    in-memory dict is the primary store; the file is a mirror that is
    loaded on startup and written on every mutation.
    """

    def __init__(self):
        self._sessions: dict = {}  # token -> EphemeralSession
        self._cleanup_interval = 300  # 5 min
        self._lock = threading.Lock()
        self._last_mtime: float = 0.0
        self._load()

    def _persist_path(self) -> str:
        """Return the path to the persistence file."""
        import os

        from vnc_remote_secure.core.paths import get_run_dir
        return os.path.join(get_run_dir(), 'ephemeral_sessions.json')

    def _load(self):
        """Load sessions from disk into memory."""
        import json
        import os
        path = self._persist_path()
        if not os.path.exists(path):
            self._last_mtime = 0.0
            return
        try:
            self._last_mtime = os.path.getmtime(path)
        except OSError:
            pass
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                for token, sdata in data.items():
                    try:
                        self._sessions[token] = EphemeralSession.from_dict(sdata)
                    except (KeyError, ValueError, TypeError) as exc:
                        # Redact the token in logs; it is a secret.
                        import hashlib
                        token_hash = hashlib.sha256(token.encode()).hexdigest()[:12]
                        logger.warning("Skipping corrupt session %s: %s", token_hash, exc)
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load ephemeral sessions: %s", exc)

    def _load_if_changed(self):
        """Reload from disk only when another process rewrote the file.

        ``get()`` used to reload only on cache MISS, so a session
        revoked by a different process (``vnc-remote session revoke``)
        stayed valid in this process's cache until restart — cross-
        process revocation silently failed for already-cached tokens.
        An mtime compare keeps the per-request cost near zero.
        """
        import os
        try:
            mtime = os.path.getmtime(self._persist_path())
        except OSError:
            return
        if mtime != self._last_mtime:
            self._load()

    def _save(self, raise_on_error: bool = False):
        """Persist sessions to disk.

        Merges the on-disk state first: another process may have
        mutated the file since our last load (e.g. ``session revoke``
        marks ``revoked``/``used`` via the CLI). Writing our stale
        in-memory copy would resurrect the revocation — terminal flags
        from disk always win.

        ``raise_on_error=True`` makes persistence failure fatal —
        ``create()`` uses it because returning a signed token that was
        never persisted hands the operator a dead share link.
        """
        import json
        import os
        path = self._persist_path()
        try:
            # Pull terminal flags (revoked, used, use_count) from the
            # disk copy into our in-memory sessions before serialising.
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        disk = json.load(f)
                    if isinstance(disk, dict):
                        now = time.time()
                        for token, sdata in disk.items():
                            session = self._sessions.get(token)
                            if session is None:
                                # A session created by another process
                                # since our last load — preserve it or
                                # our write would delete it (expired
                                # entries stay droppable for cleanup).
                                try:
                                    other = EphemeralSession.from_dict(sdata)
                                except (KeyError, ValueError, TypeError):
                                    continue
                                if not other.revoked and \
                                        other.expires_at > now:
                                    self._sessions[token] = other
                                continue
                            if sdata.get('revoked'):
                                session.revoked = True
                            if sdata.get('used'):
                                session.used = True
                            session.use_count = max(
                                session.use_count,
                                int(sdata.get('use_count', 0) or 0))
                except (OSError, ValueError):
                    pass  # corrupt file — keep in-memory state
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                token: session.to_persist_dict()
                for token, session in self._sessions.items()
            }
            # Atomic write: a crash mid-write would corrupt the file
            # and drop every active share session on the next load.
            import tempfile
            fd, tmp = tempfile.mkstemp(
                dir=os.path.dirname(path) or '.', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            try:
                self._last_mtime = os.path.getmtime(path)
            except OSError:
                pass
            # The file contains live session tokens — anyone who can
            # read it can hijack every active share session. Restrict
            # to owner-only (os.chmod alone is a no-op on Windows).
            try:
                from vnc_remote_secure.security.certificates import _restrict_key_permissions
                _restrict_key_permissions(path, writable=True)
            except Exception:  # noqa: BLE001
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
        except OSError as exc:
            if raise_on_error:
                raise RuntimeError(
                    f"Failed to persist ephemeral sessions: {exc}") from exc
            logger.error(
                "Failed to persist ephemeral sessions: %s — state "
                "changes (revocation, use counts) will not survive "
                "this process", exc)

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
        self._save(raise_on_error=True)
        try:
            from vnc_remote_secure.security.audit import audit_log
            audit_log('ephemeral_session_create', user=created_by,
                      detail=f'role={role} expires_in={expires_in} '
                             f'single_use={single_use} '
                             f'max_uses={session.max_uses} '
                             f'resource={resource or "*"}')
        except Exception:  # noqa: BLE001 - audit must not break sessions
            pass
        return session, signed

    def get(self, token: str) -> Optional[EphemeralSession]:
        """Retrieve a session by its token.

        On a cache miss the persistence file is reloaded: sessions
        created by other processes (e.g. ``vnc-remote session create``)
        after this process started must be discoverable.
        """
        session = self._sessions.get(token)
        if session is None:
            self._load()
            session = self._sessions.get(token)
        return session

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
        """Revoke a session by token.

        Accepts either the internal session token or the signed token
        string returned to users.
        """
        # If this looks like a signed token, extract the internal token.
        internal = token
        if '.' in token:
            payload = verify_ephemeral_token(token)
            if payload:
                internal = payload['session_token']
        session = self.get(internal)
        if session:
            session.revoke()
            self._save()
            try:
                from vnc_remote_secure.security.audit import audit_log
                audit_log('ephemeral_session_revoke',
                          detail=f'role={session.role}')
            except Exception:  # noqa: BLE001
                pass
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
        if expired:
            self._save()


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
                     resource: Optional[str] = None,
                     client_ip: Optional[str] = None) -> bool:
    """Check if a signed token's session has the given permission.

    This is the per-action authorization check. It verifies:
    - Token signature is valid
    - Session exists and is not revoked/expired
    - Role includes the requested permission
    - view_only and no_terminal restrictions are enforced
    - Resource binding: if token has a resource, it must match

    If the session is not in the in-memory store, the store is reloaded
    from disk so sessions created by other processes (e.g. the CLI) are
    recognized.
    """
    store = get_session_store()
    # Always reload from disk so revocations and new sessions from other
    # processes (e.g. the CLI) are visible to long-running service processes.
    store._load_if_changed()
    session = store.validate(
        signed_token, client_ip=client_ip, resource=resource)
    if not session:
        return False
    permitted = session.has_permission(permission, resource)
    # Consume single-use tokens atomically after a successful check to
    # prevent replay (INC-208). Multi-use tokens are unaffected.
    if permitted and session.single_use:
        consume_ephemeral_session(signed_token)
    return permitted


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
        view_only: If True, restricts to view-only access — control
            channels requiring ``desktop:control`` are rejected, and
            the noVNC WebSocket relay filters RFB input messages
            (KeyEvent/PointerEvent/ClientCutText) at the protocol
            layer via ``services/rfb_filter.py``.
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
    except (OSError, ValueError, RuntimeError) as exc:
        logger.warning("Failed to create ephemeral session: %s", exc)
        return None


def is_session_revoked(signed_token: str) -> bool:
    """Check if a session has been revoked (live revocation check).

    Reloads the persistence file so revocations issued by other
    processes (e.g. ``vnc-remote session revoke``) are honored by
    long-running service processes.
    """
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return True  # Invalid token = treat as revoked
    store = get_session_store()
    store._load_if_changed()
    session = store.get(payload['session_token'])
    if not session:
        return True  # Session doesn't exist = revoked
    return session.revoked


def is_session_expired(signed_token: str) -> bool:
    """Check if a session has expired (disk-fresh, cross-process)."""
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return True
    store = get_session_store()
    store._load_if_changed()
    session = store.get(payload['session_token'])
    if not session:
        return True
    return time.time() >= session.expires_at


def revoke_session(signed_token: str) -> bool:
    """Revoke a session by its signed token.

    Accepts the signed share-link token, the raw internal session token
    (e.g. the ``vnc_ephemeral`` cookie value), or the public
    ``token_id`` fingerprint shown by ``vnc-remote session list`` —
    without an id the operator cannot revoke a session whose token was
    lost.

    This propagates immediately: any subsequent check_permission,
    is_session_revoked, or check_websocket_upgrade call will reject
    the token. Additionally, all active WebSocket connections for this
    session are forcibly closed via the WebSocket registry.
    """
    store = get_session_store()
    payload = verify_ephemeral_token(signed_token)
    token = payload['session_token'] if payload else signed_token
    if not store.get(token):
        # Fingerprint form: resolve the public token_id (sha256 prefix
        # of the internal token) to the real token before revoking.
        import hashlib
        store._load_if_changed()
        for real_token, session in store._sessions.items():
            if (hashlib.sha256(real_token.encode()).hexdigest()[:12]
                    == signed_token.strip()):
                token = real_token
                break
    result = store.revoke(token)

    # Close all active WebSocket connections for this session.
    try:
        from vnc_remote_secure.security.websocket_registry import revoke_session_connections
        revoke_session_connections(token)
    except (ImportError, KeyError, RuntimeError) as exc:
        logger.debug("WebSocket registry unavailable during revoke: %s", exc)

    return result


def _claim_consumed(token: str, expires_at: float) -> bool:
    """Atomically claim a single-use session token across processes.

    Uses the shared-state backend's atomic test-and-set so only one
    process can win the claim for a given token. On backend failure
    the claim reports success — the per-process lock and persisted
    ``used``/``revoked`` flags remain as the best-effort fallback
    rather than making every share link unusable when the backend is
    down.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        ttl = max(60.0, expires_at - time.time())
        return bool(get_backend().set_if_absent(
            'ephemeral_consumed', token, True, ttl))
    except Exception:  # noqa: BLE001 - best-effort fallback
        logger.warning("Could not record ephemeral session consumption")
        return True


def _claim_use(token: str, max_uses: int, expires_at: float) -> bool:
    """Atomically claim one activation of a multi-use token.

    Uses the shared-state backend's atomic ``increment`` so two
    processes cannot both claim the same use. Returns ``True`` when
    the claim is within budget, ``False`` when the counter exceeded
    ``max_uses`` (the increment is retained — the claim is consumed
    either way, which is correct because the caller then rejects).

    On backend failure the claim reports success: the per-process
    ``use_count`` remains as the best-effort fallback rather than
    making every share link unusable when the backend is down.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        ttl = max(60.0, expires_at - time.time())
        new_count = get_backend().increment(
            'ephemeral_uses', token, 1, ttl_seconds=ttl)
        return new_count is not None and int(new_count) <= max_uses
    except Exception:  # noqa: BLE001 - best-effort fallback
        logger.warning("Could not record multi-use claim")
        return True


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
        if session.instance_id and session.instance_id != _get_instance_id():
            return False
        if session.single_use:
            # Cross-process single-use claim: store._lock only
            # serialises threads in THIS process — two services could
            # both pass the revoked check before either persists.
            # The shared-state claim is a single atomic insert.
            if not _claim_consumed(token, session.expires_at):
                return False
            session.revoke()
            store._save()
            return True  # Return inside lock to prevent race.
        else:
            return True  # Multi-use: valid, return inside lock.


def activate_ephemeral_session(signed_token: str,
                               client_ip: Optional[str] = None) -> Optional[str]:
    """Exchange a share-link token for its internal session token.

    This is the entry point of the browser flow: the landing page hands
    ``/?session=<signed_token>`` here once. Unlike
    ``consume_ephemeral_session`` (which revokes single-use tokens for
    direct bearer use), activation marks the session used *without*
    revoking it — the link is burned, but the activated session keeps
    working until its TTL expires. The caller then issues the returned
    internal token as a cookie so subsequent requests authenticate
    against the session object (preserving role, view_only,
    no_terminal, resource binding and allowed_ip).

    For multi-use tokens the link is NOT burned: each use increments
    ``use_count`` and the link keeps working until ``max_uses`` or the
    TTL is reached.

    Returns:
        The internal session token to store in the client cookie, or
        ``None`` when the link is invalid, expired, revoked, or its
        use budget is exhausted.
    """
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return None
    store = get_session_store()
    store._load_if_changed()
    token = payload['session_token']

    with store._lock:
        session = store.get(token)
        if not session:
            return None
        if session.revoked:
            return None
        if time.time() >= session.expires_at:
            return None
        if session.single_use and session.used:
            return None
        if session.max_uses > 0 and session.use_count >= session.max_uses:
            return None
        # Deployment binding: a share link issued by a different
        # deployment (foreign instance.id) must not activate here.
        if session.instance_id and session.instance_id != _get_instance_id():
            return None
        # IP binding at activation too — without it a link bound to a
        # client IP could still be *burned* by a different caller
        # (single-use DoS on the intended recipient), even though the
        # per-request check would later reject the attacker.
        # client_ip=None means "no caller context" (CLI/API paths) —
        # allowed, the per-request check still enforces the binding.
        # An empty STRING means a request resolved to no IP (suspicious,
        # e.g. malformed XFF) — denied.
        if session.allowed_ip and client_ip is not None and \
                session.allowed_ip != client_ip:
            return None
        if session.single_use:
            # Cross-process single-use claim (see
            # consume_ephemeral_session): the in-process lock cannot
            # stop two services activating the same link at once.
            if not _claim_consumed(token, session.expires_at):
                return None
        elif session.max_uses > 0:
            # Multi-use: the local read-modify-write of use_count races
            # across processes — claim one use via the shared-state
            # atomic increment and reject when the budget is exhausted.
            if not _claim_use(token, session.max_uses, session.expires_at):
                return None
        session.mark_used()
        store._save()
        try:
            from vnc_remote_secure.security.audit import audit_log
            audit_log('ephemeral_session_activate',
                      detail=f'role={session.role}')
        except Exception:  # noqa: BLE001
            pass
        return token


def check_session_permission(
    internal_token: str,
    permission: str,
    resource: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> bool:
    """Check a permission on an *activated* session by internal token.

    Used by services when the client presents the ``vnc_ephemeral``
    cookie issued by :func:`activate_ephemeral_session`. Validates the
    session's revocation/expiry/IP/resource binding and permission —
    but NOT the ``used``/``max_uses`` budget, which gates the share
    link itself, not the activated session's requests.
    """
    store = get_session_store()
    store._load_if_changed()
    session = store.get(internal_token)
    if not session:
        return False
    if session.revoked:
        return False
    if time.time() >= session.expires_at:
        return False
    # IP binding is fail-closed: a missing/unknown client_ip must not
    # silently skip an operator-configured restriction.
    if session.allowed_ip and client_ip != session.allowed_ip:
        return False
    if session.resource and resource and resource != session.resource:
        return False
    # Deployment binding must apply on this path too — the internal
    # token path duplicates is_valid()'s checks manually, so a foreign
    # deployment's activated token would otherwise slip through.
    if session.instance_id and session.instance_id != _get_instance_id():
        return False
    return session.has_permission(permission, resource)
