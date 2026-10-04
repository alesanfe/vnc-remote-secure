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

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.security.ephemeral_model import (  # noqa: F401
    _LINK_DENIAL_CHECKS,
    _PERMISSION_EXPANSION,
    _REQUEST_DENIAL_CHECKS,
    _SESSION_VALIDITY_CHECKS,
    ALL_PERMISSIONS,
    PERM_ADMIN,
    PERM_ADMIN_AUDIT,
    PERM_ADMIN_CONFIG,
    PERM_ADMIN_USERS,
    PERM_AUDIO,
    PERM_CLIPBOARD,
    PERM_CLIPBOARD_READ,
    PERM_CLIPBOARD_WRITE,
    PERM_CONTROL,
    PERM_FILE_TRANSFER,
    PERM_GAMEPAD,
    PERM_KEYBOARD,
    PERM_POINTER,
    PERM_TERMINAL,
    PERM_TERMINAL_VIEW,
    PERM_TERMINAL_WRITE,
    PERM_VIEW,
    ROLES,
    EphemeralSession,
    _denial_reason,
    _get_instance_id,
    _ip_matches,
    _session_expired,
    expand_permissions,
)
from vnc_remote_secure.security.token_signing import (
    TOKEN_TYPE_EPHEMERAL,
    sign_token,
    verify_token,
)

logger = logging.getLogger(__name__)


def create_ephemeral_token(session: EphemeralSession) -> str:
    """Create a signed token for an ephemeral session.

    Format: <type>:<payload>.<signature>
    payload: session_token:expires_at:single_use
    """
    payload = f"{session.token}:{session.expires_at}:{int(session.single_use)}"
    return sign_token(TOKEN_TYPE_EPHEMERAL, payload)


def verify_ephemeral_token(token: str) -> dict | None:
    """Verify an ephemeral token signature.

    Returns the parsed payload if valid, None otherwise.
    Does NOT check expiry or usage — caller must do that via
    the session store.
    """
    payload = verify_token(TOKEN_TYPE_EPHEMERAL, token)
    if payload is None:
        return None
    parts = payload.split(":")
    if len(parts) != 3:
        return None
    try:
        return {
            "session_token": parts[0],
            "expires_at": float(parts[1]),
            "single_use": bool(int(parts[2])),
        }
    except (ValueError, TypeError):
        return None


def preview_session(signed: str) -> dict | None:
    """Non-consuming preview of a share-link token.

    Returns what a recipient may see BEFORE accepting — role,
    expiry, coarse flags. Deliberately omits creator identity,
    bound IPs, hostnames and any infrastructure detail: the link
    grants access, not reconnaissance. Invalid/expired/revoked
    tokens all return None (uniform response, no enumeration).
    """
    import time as _time

    try:
        payload = verify_ephemeral_token(signed)
        if not payload:
            return None
        store = get_session_store()
        store._load_if_changed()
        session = store.get(payload["session_token"])
        if session is None or session.revoked:
            return None
        return {
            "role": session.role,
            "expires_in_seconds": max(0, int(session.expires_at - _time.time())),
            # El consentimiento lista lo que el enlace PUEDE hacer —
            # sin los permisos efectivos una invitación "viewer" sin
            # view_only mostraba control/terminal/archivos como
            # concedidos (los ticks solo miraban los flags).
            "permissions": sorted(session.permissions),
            "view_only": bool(session.view_only),
            "single_use": bool(session.single_use),
            "no_terminal": bool(session.no_terminal),
            "max_uses": session.max_uses,
            "resource": session.resource,
        }
    except Exception:  # noqa: BLE001 - preview is best-effort
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
        # RLock: module-level callers (consume/activate) already hold
        # it while calling get()/_save() — re-entrant so those paths
        # keep working while EVERY public mutator is now serialized
        # (previously only consume/activate locked; concurrent
        # create/revoke/list could interleave mid-_save).
        self._lock = threading.RLock()
        # (mtime_ns, size, ino) — a bare float mtime misses same-tick
        # writes on filesystems with coarse granularity.
        self._last_mtime: tuple = (0, 0, 0)
        self._load()

    def _persist_path(self) -> str:
        """Return the path to the persistence file."""

        from vnc_remote_secure.core.paths import get_run_dir

        return os.path.join(get_run_dir(), "ephemeral_sessions.json")

    def _file_sig(self, path: str) -> tuple:
        """Cheap change marker for the persistence file."""
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size, getattr(st, "st_ino", 0))

    def _load(self):
        """Load sessions from disk into memory."""
        import json

        path = self._persist_path()
        if not os.path.exists(path):
            self._last_mtime = (0, 0, 0)
            return
        with contextlib.suppress(OSError):
            self._last_mtime = self._file_sig(path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for token, sdata in data.items():
                    try:
                        self._sessions[token] = EphemeralSession.from_dict(sdata)
                    except (KeyError, ValueError, TypeError) as exc:
                        # Redact the token in logs; it is a secret.
                        # (digest, not the token — semgrep: the logged
                        # value is a 12-char sha256 prefix)
                        import hashlib

                        digest = hashlib.sha256(token.encode()).hexdigest()[:12]
                        # nosemgrep: no-secret-value-in-log (logs a truncated sha256 digest, not the token)
                        logger.warning("Skipping corrupt session %s: %s", digest, exc)
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
        try:
            sig = self._file_sig(self._persist_path())
        except OSError:
            return
        if sig != self._last_mtime:
            with self._lock:
                self._load()

    def _read_disk_sessions(self, path: str):
        """Return the on-disk session mapping for merging.

        ``None`` when the file is missing, unreadable or corrupt —
        a corrupt file is ignored: in-memory wins.
        """
        import json

        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                disk = json.load(f)
        except (OSError, ValueError):
            return None
        if not isinstance(disk, dict):
            return None
        return disk

    def _adopt_foreign_session(self, token: str, sdata, now: float) -> None:
        """Preserve a session another process created since our last
        load — writing our stale copy would delete it. Expired
        entries stay droppable for cleanup; live foreign sessions
        must survive our write."""
        try:
            other = EphemeralSession.from_dict(sdata)
        except (KeyError, ValueError, TypeError):
            return
        if not other.revoked and other.expires_at > now:
            self._sessions[token] = other

    def _merge_session_flags(self, session: EphemeralSession, sdata) -> None:
        """Merge terminal flags (revoked, used, use_count) and forensic
        fields from the on-disk record into the in-memory session —
        writing our stale copy would resurrect revocations."""
        if sdata.get("revoked"):
            session.revoked = True
        if sdata.get("used"):
            session.used = True
        session.use_count = max(session.use_count, int(sdata.get("use_count", 0) or 0))
        # Forensic fields: the freshest record wins so a use
        # observed by another process survives our save.
        other_used_at = sdata.get("last_used_at")
        if other_used_at and other_used_at > (session.last_used_at or 0):
            session.last_used_at = float(other_used_at)
            session.last_used_ip = sdata.get("last_used_ip")
        # Live-connection forensics merge the same way: freshest
        # stamp wins, counts take the max.
        for field in ("last_connected_at", "last_disconnected_at"):
            other_v = sdata.get(field)
            if other_v and other_v > (getattr(session, field) or 0):
                setattr(session, field, float(other_v))
        session.connection_count = max(
            session.connection_count, int(sdata.get("connection_count", 0) or 0)
        )

    def _merge_disk_flags(self, path: str) -> None:
        """Pull terminal flags (revoked, used, use_count) from the
        on-disk copy into our in-memory sessions, and preserve
        sessions another process created since our last load —
        writing our stale copy would resurrect revocations or delete
        foreign sessions. A corrupt file is ignored: in-memory wins."""
        disk = self._read_disk_sessions(path)
        if disk is None:
            return
        now = time.time()
        for token, sdata in disk.items():
            session = self._sessions.get(token)
            if session is None:
                self._adopt_foreign_session(token, sdata, now)
            else:
                self._merge_session_flags(session, sdata)

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
        with self._lock:
            self._save_inner(raise_on_error)

    def _save_inner(self, raise_on_error: bool = False):
        import json

        path = self._persist_path()
        try:
            self._merge_disk_flags(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {token: session.to_persist_dict() for token, session in self._sessions.items()}
            # Atomic write: a crash mid-write would corrupt the file
            # and drop every active share session on the next load.
            import tempfile

            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            with contextlib.suppress(OSError):
                self._last_mtime = self._file_sig(path)
            # The file contains live session tokens — anyone who can
            # read it can hijack every active share session. Restrict
            # to owner-only (os.chmod alone is a no-op on Windows).
            try:
                from vnc_remote_secure.security.certificates import _restrict_key_permissions

                _restrict_key_permissions(path, writable=True)
            except Exception:  # noqa: BLE001
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)
        except OSError as exc:
            if raise_on_error:
                raise RuntimeError(f"Failed to persist ephemeral sessions: {exc}") from exc
            logger.exception(
                "Failed to persist ephemeral sessions — state "
                "changes (revocation, use counts) will not survive "
                "this process"
            )

    def create(
        self,
        expires_in: int = 1800,
        role: str = "viewer",
        single_use: bool = False,
        view_only: bool = False,
        no_terminal: bool = False,
        allowed_ip: str | None = None,
        created_by: str = "admin",
        resource: str | None = None,
        max_uses: int = 0,
        permissions: set | None = None,
        label: str | None = None,
    ) -> tuple:
        """Create a new ephemeral session.

        Args:
            resource: If set, the token can only access this resource
                (e.g. 'desktop', 'terminal'). Prevents cross-resource
                token reuse.
            max_uses: Maximum uses (0 = unlimited, 1 = single-use).

        Returns:
            Tuple of (EphemeralSession, signed_token_string).

        Raises:
            ValueError: when ``EPHEMERAL_REQUIRE_RESOURCE=true`` and no
                resource binding was given — an unbound token reaches
                every resource its permissions allow, so hardened
                deployments can require the binding.
        """
        if not resource and env_flag("EPHEMERAL_REQUIRE_RESOURCE", ""):
            raise ValueError(
                "resource binding required: "
                "EPHEMERAL_REQUIRE_RESOURCE=true is set — pass "
                "--resource (desktop|terminal|audio|gamepad|files)"
            )
        token = secrets.token_urlsafe(32)
        session = EphemeralSession(
            token=token,
            role=role,
            permissions=permissions,
            expires_at=time.time() + expires_in,
            single_use=single_use,
            view_only=view_only,
            no_terminal=no_terminal,
            allowed_ip=allowed_ip,
            created_by=created_by,
            resource=resource,
            max_uses=max_uses if max_uses > 0 else (1 if single_use else 0),
            label=label,
        )
        with self._lock:
            self._sessions[token] = session
            signed = create_ephemeral_token(session)
            self._save(raise_on_error=True)
        from vnc_remote_secure.security.audit import audit_event

        audit_event(
            "ephemeral_session_create",
            user=created_by,
            detail=f"role={role} expires_in={expires_in} "
            f"single_use={single_use} "
            f"max_uses={session.max_uses} "
            f'resource={resource or "*"}',
        )
        _metric("created")
        return session, signed

    def get(self, token: str) -> EphemeralSession | None:
        """Retrieve a session by its token.

        On a cache miss the persistence file is reloaded: sessions
        created by other processes (e.g. ``vnc-remote session create``)
        after this process started must be discoverable.
        """
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                self._load()
                session = self._sessions.get(token)
            if session is not None and not session.revoked and _is_revoked_shared(token):
                # A cross-process revoke won the lost-update race
                # with a concurrent _save() — the JSON flag was
                # overwritten, but the shared marker survives. Honour
                # it locally so every downstream check (is_valid,
                # check_permission, ws upgrade) sees the session as
                # revoked.
                session.revoked = True
            return session

    def validate(
        self, signed_token: str, client_ip: str | None = None, resource: str | None = None
    ) -> EphemeralSession | None:
        """Validate a signed token and return the session if valid.

        Args:
            signed_token: The signed token string.
            client_ip: Client IP address (for IP restriction check).
            resource: Requested resource (for resource binding check).
        """
        payload = verify_ephemeral_token(signed_token)
        if not payload:
            return None
        with self._lock:
            session = self.get(payload["session_token"])
            if not session:
                return None
            if session.allowed_ip == "first-observed" and client_ip:
                # Pin the 'first-observed' marker on the bearer path
                # too — before this fix only activate() pinned it, so
                # a token used directly as Bearer (terminal/WS auth)
                # carried NO ip restriction at all.
                session.allowed_ip = client_ip
                self._save()
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
        if "." in token:
            payload = verify_ephemeral_token(token)
            if payload:
                internal = payload["session_token"]
        with self._lock:
            session = self.get(internal)
            if session:
                session.revoke()
                # Shared-state marker: a concurrent _save() in another
                # process can lose this JSON flag (merge-read then
                # os.replace is not atomic across processes), so the
                # revocation is ALSO recorded in the backend that
                # _claim_use already uses. get() consults it.
                _mark_revoked_shared(internal, session.expires_at)
                self._save()
                from vnc_remote_secure.security.audit import audit_event

                audit_event("ephemeral_session_revoke", detail=f"role={session.role}")
                return True
            return False

    def set_label(self, token: str, label: str | None) -> bool:
        """Set/replace the operator tag on a session by public id or
        internal token. Non-terminal metadata — unlike revoke() the
        write rides the normal save path; a concurrent process save
        may lose it, which is acceptable for an inventory tag."""
        with self._lock:
            session = self.find_by_token_id(token) or self.get(token)
            if session is None:
                return False
            session.label = label
            self._save()
        from vnc_remote_secure.security.audit import audit_event

        fp = hashlib.sha256(session.token.encode()).hexdigest()[:12]
        audit_event("session_label", detail=f"token_id={fp} label={label!r}")
        return True

    def list_active(self) -> list:
        """List all active (non-expired, non-revoked) sessions."""
        now = time.time()
        with self._lock:
            return [
                s.to_dict()
                for s in list(self._sessions.values())
                if not s.revoked and now < s.expires_at
            ]

    def list_revoked(self) -> list:
        """Revoked sessions still retained (until expiry/cleanup)."""
        now = time.time()
        with self._lock:
            return [
                s.to_dict()
                for s in list(self._sessions.values())
                if s.revoked and now < s.expires_at
            ]

    def list_all(self) -> list:
        """Every retained session: active, revoked, and expired records
        not yet reaped by ``cleanup()`` — the session-center history."""
        with self._lock:
            return [s.to_dict() for s in list(self._sessions.values())]

    def find_by_token_id(self, token_id: str):
        """Return the live session object for a public ``token_id``.

        The public id is ``sha256(internal_token)[:12]`` — callers
        holding only the fingerprint (the detail API, the WebSocket
        registry) resolve the internal token here without it ever
        leaving the store. Returns None for unknown/reaped ids.
        """
        with self._lock:
            self._load()
            for token, session in self._sessions.items():
                digest = hashlib.sha256(token.encode()).hexdigest()[:12]
                if hmac.compare_digest(digest, token_id):
                    return session
            return None

    def note_connection(self, internal_token: str, connected: bool = True):
        """Forensic hook called by the WebSocket registry on the
        last-connect / last-disconnect edges of a session's live
        sockets. Persists immediately — a disconnect that is only
        in-memory is invisible to the detail view of another process.
        """
        with self._lock:
            session = self._sessions.get(internal_token)
            if session is None:
                self._load()
                session = self._sessions.get(internal_token)
            if session is None:
                return
            if connected:
                session.note_connected()
            else:
                session.note_disconnected()
            self._save()

    def cleanup(self):
        """Remove expired sessions."""
        now = time.time()
        with self._lock:
            expired = [t for t, s in self._sessions.items() if now >= s.expires_at]
            for t in expired:
                del self._sessions[t]
            if expired:
                self._save()
                for _ in expired:
                    _metric("expired")


# Global session store
_store: SessionStore | None = None


def get_session_store() -> SessionStore:
    """Return the global ephemeral session store."""
    global _store
    if _store is None:
        _store = SessionStore()
    return _store


# ---------------------------------------------------------------------------
# Convenience functions for per-action authorization and live revocation
# ---------------------------------------------------------------------------


def check_permission(
    signed_token: str, permission: str, resource: str | None = None, client_ip: str | None = None
) -> bool:
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
    session = store.validate(signed_token, client_ip=client_ip, resource=resource)
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
    role="viewer",
    ttl_seconds=1800,
    single_use=False,
    view_only=False,
    no_terminal=False,
    allowed_ip=None,
    created_by="admin",
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
        _session, signed = store.create(
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
    session = store.get(payload["session_token"])
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
    session = store.get(payload["session_token"])
    if not session:
        return True
    return _session_expired(session)


def _metric(event: str) -> None:
    """Emit a session-lifecycle counter (best-effort).

    Labels are limited to the event type — token/user/IP would be
    high-cardinality by design.
    """
    from vnc_remote_secure.monitoring.prometheus import inc_counter

    inc_counter("vnc_remote_ephemeral_sessions_total", f"event={event}")


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
    token = payload["session_token"] if payload else signed_token
    if not store.get(token):
        # Fingerprint form: resolve the public token_id (sha256 prefix
        # of the internal token) to the real token before revoking.
        import hashlib

        store._load_if_changed()
        for real_token, _session in store._sessions.items():
            if hashlib.sha256(real_token.encode()).hexdigest()[:12] == signed_token.strip():
                token = real_token
                break
    result = store.revoke(token)
    if result:
        _metric("revoked")

    # Close all active WebSocket connections for this session.
    try:
        from vnc_remote_secure.security.websocket_registry import revoke_session_connections

        revoke_session_connections(token)
    except (ImportError, KeyError, RuntimeError) as exc:
        logger.debug("WebSocket registry unavailable during revoke: %s", exc)

    return result


_NS_EPH_REVOKED = "ephemeral_revoked_sessions"


def _mark_revoked_shared(token: str, expires_at: float) -> None:
    """Record a revocation in the shared-state backend.

    The JSON ``revoked`` flag can be lost when two processes interleave
    ``_save()`` (merge-read then atomic replace); the shared marker is
    written atomically and consulted by ``SessionStore.get()``. TTL
    outlives the session with the same 24h floor the WebSocket
    revocation namespace uses.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        ttl = max(86400, int(expires_at - time.time()))
        get_backend().set_ttl(_NS_EPH_REVOKED, token, True, ttl)
    except Exception as exc:  # noqa: BLE001 - best-effort mirror
        logger.debug("Could not mark ephemeral revocation shared: %s", exc)


_revocation_warned_at = 0.0


def _is_revoked_shared(token: str) -> bool:
    """Return True when the token was revoked in any process via the backend.

    Backend failure falls back to the local JSON ``revoked`` flag
    rather than denying every session — a sqlite hiccup must not be a
    self-DoS for all active sessions (new *activations* already fail
    closed via ``_claim_consumed``/``_claim_use``). The residual risk —
    a cross-process revocation whose JSON flag was lost to the
    merge-write race goes unenforced while the backend is down — is
    surfaced via a throttled warning + metric so operators see the
    degraded-enforcement window.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        return bool(get_backend().get(_NS_EPH_REVOKED, token))
    except Exception:  # noqa: BLE001 - degraded, not silent
        global _revocation_warned_at
        now = time.time()
        if now - _revocation_warned_at > 60:
            _revocation_warned_at = now
            logger.warning(
                "Revocation backend unavailable — enforcing local "
                "JSON flags only (cross-process revocations may lag)"
            )
        from vnc_remote_secure.monitoring.prometheus import inc_counter

        inc_counter("vnc_remote_shared_state_errors_total", "op=revocation_check")
        from vnc_remote_secure.security.shared_state import shared_state_strict

        if shared_state_strict():
            # Strict mode: a revocation check that cannot consult the
            # shared backend denies the session — a possibly-revoked
            # token must not keep access while enforcement is down.
            return True
        return False


def _claim_consumed(token: str, expires_at: float) -> bool:
    """Atomically claim a single-use session token across processes.

    Uses the shared-state backend's atomic test-and-set so only one
    process can win the claim for a given token.

    On backend failure the claim FAILS CLOSED: a denied legitimate
    activation is recoverable (retry), but an open claim would let a
    single-use token be consumed twice — or replayed across processes
    when one side degraded to a private memory backend.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        ttl = max(60.0, expires_at - time.time())
        return bool(get_backend().set_if_absent("ephemeral_consumed", token, True, ttl))
    except Exception:  # noqa: BLE001 - fail closed
        logger.exception("Ephemeral claim backend unavailable — denying claim")
        return False


def _claim_use(token: str, max_uses: int, expires_at: float) -> bool:
    """Atomically claim one activation of a multi-use token.

    Uses the shared-state backend's atomic ``increment`` so two
    processes cannot both claim the same use. Returns ``True`` when
    the claim is within budget, ``False`` when the counter exceeded
    ``max_uses`` (the increment is retained — the claim is consumed
    either way, which is correct because the caller then rejects).

    On backend failure the claim FAILS CLOSED (same reasoning as
    ``_claim_consumed``): a denied activation is retryable; an open
    claim would silently exceed the multi-use budget.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend

        ttl = max(60.0, expires_at - time.time())
        new_count = get_backend().increment("ephemeral_uses", token, 1, ttl_seconds=ttl)
        return new_count is not None and int(new_count) <= max_uses
    except Exception:  # noqa: BLE001 - fail closed
        logger.exception("Multi-use claim backend unavailable — denying claim")
        return False


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
    from vnc_remote_secure.security.maintenance import maintenance_active

    if maintenance_active():
        return False
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return False
    store = get_session_store()
    token = payload["session_token"]

    with store._lock:
        session = store.get(token)
        if not session:
            return False
        if session.revoked:
            return False
        if _session_expired(session):
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
            # Consumption forensics: bearer-path burns never ran
            # activate(), so without this the link's only use is
            # invisible in the detail view.
            session.used = True
            session.last_used_at = time.time()
            store._save()
            _metric("exhausted")
            return True  # Return inside lock to prevent race.
        return True  # Multi-use: valid, return inside lock.


def activate_ephemeral_session(signed_token: str, client_ip: str | None = None) -> str | None:
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
    from vnc_remote_secure.security.maintenance import maintenance_active

    if maintenance_active():
        return None
    payload = verify_ephemeral_token(signed_token)
    if not payload:
        return None
    store = get_session_store()
    store._load_if_changed()
    token = payload["session_token"]

    with store._lock:
        session = store.get(token)
        if not session or _activation_denied(session, token, client_ip):
            return None
        session.mark_used(client_ip)
        store._save()
        _metric("activated")
        if session.single_use or (session.max_uses > 0 and session.use_count >= session.max_uses):
            # A link that just burned its last use is a lifecycle
            # event distinct from activation — operators should see
            # budget exhaustion separately in metrics.
            _metric("exhausted")
        from vnc_remote_secure.security.audit import audit_event

        audit_event("ephemeral_session_activate", detail=f"role={session.role}")
        return token


def _activation_denied(session, token: str, client_ip: str | None) -> bool:
    """Every reject-before-burn rule for share-link activation."""
    if _denial_reason(session, _LINK_DENIAL_CHECKS) is not None:
        return True
    # IP binding at activation too — without it a link bound to a
    # client IP could still be *burned* by a different caller
    # (single-use DoS on the intended recipient), even though the
    # per-request check would later reject the attacker.
    # client_ip=None means "no caller context" (CLI/API paths) —
    # allowed, the per-request check still enforces the binding.
    # An empty STRING means a request resolved to no IP (suspicious,
    # e.g. malformed XFF) — denied.
    if session.allowed_ip == "first-observed" and client_ip:
        # Pin the binding to the first activation IP: the
        # operator wants "whoever redeems first" rather than a
        # literal address — useful for mobile clients whose IP is
        # unknowable at link-creation time.
        session.allowed_ip = client_ip
    if (
        session.allowed_ip
        and client_ip is not None
        and not _ip_matches(session.allowed_ip, client_ip)
    ):
        return True
    if session.single_use:
        # Cross-process single-use claim (see
        # consume_ephemeral_session): the in-process lock cannot
        # stop two services activating the same link at once.
        return not _claim_consumed(token, session.expires_at)
    # Multi-use: the local read-modify-write of use_count races
    # across processes — claim one use via the shared-state
    # atomic increment and reject when the budget is exhausted.
    return session.max_uses > 0 and not _claim_use(token, session.max_uses, session.expires_at)


def check_session_permission(
    internal_token: str,
    permission: str,
    resource: str | None = None,
    client_ip: str | None = None,
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
    if _denial_reason(session, _REQUEST_DENIAL_CHECKS, client_ip, resource) is not None:
        return False
    return session.has_permission(permission, resource)
