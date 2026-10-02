"""Domain model for ephemeral remote sessions.

Pure session semantics: the ``EphemeralSession`` record, permission
constants/roles/expansion, IP/instance binding helpers and the
denial-check pipeline that decides *why* a session is rejected.

Persistence (``SessionStore``), token sign/verify and the share-link
lifecycle live in ``security.ephemeral_sessions`` — this module is
transport- and store-free.
"""

import contextlib
import hashlib
import logging
import os
import secrets
import time

logger = logging.getLogger(__name__)

# Server instance identifier (unique per process).
_INSTANCE_ID = None


def _ip_matches(allowed_ip: str, client_ip: str | None) -> bool:
    """Return True when ``client_ip`` satisfies ``allowed_ip``.

    ``allowed_ip`` accepts a literal address (``203.0.113.7``) or a
    CIDR range (``10.0.0.0/24``, ``fd00::/8``) — subnet policies let
    a link survive a client's address churn inside one network.
    Missing or unparseable values fail closed.
    """
    if not client_ip:
        return False
    if "/" not in allowed_ip:
        return client_ip == allowed_ip
    try:
        import ipaddress

        return ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed_ip, strict=False)
    except ValueError:
        return False


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
    try:
        from vnc_remote_secure.core.paths import get_run_dir

        path = os.path.join(get_run_dir(), "instance.id")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                saved = f.read().strip()
            if saved:
                _INSTANCE_ID = saved
                return saved
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _INSTANCE_ID = f"srv_{secrets.token_hex(4)}"
        import tempfile

        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(_INSTANCE_ID)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        try:
            from vnc_remote_secure.security.certificates import (
                _restrict_key_permissions,
            )

            _restrict_key_permissions(path, writable=True)
        except Exception:  # noqa: BLE001 - ACL hardening is best-effort
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001 - fall back to process-local id
        _INSTANCE_ID = f"srv_{secrets.token_hex(4)}"
    return _INSTANCE_ID


# Permissions
PERM_VIEW = "view"
PERM_CONTROL = "control"  # umbrella: keyboard + pointer
PERM_KEYBOARD = "keyboard"
PERM_POINTER = "pointer"
PERM_CLIPBOARD = "clipboard"  # umbrella: clipboard_write + _read
PERM_CLIPBOARD_WRITE = "clipboard_write"
PERM_CLIPBOARD_READ = "clipboard_read"
PERM_FILE_TRANSFER = "file_transfer"
PERM_TERMINAL = "terminal"  # umbrella: terminal_view + terminal_write
PERM_TERMINAL_VIEW = "terminal_view"  # connect + read-only builtins
PERM_TERMINAL_WRITE = "terminal_write"  # command execution
PERM_AUDIO = "audio"
PERM_GAMEPAD = "gamepad"
PERM_ADMIN = "admin"  # umbrella: admin_* below
PERM_ADMIN_USERS = "admin_users"
PERM_ADMIN_CONFIG = "admin_config"
PERM_ADMIN_AUDIT = "admin_audit"

ALL_PERMISSIONS = {
    PERM_VIEW,
    PERM_CONTROL,
    PERM_KEYBOARD,
    PERM_POINTER,
    PERM_CLIPBOARD,
    PERM_CLIPBOARD_WRITE,
    PERM_CLIPBOARD_READ,
    PERM_FILE_TRANSFER,
    PERM_TERMINAL,
    PERM_TERMINAL_VIEW,
    PERM_TERMINAL_WRITE,
    PERM_AUDIO,
    PERM_GAMEPAD,
    PERM_ADMIN,
    PERM_ADMIN_USERS,
    PERM_ADMIN_CONFIG,
    PERM_ADMIN_AUDIT,
}

# Coarse permissions expand to their fine-grained members: a session
# holding ``control`` satisfies ``keyboard``/``pointer`` checks, but a
# session holding only ``pointer`` does NOT satisfy ``control``.
_PERMISSION_EXPANSION = {
    PERM_CONTROL: {PERM_KEYBOARD, PERM_POINTER},
    PERM_CLIPBOARD: {PERM_CLIPBOARD_WRITE, PERM_CLIPBOARD_READ},
    PERM_TERMINAL: {PERM_TERMINAL_VIEW, PERM_TERMINAL_WRITE},
    # Explicit implication, not a side effect: a writer that cannot
    # see output is useless, so write grants view. One hop only —
    # terminal_view expands to nothing.
    PERM_TERMINAL_WRITE: {PERM_TERMINAL_VIEW},
    PERM_ADMIN: {PERM_ADMIN_USERS, PERM_ADMIN_CONFIG, PERM_ADMIN_AUDIT},
}


def expand_permissions(permissions) -> set:
    """Expand umbrella permissions to their fine-grained members.

    Iterates to a fixpoint so implication chains resolve transitively
    (``terminal`` -> ``terminal_write`` -> ``terminal_view``). The loop
    is bounded by the permission count — a cycle terminates rather
    than hanging.
    """
    out = set(permissions)
    for _ in range(len(ALL_PERMISSIONS) + 1):
        grown = set(out)
        for perm in out:
            grown |= _PERMISSION_EXPANSION.get(perm, set())
        if grown == out:
            return out
        out = grown
    return out


# Roles (collections of permissions)
ROLES = {
    "viewer": {PERM_VIEW},
    "support": {PERM_VIEW, PERM_CONTROL, PERM_CLIPBOARD, PERM_AUDIO},
    "operator": {
        PERM_VIEW,
        PERM_CONTROL,
        PERM_CLIPBOARD,
        PERM_FILE_TRANSFER,
        PERM_TERMINAL,
        PERM_AUDIO,
        PERM_GAMEPAD,
    },
    "administrator": ALL_PERMISSIONS,
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
        role: str = "viewer",
        permissions: set | None = None,
        expires_at: float = 0,
        single_use: bool = False,
        view_only: bool = False,
        no_terminal: bool = False,
        allowed_ip: str | None = None,
        created_by: str = "admin",
        resource: str | None = None,
        instance_id: str | None = None,
        nonce: str | None = None,
        max_uses: int = 0,
        label: str | None = None,
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
        # Skew-immune expiry bound: expires_at alone trusts the wall
        # clock, so a clock wound back revives dead sessions. The
        # monotonic clock shares its epoch across processes within a
        # boot; a rebooted or foreign value yields a negative/odd
        # delta and the check degrades to wall-clock-only (see
        # _session_expired).
        self.created_monotonic = time.monotonic()
        self.used = False
        self.revoked = False
        # Forensics: when and from where the grant was last consumed.
        self.last_used_at: float | None = None
        self.last_used_ip: str | None = None
        # Live-connection forensics: set by the WebSocket registry
        # hooks (connect/disconnect), so the detail view can answer
        # "is anyone attached right now and for how long".
        self.last_connected_at: float | None = None
        self.last_disconnected_at: float | None = None
        self.connection_count = 0
        # Strong binding fields.
        self.resource = resource  # e.g. 'desktop', 'terminal'
        self.instance_id = instance_id or _get_instance_id()
        self.nonce = nonce or secrets.token_hex(8)
        self.max_uses = max_uses  # 0 = unlimited
        self.use_count = 0
        # Operator-assigned tag (e.g. "soporte Juan", "demo Q3") —
        # inventory metadata only; never part of auth decisions.
        self.label = label

    def is_valid(self, client_ip: str | None = None, resource: str | None = None) -> bool:
        """Check if this session is still valid.

        Args:
            client_ip: Client IP address (for IP restriction check).
            resource: Requested resource (for resource binding check).
        """
        return _denial_reason(self, _SESSION_VALIDITY_CHECKS, client_ip, resource) is None

    def has_permission(self, perm: str, resource: str | None = None) -> bool:
        """Check if this session grants a specific permission.

        Args:
            perm: Permission to check (e.g. 'view', 'control', 'terminal',
                or 'terminal:use', 'desktop:view', 'desktop:control').
                The ``resource:action`` form is normalized to the
                canonical permission name.
            resource: Resource being accessed (for resource binding).
        """
        # Normalize 'resource:action' to canonical permission names.
        # The composite wins first — 'terminal:write' must resolve to
        # the fine-grained 'terminal_write', not collapse to the
        # 'terminal' umbrella (that would let a terminal_view-only
        # session fail to satisfy it while making the granular
        # distinction meaningless). Falls back to the bare action
        # ('desktop:view' -> 'view'), then the bare resource.
        if ":" in perm:
            res, action = perm.split(":", 1)
            composite = f"{res}_{action}"
            perm = (
                composite
                if composite in ALL_PERMISSIONS
                else action if action in ALL_PERMISSIONS else res
            )
        # Resource binding: if token has a resource, it must match —
        # enforced only when the caller names the resource.
        if self.resource and resource and resource != self.resource:
            return False
        # view_only also blocks the terminal: a shell is full control,
        # so a "view-only" session that can open one is not view-only.
        # (Documented in docs/user-guide/sessions.md.)
        if self.view_only and perm in expand_permissions(
            {PERM_CONTROL, PERM_CLIPBOARD, PERM_FILE_TRANSFER, PERM_TERMINAL, PERM_GAMEPAD}
        ):
            return False
        # no_terminal must cover the fine-grained members too — a
        # terminal_view/terminal_write request would otherwise slip
        # past a flag that promised "no terminal at all".
        if self.no_terminal and perm in expand_permissions({PERM_TERMINAL}):
            return False
        return perm in expand_permissions(self.permissions)

    def mark_used(self, client_ip: str | None = None):
        """Mark this session as used (for single-use sessions) and
        record the consumption for the access detail view."""
        self.used = True
        self.use_count += 1
        self.last_used_at = time.time()
        if client_ip:
            self.last_used_ip = client_ip

    def note_connected(self):
        """A WebSocket carrying this session's grant opened."""
        self.last_connected_at = time.time()
        self.connection_count += 1

    def note_disconnected(self):
        """The last live connection for this session closed."""
        self.last_disconnected_at = time.time()

    def revoke(self):
        """Revoke this session immediately."""
        self.revoked = True

    def to_dict(self) -> dict:
        """Serialize to dict (for logging/API, no secrets)."""
        return {
            # Public identifier: sha256 of the internal token. Lets an
            # operator reference a session (revoke by id) without the
            # token itself appearing in list output.
            "token_id": hashlib.sha256(self.token.encode()).hexdigest()[:12],
            "role": self.role,
            "permissions": sorted(self.permissions),
            "expires_at": self.expires_at,
            "single_use": self.single_use,
            "view_only": self.view_only,
            "no_terminal": self.no_terminal,
            "allowed_ip": self.allowed_ip,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "created_monotonic": self.created_monotonic,
            "used": self.used,
            "revoked": self.revoked,
            "resource": self.resource,
            "instance_id": self.instance_id,
            "max_uses": self.max_uses,
            "use_count": self.use_count,
            "last_used_at": self.last_used_at,
            "last_used_ip": self.last_used_ip,
            "last_connected_at": self.last_connected_at,
            "last_disconnected_at": self.last_disconnected_at,
            "connection_count": self.connection_count,
            "label": self.label,
        }

    def to_persist_dict(self) -> dict:
        """Serialize to dict for persistence (includes token)."""
        d = self.to_dict()
        d["token"] = self.token
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "EphemeralSession":
        """Deserialize from dict (for persistence)."""
        session = cls(
            token=data["token"],
            role=data.get("role", "viewer"),
            permissions=set(data.get("permissions", [])),
            expires_at=float(data.get("expires_at", 0)),
            single_use=bool(data.get("single_use", False)),
            view_only=bool(data.get("view_only", False)),
            no_terminal=bool(data.get("no_terminal", False)),
            allowed_ip=data.get("allowed_ip"),
            created_by=data.get("created_by", "admin"),
            resource=data.get("resource"),
            instance_id=data.get("instance_id"),
            max_uses=int(data.get("max_uses", 0)),
            label=data.get("label"),
        )
        session.created_at = float(data.get("created_at", time.time()))
        session.created_monotonic = float(data.get("created_monotonic", 0))
        session.used = bool(data.get("used", False))
        session.revoked = bool(data.get("revoked", False))
        session.use_count = int(data.get("use_count", 0))
        last_used_at = data.get("last_used_at")
        session.last_used_at = float(last_used_at) if last_used_at else None
        session.last_used_ip = data.get("last_used_ip")
        for f in ("last_connected_at", "last_disconnected_at"):
            v = data.get(f)
            setattr(session, f, float(v) if v else None)
        session.connection_count = int(data.get("connection_count", 0))
        return session


def _session_expired(session: EphemeralSession) -> bool:
    """True when the session's TTL is spent.

    Two independent bounds, either sufficient:

    - Wall clock: ``time.time() >= expires_at`` — catches forward skew.
    - Monotonic: ``monotonic() - created_monotonic >= original TTL`` —
      catches backward skew (a clock wound before ``expires_at``
      revives the session under the wall bound alone).

    Sessions persisted before this field existed carry
    ``created_monotonic == 0`` and degrade to wall-clock expiry; a
    negative delta (reboot, foreign epoch) also degrades rather than
    trusting a meaningless monotonic value.
    """
    if time.time() >= session.expires_at:
        return True
    mono = getattr(session, "created_monotonic", 0)
    if not mono:
        return False
    ttl = session.expires_at - session.created_at
    if ttl <= 0:
        return True
    elapsed = time.monotonic() - mono
    return elapsed >= 0 and elapsed >= ttl


# ------------------------------------------------------------------
# Denial-check pipeline
#
# Each check returns a short reason string on denial, None on pass.
# The tuples below define the authorization decision order for each
# entry point — adding a rule is adding a function plus a tuple
# entry, and every rule is independently testable/auditable.
# ------------------------------------------------------------------


def _deny_revoked(s, _ip, _res):
    return "revoked" if s.revoked else None


def _deny_used(s, _ip, _res):
    return "single-use already consumed" if s.single_use and s.used else None


def _deny_budget(s, _ip, _res):
    return "use budget exhausted" if s.max_uses > 0 and s.use_count >= s.max_uses else None


def _deny_expired(s, _ip, _res):
    return "expired" if _session_expired(s) else None


def _deny_ip(s, client_ip, _res):
    # Fail-closed: a missing client_ip must not silently skip an
    # operator-configured restriction. 'first-observed' is the unbound
    # marker — it binds to the first activation IP inside
    # consume/activate, so it never reaches this check as a literal.
    if not s.allowed_ip or s.allowed_ip == "first-observed":
        return None
    return None if _ip_matches(s.allowed_ip, client_ip) else "ip binding"


def _deny_resource(s, _ip, resource):
    # Resource binding restricts WHERE a permission may be used —
    # enforced only when the caller names a resource (action-level
    # checks without resource context assert the permission exists;
    # see TestResourceBinding contract).
    if s.resource and resource and resource != s.resource:
        return "resource binding"
    return None


def _deny_foreign_instance(s, _ip, _res):
    # Deployment binding: a token issued by a different deployment
    # (different persisted instance.id) must not authenticate here.
    if s.instance_id and s.instance_id != _get_instance_id():
        return "foreign deployment"
    return None


def _deny_drained(_s, _ip, _res):
    # Deferred maintenance drain: `maintenance on --drain-timeout N`
    # writes wall+monotonic deadlines into the flag; once reached, the
    # first process to notice claims the drain marker and revokes all
    # sessions — propagating to live websockets, so grace ends in an
    # actual close, not just a denied next check.
    from vnc_remote_secure.security.maintenance import enforce_drain_deadline

    return "maintenance drain" if enforce_drain_deadline() else None


# Validity of an already-activated session (EphemeralSession.is_valid).
_SESSION_VALIDITY_CHECKS = (
    _deny_revoked,
    _deny_used,
    _deny_budget,
    _deny_expired,
    _deny_drained,
    _deny_ip,
    _deny_resource,
    _deny_foreign_instance,
)

# Reject-before-burn rules for share-link activation — IP binding is
# applied separately in _activation_denied because it may PIN the
# 'first-observed' marker before matching.
_LINK_DENIAL_CHECKS = (
    _deny_revoked,
    _deny_expired,
    _deny_used,
    _deny_budget,
    _deny_foreign_instance,
)

# Per-request checks on an activated session (check_session_permission)
# — the link budget gates the link, not the session's requests.
_REQUEST_DENIAL_CHECKS = (
    _deny_revoked,
    _deny_expired,
    _deny_drained,
    _deny_ip,
    _deny_resource,
    _deny_foreign_instance,
)


def _denial_reason(session, checks, client_ip=None, resource=None):
    """First denial reason across *checks*, or None when all pass."""
    for check in checks:
        reason = check(session, client_ip, resource)
        if reason is not None:
            return reason
    return None
