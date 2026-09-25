"""Request-body schemas for ``/api/v1/*`` mutations.

Pydantic models in strict mode — ``strict=True`` blocks coercions like
``ttl_seconds: true`` or ``"123"`` → ``123`` and ``extra='forbid'``
rejects misspelled fields instead of silently ignoring them (a typo'd
flag must never produce a wider share link).

Every model mirrors the checks the handlers used to run by hand;
validators keep domain rules (role names, permission sets, IP formats)
in exactly one place — the schema, not scattered ``isinstance``
blocks.
"""
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

# Resources a share link may be bound to (validation surface; the
# domain rule that requires admin:* for admin-granting links lives in
# engine.application.sessions.ADMINISH_PERMS).
_RESOURCES = frozenset({'desktop', 'terminal', 'audio', 'gamepad'})


def _resources() -> frozenset:
    """Valid share-link resource names."""
    return _RESOURCES


def _roles() -> frozenset:
    from vnc_remote_secure.security.ephemeral_sessions import ROLES
    return ROLES


def _permissions() -> frozenset:
    from vnc_remote_secure.security.ephemeral_sessions import (
        ALL_PERMISSIONS,
    )
    return ALL_PERMISSIONS


def _operator_roles() -> frozenset:
    from vnc_remote_secure.security.operator_users import ROLE_PERMISSIONS
    return frozenset(ROLE_PERMISSIONS)


def _valid_username(value: str) -> bool:
    from vnc_remote_secure.security.operator_users import _valid_username as v
    return v(value)


def _valid_allowed_ip(value: str) -> bool:
    """IP, CIDR or the 'first-observed' bind-on-first-use marker."""
    if value == 'first-observed':
        return True
    import ipaddress
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class StrictBody(BaseModel):
    """Base for all request bodies — strict types, no extra keys."""
    model_config = ConfigDict(strict=True, extra='forbid')


class LoginRequest(StrictBody):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)
    totp: str | None = Field(default=None, max_length=64)


class StepUpRequest(StrictBody):
    password: str = Field(min_length=1, max_length=256)
    # Bound grant: catalog operation id + concrete target. '' means a
    # generic recent-auth grant only (legacy callers).
    operation: str = Field(default='', max_length=64)
    resource: str = Field(default='', max_length=256)


class TokenBody(StrictBody):
    """Share-link preview/activate — the token IS the credential."""
    token: str = Field(min_length=1, max_length=4096)


class MaintenanceRequest(StrictBody):
    active: bool
    reason: str = Field(default='', max_length=512)
    drain: bool = False
    drain_timeout: int = Field(default=0, ge=0, le=86400)


class SessionCreateRequest(StrictBody):
    role: str = 'viewer'
    permissions: list[str] | None = None
    ttl_seconds: int = Field(default=1800, ge=60, le=7 * 86400)
    max_uses: int = Field(default=0, ge=0, le=1000)
    single_use: bool = False
    view_only: bool = False
    no_terminal: bool = False
    allowed_ip: str | None = Field(default=None, max_length=64)
    resource: str | None = None

    @field_validator('role')
    @classmethod
    def _role_known(cls, v: str) -> str:
        if v not in _roles():
            raise ValueError(f'Unknown role: {v}')
        return v

    @field_validator('permissions')
    @classmethod
    def _permissions_known(cls, v):
        if v is None:
            return None
        unknown = set(v) - _permissions()
        if unknown:
            raise ValueError(f'Unknown permissions: {sorted(unknown)}')
        if not v:
            raise ValueError('permissions must not be empty')
        return v

    @field_validator('allowed_ip')
    @classmethod
    def _allowed_ip_valid(cls, v):
        if v is None:
            return None
        v = v.strip()
        if not _valid_allowed_ip(v):
            raise ValueError(
                "allowed_ip is not a valid IP, CIDR, or 'first-observed'")
        return v

    @field_validator('resource')
    @classmethod
    def _resource_known(cls, v):
        if v is not None and v not in _resources():
            raise ValueError(
                f'resource must be one of {sorted(_resources())}')
        return v


class SessionRevokeRequest(StrictBody):
    token_id: str = Field(min_length=1, max_length=128)


class OperatorCreateRequest(StrictBody):
    username: str = Field(min_length=1, max_length=64)
    # Password strength stays with core.validation.validate_password —
    # the model only enforces type/bounds so error text is unchanged.
    password: str = Field(min_length=1, max_length=256)
    role: str = 'viewer'
    enabled: bool = True

    @field_validator('username')
    @classmethod
    def _username_shape(cls, v: str) -> str:
        if not _valid_username(v.strip()):
            raise ValueError(
                'username must be 1-64 chars of [a-zA-Z0-9._-@]')
        return v.strip()

    @field_validator('role')
    @classmethod
    def _role_known(cls, v: str) -> str:
        if v not in _operator_roles():
            raise ValueError(f'Unknown role: {v}')
        return v


class OperatorUpdateRequest(StrictBody):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=1,
                                 max_length=256)

    @field_validator('role')
    @classmethod
    def _role_known(cls, v):
        if v is not None and v not in _operator_roles():
            raise ValueError(f'Unknown role: {v}')
        return v


class PasskeyRegisterRequest(StrictBody):
    credential: dict
    name: str = Field(default='', max_length=128)


class PasskeyRenameRequest(StrictBody):
    name: str = Field(max_length=128)


class PasskeyAuthBeginRequest(StrictBody):
    username: str = Field(min_length=1, max_length=128)


class PasskeyAuthCompleteRequest(StrictBody):
    # username may be empty — resident/discoverable credentials do not
    # carry one.
    username: str = Field(default='', max_length=128)
    credential: dict


class SystemUserCreateRequest(StrictBody):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256)


class SecretsCheckRequest(StrictBody):
    fix: bool = False


class ConfigMigrateRequest(StrictBody):
    # Empty body = real apply (non-dry-run) — matches the documented
    # POST /config/migrate semantics.
    dry_run: bool = False


class LifecycleRequest(StrictBody):
    action: Literal['start', 'stop', 'restart']


class BackupFileRequest(StrictBody):
    file: str = Field(min_length=1, max_length=256)


class UpgradeRequest(StrictBody):
    source: str | None = Field(default=None, max_length=256)
