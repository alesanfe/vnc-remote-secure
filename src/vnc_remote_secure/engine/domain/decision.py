"""Shared domain result types — commands in, decisions/results out.

A use case returns a Result; the Backend translates it into an HTTP
envelope. Domain objects never carry status codes or response bodies.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Decision:
    """A yes/no domain answer with a machine-readable reason."""
    allowed: bool
    reason_code: str = ''
    detail: str = ''


@dataclass(frozen=True)
class UseCaseError(Exception):  # noqa: N818 - domain error base
    """Typed failure a use case may raise; the Backend maps `code`
    to a public error — never the message internals."""
    code: str
    detail: str = ''
    retryable: bool = False

    def __str__(self) -> str:
        return f'{self.code}: {self.detail}'


# Canonical error codes — the Backend maps these to HTTP statuses and
# the Frontend to localized messages. Extend, don't invent ad hoc.
ERR_NOT_FOUND = 'NOT_FOUND_OR_NOT_AUTHORIZED'
ERR_PERMISSION = 'PERMISSION_DENIED'
ERR_CONFLICT = 'CONFLICT'
ERR_INVALID = 'INVALID_REQUEST'
ERR_POLICY = 'AUTH_POLICY_DENIED'
ERR_LAST_ADMIN = 'LAST_ADMINISTRATOR_VIOLATION'
ERR_STEP_UP = 'STEP_UP_REQUIRED'


@dataclass(frozen=True)
class Command:
    """Base for use-case inputs. Frozen: a command is a fact."""
    actor: str = ''
    request_id: str = ''
    extra: dict = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class Result:
    """Base for use-case outputs. Serializable to a public DTO by a
    Backend serializer — never returned raw over the wire."""
    audit_event: str = ''
    audit_detail: str = ''
