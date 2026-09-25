"""Typed use-case DTOs — shared by CLI, REST and jobs.

``OperationResult`` is a dict subclass so transports and tests keep
the flat wire shape (``result['job_id']``) while the construction is
typed: code, warnings, retryable hint and optional job handle. Domain
failures still raise :class:`UseCaseError` — success is implicit.

``CommandContext`` is the transport-to-engine context bundle —
identity plus which surface issued the command. Bound step-up grants
are only consumed for the ``'api'`` transport; the local CLI shell is
itself the authentication boundary.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandContext:
    transport: str = 'cli'       # 'cli' | 'api'
    username: str = ''
    sid: str = ''                # operator session id (api only)

    @classmethod
    def from_ctx(cls, ctx: dict | 'CommandContext' | None,
                 username: str = '') -> 'CommandContext':
        if isinstance(ctx, CommandContext):
            return ctx
        ctx = ctx or {}
        return cls(
            transport=str(ctx.get('transport') or 'cli'),
            username=str(ctx.get('username') or username),
            sid=str(ctx.get('sid') or ''))


class OperationResult(dict):
    """Flat wire payload with typed metadata.

    ``OperationResult(code='BACKUP_ACCEPTED', job_id=jid,
                       action='stop', pid=4242)`` serializes as::

        {'code': 'BACKUP_ACCEPTED', 'accepted': True,
         'job_id': '...', 'action': 'stop', 'pid': 4242}
    """

    def __init__(self, *, code: str = 'OK',
                 warnings: list[str] | tuple[str, ...] = (),
                 retryable: bool = False,
                 job_id: str | None = None,
                 accepted: bool | None = None,
                 **data):
        super().__init__(data)
        self['success'] = True
        self['code'] = code
        if warnings:
            self['warnings'] = list(warnings)
        if retryable:
            self['retryable'] = True
        if job_id is not None:
            self['job_id'] = job_id
        if accepted is not None:
            self['accepted'] = accepted
