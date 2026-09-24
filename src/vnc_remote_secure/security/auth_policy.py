"""Declarative authentication-assurance policy for sensitive operations.

Sessions record *how* the user authenticated (``auth_method``,
``mfa``, ``phishing_resistant``, ``user_verified``,
``authenticated_at``). This module is the consumer: a central registry
maps sensitive operations to their requirements, and ``evaluate()``
returns a structured decision — no scattered ``if not
session['phishing_resistant']`` checks diverging per route.

Capability checks stay separate: holding ``admin_secrets`` does NOT
waive a recent-auth requirement.

Enforcement is profile-scaled to avoid lockouts:

- ``development``: evaluate + audit, never block.
- ``trusted-lan``: enforce ``require_mfa`` and ``max_auth_age``;
  phishing-resistance requirements are audited but not enforced
  (deployments may legitimately lack WebAuthn).
- ``private-overlay`` / ``public-hardened``: enforce everything.
"""

import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthRequirement:
    """What a sensitive operation demands from the login ceremony.

    ``alternatives`` expresses method choice: a tuple of property
    tuples, satisfied when the session has EVERY property in ANY one
    tuple — e.g. ``(('mfa',), ('phishing_resistant','user_verified'))``
    accepts either verified MFA or a UV passkey ceremony. It exists
    because ``mfa`` alone would deny a phishing-resistant passkey
    session that never ran a second factor.
    """
    require_mfa: bool = False
    require_phishing_resistant: bool = False
    require_user_verified: bool = False
    max_auth_age_seconds: int | None = None
    alternatives: tuple = ()


@dataclass(frozen=True)
class AuthDecision:
    """Structured, auditable outcome of a policy evaluation.

    ``allowed`` answers "may this proceed"; ``requirements_satisfied``
    answers "did the session meet the policy" — a pending/audit-only
    op can be allowed with unsatisfied requirements, and conflating
    them is exactly how fake guarantees happen.
    """
    allowed: bool
    operation: str
    reason_code: str | None          # 'MFA_REQUIRED', 'AUTH_TOO_OLD'...
    observed_method: str | None
    auth_age_seconds: int | None
    missing: tuple                   # properties the session lacked
    enforced: bool                   # False => audit-only (dev/lan)
    requirements_satisfied: bool = True


AUTH_POLICIES: dict[str, AuthRequirement] = {
    'open_terminal': AuthRequirement(
        # Recent auth AND (verified MFA OR a UV passkey ceremony) —
        # a phishing-resistant session shouldn't be denied for
        # lacking a 'mfa' flag it never needed.
        alternatives=(('mfa',),
                      ('phishing_resistant', 'user_verified')),
        max_auth_age_seconds=600),
    'create_admin': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'delete_admin': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'webauthn_register': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'webauthn_delete': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
}

# Declared but NOT yet enforced anywhere — CLI ops have no session
# context. Listing them here (not in AUTH_POLICIES) keeps the
# registry honest: a policy that no call site evaluates is not a
# control, it's documentation. The contract test pins that every
# AUTH_POLICIES key appears in POLICY_ENFORCEMENT_POINTS.
PENDING_POLICIES: dict[str, AuthRequirement] = {
    'secrets.rotate': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
    'backup.restore': AuthRequirement(
        alternatives=(('mfa',),
                      ('phishing_resistant', 'user_verified')),
        max_auth_age_seconds=300),
    'operator.grant_admin': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
}

# Where each enforced policy is actually checked — the contract test
# asserts declared == enforced.
POLICY_ENFORCEMENT_POINTS: dict[str, frozenset] = {
    'open_terminal': frozenset({'services/terminal.py:open_terminal'}),
    'create_admin': frozenset({'web/routes/users.py:create_user'}),
    'delete_admin': frozenset({'web/routes/users.py:delete_user'}),
    'webauthn_register': frozenset(
        {'web/routes/users.py:webauthn_register_begin'}),
    'webauthn_delete': frozenset(
        {'web/routes/users.py:webauthn_delete_credential'}),
}

# Profile -> which requirement fields actually deny (rest audit-only).
_ENFORCE_MFA_ONLY = ('trusted-lan',)
_ENFORCE_ALL = ('private-overlay', 'public-hardened')

_CTX_NS = 'web_auth_context'


def _session_key(session_id: str) -> str:
    """Derive the shared-state key for a session's auth context.

    Keyed by the SESSION id (``username:created`` — the same stable,
    server-issued pair the revocation layer uses, so it survives
    cookie refreshes), never by bare username — otherwise a strong
    login (WebAuthn+UV) would overwrite the context of a weaker
    concurrent session of the same principal and silently elevate it.
    The hash keeps identifiers out of shared state; the key alone
    cannot authenticate.
    """
    import hashlib
    return hashlib.sha256(session_id.encode('utf-8')).hexdigest()


def session_id_for_cookie(cookie_value: str) -> str | None:
    """Resolve a verified ``vnc_session`` cookie to its stable
    random session id. None if the cookie is invalid or predates the
    v3 payload (legacy cookies carry no sid — callers fail closed)."""
    try:
        from vnc_remote_secure.security.sessions import verify_session_cookie
        parsed = verify_session_cookie(cookie_value)
        if parsed:
            return parsed.get('sid')
    except Exception:  # noqa: BLE001
        pass
    return None


def record_auth_context(session_id: str, ctx: dict,
                        stable_id: str | None = None,
                        expires_at: int | None = None) -> None:
    """Persist the login's auth properties for cross-process policy
    checks — the Flask session is a signed cookie unavailable to the
    terminal/health services, so enforcement needs shared state.

    ``stable_id`` (``username:created``) indexes the context so
    revocation paths that only hold the stable pair can still drop
    the record. The operator epoch is stamped in — a ctx older than
    the last credential rotation denies even if it survives. The TTL
    never exceeds the session's absolute expiry — a late refresh must
    not extend the assurance record past the session it belongs to."""
    try:
        from vnc_remote_secure.security.sessions import operator_session_epoch
        from vnc_remote_secure.security.shared_state import get_backend
        ctx = dict(ctx)
        ctx['operator_epoch'] = operator_session_epoch()
        be = get_backend()
        ttl = int(os.environ.get('SESSION_MAX_LIFETIME', '86400'))
        if expires_at:
            ttl = min(ttl, max(1, expires_at - int(time.time())))
        be.set_ttl(_CTX_NS, _session_key(session_id), ctx, ttl)
        if stable_id:
            # Composite key = a SET of sids per stable pair — two
            # same-second logins share username:created, so a single
            # idx value would overwrite one session's index entry.
            be.set_ttl(_CTX_NS,
                       f'idx:{_session_key(stable_id)}:{_session_key(session_id)}',
                       '1', ttl)
    except Exception:  # noqa: BLE001 - ctx is advisory if state is down
        logger.debug('Could not record auth context', exc_info=True)


_CTX_FIELDS = frozenset({
    'auth_method', 'mfa', 'phishing_resistant', 'user_verified',
    'authenticated_at', 'username',
})


def update_auth_context(session_id: str, **fields) -> None:
    """Merge fields into an existing session's auth context — used
    when a step-up ceremony refreshes ``authenticated_at`` without
    re-issuing the session cookie. Fields outside ``_CTX_FIELDS``
    are rejected (arbitrary writes would let a compromised call
    site fabricate assurance properties)."""
    bad = [k for k in fields if k not in _CTX_FIELDS]
    if bad:
        logger.warning('auth_context update rejected unknown '
                       'fields: %s', bad)
        return
    if 'authenticated_at' in fields and not isinstance(
            fields['authenticated_at'], (int, float)):
        return
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        key = _session_key(session_id)
        ctx = be.get(_CTX_NS, key)
        if isinstance(ctx, dict):
            ctx.update(fields)
            ttl = int(os.environ.get('SESSION_MAX_LIFETIME', '86400'))
            be.set_ttl(_CTX_NS, key, ctx, ttl)
    except Exception:  # noqa: BLE001
        logger.debug('Could not update auth context', exc_info=True)


def auth_context_for(session_id: str) -> dict:
    """Load the recorded auth context for this SESSION (empty if none)."""
    if not session_id:
        return {}
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        return get_backend().get(_CTX_NS,
                                 _session_key(session_id)) or {}
    except Exception:  # noqa: BLE001
        return {}


def drop_auth_context(session_id: str,
                      stable_id: str | None = None) -> None:
    """Delete one session's auth context — logout, revocation, or any
    event that invalidates the session must drop it too. When
    ``stable_id`` is known, the index entry is removed as well so no
    orphan ``idx:`` records survive."""
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        be.delete(_CTX_NS, _session_key(session_id))
        if stable_id:
            be.delete(
                _CTX_NS,
                f'idx:{_session_key(stable_id)}:'
                f'{_session_key(session_id)}')
    except Exception:  # noqa: BLE001
        logger.debug('Could not drop auth context', exc_info=True)


def drop_auth_context_for_cookie(cookie_value: str) -> None:
    """v3 cookie → drop exactly ONE session's context + index entry.
    Never escalates to the shared stable pair."""
    try:
        from vnc_remote_secure.security.sessions import verify_session_cookie
        parsed = verify_session_cookie(cookie_value)
        if parsed and parsed.get('sid'):
            stable = (f"{parsed['username']}:{parsed['created']}"
                      if parsed.get('created') else None)
            drop_auth_context(parsed['sid'], stable_id=stable)
    except Exception:  # noqa: BLE001
        logger.debug('Could not drop ctx for cookie', exc_info=True)


def drop_auth_contexts_for_stable(stable_id: str) -> None:
    """Stable ``username:created`` pair → revoking it revokes EVERY
    session sharing it, so every indexed context goes."""
    if not stable_id:
        return
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        prefix = f'idx:{_session_key(stable_id)}:'
        for idx_key in be.list_keys(_CTX_NS, prefix=prefix):
            be.delete(_CTX_NS, idx_key)
            # idx key embeds sha256(sid) — drop the ctx record.
            be.delete(_CTX_NS, idx_key[len(prefix):])
    except Exception:  # noqa: BLE001
        logger.debug('Could not resolve ctx by stable id',
                     exc_info=True)


def drop_auth_context_for(cookie_or_stable: str) -> None:
    """Router kept for callers holding an untyped value: a v3 cookie
    resolves to one sid; anything else is treated as a stable pair.
    New call sites should use the typed variants instead."""
    if session_id_for_cookie(cookie_or_stable) is not None:
        drop_auth_context_for_cookie(cookie_or_stable)
    else:
        drop_auth_contexts_for_stable(cookie_or_stable)


def drop_all_auth_contexts() -> int:
    """Delete every recorded auth context — credential rotation
    (operator epoch bump) invalidates all sessions, so their
    assurance records must not outlive them."""
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        n = 0
        for key in be.list_keys(_CTX_NS):
            be.delete(_CTX_NS, key)
            n += 1
        return n
    except Exception:  # noqa: BLE001
        logger.debug('Could not drop auth contexts', exc_info=True)
        return 0


def _profile() -> str:
    try:
        from vnc_remote_secure.security.profiles import get_profile
        return get_profile()
    except Exception:  # noqa: BLE001
        return 'development'


def evaluate(operation: str, session_ctx: dict,
             profile: str | None = None) -> AuthDecision:
    """Evaluate the session context against the operation's policy.

    ``session_ctx`` carries the properties recorded at login:
    ``auth_method``, ``mfa``, ``phishing_resistant``,
    ``user_verified``, ``authenticated_at``. Unknown operations have
    no requirement and pass (declare one here to gate them).
    """
    req = AUTH_POLICIES.get(operation)
    pending = False
    if req is None:
        # Pending ops (declared, no enforcement point yet) still get
        # a real evaluation — the decision is audit-only regardless
        # of profile, so a future call site inherits working logic.
        req = PENDING_POLICIES.get(operation)
        pending = req is not None
    method = session_ctx.get('auth_method')
    auth_at = session_ctx.get('authenticated_at')
    age = (int(time.time() - auth_at)
           if isinstance(auth_at, (int, float)) else None)
    # A timestamp far in the future is corruption or tampering, not
    # "very fresh auth" — small skew tolerance only.
    if isinstance(auth_at, (int, float)) and age is not None \
            and age < -30:
        logger.warning('auth_context authenticated_at is %.0fs in '
                       'the future — denying', -age)
        from vnc_remote_secure.security.audit import audit_event
        audit_event('auth_policy', result='denied',
                    user=session_ctx.get('username', '?'),
                    detail=f'op={operation} future_timestamp age={age}')
        return AuthDecision(False, operation, 'INVALID_AUTH_CONTEXT',
                            method, age, ('recent_auth',),
                            enforced=True)
    if req is None:
        return AuthDecision(True, operation, None, method, age, (),
                            enforced=False)

    # The context must belong to the current operator epoch — a
    # record written before a credential rotation is stale even if
    # the physical entry survived (logical invalidation, not just
    # cleanup).
    ctx_epoch = session_ctx.get('operator_epoch')
    if ctx_epoch is not None:
        try:
            from vnc_remote_secure.security.sessions import operator_session_epoch
            if float(ctx_epoch) < operator_session_epoch():
                return AuthDecision(
                    False, operation, 'SESSION_REVOKED', method, age,
                    ('current_epoch',), enforced=True,
                    requirements_satisfied=False)
        except Exception:  # noqa: BLE001 - can't prove epoch => deny
            return AuthDecision(
                False, operation, 'AUTH_CONTEXT_INVALID', method, age,
                ('operator_epoch',), enforced=True,
                requirements_satisfied=False)

    profile = profile if profile is not None else _profile()
    enforce_all = (profile in _ENFORCE_ALL) and not pending
    enforce_mfa = (enforce_all
                   or profile in _ENFORCE_MFA_ONLY) and not pending
    missing = []
    if req.require_mfa and not session_ctx.get('mfa'):
        missing.append('mfa')
    if req.require_phishing_resistant \
            and not session_ctx.get('phishing_resistant'):
        missing.append('phishing_resistant')
    if req.require_user_verified \
            and session_ctx.get('user_verified') is not True:
        missing.append('user_verified')
    # AnyOf: satisfied when EVERY property in ANY alternative holds.
    if req.alternatives and not any(
            all(session_ctx.get(p) for p in alt)
            for alt in req.alternatives):
        missing.append('strong_method')
    if (req.max_auth_age_seconds is not None
            and (age is None or age > req.max_auth_age_seconds)):
        missing.append('recent_auth')

    # Split missing props by whether this profile enforces them.
    enforced_missing = [m for m in missing
                        if m in ('mfa', 'recent_auth', 'strong_method')
                        or enforce_all]
    audited_missing = [m for m in missing
                       if m not in enforced_missing]
    enforced = enforce_mfa or enforce_all
    allowed = not enforced_missing if enforced else True

    if missing:
        from vnc_remote_secure.security.audit import audit_event
        audit_event(
            'auth_policy', user=session_ctx.get('username', '?'),
            result='denied' if (enforced and not allowed)
            else 'audit-only',
            detail=(f'op={operation} missing={"+".join(missing)} '
                    f'enforced={enforced_missing} '
                    f'audited={audited_missing} age={age}'))
        logger.info('Auth policy %s for %s: missing=%s enforced=%s',
                    'DENY' if (enforced and not allowed)
                    else 'audit', operation, missing, enforced)

    reason = None
    if pending and missing:
        reason = 'POLICY_PENDING'
    elif enforced and not allowed:
        reason = ('AUTH_TOO_OLD' if enforced_missing == ['recent_auth']
                  else 'MFA_REQUIRED' if 'mfa' in enforced_missing
                  else 'STRONG_AUTH_REQUIRED')
    return AuthDecision(allowed, operation, reason, method, age,
                        tuple(missing), enforced=enforced,
                        requirements_satisfied=not missing)
