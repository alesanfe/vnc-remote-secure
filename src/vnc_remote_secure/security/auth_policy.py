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
    """What a sensitive operation demands from the login ceremony."""
    require_mfa: bool = False
    require_phishing_resistant: bool = False
    require_user_verified: bool = False
    max_auth_age_seconds: int | None = None


@dataclass(frozen=True)
class AuthDecision:
    """Structured, auditable outcome of a policy evaluation."""
    allowed: bool
    operation: str
    reason_code: str | None          # 'MFA_REQUIRED', 'AUTH_TOO_OLD'...
    observed_method: str | None
    auth_age_seconds: int | None
    missing: tuple                   # properties the session lacked
    enforced: bool                   # False => audit-only (dev/lan)


AUTH_POLICIES: dict[str, AuthRequirement] = {
    'open_terminal': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=600),
    'create_admin': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'delete_admin': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'webauthn_register': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'webauthn_delete': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
    'secrets.rotate': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
    'backup.restore': AuthRequirement(
        require_mfa=True, max_auth_age_seconds=300),
    'operator.grant_admin': AuthRequirement(
        require_phishing_resistant=True, require_user_verified=True,
        max_auth_age_seconds=300),
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
    session id (``username:created``). None if the cookie is invalid."""
    try:
        from vnc_remote_secure.security.sessions import verify_session_cookie
        parsed = verify_session_cookie(cookie_value)
        if parsed and parsed.get('username') and parsed.get('created'):
            return f"{parsed['username']}:{parsed['created']}"
    except Exception:  # noqa: BLE001
        pass
    return None


def record_auth_context(session_id: str, ctx: dict) -> None:
    """Persist the login's auth properties for cross-process policy
    checks — the Flask session is a signed cookie unavailable to the
    terminal/health services, so enforcement needs shared state."""
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        ttl = int(os.environ.get('SESSION_MAX_LIFETIME', '86400'))
        get_backend().set_ttl(_CTX_NS, _session_key(session_id),
                              ctx, ttl)
    except Exception:  # noqa: BLE001 - ctx is advisory if state is down
        logger.debug('Could not record auth context', exc_info=True)


def update_auth_context(session_id: str, **fields) -> None:
    """Merge fields into an existing session's auth context — used
    when a step-up ceremony refreshes ``authenticated_at`` without
    re-issuing the session cookie."""
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


def drop_auth_context(session_id: str) -> None:
    """Delete a session's auth context — logout, revocation, or any
    event that invalidates the session must drop it too."""
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().delete(_CTX_NS, _session_key(session_id))
    except Exception:  # noqa: BLE001
        logger.debug('Could not drop auth context', exc_info=True)


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

    profile = profile if profile is not None else _profile()
    enforce_all = profile in _ENFORCE_ALL
    enforce_mfa = enforce_all or profile in _ENFORCE_MFA_ONLY
    missing = []
    if req.require_mfa and not session_ctx.get('mfa'):
        missing.append('mfa')
    if req.require_phishing_resistant \
            and not session_ctx.get('phishing_resistant'):
        missing.append('phishing_resistant')
    if req.require_user_verified \
            and session_ctx.get('user_verified') is not True:
        missing.append('user_verified')
    if (req.max_auth_age_seconds is not None
            and (age is None or age > req.max_auth_age_seconds)):
        missing.append('recent_auth')

    # Split missing props by whether this profile enforces them.
    enforced_missing = [m for m in missing
                        if m in ('mfa', 'recent_auth') or enforce_all]
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
    if enforced and not allowed:
        reason = ('AUTH_TOO_OLD' if enforced_missing == ['recent_auth']
                  else 'MFA_REQUIRED' if 'mfa' in enforced_missing
                  else 'STRONG_AUTH_REQUIRED')
    return AuthDecision(allowed, operation, reason, method, age,
                        tuple(missing), enforced=enforced)
