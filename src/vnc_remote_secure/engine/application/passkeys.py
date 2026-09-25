"""Passkey management use cases — the public view never exposes raw
WebAuthn credential ids.

``credential_ref`` is ``sha256(credential_id)[:16]`` — stable, opaque,
and useless to anyone who captures a URL or a screenshot.

Domain rules:

* Registration (begin/complete) is **self-service only** — an
  authenticator attestation binds to the holder's browser, so an admin
  cannot mint credentials for another account.
* Registration requires a *recent* authentication (step-up): the
  ``step_up_auth`` timestamp recorded when the operator session was
  minted must be within the manager's window.
* Rename/delete are allowed for the owner or an ``admin_users``
  operator.
* Deleting the **last passkey** of an account whose MFA policy would
  then be unsatisfiable is refused (``ERR_LAST_ADMIN``-style 409).
"""
from __future__ import annotations

import hashlib

from vnc_remote_secure.engine.domain.decision import (
    ERR_CONFLICT,
    ERR_INVALID,
    ERR_LAST_ADMIN,
    ERR_NOT_FOUND,
    ERR_PERMISSION,
    ERR_STEP_UP,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores

_REF_LEN = 16


def credential_ref(credential_id: str) -> str:
    """Opaque public reference for a credential id."""
    return hashlib.sha256(credential_id.encode()).hexdigest()[:_REF_LEN]


def _audit(event: str, actor: str, detail: str,
           result: str = '') -> None:
    stores.audit(event, actor, detail, result=result)


def _resolve_ref(username: str, ref: str) -> str | None:
    """Map a public ref to the stored credential id owned by
    *username* — refs of other users resolve to None (no oracle)."""
    if not ref or len(ref) > 64 or not all(
            c in '0123456789abcdef' for c in ref):
        return None
    for c in stores.credential_list(username):
        if credential_ref(c['credential_id']) == ref:
            return c['credential_id']
    return None


def list_passkeys(username: str) -> list:
    """Public passkey view: ref, name, created_at, sign_count."""
    return [{
        'ref': credential_ref(c['credential_id']),
        'name': c.get('name', ''),
        'created_at': c.get('created_at', ''),
        'sign_count': c.get('sign_count', 0),
    } for c in stores.credential_list(username)]


def _gate_feature() -> None:
    """Refuse when the feature is off or RP config is unsafe."""
    err = stores.webauthn_gate_error()
    if err:
        raise UseCaseError(ERR_INVALID, err)


def _gate_step_up(actor: str, action: str) -> None:
    err = stores.step_up_error(actor, action)
    if err:
        _audit('api_permission_denied', actor, f'step-up: {action}')
        raise UseCaseError(ERR_STEP_UP, err)


def rp_id() -> str:
    return stores.env('WEBAUTHN_RP_ID').strip() or 'localhost'


def webauthn_origin() -> str:
    return stores.env('WEBAUTHN_ORIGIN').strip() \
        or f'https://{rp_id()}'


def rp_name() -> str:
    return stores.env('WEBAUTHN_RP_NAME').strip() \
        or 'VNC Remote Secure'


def begin_registration(actor: str, username: str) -> dict:
    """PublicKeyCredentialCreationOptions for *username*.

    Self-service only + step-up — a session older than the step-up
    window cannot mint new auth factors.
    """
    _gate_feature()
    if username != actor:
        raise UseCaseError(
            ERR_PERMISSION,
            'passkey registration is self-service only')
    _gate_step_up(actor, 'webauthn_register')
    _audit('passkey_register_begin', actor, f'target={username}')
    return stores.webauthn_begin(username, rp_id(), rp_name())


def complete_registration(actor: str, username: str, credential: dict,
                          name: str) -> None:
    """Verify the attestation and persist the credential."""
    _gate_feature()
    if username != actor:
        raise UseCaseError(
            ERR_PERMISSION,
            'passkey registration is self-service only')
    if not isinstance(credential, dict) or 'id' not in credential:
        raise UseCaseError(ERR_INVALID, 'credential object required')
    ok, message = stores.webauthn_complete(
        username, credential, rp_id(), webauthn_origin(), name=name[:64])
    if not ok:
        raise UseCaseError(ERR_INVALID, message)
    _audit('passkey_registered', actor, f'target={username}')


def gate_manage(actor: str, actor_perms: set, username: str) -> None:
    """Rename/revoke: the owner, or an admin_users operator."""
    if username != actor and 'admin_users' not in actor_perms \
            and 'admin:*' not in actor_perms:
        raise UseCaseError(
            ERR_PERMISSION,
            'managing another operator\'s passkeys requires admin_users')


def rename_passkey(actor: str, actor_perms: set, username: str,
                   ref: str, name: str) -> None:
    """Rename a credential (metadata only — no cryptographic effect)."""
    gate_manage(actor, actor_perms, username)
    cid = _resolve_ref(username, ref)
    if cid is None:
        raise UseCaseError(ERR_NOT_FOUND, 'passkey not found')
    if len(name) > 64:
        raise UseCaseError(ERR_INVALID, 'name too long')
    if not stores.credential_rename(cid, name):
        raise UseCaseError(ERR_NOT_FOUND, 'passkey not found')
    _audit('passkey_renamed', actor, f'target={username} ref={ref}')


def delete_passkey(actor: str, actor_perms: set, username: str,
                   ref: str) -> None:
    """Remove a credential. The account must keep a usable auth
    method: refusing the last passkey when MFA is required and no TOTP
    fallback exists prevents lockout."""
    gate_manage(actor, actor_perms, username)
    _gate_step_up(actor, 'webauthn_revoke')
    cid = _resolve_ref(username, ref)
    if cid is None:
        raise UseCaseError(ERR_NOT_FOUND, 'passkey not found')
    remaining = [c for c in stores.credential_list(username)
                 if c['credential_id'] != cid]
    if not remaining:
        # Last passkey — is another auth method still usable?
        rec = stores.operator_load_store().get(username)
        has_password = bool(
            rec and rec.get('password_hash')) or (
            username == 'admin' and stores.env('LANDING_PASSWORD'))
        try:
            mfa_ok = not stores.mfa_required() or stores.mfa_available()
        except Exception:  # noqa: BLE001 - assume MFA may be required
            mfa_ok = False
        if not has_password or not mfa_ok:
            _audit('api_permission_denied', actor,
                   f'last passkey removal refused for {username}')
            raise UseCaseError(
                ERR_LAST_ADMIN,
                'refused: removing the last passkey would leave the '
                'account without a usable second factor')
    if not stores.credential_delete(cid, username):
        raise UseCaseError(ERR_CONFLICT, 'passkey delete failed')
    _audit('passkey_revoked', actor, f'target={username} ref={ref}')
