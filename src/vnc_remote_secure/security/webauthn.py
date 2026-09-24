"""WebAuthn/passkey support — phishing-resistant second factor and
passwordless login for operator/admin accounts.

Design:

- Optional dependency: the ``webauthn`` package (``pip install
  vnc-remote-secure[webauthn]``). Without it every entry point
  reports unavailable; ``WEBAUTHN_ENABLED=true`` is required either
  way, so deployments opt in explicitly.
- Credentials persist in ``<data_dir>/webauthn_credentials.json``
  (0600): credential id -> public key, sign counter, transports,
  friendly name, owner.
- Ceremony challenges live in the shared-state backend
  (``webauthn_challenges`` namespace, 120 s TTL, single-use) so a
  challenge issued by one process verifies in another and cannot be
  replayed.
- ``sign_count`` regression is treated as a cloned authenticator and
  rejected per the WebAuthn spec.
"""

import base64
import binascii
import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.paths import get_data_dir

logger = logging.getLogger(__name__)

_CHALLENGE_NS = 'webauthn_challenges'
_CHALLENGE_TTL = 120  # seconds


def webauthn_available() -> bool:
    """True when the feature is enabled AND the library imports."""
    if not env_flag('WEBAUTHN_ENABLED'):
        return False
    try:
        import webauthn  # noqa: F401
        return True
    except ImportError:
        return False


def _public_or_proxied() -> bool:
    """True when the deployment sits behind a proxy or is hardened.

    Inferred ``WEBAUTHN_ORIGIN``/``WEBAUTHN_RP_ID`` (from request Host
    and url_root) are only safe when the app terminates connections
    directly on a trusted host. Behind a reverse proxy or under a
    hardened profile, Host/scheme are attacker-influenceable, so
    explicit configuration is mandatory.
    """
    if env_flag('TRUSTED_PROXY'):
        return True
    try:
        from vnc_remote_secure.security.profiles import _PROFILE_ALIASES, get_profile
        profile = _PROFILE_ALIASES.get(get_profile(), get_profile())
        return profile in ('public-hardened', 'private-overlay',
                           'trusted-lan')
    except Exception:  # noqa: BLE001 - unknown profile → don't enforce
        return False


def rp_config_error() -> str | None:
    """Error string when inferred RP config is unsafe, else None."""
    if not webauthn_available() or not _public_or_proxied():
        return None
    missing = [v for v in ('WEBAUTHN_ORIGIN', 'WEBAUTHN_RP_ID')
               if not os.environ.get(v, '').strip()]
    if not missing:
        return None
    return ('WebAuthn behind a reverse proxy or hardened profile '
            f'requires explicit {"/".join(missing)} — refusing to '
            'infer origin/RP ID from request data.')


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def _b64d(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# ------------------------------------------------------------------
# Credential store
# ------------------------------------------------------------------

def _store_path() -> str:
    return os.path.join(get_data_dir(), 'webauthn_credentials.json')


_STORE_FORMAT_VERSION = 1


@contextlib.contextmanager
def _store_lock():
    """Cross-process lock for store read-modify-write.

    ``_save_store`` writes atomically, but atomicity alone doesn't
    stop two services from interleaving load→mutate→save (lost
    update: the second writer silently drops the first's credential).
    flock/msvcrt serialise the critical section; the lock file lives
    next to the store so it follows the same isolation in tests.
    """
    lock_path = _store_path() + '.lock'
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT)
    try:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == 'nt':
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _load_store() -> dict:
    path = Path(_store_path())
    if path.is_symlink():
        # A symlinked credential store is a redirection attack —
        # refuse to follow it rather than read attacker-chosen data.
        logger.warning('Refusing symlinked WebAuthn store: %s', path)
        return {}
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    # Versioned envelope since format v1; tolerate a bare legacy map
    # (credential_id -> record) written before versioning existed.
    if isinstance(raw, dict) and 'credentials' in raw:
        creds = raw.get('credentials')
        return creds if isinstance(creds, dict) else {}
    return raw if isinstance(raw, dict) else {}


def _save_store(store: dict) -> None:
    """Atomically persist the credential store.

    write_text() truncates before writing — a crash mid-write used to
    leave a torn file that loads as empty, silently de-registering
    every passkey. Write to a sibling temp file, fsync, then rename.
    """
    import tempfile
    path = Path(_store_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {'format_version': _STORE_FORMAT_VERSION,
         'credentials': store}, indent=2)
    if path.is_symlink():
        raise RuntimeError(
            f'Refusing to write WebAuthn store through symlink: {path}')
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix='.webauthn-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:  # Windows ACLs handled by _restrict_key_permissions
        from vnc_remote_secure.security.certificates import _restrict_key_permissions
        _restrict_key_permissions(str(path), writable=True)


def list_credentials(username: str) -> list:
    """Public view of *username*'s credentials (no public keys)."""
    return [
        {'credential_id': cid, 'name': rec.get('name', ''),
         'created_at': rec.get('created_at', ''),
         'sign_count': rec.get('sign_count', 0)}
        for cid, rec in _load_store().items()
        if rec.get('username') == username
    ]


def delete_credential(credential_id: str, username: str) -> bool:
    """Remove a credential owned by *username*. Returns True if deleted."""
    with _store_lock():
        store = _load_store()
        rec = store.get(credential_id)
        if not rec or rec.get('username') != username:
            return False
        del store[credential_id]
        _save_store(store)
    return True


def _user_credentials(username: str) -> dict:
    return {cid: rec for cid, rec in _load_store().items()
            if rec.get('username') == username}


# ------------------------------------------------------------------
# Ceremony challenges (shared-state, single-use, TTL-bound)
# ------------------------------------------------------------------

def _put_challenge(purpose: str, username: str, challenge: bytes) -> None:
    from vnc_remote_secure.security.shared_state import get_backend
    get_backend().set_ttl(
        _CHALLENGE_NS, f'{purpose}:{username}', _b64e(challenge),
        _CHALLENGE_TTL)


def _pop_challenge(purpose: str, username: str) -> bytes | None:
    """Return and consume the pending challenge (single-use)."""
    from vnc_remote_secure.security.shared_state import get_backend
    key = f'{purpose}:{username}'
    raw = get_backend().get(_CHALLENGE_NS, key)
    if raw is None:
        return None
    try:
        get_backend().delete(_CHALLENGE_NS, key)
    except Exception:  # noqa: BLE001 - consumed either way
        pass
    try:
        return _b64d(raw)
    except (binascii.Error, ValueError):
        return None


# ------------------------------------------------------------------
# Registration ceremony
# ------------------------------------------------------------------

def begin_registration(username: str, display_name: str,
                       rp_id: str, rp_name: str) -> dict:
    """Build PublicKeyCredentialCreationOptions for *username*."""
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )
    exclude = []
    for cid in _user_credentials(username):
        try:
            exclude.append(PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=_b64d(cid)))
        except (binascii.Error, ValueError):
            # A hand-edited store may carry undecodable ids — skip
            # them rather than break the whole ceremony.
            continue
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=username.encode('utf-8'),
        user_name=username,
        user_display_name=display_name or username,
        exclude_credentials=exclude,
    )
    _put_challenge('register', username, options.challenge)
    return json.loads(options_to_json(options))


def complete_registration(username: str, credential: dict,
                          rp_id: str, origin: str,
                          name: str = '') -> tuple[bool, str]:
    """Verify an attestation and persist the credential."""
    challenge = _pop_challenge('register', username)
    if challenge is None:
        return False, 'No registration in progress or it expired.'
    from webauthn import verify_registration_response
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as exc:  # noqa: BLE001 - verification failure = deny
        logger.warning('WebAuthn registration rejected: %s', exc)
        return False, 'Registration verification failed.'
    cid = _b64e(verification.credential_id)
    with _store_lock():
        store = _load_store()
        if cid in store:
            return False, 'Credential already registered.'
        store[cid] = {
            'username': username,
            'public_key': _b64e(verification.credential_public_key),
            'sign_count': verification.sign_count,
            'name': name,
            'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                        time.gmtime()),
        }
        _save_store(store)
    from vnc_remote_secure.security.audit import audit_event
    audit_event('webauthn_register', user=username,
                detail=f'credential={cid[:12]}')
    return True, 'Passkey registered.'


# ------------------------------------------------------------------
# Authentication ceremony
# ------------------------------------------------------------------

def begin_authentication(username: str, rp_id: str) -> dict | None:
    """Build PublicKeyCredentialRequestOptions, or None when the
    user holds no credentials."""
    creds = _user_credentials(username)
    if not creds:
        return None
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )
    allow = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=_b64d(cid))
        for cid in creds
    ]
    options = generate_authentication_options(
        rp_id=rp_id, allow_credentials=allow)
    _put_challenge('assert', username, options.challenge)
    return json.loads(options_to_json(options))


@dataclass(frozen=True)
class AssertionResult:
    """Outcome of a WebAuthn authentication ceremony."""
    ok: bool
    message: str
    user_verified: bool = False  # ceremony UV — False on failure too
    credential_id: str | None = None


def complete_authentication(username: str, credential: dict,
                            rp_id: str, origin: str) -> AssertionResult:
    """Verify an assertion. Clone detection via sign_count regression.

    ``user_verified`` comes from the ceremony itself — a passkey login
    where the authenticator skipped UV is distinguishable from one
    that verified the user.
    """
    challenge = _pop_challenge('assert', username)
    if challenge is None:
        return AssertionResult(
            False, 'No authentication in progress or it expired.')
    cred_id = credential.get('id', '')
    rec = _load_store().get(cred_id)
    if not rec or rec.get('username') != username:
        return AssertionResult(False, 'Unknown credential.')
    from webauthn import verify_authentication_response
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=_b64d(rec['public_key']),
            credential_current_sign_count=int(
                rec.get('sign_count', 0)),
        )
    except Exception as exc:  # noqa: BLE001 - verification failure = deny
        logger.warning('WebAuthn assertion rejected: %s', exc)
        return AssertionResult(False, 'Authentication verification failed.')
    uv = bool(getattr(verification, 'user_verified', False))
    with _store_lock():
        store = _load_store()
        if cred_id in store:
            store[cred_id]['sign_count'] = verification.new_sign_count
            _save_store(store)
    from vnc_remote_secure.security.audit import audit_event
    audit_event('webauthn_assert', user=username,
                detail=f'credential={cred_id[:12]} uv={uv}')
    return AssertionResult(True, 'Authenticated.', user_verified=uv,
                           credential_id=cred_id)
