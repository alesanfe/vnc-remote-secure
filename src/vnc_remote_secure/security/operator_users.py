"""Multi-operator user store with role-based permissions.

Replaces the single-credential operator model (env password = full
admin) with per-operator accounts carrying a role:

- ``admin``    — ``admin:*`` (all administrative permissions)
- ``operator`` — ``admin_sessions`` + ``admin_audit`` (session
                 lifecycle, gamepad kill-switch, audit viewing)
- ``viewer``   — read-only portal access, no mutations

The env-configured credentials keep working as the bootstrap
``admin`` account so existing deployments are not locked out — the
store is checked first and env acts as the fallback.

Store: ``<data_dir>/operator_users.json`` — ``0o600``, atomic
tmp+rename writes, survives restarts (unlike run-dir session state).
"""
import hashlib
import json
import logging
import os
import time

from vnc_remote_secure.core.paths import get_data_dir

logger = logging.getLogger(__name__)

# Role -> permission set. `admin:*` is the umbrella expanded by
# _permissions_for; viewer gets the empty set (read-only surface).
ROLE_PERMISSIONS = {
    'admin': {'admin:*'},
    'operator': {'admin_sessions', 'admin_audit'},
    'viewer': set(),
}

# Permissions the admin umbrella expands into. Kept explicit so a
# new sensitive capability is NOT silently granted to admin — the
# permission must be registered here AND enforced at its endpoint.
ADMIN_PERMISSIONS = {
    'admin_users',
    'admin_config',
    'admin_audit',
    'admin_sessions',
}

_VALID_USERNAME_LEN = (1, 64)


def _store_path() -> str:
    """Return the operator store path (data dir — persistent state)."""
    return os.path.join(get_data_dir(), 'operator_users.json')


def load_store() -> dict:
    """Load the store; a corrupt file fails closed (empty store)."""
    try:
        with open(_store_path(), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    """Write the store atomically with owner-only permissions."""
    path = _store_path()
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        # No-op on Windows (ACLs handled separately); on POSIX a
        # failed chmod leaves the credential store world-readable.
        logger.debug(
            'Could not restrict %s to 0o600: %s', path, exc)


# Current password-hash policy. New hashes are Argon2id
# (argon2-cffi PHC format); legacy ``pbkdf2:`` hashes verify and are
# transparently rehashed on the next successful login
# (rehash-on-login), so the migration needs no password reset.
_PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Hash ``password`` as an ``$argon2id$`` PHC string.

    Falls back to the legacy pbkdf2 format only when argon2-cffi is
    unavailable — argon2-cffi is a declared dependency, so the
    fallback exists to keep minimal/test environments importable.
    """
    try:
        from argon2 import PasswordHasher
        return PasswordHasher().hash(password)
    except ImportError:  # pragma: no cover - dependency missing
        salt = os.urandom(16).hex()
        dk = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt.encode('utf-8'),
            _PBKDF2_ITERATIONS)
        return f'pbkdf2:sha256:{_PBKDF2_ITERATIONS}${salt}${dk.hex()}'


_DUMMY_ARGON2 = None


def _dummy_hash() -> str:
    """A constant-cost hash for unknown-user verification.

    Verifying a real argon2id hash (not skipping the KDF) keeps the
    timing envelope identical for existent and nonexistent accounts.
    """
    global _DUMMY_ARGON2
    if _DUMMY_ARGON2 is None:
        import secrets as _secrets
        _DUMMY_ARGON2 = hash_password(_secrets.token_urlsafe(16))
    return _DUMMY_ARGON2


def _stored_iterations(stored: str) -> int:
    """Return the iteration count of a ``pbkdf2:sha256:N$…`` hash."""
    try:
        scheme = stored.split('$', 1)[0]
        parts = scheme.split(':')
        if parts[0] != 'pbkdf2' or len(parts) != 3:
            return 0
        return int(parts[2])
    except (ValueError, IndexError):
        return 0


def _valid_username(username: str) -> bool:
    """Restrict usernames — they land in audit logs and API output."""
    if not isinstance(username, str):
        return False
    if not (_VALID_USERNAME_LEN[0] <= len(username)
            <= _VALID_USERNAME_LEN[1]):
        return False
    return all(c.isalnum() or c in '._-@' for c in username)


def add_user(username: str, password: str, role: str) -> None:
    """Add an operator account. Raises ``ValueError`` on bad input."""
    if not _valid_username(username):
        raise ValueError(
            'Username must be 1-64 chars of [a-zA-Z0-9._-@]')
    if role not in ROLE_PERMISSIONS:
        raise ValueError(
            f'Unknown role {role!r} — expected one of '
            + ', '.join(sorted(ROLE_PERMISSIONS)))
    if not password:
        raise ValueError('Password must not be empty')
    data = load_store()
    if username in data:
        raise ValueError(f'Operator {username!r} already exists')
    data[username] = {
        'password_hash': hash_password(password),
        'role': role,
        'disabled': False,
        'created_at': int(time.time()),
    }
    _save(data)


def remove_user(username: str) -> bool:
    """Remove an operator account; returns True when it existed."""
    data = load_store()
    if username not in data:
        return False
    del data[username]
    _save(data)
    return True


def _mark_sessions_revoked(username: str) -> None:
    """Invalidate every vnc_op session issued for ``username``.

    The shared ``op_revoked_users`` mark is compared against each
    cookie's issue time (exp - TTL) at verification — password, role
    and disable changes kill the operator's live sessions without
    enumerating them. Best-effort: a backend outage must not block
    the account mutation itself.
    """
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().set_ttl(
            'op_revoked_users', username, str(time.time()),
            86400 * 30)
    except Exception:  # noqa: BLE001
        pass


def set_password(username: str, password: str) -> bool:
    """Replace an operator's password; False when unknown."""
    data = load_store()
    if username not in data:
        return False
    data[username]['password_hash'] = hash_password(password)
    _save(data)
    _mark_sessions_revoked(username)
    return True


def set_role(username: str, role: str) -> bool:
    """Change an operator's role; False when unknown user/role."""
    if role not in ROLE_PERMISSIONS:
        return False
    data = load_store()
    if username not in data:
        return False
    data[username]['role'] = role
    _save(data)
    _mark_sessions_revoked(username)
    return True


def set_disabled(username: str, disabled: bool) -> bool:
    """Disable/enable an account without deleting it."""
    data = load_store()
    if username not in data:
        return False
    data[username]['disabled'] = bool(disabled)
    _save(data)
    _mark_sessions_revoked(username)
    return True


def list_users() -> list:
    """Return ``[{username, role, disabled, created_at}]`` — no hashes."""
    return [
        {'username': name,
         'role': rec.get('role', 'viewer'),
         'disabled': bool(rec.get('disabled')),
         'created_at': rec.get('created_at')}
        for name, rec in sorted(load_store().items())
    ]


def _permissions_for(role: str) -> set:
    """Expand a role into concrete permissions (umbrella included)."""
    perms = set(ROLE_PERMISSIONS.get(role, set()))
    if 'admin:*' in perms:
        perms |= ADMIN_PERMISSIONS
    return perms


def verify(username: str, password: str):
    """Verify credentials; return the user record or ``None``.

    Exactly one pbkdf2 verification runs per attempt — a fast
    early-return on an unknown username would leak account existence
    through timing.
    """
    rec = load_store().get(username)
    stored = (rec or {}).get('password_hash') or _dummy_hash()
    from vnc_remote_secure.security.credentials import verify_password
    ok = verify_password(password, stored)
    if not ok or rec is None or rec.get('disabled'):
        return None
    # Rehash-on-login: a legacy pbkdf2/scrypt hash (or a pbkdf2 hash
    # minted under a weaker iteration policy) is upgraded to the
    # current Argon2id format while the plaintext is still in hand.
    needs_rehash = not stored.startswith('$argon2')
    if not needs_rehash:
        try:
            from argon2 import PasswordHasher
            needs_rehash = PasswordHasher().check_needs_rehash(stored)
        except Exception:  # noqa: BLE001 - unknown params → keep hash
            needs_rehash = False
    if needs_rehash:
        try:
            data = load_store()
            if username in data:
                data[username]['password_hash'] = hash_password(password)
                _save(data)
                logger.info(
                    'Upgraded password hash for %r to argon2id',
                    username)
        except OSError:
            # Rehash is best-effort — the login already succeeded; a
            # read-only store must not lock the operator out.
            logger.debug('Could not rehash password for %r', username)
    return {'username': username,
            'role': rec.get('role', 'viewer'),
            'permissions': sorted(_permissions_for(
                rec.get('role', 'viewer')))}


def get_permissions(username: str) -> set:
    """Return the permission set for a stored operator.

    The built-in env-authenticated operator is always ``admin`` —
    deployments without a store keep full access (bootstrap path).
    """
    rec = load_store().get(username)
    if rec is None:
        # Env-credential fallback authenticates as the built-in admin
        # under whatever username the env config defines.
        return _permissions_for('admin')
    if rec.get('disabled'):
        return set()
    return _permissions_for(rec.get('role', 'viewer'))


def has_permission(username: str, permission: str) -> bool:
    """Return True when ``username`` holds ``permission`` (or ``admin:*``)."""
    return permission in get_permissions(username)

