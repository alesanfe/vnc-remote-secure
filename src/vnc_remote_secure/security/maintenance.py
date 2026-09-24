"""Maintenance mode — drain new non-admin access without a restart.

While active:

- New share-link activations are denied (``activate_ephemeral_session``
  and ``consume_ephemeral_session`` fail closed).
- New logins are denied unless the account can administer the
  deployment (operator-store accounts and the env bootstrap admins).
- Existing sessions keep working — maintenance mode blocks *new*
  sessions; operators drain or revoke the rest explicitly.

Activation sources, first match wins:

- ``MAINTENANCE_MODE=true`` — env-level, e.g. set in the systemd unit
  before an upgrade window.
- A flag file ``<run_dir>/maintenance.json`` written by
  ``vnc-remote maintenance on`` — runtime toggle, no restart needed.
"""

import json
import logging
import os
import time
from pathlib import Path

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.paths import get_run_dir

logger = logging.getLogger(__name__)

_FLAG_NAME = 'maintenance.json'


def _flag_path() -> str:
    return os.path.join(get_run_dir(), _FLAG_NAME)


def maintenance_active() -> bool:
    """True when maintenance mode is on via env or the flag file."""
    if env_flag('MAINTENANCE_MODE'):
        return True
    try:
        return os.path.exists(_flag_path())
    except OSError:
        return False


def maintenance_info() -> dict | None:
    """Describe the active maintenance state, or None when inactive."""
    if env_flag('MAINTENANCE_MODE'):
        return {'source': 'env', 'by': None, 'since': None, 'reason': ''}
    try:
        data = json.loads(Path(_flag_path()).read_text(encoding='utf-8'))
        data['source'] = 'flag-file'
        return data
    except (OSError, ValueError):
        return None


def set_maintenance(active: bool, by: str = 'cli',
                    reason: str = '',
                    drain_at: float | None = None) -> None:
    """Toggle maintenance mode via the runtime flag file.

    ``drain_at`` (epoch seconds) schedules a deferred drain: existing
    ephemeral sessions stay valid until the deadline, then fail
    closed. A monotonic bound is stored alongside — a backward wall
    clock must not extend the grace period (same defence as session
    expiry). ``drain_mono`` is comparable across processes within the
    same boot; after a reboot it degrades to wall-clock only.
    """
    path = _flag_path()
    # A fresh maintenance window must drain again — clear the
    # "already swept" claim so enforce_drain_deadline() fires.
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().delete('maintenance', 'drain_done')
    except Exception:  # noqa: BLE001 - marker cleanup is best-effort
        pass
    if active:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        data: dict = {
            'by': by,
            'since': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'reason': reason,
        }
        if drain_at is not None:
            data['drain_at'] = drain_at
            data['drain_mono'] = (time.monotonic()
                                  + (drain_at - time.time()))
        Path(path).write_text(json.dumps(data), encoding='utf-8')
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def drain_deadline_passed() -> bool:
    """True when a scheduled drain deadline has been reached.

    Either bound suffices — wall clock catches forward skew, the
    same-boot monotonic bound catches backward skew (a wound-back
    clock must not extend the grace period).
    """
    try:
        data = json.loads(Path(_flag_path()).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    drain_at = data.get('drain_at')
    if isinstance(drain_at, (int, float)) and time.time() >= drain_at:
        return True
    drain_mono = data.get('drain_mono')
    if isinstance(drain_mono, (int, float)) and drain_mono >= 0:
        return time.monotonic() >= drain_mono
    return False


def enforce_drain_deadline() -> bool:
    """When the deadline passed, materialize the drain exactly once.

    The first process to notice claims a shared-state marker and
    revokes every active session — that propagates to live WebSocket
    connections via the registry, so "grace → force" actually closes
    streams instead of only denying the next permission check.
    Returns True whenever the deadline is reached (drained or
    actively draining).
    """
    if not drain_deadline_passed():
        return False
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        # The claim is a LEASE, not a completion record: it expires in
        # 30s. An executor that claims and dies before revoking leaves
        # no false "done" marker — the next process to check retries
        # the sweep. drain_sessions() is idempotent, so a duplicate
        # sweep is harmless while a skipped one is not.
        if get_backend().set_if_absent(
                'maintenance', 'drain_done', '1', ttl_seconds=30):
            n = drain_sessions()
            logger.info('Maintenance drain deadline reached — '
                        'revoked %d ephemeral session(s)', n)
    except Exception:  # noqa: BLE001 - deny regardless of sweep result
        logger.warning('Drain sweep failed; sessions still denied',
                       exc_info=True)
    return True


def drain_sessions() -> int:
    """Revoke every active ephemeral share session.

    ``vnc-remote maintenance on --drain``: maintenance mode alone
    blocks NEW sessions but lets existing share links live out their
    TTL — draining is the explicit kill for upgrades where "keep
    working until expiry" is not acceptable. Revocation propagates to
    live WebSocket connections through the shared-state backend.
    Operator/admin accounts are unaffected: they authenticate via
    credentials, not share links.

    Returns the number of sessions revoked.
    """
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store, revoke_session
    store = get_session_store()
    store._load_if_changed()
    count = 0
    for s in store.list_active():
        if revoke_session(s['token_id']):
            count += 1
    return count


def maintenance_login_allowed(username: str) -> bool:
    """True when *username* may start a new session in maintenance.

    Only accounts that can administer the deployment get in: stored
    operator accounts (any permission set) and the env bootstrap
    admins. Everyone else — including share-link guests, who never
    reach this function — is refused.
    """
    if not maintenance_active():
        return True
    username = str(username)
    try:
        from vnc_remote_secure.security.operator_users import get_permissions
        if get_permissions(username):
            return True
    except Exception:  # noqa: BLE001 - fall through to env admins
        logger.debug('Operator store unavailable during maintenance '
                     'check', exc_info=True)
    env_admins = {
        os.environ.get('USER_UI_USERNAME', ''),
        os.environ.get('TTYD_USERNAME', ''),
    }
    env_admins.discard('')
    return username in env_admins
