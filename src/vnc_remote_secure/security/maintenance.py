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


def _boot_id() -> str | None:
    """Boot-scoped identifier for comparing monotonic deadlines.

    ``time.monotonic()`` epochs are only comparable within the same
    boot. Linux exposes a random boot id; elsewhere psutil's boot_time
    is a surrogate. None means "unknown" — the caller must then ignore
    the monotonic bound rather than compare epochs across boots.
    """
    try:
        with open('/proc/sys/kernel/random/boot_id',
                  encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        pass
    try:
        import psutil
        return f'boottime:{psutil.boot_time()}'
    except ImportError:
        return None
    except Exception:  # noqa: BLE001
        return None


def _read_flag() -> dict:
    try:
        return json.loads(Path(_flag_path()).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


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
    # Stale generation keys would accumulate one pair per window —
    # clean them when a new window opens.
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        for key in be.list_keys('maintenance', prefix='drain_'):
            be.delete('maintenance', key)
    except Exception:  # noqa: BLE001 - marker cleanup is best-effort
        pass
    if active:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        import secrets as _secrets
        data: dict = {
            'by': by,
            'since': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'reason': reason,
            # Per-window id: a sweeper from maintenance window A can
            # never mark window B as drained — drain completion is
            # recorded against THIS generation.
            'maintenance_id': _secrets.token_hex(8),
        }
        if drain_at is not None:
            data['drain_at'] = drain_at
            data['drain_mono'] = (time.monotonic()
                                  + (drain_at - time.time()))
            data['boot_id'] = _boot_id()
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
    data = _read_flag()
    drain_at = data.get('drain_at')
    if isinstance(drain_at, (int, float)) and time.time() >= drain_at:
        return True
    drain_mono = data.get('drain_mono')
    # The monotonic bound is only valid within the same boot —
    # comparing epochs across a restart would deny sessions early or
    # extend the grace period arbitrarily.
    if (isinstance(drain_mono, (int, float)) and drain_mono >= 0
            and data.get('boot_id') and data['boot_id'] == _boot_id()):
        return time.monotonic() >= drain_mono
    return False


def enforce_drain_deadline() -> bool:
    """When the deadline passed, materialize the drain exactly once
    per maintenance generation.

    Completion is recorded against ``maintenance_id`` — a sweeper
    from an older window cannot mark a NEW window done, and a window
    already swept skips the revocation entirely (no repeated sweeps
    for the rest of the maintenance period). The claim is a 30s
    lease: an executor that dies mid-sweep leaves no false "done",
    and the next checker retries. ``drain_sessions()`` is idempotent,
    so a duplicate sweep is harmless while a skipped one is not.

    Returns True whenever the deadline is reached (drained or
    actively draining).
    """
    if not drain_deadline_passed():
        return False
    mid = _read_flag().get('maintenance_id', '')
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        if mid and be.get('maintenance', f'drain_done:{mid}'):
            return True  # this generation already swept
        # The lease AND the done-marker are generation-scoped — a
        # sweeper from an older window can't claim or complete this
        # one, and a stale lease never blocks a new generation.
        if be.set_if_absent('maintenance', f'drain_lease:{mid}', '1',
                            ttl_seconds=30):
            # Re-validate right before the destructive effect: the
            # window may have been cancelled (or a NEW window opened)
            # between the lease claim and now — a sweeper for a dead
            # generation must not revoke sessions.
            if _read_flag().get('maintenance_id', '') != mid:
                logger.info('Drain aborted: maintenance generation '
                            'changed before the sweep')
                return True
            n = drain_sessions()
            # Confirm the generation once more before recording
            # completion — a swap between the sweep and this write
            # would otherwise stamp "done" onto a different window.
            if _read_flag().get('maintenance_id', '') == mid:
                # TTL bounds the marker — a generation's record needn't
                # outlive the deployment's maintenance cadence.
                be.set_ttl('maintenance', f'drain_done:{mid}', '1',
                           30 * 86400)
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
