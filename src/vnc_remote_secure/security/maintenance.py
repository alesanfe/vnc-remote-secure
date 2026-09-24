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
                    reason: str = '') -> None:
    """Toggle maintenance mode via the runtime flag file."""
    path = _flag_path()
    if active:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            'by': by,
            'since': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'reason': reason,
        }), encoding='utf-8')
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


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
