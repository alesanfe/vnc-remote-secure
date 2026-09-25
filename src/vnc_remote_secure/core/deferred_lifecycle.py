"""Deferred lifecycle runner — lets the REST API run
``start``/``stop``/``restart`` on the service set even when the
portal service itself is one of the targets.

The API route spawns this module as a *detached* child
(``python -m vnc_remote_secure.core.deferred_lifecycle <action>
[delay_s]``), answers the request, and the child sleeps ``delay_s``
before touching the service manager — so the HTTP response is
already on the wire when ``stop``/``restart`` kills the portal
process that spawned it.

On Windows the child gets ``CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS``;
on POSIX ``start_new_session=True`` — either way it survives the
parent's exit and stdio never holds the parent's console/sockets open.
"""
import logging
import os
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

_ACTIONS = ('start', 'stop', 'restart')
_DEFAULT_DELAY = 1.5


def spawn_lifecycle(action: str, delay: float = _DEFAULT_DELAY) -> int:
    """Spawn the detached deferred runner; returns its PID.

    Raises ``ValueError`` on an unknown action and ``OSError`` if the
    child cannot be spawned. The caller answers HTTP while this child
    waits out the delay, then runs the lifecycle action.
    """
    if action not in _ACTIONS:
        raise ValueError(f'action must be one of {_ACTIONS}')
    cmd = [sys.executable, '-m',
           'vnc_remote_secure.core.deferred_lifecycle',
           action, f'{delay:.2f}']
    devnull = open(os.devnull, 'rb')  # noqa: SIM115 - child's stdin lives past us
    kwargs = {
        'stdin': devnull,
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.DEVNULL,
        'close_fds': True,
    }
    if os.name == 'nt':
        kwargs['creationflags'] = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS)
    else:
        kwargs['start_new_session'] = True
    proc = subprocess.Popen(cmd, **kwargs)  # noqa: S603
    logger.info('Deferred lifecycle %s spawned (pid %s, delay %ss)',
                action, proc.pid, delay)
    return proc.pid


def run_action(action: str) -> int:
    """Run the lifecycle action in THIS process (after the delay)."""
    if action == 'stop':
        from vnc_remote_secure.core.service_manager import stop_all
        results = stop_all()
        return 0 if 'error' not in results else 1
    if action == 'restart':
        from vnc_remote_secure.core.lifecycle import startup
        from vnc_remote_secure.core.service_manager import restart_all
        from vnc_remote_secure.security.profiles import get_blocking_findings
        startup()
        if get_blocking_findings():
            logger.error('Deferred restart refused: blocking findings')
            return 1
        results = restart_all()
        return 0 if all(results.values()) else 1
    # action == 'start' — idempotent; starts whatever is down.
    from vnc_remote_secure.core.lifecycle import startup
    from vnc_remote_secure.core.service_manager import start_all
    from vnc_remote_secure.security.profiles import get_blocking_findings
    startup()
    if get_blocking_findings():
        logger.error('Deferred start refused: blocking findings')
        return 1
    results = start_all()
    return 0 if all(results.values()) else 1


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) < 1 or argv[0] not in _ACTIONS:
        print(f'Usage: python -m {__name__} '
              f'<{"|".join(_ACTIONS)}> [delay_s]')
        return 2
    action = argv[0]
    try:
        delay = float(argv[1]) if len(argv) > 1 else _DEFAULT_DELAY
    except ValueError:
        delay = _DEFAULT_DELAY
    # Bound the delay — a huge value would keep a hidden process
    # parked on the host for days.
    delay = max(0.0, min(delay, 60.0))
    logging.basicConfig(level=logging.INFO)
    time.sleep(delay)
    return run_action(action)


if __name__ == '__main__':
    raise SystemExit(main())
