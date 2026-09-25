"""Deferred job runner — detached executor for destructive API ops.

``POST /api/v1/lifecycle`` / ``/backups/restore`` / ``/upgrade*``
persist a *queued* job on the shared-state backend BEFORE answering,
then spawn this module as a detached child
(``python -m vnc_remote_secure.core.deferred_lifecycle run <job_id>
[delay_s]``). The child:

1. sleeps ``delay_s`` — a courtesy so the 202 response is flushed
   before ``stop``/``restart`` can kill the portal serving it;
2. **claims** the job (atomic ``set_if_absent`` — a retried or
   double-spawned runner exits without re-running the operation);
3. executes the persisted payload and reports progress/result on the
   job record — the operator watches it in the jobs panel even when
   the portal process died mid-run;
4. releases the ``destructive`` op-class lock.

The *persisted job* is the guarantee — the delay only covers the
response flush. If the portal dies instantly the child still runs
because it was already detached.

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
# Mutex shared by every destructive op class — lifecycle, restore and
# upgrade must never overlap.
_OP_LOCK = 'destructive'


def spawn_job_runner(jid: str, delay: float = _DEFAULT_DELAY) -> int:
    """Spawn the detached runner for a queued job; returns its PID.

    Raises ``OSError`` if the child cannot be spawned. The job must
    already be persisted — the child claims it by id.
    """
    from vnc_remote_secure.core.test_isolation import guard_spawn
    guard_spawn('lifecycle runner')
    cmd = [sys.executable, '-m',
           'vnc_remote_secure.core.deferred_lifecycle',
           'run', jid, f'{delay:.2f}']
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
    logger.info('Deferred job runner spawned (pid %s, job %s)',
                proc.pid, jid)
    return proc.pid


# ---------------------------------------------------------------------------
# Payload execution
# ---------------------------------------------------------------------------

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
    if action != 'start':
        return 2
    # 'start' — idempotent; starts whatever is down.
    from vnc_remote_secure.core.lifecycle import startup
    from vnc_remote_secure.core.service_manager import start_all
    from vnc_remote_secure.security.profiles import get_blocking_findings
    startup()
    if get_blocking_findings():
        logger.error('Deferred start refused: blocking findings')
        return 1
    results = start_all()
    return 0 if all(results.values()) else 1


def _exec_lifecycle(payload: dict, progress) -> tuple[bool, str]:
    action = str(payload.get('action', ''))
    progress('service_manager', f'lifecycle {action}', pct=40)
    rc = run_action(action)
    return rc == 0, f'lifecycle {action} rc={rc}'


def _exec_restore(payload: dict, progress) -> tuple[bool, str]:
    path = str(payload.get('path', ''))
    if not path:
        return False, 'empty backup path'
    progress('preflight', f'reading {os.path.basename(path)}',
             pct=20)
    from vnc_remote_secure.core.backup import restore_backup
    ok = bool(restore_backup(path))
    progress('restore', f'{os.path.basename(path)} restored={ok}',
             pct=90)
    return ok, f'restored={os.path.basename(path)}' if ok else \
        'restore failed'


def _exec_upgrade(payload: dict, progress) -> tuple[bool, str]:
    source = payload.get('source') or None
    progress('preflight', 'backup + download', pct=15)
    from vnc_remote_secure.core.upgrader import perform_upgrade
    result = perform_upgrade(source)
    return bool(result.get('ok')), (
        f"{result.get('previous', '?')} → {result.get('version', '?')}"
        if result.get('ok') else str(result.get('error', 'failed')))


def _exec_rollback(payload: dict, progress) -> tuple[bool, str]:
    progress('restore', 'rolling back pre-upgrade snapshot',
             pct=30)
    from vnc_remote_secure.core.upgrader import perform_rollback
    result = perform_rollback()
    return bool(result.get('ok')), (
        f"restored={result.get('restored')}" if result.get('ok')
        else str(result.get('error', 'failed')))


_EXECUTORS = {
    'lifecycle.action': _exec_lifecycle,
    'backup.restore': _exec_restore,
    'upgrade.run': _exec_upgrade,
    'upgrade.rollback': _exec_rollback,
}


def run_job(jid: str) -> int:
    """Claim and execute a persisted queued job in THIS process."""
    from vnc_remote_secure.security import audit as audit_mod
    from vnc_remote_secure.security import jobs
    job = jobs.job_get(jid)
    if job is None:
        logger.error('job %s not found', jid)
        return 2
    if not jobs.job_claim(jid, f'pid-{os.getpid()}'):
        logger.warning('job %s already claimed — not re-running', jid)
        return 2
    payload = job.get('payload') or {}
    op = str(payload.get('op', ''))
    executor = _EXECUTORS.get(op)
    if executor is None:
        jobs.job_fail(jid, f'unknown op {op!r}')
        jobs.job_unlock(_OP_LOCK, jid)
        return 2
    actor = job.get('actor', '?')
    jobs.job_progress(jid, 'claim', percent=5,
                      detail=f'pid={os.getpid()}')
    try:
        ok, detail = executor(
            payload,
            lambda phase, d='', pct=None: jobs.job_progress(
                jid, phase, d, percent=pct))
    except Exception as exc:  # noqa: BLE001 - record and release
        jobs.job_fail(jid, str(exc)[:256])
        jobs.job_unlock(_OP_LOCK, jid)
        audit_mod.audit_event(
            op, user=actor, result='failure',
            detail=f'job {jid}: {exc}'[:256])
        return 1
    if ok:
        jobs.job_finish(jid, detail)
    else:
        jobs.job_fail(jid, detail)
    jobs.job_unlock(_OP_LOCK, jid)
    audit_mod.audit_event(
        op, user=actor, result='success' if ok else 'failure',
        detail=f'job {jid}: {detail}'[:256])
    return 0 if ok else 1


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(f'Usage: python -m {__name__} '
              f'run <job_id> [delay_s] | <{"|".join(_ACTIONS)}> [delay_s]')
        return 2
    try:
        delay = float(argv[2] if argv[0] == 'run' and len(argv) > 2
                      else (argv[1] if len(argv) > 1 else _DEFAULT_DELAY))
    except ValueError:
        delay = _DEFAULT_DELAY
    # Bound the delay — a huge value would keep a hidden process
    # parked on the host for days.
    delay = max(0.0, min(delay, 60.0))
    logging.basicConfig(level=logging.INFO)
    time.sleep(delay)
    if argv[0] == 'run':
        if len(argv) < 2:
            return 2
        return run_job(argv[1])
    if argv[0] in _ACTIONS:
        # Legacy/debug mode — runs the lifecycle action with no job
        # record. API paths always go through `run <job_id>`.
        return run_action(argv[0])
    print(f'Usage: python -m {__name__} '
          f'run <job_id> [delay_s] | <{"|".join(_ACTIONS)}> [delay_s]')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
