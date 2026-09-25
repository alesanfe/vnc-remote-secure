"""Operations use cases — the same verbs the CLI exposes
(``backup``, ``restore``, ``secrets``, ``config``, lifecycle,
``upgrade``, ``verify``, ``version``), expressed as
transport-free functions so the REST surface is byte-equivalent.

Rules owned here:

* backup names resolve ONLY against ``stores.backups_paths()`` — a
  raw filename from the wire never reaches the filesystem layer;
* destructive ops (lifecycle/restore/upgrade) persist a QUEUED job
  before answering and a detached runner claims+executes it — the
  response is guaranteed even when the operation kills the portal;
* the ``destructive`` job lock serializes those classes — a restore
  can never overlap a restart;
* ``authentication_policy: stepup-bound`` catalog entries consume a
  single-use grant tied to operation+resource+session (``auth_ctx``);
  CLI callers pass ``transport='cli'`` — a local shell is itself the
  authentication surface;
* every mutation writes an audit event; job-based ones also audit the
  outcome when the runner finishes.
"""
from __future__ import annotations

import os

from vnc_remote_secure.engine.domain.decision import (
    ERR_CONFLICT,
    ERR_INVALID,
    ERR_NOT_FOUND,
    ERR_STEP_UP,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores

# Op-class mutex: lifecycle, restore and upgrade must never overlap.
_DESTRUCTIVE_LOCK = 'destructive'


def _require_bound_step_up(actor: str, operation_id: str,
                           resource: str = '',
                           auth_ctx: dict | None = None) -> None:
    """Consume a single-use grant bound to operation+resource+session.

    Only enforced for ``transport='api'`` callers — the CLI has no web
    grant surface (the local shell IS the authentication boundary), so
    the same use case stays callable from ``vnc-remote`` while the UI
    gets per-operation re-authentication.
    """
    if not auth_ctx or auth_ctx.get('transport') != 'api':
        return
    if not stores.step_up_consume(
            auth_ctx.get('username', actor), operation_id,
            resource, auth_ctx.get('sid', '')):
        raise UseCaseError(
            ERR_STEP_UP,
            're-authentication required for this operation')


def _queue_destructive(actor: str, kind: str, target: str,
                       payload: dict) -> str:
    """Enqueue a job and grab the destructive-op mutex — returns jid.

    The lock is released by the deferred runner when it finishes;
    callers that fail to spawn must ``job_unlock`` themselves."""
    jid = stores.job_enqueue(kind, actor, target, payload)
    if not stores.job_lock(_DESTRUCTIVE_LOCK, jid):
        stores.job_fail(jid, 'another destructive operation is running')
        raise UseCaseError(
            ERR_CONFLICT,
            'another destructive operation is in progress')
    return jid


def _spawn_runner(actor: str, jid: str, audit_event: str,
                  target: str) -> int:
    try:
        pid = stores.lifecycle_spawn(jid)
    except (OSError, ValueError) as exc:
        stores.job_unlock(_DESTRUCTIVE_LOCK, jid)
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID,
                           f'could not spawn job runner: {exc}')
    stores.audit(audit_event, actor, f'queued jid={jid} {target}')
    return pid

# ---------------------------------------------------------------------------
# Version / status
# ---------------------------------------------------------------------------

def version() -> dict:
    """``vnc-remote version`` as a read model."""
    return {'version': stores.version_info()}


def lifecycle_status() -> dict:
    """``vnc-remote status`` as a read model (PIDs + port health)."""
    return stores.service_status()


# ---------------------------------------------------------------------------
# Lifecycle — deferred runner so the answer escapes before services die
# ---------------------------------------------------------------------------

_LIFECYCLE_ACTIONS = ('start', 'stop', 'restart')


def lifecycle_action(actor: str, action: str,
                     auth_ctx: dict | None = None) -> dict:
    """Queue ``vnc-remote <action>`` as a deferred claimed job.

    The job is persisted BEFORE the caller answers; the detached
    runner claims it, sleeps briefly (response flush), then runs the
    action — so ``stop``/``restart`` can kill the portal without
    losing either the response or the operation.
    """
    action = str(action or '').lower()
    if action not in _LIFECYCLE_ACTIONS:
        raise UseCaseError(
            ERR_INVALID,
            f'action must be one of {list(_LIFECYCLE_ACTIONS)}')
    _require_bound_step_up(actor, 'lifecycle.action', action, auth_ctx)
    jid = _queue_destructive(
        actor, 'lifecycle', action,
        payload={'op': 'lifecycle.action', 'action': action})
    pid = _spawn_runner(actor, jid, 'lifecycle_action', action)
    return {'action': action, 'job_id': jid, 'pid': pid,
            'accepted': True}


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

def _resolve_backup(name: str) -> str:
    """Map a wire name to a real backup path — never trust the client.

    Only the basename of a file ``list_backups`` returns is accepted,
    so ``../../etc/passwd`` or absolute paths die here.
    """
    wanted = os.path.basename(str(name or '').strip())
    for p in stores.backups_paths():
        if os.path.basename(p) == wanted:
            return p
    raise UseCaseError(ERR_NOT_FOUND, 'backup not found')


def create_backup(actor: str, auth_ctx: dict | None = None) -> dict:
    """``vnc-remote backup`` — archive config + secrets + audit."""
    _require_bound_step_up(actor, 'backup.create', '', auth_ctx)
    jid = stores.job_start('backup', actor)
    try:
        path = stores.backup_create()
    except Exception:  # noqa: BLE001 - surface generic failure
        stores.job_fail(jid, 'creation failed')
        raise UseCaseError(ERR_INVALID, 'backup creation failed')
    name = os.path.basename(path)
    stores.audit('backup_create', actor, name)
    stores.job_finish(jid, name)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = None
    return {'created': True, 'name': name, 'size': size}


def verify_backup(actor: str, name: str) -> dict:
    """``vnc-remote verify backup <file>`` — CRC-check every member."""
    path = _resolve_backup(name)
    ok, message, count = stores.backup_verify(path)
    stores.audit('backup_verify', actor,
                 f'{os.path.basename(path)} ok={int(bool(ok))}')
    return {'file': os.path.basename(path), 'ok': bool(ok),
            'members': count, 'message': message}


def restore_backup(actor: str, name: str,
                   auth_ctx: dict | None = None) -> dict:
    """``vnc-remote restore <file>`` — runs as a claimed job.

    Returns ``job_id`` for progress tracking; the restore itself
    overwrites live config in the detached executor."""
    path = _resolve_backup(name)
    base = os.path.basename(path)
    _require_bound_step_up(actor, 'backup.restore', base, auth_ctx)
    jid = _queue_destructive(
        actor, 'restore', base,
        payload={'op': 'backup.restore', 'path': path, 'name': base})
    _spawn_runner(actor, jid, 'backup_restore', base)
    return {'accepted': True, 'job_id': jid, 'name': base}


# ---------------------------------------------------------------------------
# Secrets — rotation, hygiene, signing key, recovery codes
# ---------------------------------------------------------------------------

def secrets_status() -> dict:
    """``vnc-remote secrets status`` — set/missing/weak, never values."""
    return {'secrets': stores.secret_status_map()}


def secret_redact(name: str) -> dict:
    """``vnc-remote secrets redact --name X`` — fingerprint only."""
    name = str(name or '').strip().upper()
    allowed = stores.secret_rotatable_names()
    if name not in allowed:
        raise UseCaseError(
            ERR_INVALID,
            f'unknown secret; allowed: {sorted(allowed)}')
    return {'name': name, 'redacted': stores.secret_redact(name)}


def rotate_secret(actor: str, name: str,
                  auth_ctx: dict | None = None) -> dict:
    """``vnc-remote secrets rotate --name X`` — hard cutover."""
    name = str(name or '').strip().upper()
    allowed = stores.secret_rotatable_names()
    if name not in allowed:
        raise UseCaseError(
            ERR_INVALID,
            f'unknown secret; allowed: {sorted(allowed)}')
    _require_bound_step_up(actor, 'secrets.rotate', name, auth_ctx)
    jid = stores.job_start('secret_rotate', actor, name)
    try:
        result = stores.secret_rotate(name)
    except (ValueError, OSError) as exc:
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID, str(exc))
    stores.audit('secret_rotate', actor,
                 f"name={result['name']} fp={result['fingerprint']}")
    stores.job_finish(jid, result['name'])
    return result


def rotate_signing_key(actor: str,
                       auth_ctx: dict | None = None) -> dict:
    """``vnc-remote secrets rotate-signing`` — 7-day coexistence."""
    _require_bound_step_up(actor, 'secrets.rotate_signing', '',
                           auth_ctx)
    try:
        result = stores.secret_rotate_signing()
    except RuntimeError as exc:
        raise UseCaseError(ERR_INVALID, str(exc))
    stores.audit('signing_key_rotate', actor, 'window=7d')
    return result


def secrets_check(actor: str, fix: bool = False) -> dict:
    """``vnc-remote secrets check [--fix]`` — TLS + file permissions."""
    result = stores.secrets_check(fix=fix)
    stores.audit('secrets_check', actor,
                 f'fix={int(bool(fix))}')
    if isinstance(result, dict):
        return {'findings': result.get('remaining', []),
                'fixed': result.get('fixed', []), 'ok': not any(
                    f.get('severity') == 'critical'
                    for f in result.get('remaining', []))}
    return {'findings': result, 'fixed': [], 'ok': not any(
        f.get('severity') == 'critical' for f in result)}


def recovery_codes(actor: str,
                   auth_ctx: dict | None = None) -> dict:
    """``vnc-remote secrets recovery-codes`` — shown once."""
    _require_bound_step_up(actor, 'secrets.recovery_codes', '',
                           auth_ctx)
    try:
        codes = stores.recovery_codes_generate(8)
    except OSError as exc:
        raise UseCaseError(ERR_INVALID, str(exc))
    stores.audit('recovery_codes_generate', actor, 'count=8')
    return {'codes': codes}


# ---------------------------------------------------------------------------
# Config — effective/explain/validate/diff/migrate
# ---------------------------------------------------------------------------

def config_explain(name: str) -> dict:
    """``vnc-remote config explain NAME`` — value + provenance."""
    name = str(name or '').strip().upper()
    for entry in stores.config_effective_profile(None):
        if entry.get('name') == name:
            return {'entry': entry}
    raise UseCaseError(ERR_NOT_FOUND, f'unknown variable: {name}')


def config_validate(profile: str | None = None) -> dict:
    """``vnc-remote config validate`` — contradiction findings."""
    findings = stores.config_validate(profile)
    criticals = [f for f in findings if f.get('severity') == 'critical']
    return {'profile': profile, 'findings': findings,
            'ok': not criticals}


def config_diff(profile_a: str, profile_b: str) -> dict:
    """``vnc-remote config diff A B``."""
    profile_a = str(profile_a or '').strip()
    profile_b = str(profile_b or '').strip()
    if not profile_a or not profile_b:
        raise UseCaseError(ERR_INVALID, 'profile_a and profile_b required')
    return {'a': profile_a, 'b': profile_b,
            'diffs': stores.config_diff(profile_a, profile_b)}


def config_migrate(actor: str, dry_run: bool = False,
                   auth_ctx: dict | None = None) -> dict:
    """``vnc-remote config migrate [--dry-run]``.

    Dry-run is a read-only preview — no grant required; applying the
    migration consumes a bound grant."""
    if not dry_run:
        _require_bound_step_up(actor, 'config.migrate', 'apply',
                               auth_ctx)
    try:
        result = stores.config_migrate(dry_run=dry_run)
    except FileNotFoundError:
        raise UseCaseError(ERR_NOT_FOUND, 'no .env file found')
    if result['applied']:
        stores.audit('config_migrate', actor,
                     f"changes={len(result['changes'])}")
    return result


# ---------------------------------------------------------------------------
# Upgrade — check / run / rollback
# ---------------------------------------------------------------------------

def upgrade_status() -> dict:
    """``vnc-remote upgrade --check`` as a read model."""
    return stores.upgrade_check()


def upgrade_run(actor: str, source: str | None = None,
                auth_ctx: dict | None = None) -> dict:
    """``vnc-remote upgrade`` — runs as a claimed deferred job.

    Download + install take longer than a request should hold; the
    response carries ``job_id`` and the jobs panel shows
    backup → install → rollback status."""
    source = str(source or '').strip() or None
    _require_bound_step_up(actor, 'upgrade.run',
                           source or 'latest', auth_ctx)
    jid = _queue_destructive(
        actor, 'upgrade', source or 'latest',
        payload={'op': 'upgrade.run', 'source': source})
    _spawn_runner(actor, jid, 'upgrade_run', source or 'latest')
    return {'accepted': True, 'job_id': jid,
            'source': source or 'latest'}


def upgrade_rollback(actor: str,
                     auth_ctx: dict | None = None) -> dict:
    """``vnc-remote upgrade --rollback`` — claimed deferred job."""
    _require_bound_step_up(actor, 'upgrade.rollback', '', auth_ctx)
    jid = _queue_destructive(
        actor, 'upgrade_rollback', '',
        payload={'op': 'upgrade.rollback'})
    _spawn_runner(actor, jid, 'upgrade_rollback', '')
    return {'accepted': True, 'job_id': jid}


def job_status(jid: str) -> dict:
    """Read model for a queued/claimed job — jobs-panel detail."""
    job = stores.job_get(str(jid or ''))
    if job is None:
        raise UseCaseError(ERR_NOT_FOUND, 'job not found')
    return {'job': job}
