"""Operations use cases — the same verbs the CLI exposes
(``backup``, ``restore``, ``secrets``, ``config``, lifecycle,
``upgrade``, ``verify``, ``version``), expressed as
transport-free functions so the REST surface is byte-equivalent.

Rules owned here:

* backup names resolve ONLY against ``stores.backups_paths()`` — a
  raw filename from the wire never reaches the filesystem layer;
* lifecycle actions spawn the detached deferred runner so the portal
  process serving the request survives to answer it;
* every mutation writes an audit event; destructive ones also record
  a job-ledger entry (the UI shows them in the jobs panel).
"""
from __future__ import annotations

import os

from vnc_remote_secure.engine.domain.decision import (
    ERR_INVALID,
    ERR_NOT_FOUND,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores

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


def lifecycle_action(actor: str, action: str) -> dict:
    """Queue ``vnc-remote <action>`` on a detached child process.

    The runner sleeps a short delay before touching the service
    manager, giving this request time to flush its response even when
    ``stop``/``restart`` will kill the portal that spawned it.
    """
    action = str(action or '').lower()
    if action not in _LIFECYCLE_ACTIONS:
        raise UseCaseError(
            ERR_INVALID,
            f'action must be one of {list(_LIFECYCLE_ACTIONS)}')
    jid = stores.job_start('lifecycle', actor, action)
    try:
        pid = stores.lifecycle_spawn(action)
    except (OSError, ValueError) as exc:
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID,
                           f'could not spawn lifecycle runner: {exc}')
    stores.audit('lifecycle_action', actor, f'action={action} pid={pid}')
    stores.job_finish(jid, f'pid={pid}')
    return {'action': action, 'pid': pid, 'accepted': True}


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


def create_backup(actor: str) -> dict:
    """``vnc-remote backup`` — archive config + secrets + audit."""
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


def restore_backup(actor: str, name: str) -> dict:
    """``vnc-remote restore <file>`` — overwrites live config."""
    path = _resolve_backup(name)
    jid = stores.job_start('restore', actor, os.path.basename(path))
    try:
        ok = stores.backup_restore(path)
    except (FileNotFoundError, RuntimeError) as exc:
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID, str(exc))
    if not ok:
        stores.job_fail(jid, 'restore failed')
        raise UseCaseError(ERR_INVALID, 'restore failed')
    stores.audit('backup_restore', actor, os.path.basename(path))
    stores.job_finish(jid, os.path.basename(path))
    return {'restored': True, 'name': os.path.basename(path)}


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


def rotate_secret(actor: str, name: str) -> dict:
    """``vnc-remote secrets rotate --name X`` — hard cutover."""
    jid = stores.job_start('secret_rotate', actor,
                           str(name or '').upper())
    try:
        result = stores.secret_rotate(name)
    except (ValueError, OSError) as exc:
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID, str(exc))
    stores.audit('secret_rotate', actor,
                 f"name={result['name']} fp={result['fingerprint']}")
    stores.job_finish(jid, result['name'])
    return result


def rotate_signing_key(actor: str) -> dict:
    """``vnc-remote secrets rotate-signing`` — 7-day coexistence."""
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


def recovery_codes(actor: str) -> dict:
    """``vnc-remote secrets recovery-codes`` — shown once."""
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


def config_migrate(actor: str, dry_run: bool = False) -> dict:
    """``vnc-remote config migrate [--dry-run]``."""
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


def upgrade_run(actor: str, source: str | None = None) -> dict:
    """``vnc-remote upgrade`` — pip self-upgrade w/ auto-rollback.

    Long-running (download + install); runs under a job-ledger entry
    so the UI shows it in the jobs panel.
    """
    jid = stores.job_start('upgrade', actor, source or 'latest')
    try:
        result = stores.upgrade_run(source=source)
    except Exception:  # noqa: BLE001
        stores.job_fail(jid, 'upgrade failed')
        raise UseCaseError(ERR_INVALID, 'upgrade failed')
    if not result.get('ok'):
        stores.job_fail(jid, result.get('error', 'unknown'))
        raise UseCaseError(ERR_INVALID,
                           result.get('error', 'upgrade failed'))
    stores.audit('upgrade_run', actor,
                 f"{result.get('previous')}->{result.get('version')}")
    stores.job_finish(jid, f"{result.get('version')}")
    return result


def upgrade_rollback(actor: str) -> dict:
    """``vnc-remote upgrade --rollback``."""
    jid = stores.job_start('upgrade_rollback', actor)
    result = stores.upgrade_rollback()
    if not result.get('ok'):
        stores.job_fail(jid, result.get('error', 'unknown'))
        raise UseCaseError(ERR_INVALID,
                           result.get('error', 'rollback failed'))
    stores.audit('upgrade_rollback', actor,
                 f"restored={result.get('restored', '')}")
    stores.job_finish(jid)
    return result
