"""Config env-file history — snapshots + rollback.

Every code path that mutates the effective env file (``migrate_env``,
``set_env_persistent`` — secret rotation, recovery-code consumption)
snapshots the previous content first: a bad migration, a fat-fingered
rotation or an attacker who reached ``admin_config`` leaves a
recoverable receipt instead of an overwritten file.

Layout under ``<project>/backups/config_history/`` (0o700 — snapshots
contain secrets):

    <epoch_ms>_<digest8>.env     snapshot of the env file
    <epoch_ms>_<digest8>.json    sidecar: {ts, actor, reason, size,
                                          source, sha256}

``list_history()`` reads the sidecars newest-first;
``rollback(snapshot_id)`` restores the snapshot onto its recorded
``source`` (validated — a tampered sidecar cannot turn this into an
arbitrary file write) after snapshotting the current content, so a
rollback is itself reversible.
"""
import contextlib
import hashlib
import json
import os
import re
import tempfile
import time

_KEEP = 50          # never retain more than 50 snapshots
_ID_RE = re.compile(r'^[0-9]+_[0-9a-f]{8}$')


def _env_targets() -> set:
    """Real paths a snapshot may legitimately restore onto."""
    from vnc_remote_secure.core.config import _system_env_path
    from vnc_remote_secure.core.paths import find_project_root
    out = set()
    for p in (os.path.join(find_project_root(), '.env'),
              _system_env_path()):
        with contextlib.suppress(OSError, ValueError):
            out.add(os.path.realpath(p))
    return out


def _history_dir() -> str:
    from vnc_remote_secure.core.paths import find_project_root
    d = os.path.join(find_project_root(), 'backups', 'config_history')
    os.makedirs(d, exist_ok=True)
    # Snapshots hold plaintext secrets — same hardening as backups/.
    # nosemgrep: python.lang.security.insecure-file-permissions.insecure-file-permissions (0o700 hardens)
    with contextlib.suppress(OSError):
        os.chmod(d, 0o700)
    return d


def snapshot(path: str | None = None, actor: str = '',
             reason: str = '') -> str | None:
    """Copy the given env file (default: project .env) into the
    history dir; returns the snapshot id.

    ``None`` when the file does not exist (fresh install) — nothing
    was lost. Rotates out the oldest entries past ``_KEEP``.
    """
    if path is None:
        from vnc_remote_secure.core.paths import find_project_root
        path = os.path.join(find_project_root(), '.env')
    if not os.path.isfile(path):
        return None
    data = open(path, 'rb').read()
    digest = hashlib.sha256(data).hexdigest()[:8]
    sid = f'{int(time.time() * 1000)}_{digest}'
    d = _history_dir()
    env_dst = os.path.join(d, f'{sid}.env')
    # The file carries secrets — write+replace atomically, owner-only.
    fd, tmp = tempfile.mkstemp(dir=d, suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, env_dst)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    sidecar = {
        'id': sid, 'ts': time.time(), 'actor': actor or '?',
        'reason': reason[:200], 'size': len(data), 'sha256': digest,
        'source': os.path.basename(path),
        'source_path': os.path.realpath(path),
    }
    with open(os.path.join(d, f'{sid}.json'), 'w',
              encoding='utf-8') as f:
        json.dump(sidecar, f)
    _rotate(d)
    return sid


def _rotate(d: str) -> None:
    """Drop the oldest snapshots beyond ``_KEEP`` (bounded dir)."""
    entries = [n[:-5] for n in os.listdir(d) if n.endswith('.json')]
    entries.sort(reverse=True)
    for sid in entries[_KEEP:]:
        for ext in ('.env', '.json'):
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(d, sid + ext))


def list_history() -> list:
    """Snapshot records newest-first (id, ts, actor, reason, size,
    source — never the env contents)."""
    try:
        d = _history_dir()
    except OSError:
        return []
    out = []
    for name in os.listdir(d):
        if not name.endswith('.json'):
            continue
        try:
            with open(os.path.join(d, name), encoding='utf-8') as f:
                rec = json.load(f)
            if _ID_RE.match(str(rec.get('id', ''))):
                rec.pop('source_path', None)  # don't leak fs layout
                out.append(rec)
        except (OSError, ValueError):
            continue
    out.sort(key=lambda r: r.get('ts', 0), reverse=True)
    return out[:_KEEP]


def _sidecar(d: str, sid: str) -> dict | None:
    try:
        with open(os.path.join(d, f'{sid}.json'),
                  encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def rollback(snapshot_id: str, actor: str = '') -> dict:
    """Restore ``snapshot_id`` over the env file it was taken from.

    The live file is snapshotted first so the rollback itself is
    reversible. The target is the sidecar's recorded ``source_path``
    re-validated against the known env-file set — a forged sidecar
    pointing at an arbitrary path is rejected.
    """
    sid = str(snapshot_id or '').strip()
    if not _ID_RE.match(sid):
        raise ValueError(f'invalid snapshot id: {snapshot_id!r}')
    d = _history_dir()
    src = os.path.join(d, f'{sid}.env')
    if not os.path.isfile(src):
        raise FileNotFoundError(f'unknown snapshot: {sid}')
    rec = _sidecar(d, sid) or {}
    target = os.path.realpath(rec.get('source_path') or '')
    if not target or target not in _env_targets():
        raise ValueError(f'snapshot {sid} has no valid restore target')
    # Snapshot the live file before overwriting — undo of undo.
    snapshot(target, actor or '?', f'pre-rollback of {sid}')
    data = open(src, 'rb').read()
    from vnc_remote_secure.core.test_isolation import guard_write
    guard_write(target, 'config rollback')
    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(target) or '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return {'restored': sid, 'target': rec.get('source', 'env'),
            'size': len(data)}
