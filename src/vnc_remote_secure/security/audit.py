"""Structured, tamper-evident audit logging for VNC Remote Secure.

Records security-relevant events as JSON lines (one per line) to a
dedicated audit log file. Each entry includes:

- ``timestamp``: ISO 8601 UTC
- ``event``: event type (e.g. ``login``, ``session_create``, ``ws_upgrade``)
- ``user``: the acting user (or ``anonymous``)
- ``ip``: source IP (or ``unknown``)
- ``result``: ``success`` or ``failure``
- ``detail``: human-readable description
- ``hash``: SHA-256 chain hash (each entry includes the hash of the
  previous entry, making tampering detectable)

The audit log is append-only. The first entry is a trusted anchor
that records the chain's genesis hash and is verified on every
startup via :func:`verify_chain_on_startup`. Callers should use
:func:`audit_log` for all security-relevant actions.

Log rotation: when the log exceeds ``AUDIT_LOG_MAX_BYTES`` (default
10 MB), it is rotated to ``audit.jsonl.1`` and a new anchor entry is
written to the fresh log.
"""
import contextlib
import hashlib
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

def _audit_log_file() -> str:
    """Return the audit log path, resolved lazily.

    Uses the canonical platform log directory (``core.paths.get_log_dir``)
    instead of a package-relative ``logs/`` so the file lands under
    ``/var/log/vnc-remote-secure`` (root Linux), the XDG data dir
    (non-root Linux), or ``%ProgramData%\\VncRemoteSecure\\logs``
    (Windows). ``AUDIT_LOG_FILE`` overrides entirely.
    """
    override = os.environ.get('AUDIT_LOG_FILE', '')
    if override:
        return override
    from vnc_remote_secure.core.paths import get_log_dir
    return os.path.join(get_log_dir(), 'audit.jsonl')

# Rotation threshold (default 10 MB).
_AUDIT_LOG_MAX_BYTES = int(os.environ.get('AUDIT_LOG_MAX_BYTES', str(10 * 1024 * 1024)))

# The genesis anchor hash — a fixed, well-known value that starts
# every fresh audit chain. This is verified on startup to detect
# truncation attacks.
_ANCHOR_HASH = '0000000000000000000000000000000000000000000000000000000000000000'

# In-memory chain hash cache. For multi-process deployments, the
# hash is re-read from the file before each write to ensure the chain
# remains consistent across processes.
_chain_hash = ''
_chain_lock = threading.Lock()
_startup_verified = False


def _load_chain_hash():
    """Load the last chain hash from the audit log file."""
    global _chain_hash
    try:
        path = Path(_audit_log_file())
        if path.exists():
            lines = path.read_text(encoding='utf-8').strip().split('\n')
            if lines:
                last = json.loads(lines[-1])
                _chain_hash = last.get('hash', '')
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Could not load audit chain hash: %s", exc)
        _chain_hash = ''


def _compute_hash(prev_hash: str, entry: dict) -> str:
    """Compute the chain hash for a new entry."""
    # Hash includes the previous hash and the entry content (excluding
    # the hash field itself) to form a tamper-evident chain.
    entry_copy = {k: v for k, v in entry.items() if k != 'hash'}
    entry_copy['prev_hash'] = prev_hash
    canonical = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _write_anchor():
    """Write the initial anchor entry to a fresh audit log."""
    global _chain_hash
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'event': 'anchor',
        'user': 'system',
        'ip': 'unknown',
        'result': 'success',
        'detail': 'Audit chain anchor — genesis entry',
    }
    entry['hash'] = _compute_hash(_ANCHOR_HASH, entry)
    _chain_hash = entry['hash']
    path = Path(_audit_log_file())
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(entry, separators=(',', ':')) + '\n')
    _set_secure_perms(path)


def _set_secure_perms(path):
    """Restrict audit log file permissions to owner-only.

    ``os.chmod`` is a no-op on Windows ACLs — the audit log under
    ``%ProgramData%`` stayed readable by the ``Users`` group. Use the
    platform-aware icacls/chmod helper used for private keys.
    """
    try:
        from vnc_remote_secure.security.certificates import _restrict_key_permissions
        _restrict_key_permissions(str(path), writable=True)
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


@contextlib.contextmanager
def _audit_file_lock():
    """Cross-process advisory lock for audit log writes.

    Serializes the read-hash → compute → append critical section (and
    rotation) so concurrent writers in different processes cannot fork
    the chain. Uses ``flock`` on POSIX and ``msvcrt.locking`` on
    Windows; degrades to the process-local threading lock when neither
    is available.
    """
    lock_path = Path(_audit_log_file()).with_suffix('.lock')
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        yield
        return
    acquired = None
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = 'fcntl'
        except ImportError:
            try:
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                acquired = 'msvcrt'
            except (ImportError, OSError):
                pass
        yield
    finally:
        try:
            if acquired == 'fcntl':
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif acquired == 'msvcrt':
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.close(fd)


def _maybe_rotate():
    """Rotate the audit log if it exceeds the configured max size.

    The caller must hold the cross-process audit lock
    (:func:`_audit_file_lock`).
    """
    path = Path(_audit_log_file())
    if not path.exists():
        return
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < _AUDIT_LOG_MAX_BYTES:
        return
    rotated = path.with_suffix('.jsonl.1')
    try:
        if rotated.exists():
            rotated.unlink()
        path.rename(rotated)
        logger.info("Rotated audit log to %s", rotated)
    except OSError as exc:
        logger.warning("Could not rotate audit log: %s", exc)
        return
    # Write a fresh anchor to the new log.
    _write_anchor()


def verify_chain_on_startup():
    """Verify the audit chain on startup and write an anchor if needed.

    Called once at process start. If the log does not exist or is
    empty, a fresh anchor is written. If the log exists, the chain is
    verified; if verification fails, a warning is logged but the
    chain continues (the operator must investigate).
    """
    global _startup_verified
    if _startup_verified:
        return
    _startup_verified = True
    path = Path(_audit_log_file())
    if not path.exists() or path.stat().st_size == 0:
        _write_anchor()
        logger.info("Created fresh audit log with anchor entry")
        return
    ok, msg = verify_chain()
    if ok:
        logger.info("Audit chain verified on startup: %s", msg)
    else:
        logger.warning("Audit chain verification FAILED on startup: %s", msg)
    _set_secure_perms(path)


def audit_log(
    event: str,
    user: str = 'anonymous',
    ip: str = 'unknown',
    result: str = 'success',
    detail: str = '',
    extra: Optional[dict] = None,
) -> dict:
    """Write a structured audit log entry.

    Args:
        event: Event type (e.g. ``login``, ``session_create``, ``ws_upgrade``).
        user: The acting user.
        ip: Source IP address.
        result: ``success`` or ``failure``.
        detail: Human-readable description.
        extra: Optional additional fields to include.

    Returns:
        The audit entry dict that was written.
    """
    global _chain_hash
    with _chain_lock, _audit_file_lock():
        # Ensure startup verification has run at least once.
        if not _startup_verified:
            verify_chain_on_startup()

        # Rotate if needed before writing.
        _maybe_rotate()

        # Always re-read the last hash from the file so that entries
        # written by other processes are correctly chained. The
        # cross-process file lock serializes read-hash → compute →
        # append so concurrent writers cannot fork the chain.
        _load_chain_hash()

        # Scrub secrets from free-text fields before they hit disk —
        # a caller that interpolates a credential into ``detail`` or
        # ``extra`` would otherwise persist it in cleartext.
        from vnc_remote_secure.security.redaction import redact_text

        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event': event,
            'user': user,
            'ip': ip,
            'result': result,
            'detail': redact_text(detail) if detail else detail,
        }
        if extra:
            for k, v in extra.items():
                entry[k] = redact_text(v) if isinstance(v, str) else v

        # Compute chain hash for tamper-evidence.
        entry['hash'] = _compute_hash(_chain_hash, entry)
        _chain_hash = entry['hash']

        # Append to log file (create parent dirs if needed).
        line = json.dumps(entry, separators=(',', ':')) + '\n'
        try:
            path = Path(_audit_log_file())
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'a', encoding='utf-8') as f:
                f.write(line)
            _set_secure_perms(path)
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

        # Optional mirror sink: append the same line to a second,
        # independently-controlled path (a mounted network share or
        # WORM store) so rewriting the primary log leaves the mirror
        # intact. ``AUDIT_MIRROR_FILE`` unset = disabled. Read at call
        # time so a later load_env_file() still applies.
        mirror = os.environ.get('AUDIT_MIRROR_FILE', '').strip()
        if mirror:
            try:
                mpath = Path(mirror)
                mpath.parent.mkdir(parents=True, exist_ok=True)
                with open(mpath, 'a', encoding='utf-8') as mf:
                    mf.write(line)
            except Exception as e:
                logger.error("Failed to write audit mirror: %s", e)

    # Also log at INFO level for console visibility.
    logger.info(
        "AUDIT: %s %s by %s from %s — %s",
        event, result, user, ip, detail,
    )
    return entry


def verify_chain() -> tuple:
    """Verify the integrity of the audit log chain.

    Returns:
        ``(True, '')`` if the chain is intact, ``(False, message)``
        if tampering is detected.
    """
    path = Path(_audit_log_file())
    if not path.exists():
        return True, 'No audit log file'

    lines = path.read_text(encoding='utf-8').strip().split('\n')
    if not lines or lines == ['']:
        return True, 'Empty audit log'

    prev_hash = ''
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, f'Invalid JSON at line {i + 1}'
        stored_hash = entry.pop('hash', '')
        # The first entry must be the anchor, chained from _ANCHOR_HASH.
        if i == 0:
            if entry.get('event') != 'anchor':
                return False, 'Missing anchor entry at line 1'
            prev_hash = _ANCHOR_HASH
        computed = _compute_hash(prev_hash, entry)
        if computed != stored_hash:
            return False, f'Hash mismatch at line {i + 1}: chain broken'
        prev_hash = stored_hash

    return True, f'Chain intact ({len(lines)} entries)'


def get_audit_entries(limit: int = 100, event: Optional[str] = None) -> list:
    """Read recent audit log entries.

    Args:
        limit: Maximum number of entries to return.
        event: Filter by event type (optional).

    Returns:
        List of audit entry dicts (newest first).
    """
    path = Path(_audit_log_file())
    if not path.exists():
        return []

    lines = path.read_text(encoding='utf-8').strip().split('\n')
    entries = []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
            if event is None or entry.get('event') == event:
                entries.append(entry)
                if len(entries) >= limit:
                    break
        except json.JSONDecodeError:
            continue
    return entries
