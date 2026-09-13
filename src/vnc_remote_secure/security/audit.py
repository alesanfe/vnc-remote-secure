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

The audit log is append-only. Callers should use :func:`audit_log` for
all security-relevant actions.
"""
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Audit log file path (configurable via AUDIT_LOG_FILE env var).
_DEFAULT_AUDIT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    '..', 'logs',
)
_AUDIT_LOG_FILE = os.environ.get(
    'AUDIT_LOG_FILE',
    os.path.join(_DEFAULT_AUDIT_DIR, 'audit.jsonl'),
)

# In-memory chain hash (loaded from the last line of the log file).
_chain_hash = ''


def _load_chain_hash():
    """Load the last chain hash from the audit log file."""
    global _chain_hash
    try:
        path = Path(_AUDIT_LOG_FILE)
        if path.exists():
            lines = path.read_text(encoding='utf-8').strip().split('\n')
            if lines:
                last = json.loads(lines[-1])
                _chain_hash = last.get('hash', '')
    except Exception:
        _chain_hash = ''


def _compute_hash(prev_hash: str, entry: dict) -> str:
    """Compute the chain hash for a new entry."""
    # Hash includes the previous hash and the entry content (excluding
    # the hash field itself) to form a tamper-evident chain.
    entry_copy = {k: v for k, v in entry.items() if k != 'hash'}
    entry_copy['prev_hash'] = prev_hash
    canonical = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


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
    if not _chain_hash:
        _load_chain_hash()

    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'event': event,
        'user': user,
        'ip': ip,
        'result': result,
        'detail': detail,
    }
    if extra:
        entry.update(extra)

    # Compute chain hash for tamper-evidence.
    entry['hash'] = _compute_hash(_chain_hash, entry)
    _chain_hash = entry['hash']

    # Append to log file (create parent dirs if needed).
    try:
        path = Path(_AUDIT_LOG_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
    except Exception as e:
        logger.error("Failed to write audit log: %s", e)

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
    path = Path(_AUDIT_LOG_FILE)
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
    path = Path(_AUDIT_LOG_FILE)
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
