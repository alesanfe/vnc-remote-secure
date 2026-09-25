"""Network export sinks for audit events.

Every entry that reaches the local audit log is also forwarded to the
configured network sinks — a host compromise can rewrite the local
file but not records already shipped off-box.

Sinks (all disabled unless configured):

- ``AUDIT_SYSLOG_HOST`` (+ ``AUDIT_SYSLOG_PORT``=514,
  ``AUDIT_SYSLOG_PROTO``=udp|tcp, ``AUDIT_SYSLOG_FACILITY``=4) —
  RFC 5424 messages. The MSG field carries the exact JSON line
  written to the local log (chain hash included), so the SIEM side
  can verify tamper-evidence independently.
- ``AUDIT_EXPORT_WEBHOOK`` — HTTPS POST of the entry dict through the
  same DNS-pinned, redirect-refusing, SSRF-validated transport as
  alert webhooks.

Export is best-effort: a failed sink is logged and escalated through
``monitoring.alerts`` after repeated failures, but never aborts the
audited action (``AUDIT_STRICT`` governs local persistence, not
transit). Export runs outside the audit chain lock so a slow sink
cannot stall writers.
"""

import json
import logging
import os
import socket
import time

logger = logging.getLogger(__name__)

# Consecutive-export-failure counter. The first failure is a log
# line; after _ALERT_THRESHOLD consecutive misses the operator gets
# one throttled alert — a dead SIEM sink is a security regression,
# not noise.
_consecutive_failures = 0
_ALERT_THRESHOLD = 10
_ALERTED = False

_SYSLOG_TIMEOUT = 3.0
# SD-ID registered for this product in the private-enterprise range
# would be ideal; an @-name is the conventional stand-in.
_SD_ID = 'vrs@8314'


def _sd_escape(value) -> str:
    """Escape a PARAM-VALUE per RFC 5424 §6.3.3."""
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')


def _severity(entry: dict) -> int:
    """RFC 5424 severity: warning for failures, info otherwise."""
    return 6 if entry.get('result') == 'success' else 4


def format_syslog(entry: dict, line: str) -> bytes:
    """Render an RFC 5424 syslog message for *entry*.

    ``line`` is the exact JSON line persisted locally — carrying it
    verbatim lets the collector recompute/verify the chain hash.
    """
    facility = int(os.environ.get('AUDIT_SYSLOG_FACILITY', '4') or '4')
    pri = facility * 8 + _severity(entry)
    ts = entry.get('timestamp') or time.strftime(
        '%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    host = socket.gethostname() or '-'
    msgid = entry.get('event') or '-'
    sd = (f'[{_SD_ID} seq="{_sd_escape(entry.get("seq", ""))}"'
          f' result="{_sd_escape(entry.get("result", ""))}"]')
    msg = (f'<{pri}>1 {ts} {host} vnc-remote-secure {os.getpid()}'
           f' {msgid} {sd} {line.rstrip()}')
    return msg.encode('utf-8', errors='replace')


def _send_syslog(data: bytes, host: str, port: int, proto: str) -> None:
    if proto == 'tcp':
        # Non-transparent framing (newline-terminated) — the MSG is
        # single-line JSON so no embedded newlines can desync it.
        with socket.create_connection(
                (host, port), timeout=_SYSLOG_TIMEOUT) as sock:
            sock.sendall(data + b'\n')
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SYSLOG_TIMEOUT)
            sock.sendto(data, (host, port))


def _export_syslog(entry: dict, line: str) -> bool:
    host = os.environ.get('AUDIT_SYSLOG_HOST', '').strip()
    if not host:
        return True
    port = int(os.environ.get('AUDIT_SYSLOG_PORT', '514') or '514')
    proto = os.environ.get('AUDIT_SYSLOG_PROTO', 'udp').strip().lower()
    _send_syslog(format_syslog(entry, line), host, port, proto)
    return True


def _export_webhook(entry: dict) -> bool:
    url = os.environ.get('AUDIT_EXPORT_WEBHOOK', '').strip()
    if not url:
        return True
    from vnc_remote_secure.security.http_client import (
        secure_post,
        validate_url,
    )
    err = validate_url(url)
    if err:
        logger.warning('AUDIT_EXPORT_WEBHOOK rejected: %s', err)
        return False
    body = json.dumps({'audit': entry}).encode('utf-8')
    try:
        status = secure_post(
            url, body, {'Content-Type': 'application/json'})
    except Exception:  # noqa: BLE001 - export must not break requests
        logger.warning('Audit webhook POST failed')
        return False
    return 200 <= status < 300


def _note_failure() -> None:
    """Escalate sustained export failures (once, throttled)."""
    global _consecutive_failures, _ALERTED
    _consecutive_failures += 1
    if _consecutive_failures < _ALERT_THRESHOLD or _ALERTED:
        return
    _ALERTED = True
    try:
        from vnc_remote_secure.monitoring.alerts import notify
        notify('Audit export failing',
               f'{_consecutive_failures} consecutive audit export '
               'failures — check AUDIT_SYSLOG_HOST / '
               'AUDIT_EXPORT_WEBHOOK reachability.',
               severity='warning')
    except Exception:  # noqa: BLE001 - alerting must not break export
        logger.debug('Could not dispatch audit-export alert')


def export_entry(entry: dict, line: str) -> None:
    """Forward a persisted audit entry to all configured sinks.

    Called by :func:`security.audit.audit_log` after the entry is
    chained on disk. Never raises — export must not break requests.
    """
    global _consecutive_failures, _ALERTED
    ok = True
    try:
        _export_syslog(entry, line)
    except Exception:
        ok = False
        logger.exception('Audit syslog export failed')
    try:
        if not _export_webhook(entry):
            ok = False
    except Exception:
        ok = False
        logger.exception('Audit webhook export failed')
    if ok:
        _consecutive_failures = 0
        _ALERTED = False
    else:
        _note_failure()

