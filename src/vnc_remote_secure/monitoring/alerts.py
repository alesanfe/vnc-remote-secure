"""Alert system for VNC Remote Secure.

A lightweight in-memory alert store. Alerts are timestamped records
with a severity level and message. The store is process-local; for
multi-process deployments a shared backend would be needed.
"""
import time
from collections import deque

# Severity levels ordered by importance.
LEVELS = ('debug', 'info', 'warning', 'error', 'critical')

# In-memory ring buffer of alerts (newest first).
_store = deque(maxlen=1000)


def send_alert(level, message):
    """Record an alert.

    Args:
        level: One of ``LEVELS`` (case-insensitive).
        message: Human-readable alert description.

    Returns:
        The created alert dict.
    """
    level = str(level).lower()
    if level not in LEVELS:
        level = 'info'
    alert = {
        'level': level,
        'message': str(message),
        'timestamp': time.time(),
    }
    _store.appendleft(alert)
    return alert


def get_alerts(level=None, limit=100):
    """Return alerts, newest first.

    Args:
        level: Optional severity filter (e.g. ``'error'``).
        limit: Maximum number of alerts to return.

    Returns:
        A list of alert dicts.
    """
    alerts = list(_store)
    if level:
        level = str(level).lower()
        alerts = [a for a in alerts if a['level'] == level]
    return alerts[:limit]


def clear_alerts():
    """Remove all stored alerts."""
    _store.clear()
    return True
