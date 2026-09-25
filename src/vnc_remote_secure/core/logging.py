"""Logging configuration for VNC Remote Secure."""
import logging
import os
import sys


class _SecretScrubFilter(logging.Filter):
    """Redact configured secret VALUES from rendered log records.

    Defense in depth: call sites should never log secrets, but a
    stray ``logger.info("token=%s", token)`` must not leak the value
    into stderr/log files. The filter replaces any occurrence of a
    configured secret's value with ``***REDACTED***``. Values shorter
    than 6 chars are skipped (too high a false-positive rate).
    """

    @classmethod
    def _secret_values(cls):
        # No caching: a secret rotated via `secrets rotate` must be
        # scrubbed immediately — a cached list would keep redacting
        # the stale value while the live one leaks.
        values = []
        try:
            from vnc_remote_secure.security.redaction import SECRET_VARS
            for name in SECRET_VARS:
                val = os.environ.get(name, '')
                if isinstance(val, str) and len(val) >= 6:
                    values.append(val)
        except Exception:  # noqa: BLE001 - never break logging
            pass
        return values

    def filter(self, record):
        try:
            msg = record.getMessage()
            scrubbed = False
            for val in self._secret_values():
                if val and val in msg:
                    msg = msg.replace(val, '***REDACTED***')
                    scrubbed = True
            if scrubbed:
                record.msg = msg
                record.args = ()
        except Exception:  # noqa: BLE001 - never break logging
            pass
        return True


def _json_formatter():
    """JSON-lines formatter built on structlog's ProcessorFormatter.

    Renders stdlib records as ``ts``/``level``/``logger``/``msg`` (the
    historical field names this project already emits) plus
    ``exception`` when ``exc_info`` is set. Using structlog instead of
    a hand-rolled json.dumps keeps the format consistent if call
    sites later bind contextvars (request_id, operator_ref, …) — the
    extra fields pass through automatically.
    """
    import structlog

    def _rename_fields(_logger, _name, event_dict):
        exc = event_dict.pop('exception', None)
        renamed = {
            'ts': event_dict.pop('timestamp', ''),
            'level': str(event_dict.pop('level', '')).upper(),
            'logger': event_dict.pop('logger', _name),
            'msg': event_dict.pop('event', ''),
        }
        if exc:
            renamed['exception'] = exc
        renamed.update(event_dict)
        return renamed

    return structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt='iso'),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _rename_fields,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
    )


def setup_logging(verbose=False, json_output=False):
    """Configure logging for the application.

    Args:
        verbose: If True, set log level to DEBUG; otherwise INFO.
        json_output: If True, format log records as JSON lines
            (``ts``/``level``/``logger``/``msg``).

    Returns:
        The configured root ``logging.Logger`` for the
        ``vnc_remote_secure`` namespace.
    """
    # LOG_LEVEL env is honored (config['log_level'] reads the same
    # var) — without this the documented knob silently did nothing.
    # --verbose still wins over the env var.
    env_level = os.environ.get('LOG_LEVEL', '').strip().upper()
    if verbose:
        level = logging.DEBUG
    elif env_level in ('DEBUG', 'INFO', 'WARNING', 'WARN', 'ERROR', 'CRITICAL', 'FATAL'):
        level = {'WARN': 'WARNING', 'FATAL': 'CRITICAL'}.get(env_level, env_level)
        level = getattr(logging, level)
    else:
        level = logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    if json_output:
        formatter = _json_formatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
    handler.setFormatter(formatter)
    handler.addFilter(_SecretScrubFilter())
    logger = logging.getLogger('vnc_remote_secure')
    logger.setLevel(level)
    # Avoid duplicate handlers when called multiple times.
    if not logger.handlers:
        logger.addHandler(handler)
    logger.propagate = False
    return logger
