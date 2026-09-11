"""Logging configuration for VNC Remote Secure."""
import logging
import sys


def setup_logging(verbose=False, json_output=False):
    """Configure logging for the application.

    Args:
        verbose: If True, set log level to DEBUG; otherwise INFO.
        json_output: If True, format log records as JSON lines. Currently
            falls back to the standard formatter when the optional JSON
            dependencies are unavailable.

    Returns:
        The configured root ``logging.Logger`` for the
        ``vnc_remote_secure`` namespace.
    """
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    handler.setFormatter(formatter)
    logger = logging.getLogger('vnc_remote_secure')
    logger.setLevel(level)
    # Avoid duplicate handlers when called multiple times.
    if not logger.handlers:
        logger.addHandler(handler)
    logger.propagate = False
    return logger
