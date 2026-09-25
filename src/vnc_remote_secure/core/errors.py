"""Unified error handling helpers for VNC Remote Secure services.

All HTTP services should use these helpers to ensure consistent error
response formats across landing, health, terminal, and other services.

Error responses follow a structured schema:

    {
        "error": true,
        "code": "ERR_...",
        "message": "Human-readable message",
        "detail": "Optional additional context",
        "request_id": "Optional correlation ID"
    }
"""
import json
import logging

logger = logging.getLogger(__name__)


def error_json(
    message: str,
    status_code: int = 500,
    detail: str | None = None,
    code: str | None = None,
    request_id: str | None = None,
) -> tuple[str, int]:
    """Return a JSON error response tuple for HTTP handlers.

    Returns (body_string, status_code) where body_string is a JSON
    object with a structured error schema.
    """
    body = {'error': True, 'message': str(message)}
    if code:
        body['code'] = code
    if detail is not None:
        body['detail'] = str(detail)
    if request_id:
        body['request_id'] = request_id
    return json.dumps(body), status_code


def log_exception(exc, context: str = ''):
    """Log an exception with optional context string."""
    if context:
        logger.warning("%s: %s", context, exc, exc_info=True)
    else:
        logger.warning("Unhandled exception: %s", exc, exc_info=True)



