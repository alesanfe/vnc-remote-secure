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
import uuid
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Error code registry.
ERROR_CODES = {
    'ERR_AUTH_REQUIRED': 401,
    'ERR_AUTH_FAILED': 401,
    'ERR_MFA_REQUIRED': 403,
    'ERR_PERMISSION_DENIED': 403,
    'ERR_SESSION_EXPIRED': 403,
    'ERR_SESSION_REVOKED': 403,
    'ERR_RATE_LIMITED': 429,
    'ERR_NOT_FOUND': 404,
    'ERR_CONFLICT': 409,
    'ERR_VALIDATION': 422,
    'ERR_CONFIG': 500,
    'ERR_INTERNAL': 500,
    'ERR_UNAVAILABLE': 503,
}


def error_json(
    message: str,
    status_code: int = 500,
    detail: Optional[str] = None,
    code: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Tuple[str, int]:
    """Return a JSON error response tuple for Flask/http.server handlers.

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


def error_json_response(
    message: str,
    status_code: int = 400,
    detail: Optional[str] = None,
    code: Optional[str] = None,
    request_id: Optional[str] = None,
):
    """Flask-compatible JSON error response.

    Returns a ``(jsonify_response, status_code)`` tuple suitable for
    direct return from Flask view functions.
    """
    from flask import jsonify
    body = {'error': True, 'message': str(message)}
    if code:
        body['code'] = code
    if detail is not None:
        body['detail'] = str(detail)
    if request_id:
        body['request_id'] = request_id
    return jsonify(body), status_code


def structured_error(
    code: str,
    message: str,
    detail: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Tuple[str, int]:
    """Create a structured error using a registered error code.

    Looks up the HTTP status code from :data:`ERROR_CODES` and delegates
    to :func:`error_json`.
    """
    status = ERROR_CODES.get(code, 500)
    return error_json(message, status, detail, code, request_id)


def generate_request_id() -> str:
    """Generate a unique request ID for error correlation."""
    return str(uuid.uuid4())


# Backward-compatible alias (deprecated; use error_json_response in new code).
json_error = error_json_response
