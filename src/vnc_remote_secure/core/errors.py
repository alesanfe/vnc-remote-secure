"""Unified error handling helpers for VNC Remote Secure services.

All HTTP services should use these helpers to ensure consistent error
response formats across landing, health, terminal, and other services.
"""
import json
import logging

logger = logging.getLogger(__name__)


def error_json(message, status_code=500, detail=None):
    """Return a JSON error response tuple for Flask/http.server handlers.

    Returns (body_string, status_code) where body_string is a JSON
    object with 'error' and 'message' keys.
    """
    body = {'error': True, 'message': str(message)}
    if detail is not None:
        body['detail'] = str(detail)
    return json.dumps(body), status_code


def log_exception(exc, context=''):
    """Log an exception with optional context string."""
    if context:
        logger.warning("%s: %s", context, exc, exc_info=True)
    else:
        logger.warning("Unhandled exception: %s", exc, exc_info=True)


def error_json_response(message, status_code=400, detail=None):
    """Flask-compatible JSON error response.

    Returns a ``(jsonify_response, status_code)`` tuple suitable for
    direct return from Flask view functions. Uses the same envelope
    as :func:`error_json` so all HTTP services share one error schema.
    """
    from flask import jsonify
    body = {'error': True, 'message': str(message)}
    if detail is not None:
        body['detail'] = str(detail)
    return jsonify(body), status_code


# Backward-compatible alias (deprecated; use error_json_response in new code).
json_error = error_json_response
