"""Shared HTTP authentication helpers for VNC Remote Secure services.

Provides Basic-auth and Bearer-token validation plus a Flask decorator
so that landing, terminal, health, and the Flask UI use a single auth
model instead of each service implementing its own.
"""
import base64
import functools
import hmac
import logging
import os

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)


def check_basic_auth(auth_header, expected_username, expected_password):
    """Validate an ``Authorization: Basic <b64>`` header.

    Returns ``True`` if the decoded ``username:password`` matches the
    expected credentials (constant-time comparison).
    """
    if not auth_header or not auth_header.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        expected = f'{expected_username}:{expected_password}'
        return hmac.compare_digest(decoded, expected)
    except Exception as exc:
        logger.warning("Basic auth check failed: %s", exc)
        return False


def check_bearer_token(auth_header, expected_token):
    """Validate an ``Authorization: Bearer <token>`` header.

    Returns ``True`` if the token matches (constant-time comparison).
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header[7:]
    return hmac.compare_digest(token, expected_token)


def check_landing_auth(auth_header):
    """Check landing-page auth using ``LANDING_PASSWORD`` (username ``admin``).

    Returns ``True`` if auth is disabled (no password set) or the
    credentials match.
    """
    load_env_file()
    password = os.environ.get('LANDING_PASSWORD', '')
    if not password:
        return True  # Auth disabled
    return check_basic_auth(auth_header, 'admin', password)


def check_terminal_auth(auth_header):
    """Check terminal auth using ``TTYD_USERNAME`` / ``TTYD_PASSWD``."""
    load_env_file()
    from vnc_remote_secure.core.constants import DEFAULT_TTYD_USERNAME
    username = os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME)
    password = os.environ.get('TTYD_PASSWD', '')
    if not password:
        return False
    return check_basic_auth(auth_header, username, password)


def check_health_auth(auth_header):
    """Check health endpoint auth using optional ``HEALTH_AUTH_TOKEN``.

    Returns ``True`` if no token is configured (open access, intended
    for localhost binding) or the Bearer token matches.
    """
    load_env_file()
    token = os.environ.get('HEALTH_AUTH_TOKEN', '')
    if not token:
        return True  # Open access (localhost default)
    return check_bearer_token(auth_header, token)


def require_auth(check_func, scheme='Basic', realm='VNC Remote Secure'):
    """Flask decorator that requires authentication via ``check_func``.

    ``check_func`` receives the ``Authorization`` header value and
    returns ``True`` if access is allowed. On failure, returns a
    uniform JSON 401 response with ``WWW-Authenticate`` header.

    ``scheme`` selects the ``WWW-Authenticate`` challenge advertised to
    clients (e.g., ``'Bearer'`` for token-based health auth).
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            from flask import request

            from vnc_remote_secure.core.errors import json_error
            auth = request.headers.get('Authorization', '')
            if not check_func(auth):
                resp, status = json_error('Unauthorized', 401)
                resp.headers['WWW-Authenticate'] = f'{scheme} realm="{realm}"'
                resp.status_code = status
                return resp
            return view(*args, **kwargs)
        return wrapper
    return decorator
