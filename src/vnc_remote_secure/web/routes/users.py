"""User management route handler for the web UI.

Provides login/logout and user CRUD endpoints. Authentication is backed
by :mod:`vnc_remote_secure.security.authentication` and rate-limited via
:mod:`vnc_remote_secure.security.rate_limiting`.
"""
import logging
import os
import secrets

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from vnc_remote_secure.core.errors import json_error
from vnc_remote_secure.core.exceptions import SecurityError
from vnc_remote_secure.core.validation import sanitize_input, validate_username
from vnc_remote_secure.security.authentication import (
    authenticate,
    create_web_session,
    validate_session_token,
)
from vnc_remote_secure.security.rate_limiting import check_rate_limit

users_bp = Blueprint('users', __name__)


def _client_ip():
    """Return the request client IP.

    Respects ``X-Forwarded-For`` only when ``TRUSTED_PROXY=true`` (i.e.
    when the operator has confirmed the app sits behind a trusted reverse
    proxy). Otherwise the direct ``remote_addr`` is used to prevent
    spoofing.
    """
    trusted = os.environ.get('TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
    if trusted:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _check_csrf():
    """Validate the CSRF token for state-changing requests.

    The token is stored in ``session['csrf_token']`` on login and must be
    supplied via the ``X-CSRF-Token`` header or a ``csrf_token`` form field.
    Returns ``True`` if the token matches.
    """
    expected = session.get('csrf_token')
    if not expected:
        return False
    sent = (
        request.headers.get('X-CSRF-Token')
        or request.form.get('csrf_token')
        or (request.get_json(silent=True) or {}).get('csrf_token')
    )
    if not sent:
        return False
    return secrets.compare_digest(str(sent), str(expected))


@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate a user and create a session.

    GET renders the login form; POST validates credentials, applies
    rate limiting, and stores a session token on success.
    """
    if request.method == 'POST':
        ip = _client_ip()
        if not check_rate_limit(ip):
            return json_error('Too many attempts. Try again later.', 429)
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        if authenticate(username, password):
            create_web_session(session, username)
            return redirect(url_for('users.users'))
        return render_template('login.html', error='Invalid credentials'), 401
    return render_template('login.html')


@users_bp.route('/logout', methods=['POST'])
def logout():
    """Clear the session and redirect to login.

    POST is required to prevent CSRF attacks via simple GET links.
    A valid CSRF token (issued on login) must be supplied.
    """
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)
    session.clear()
    return redirect(url_for('users.login'))


@users_bp.route('/users')
def users():
    """Render the user management page (requires authentication)."""
    token = session.get('token')
    if not token:
        return redirect(url_for('users.login'))
    try:
        validate_session_token(token)
    except SecurityError as exc:
        logging.getLogger(__name__).warning(
            "Invalid session token: %s", exc
        )
        session.clear()
        return redirect(url_for('users.login'))
    return render_template('users.html')


@users_bp.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def api_users():
    """JSON API for user management (requires authentication).

    State-changing methods (POST, DELETE) require a valid CSRF token.
    The endpoints are currently stubs that return 501 Not Implemented
    for write operations until platform user management is wired in.
    """
    token = session.get('token')
    if not token:
        return json_error('Not authenticated', 401)
    try:
        validate_session_token(token)
    except SecurityError as exc:
        return json_error(str(exc), 401)

    if request.method == 'GET':
        # Return a placeholder list; real user enumeration is platform-specific.
        return jsonify({'users': []})

    # POST and DELETE are state-changing: require CSRF protection.
    if not _check_csrf():
        return json_error('Invalid or missing CSRF token', 403)

    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error('Request body must be a JSON object', 400)
        username = sanitize_input(data.get('username', ''))
        try:
            validate_username(username)
        except ValueError as exc:
            return json_error(str(exc), 400)
        # Not yet implemented: delegate to platform user management.
        return json_error('User creation not implemented in this build', 501)

    if request.method == 'DELETE':
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error('Request body must be a JSON object', 400)
        username = sanitize_input(data.get('username', ''))
        try:
            validate_username(username)
        except ValueError as exc:
            return json_error(str(exc), 400)
        return json_error('User deletion not implemented in this build', 501)

    return json_error('Method not allowed', 405)
