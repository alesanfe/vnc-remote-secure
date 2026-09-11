"""User management route handler for the web UI.

Provides login/logout and user CRUD endpoints. Authentication is backed
by :mod:`vnc_remote_secure.security.authentication` and rate-limited via
:mod:`vnc_remote_secure.security.rate_limiting`.
"""
from flask import (Blueprint, jsonify, redirect, render_template,
                   request, session, url_for)

from vnc_remote_secure.core.validation import sanitize_input, validate_username
from vnc_remote_secure.security.authentication import (
    authenticate,
    create_session_token,
    validate_session_token,
)
from vnc_remote_secure.security.rate_limiting import check_rate_limit

users_bp = Blueprint('users', __name__)


def _client_ip():
    """Return the request client IP (respects X-Forwarded-For)."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate a user and create a session.

    GET renders the login form; POST validates credentials, applies
    rate limiting, and stores a session token on success.
    """
    if request.method == 'POST':
        ip = _client_ip()
        if not check_rate_limit(ip):
            return jsonify({'error': 'Too many attempts. Try again later.'}), 429
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        if authenticate(username, password):
            session['user'] = username
            session['token'] = create_session_token(username)
            return redirect(url_for('users.users'))
        return render_template('login.html', error='Invalid credentials'), 401
    return render_template('login.html')


@users_bp.route('/logout')
def logout():
    """Clear the session and redirect to login."""
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
    except Exception:
        session.clear()
        return redirect(url_for('users.login'))
    return render_template('users.html')


@users_bp.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def api_users():
    """JSON API for user management (requires authentication)."""
    token = session.get('token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        validate_session_token(token)
    except Exception as exc:
        return jsonify({'error': str(exc)}), 401

    if request.method == 'GET':
        # Return a placeholder list; real user enumeration is platform-specific.
        return jsonify({'users': []})

    if request.method == 'POST':
        username = sanitize_input(request.json.get('username', ''))
        try:
            validate_username(username)
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
        # Delegated to platform user management in a full deployment.
        return jsonify({'status': 'created', 'username': username}), 201

    if request.method == 'DELETE':
        username = sanitize_input(request.json.get('username', ''))
        return jsonify({'status': 'deleted', 'username': username})

    return jsonify({'error': 'Method not allowed'}), 405
