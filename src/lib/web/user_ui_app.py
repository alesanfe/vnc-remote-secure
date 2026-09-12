#!/usr/bin/env python3
"""
User Management UI for Raspberry Pi VNC Remote.
Provides web interface for user management.

DEPRECATED: This is the legacy Bash-stack user management UI. The
preferred implementation is the package-based ``vnc_remote_secure.web``
Flask application (``web/routes/users.py``) which is cross-platform,
uses session tokens, and shares ``RESERVED_USERNAMES`` with the rest
of the package. This module is retained for the Bash stack only and
will be removed once the Bash stack migrates to the package CLI.
"""

import getpass
import os
import re
import secrets
import subprocess
import time
from collections import defaultdict
from functools import wraps

from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Session cookie security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true',
    PERMANENT_SESSION_LIFETIME=1800,
)

# Session timeout in seconds (default: 30 minutes)
SESSION_TIMEOUT = int(os.environ.get('USER_UI_SESSION_TIMEOUT', '1800'))

# Reserved usernames that cannot be created or deleted via the UI.
# Import from the shared constants to keep both UIs in sync.
try:
    from vnc_remote_secure.core.constants import RESERVED_USERNAMES as RESERVED_USERNAMES
except ImportError:
    # Fallback for standalone execution outside the package
    RESERVED_USERNAMES = {'root', 'pi', 'admin', 'daemon', 'bin', 'sys', 'nobody', 'www-data'}

# Hash the admin password at startup using werkzeug (salted pbkdf2)
_ADMIN_PASSWORD = os.environ.get('USER_UI_PASSWORD', '')
_ADMIN_PASSWORD_HASH = generate_password_hash(_ADMIN_PASSWORD) if _ADMIN_PASSWORD else ''

# Simple in-memory rate limiter for login attempts
# Maps IP -> list of timestamps of failed attempts
_LOGIN_ATTEMPTS = defaultdict(list)
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 300  # 5 minutes


def _is_rate_limited(client_ip):
    """Check if the IP has exceeded the login attempt limit."""
    now = time.time()
    # Remove attempts outside the window
    _LOGIN_ATTEMPTS[client_ip] = [
        t for t in _LOGIN_ATTEMPTS[client_ip] if now - t < _LOGIN_WINDOW
    ]
    return len(_LOGIN_ATTEMPTS[client_ip]) >= _LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(client_ip):
    """Record a failed login attempt for rate limiting."""
    _LOGIN_ATTEMPTS[client_ip].append(time.time())


def _clear_failed_attempts(client_ip):
    """Clear failed attempts after successful login."""
    _LOGIN_ATTEMPTS.pop(client_ip, None)


def _get_client_ip():
    """Get the real client IP, respecting X-Forwarded-For only from trusted proxies."""
    # If behind a trusted reverse proxy, use X-Forwarded-For
    # Set TRUSTED_PROXY=true (or 1/yes) in env to enable X-Forwarded-For parsing
    if os.environ.get('TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes'):
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            # Take the first IP (leftmost) in the chain
            return forwarded.split(',')[0].strip()
    return request.remote_addr or ''


def _verify_password(password, stored_hash):
    """Verify a password against a stored hash using constant-time comparison."""
    if not stored_hash:
        return False
    return check_password_hash(stored_hash, password)


# Input sanitization
def sanitize_username(username):
    """Sanitize username to prevent command injection."""
    if not username:
        return None
    # Only allow alphanumeric, underscore, hyphen, and dot
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return None
    if len(username) > 32:
        return None
    return username


def sanitize_string(input_str):
    """Basic string sanitization: remove shell metacharacters and control chars."""
    if not input_str:
        return None
    # Remove shell metacharacters, newlines, colons, and control characters
    # Colons and newlines are dangerous when passed to chpasswd
    sanitized = re.sub(r'[;&|`$()\n\r:\x00-\x1f]', '', str(input_str))
    return sanitized if sanitized else None


def login_required(view):
    """Decorator that enforces login and session timeout."""
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        if session.get('login_time') and \
                (time.time() - session['login_time']) > SESSION_TIMEOUT:
            session.clear()
            flash('Session expired. Please log in again.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return decorated_function


def validate_csrf_token():
    """Validate the CSRF token from the form against the session."""
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    return (token and session.get('csrf_token')
            and secrets.compare_digest(token, session['csrf_token']))


def require_csrf(view):
    """Decorator for POST routes that validates CSRF token."""
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if not validate_csrf_token():
            flash('Invalid or missing CSRF token. Please try again.')
            return redirect(url_for('users'))
        return view(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required
def index():
    """Render the index page."""
    return render_template('index.html', csrf_token=session.get('csrf_token', ''))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login (GET shows form, POST validates password)."""
    client_ip = _get_client_ip()
    if request.method == 'POST':
        if _is_rate_limited(client_ip):
            flash('Too many login attempts. Please try again later.')
            return render_template('login.html')
        password = request.form.get('password', '')
        if _verify_password(password, _ADMIN_PASSWORD_HASH):
            _clear_failed_attempts(client_ip)
            # Use the shared session helper to align with the Flask UI
            try:
                from vnc_remote_secure.security.authentication import create_web_session
                create_web_session(session, 'admin')
            except ImportError:
                # Fallback for standalone execution outside the package
                session['user'] = 'admin'
                session['login_time'] = time.time()
                session['token'] = ''
                session['csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('index'))
        _record_failed_attempt(client_ip)
        flash('Invalid password')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@require_csrf
def logout():
    """Clear session and redirect to login (POST-only + CSRF to prevent abuse)."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/users')
@login_required
def users():
    """List system users."""
    try:
        result = subprocess.run(
            ['getent', 'passwd'],
            capture_output=True, text=True, check=False,
        )
        user_list = []
        for line in result.stdout.split('\n'):
            if line:
                parts = line.split(':')
                if len(parts) >= 7:
                    user_list.append({
                        'username': parts[0],
                        'uid': parts[2],
                        'home': parts[5],
                    })
        return render_template(
            'users.html',
            users=user_list,
            csrf_token=session.get('csrf_token', ''),
            RESERVED_USERNAMES=RESERVED_USERNAMES,
        )
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("User list failed")
        return 'Internal Server Error', 500


@app.route('/create_user', methods=['POST'])
@login_required
@require_csrf
def create_user():
    """Create a new system user."""
    username = sanitize_username(request.form.get('username'))
    password = sanitize_string(request.form.get('password'))

    if not username:
        flash('Invalid username format')
        return redirect(url_for('users'))

    if not password or len(password) < 8:
        flash('Password must be at least 8 characters')
        return redirect(url_for('users'))

    if username in RESERVED_USERNAMES:
        flash('Cannot create system users')
        return redirect(url_for('users'))

    user_created = False
    try:
        subprocess.run(
            ['sudo', 'useradd', '-m', '-s', '/bin/bash', username],
            check=True,
        )
        user_created = True
        with subprocess.Popen(
            ['sudo', 'chpasswd'],
            stdin=subprocess.PIPE, text=True,
        ) as process:
            process.communicate(input=f'{username}:{password}\n')
            if process.returncode != 0:
                raise RuntimeError('chpasswd failed')
        flash(f'User {username} created successfully')
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("User creation failed for %s", username)
        flash('Error creating user. Check server logs for details.')
        # Only cleanup if useradd succeeded (don't delete pre-existing users)
        if user_created:
            subprocess.run(
                ['sudo', 'userdel', '--remove-home', username],
                stderr=subprocess.DEVNULL, check=False,
            )

    return redirect(url_for('users'))


@app.route('/delete_user/<username>', methods=['POST'])
@login_required
@require_csrf
def delete_user(username):
    """Delete a system user."""
    username = sanitize_username(username)

    if not username:
        flash('Invalid username')
        return redirect(url_for('users'))

    if username in RESERVED_USERNAMES or username == getpass.getuser():
        flash('Cannot delete system users')
        return redirect(url_for('users'))

    try:
        subprocess.run(
            ['sudo', 'userdel', '--remove-home', username],
            check=True,
        )
        flash(f'User {username} deleted successfully')
    except Exception as exc:  # pylint: disable=broad-except
        # Log full error internally but show generic message to avoid leaking paths/commands
        app.logger.error('Error deleting user %s: %s', username, exc)
        flash('Error deleting user. Check server logs for details.')

    return redirect(url_for('users'))


# Protect Flask's default /static endpoint with the same auth as the app.
@app.route('/static/<path:filename>')
@login_required
def protected_static(filename):
    """Serve static files only to authenticated users."""
    return app.send_static_file(filename)


if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=int(os.environ.get('USER_UI_PORT', 8081)),
        debug=False,
    )
