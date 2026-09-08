#!/usr/bin/env python3
"""
User Management UI for Raspberry Pi VNC Remote
Provides web interface for user management
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import subprocess
import os
import secrets
import re

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

ADMIN_PASSWORD = os.environ.get('USER_UI_PASSWORD', 'admin123')

# Input sanitization
def sanitize_username(username):
    """Sanitize username to prevent command injection"""
    if not username:
        return None
    # Only allow alphanumeric, underscore, hyphen, and dot
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return None
    # Limit length
    if len(username) > 32:
        return None
    return username

def sanitize_string(input_str):
    """Basic string sanitization"""
    if not input_str:
        return None
    # Remove potentially dangerous characters
    return re.sub(r'[;&|`$()]', '', str(input_str))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    try:
        result = subprocess.run(['getent', 'passwd'], capture_output=True, text=True)
        users = []
        for line in result.stdout.split('\n'):
            if line:
                parts = line.split(':')
                users.append({'username': parts[0], 'uid': parts[2], 'home': parts[5]})
        return render_template('users.html', users=users)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    username = sanitize_username(request.form.get('username'))
    password = sanitize_string(request.form.get('password'))
    
    if not username:
        flash('Invalid username format')
        return redirect(url_for('users'))
    
    if not password or len(password) < 8:
        flash('Password must be at least 8 characters')
        return redirect(url_for('users'))
    
    if username in ['root', 'pi', 'admin']:
        flash('Cannot create system users')
        return redirect(url_for('users'))
    
    try:
        subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/bash', username], check=True)
        # Fixed chpasswd command
        process = subprocess.Popen(['sudo', 'chpasswd'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=f'{username}:{password}\n')
        if process.returncode != 0:
            raise Exception('chpasswd failed')
        flash(f'User {username} created successfully')
    except Exception as e:
        flash(f'Error creating user: {str(e)}')
        # Cleanup if user creation partially succeeded
        subprocess.run(['sudo', 'deluser', '--remove-home', username], stderr=subprocess.DEVNULL)
    
    return redirect(url_for('users'))

@app.route('/delete_user/<username>')
@login_required
def delete_user(username):
    username = sanitize_username(username)
    
    if not username:
        flash('Invalid username')
        return redirect(url_for('users'))
    
    if username in ['root', 'pi', 'admin', os.environ.get('USER', '')]:
        flash('Cannot delete system users')
        return redirect(url_for('users'))
    
    try:
        subprocess.run(['sudo', 'deluser', '--remove-home', username], check=True)
        flash(f'User {username} deleted successfully')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}')
    
    return redirect(url_for('users'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('USER_UI_PORT', 8081)), debug=False)
