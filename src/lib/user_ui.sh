#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# USER MANAGEMENT UI MODULE
# ============================================================================

# User UI Configuration
export USER_UI_ENABLED="${USER_UI_ENABLED:-false}"
export USER_UI_PORT="${USER_UI_PORT:-8081}"
export USER_UI_PASSWORD="${USER_UI_PASSWORD:-admin123}"

# Install Flask dependencies
install_flask_deps() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing Flask dependencies..." "⚙️"
    
    sudo apt update
    sudo apt install -y python3 python3-pip
    pip3 install flask flask-login --user 2>/dev/null || sudo pip3 install flask flask-login
    
    success "Flask dependencies installed."
}

# Create Flask user management UI
create_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return
    
    log "yellow" "Creating User Management UI..." "⚙️"
    
    local ui_dir="$PROJECT_DIR/user_ui"
    mkdir -p "$ui_dir/templates"
    
    # Create Flask app
    cat > "$ui_dir/app.py" <<'EOF'
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
EOF
    
    # Create login template
    cat > "$ui_dir/templates/login.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VNC Remote - Login</title>
    <style>
        body { font-family: Arial; max-width: 400px; margin: 100px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
        .flash { padding: 10px; background: #f8d7da; margin: 10px 0; }
    </style>
</head>
<body>
    <h2>VNC Remote - User Management</h2>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="flash">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <form method="POST">
        <input type="password" name="password" placeholder="Admin Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
EOF
    
    # Create index template
    cat > "$ui_dir/templates/index.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VNC Remote - Dashboard</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
        .menu a { margin: 10px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; }
        .menu a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>VNC Remote - User Management Dashboard</h1>
    <div class="menu">
        <a href="/users">Manage Users</a>
        <a href="/logout">Logout</a>
    </div>
</body>
</html>
EOF
    
    # Create users template
    cat > "$ui_dir/templates/users.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VNC Remote - Users</title>
    <style>
        body { font-family: Arial; max-width: 1000px; margin: 50px auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f4f4f4; }
        .btn { padding: 5px 10px; text-decoration: none; color: white; }
        .btn-danger { background: #dc3545; }
        .btn-success { background: #28a745; }
        .flash { padding: 10px; background: #f8d7da; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>User Management</h1>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="flash">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <a href="/" class="btn btn-success">Back to Dashboard</a>
    <h2>Create New User</h2>
    <form method="POST" action="/create_user">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" class="btn btn-success">Create User</button>
    </form>
    <h2>Existing Users</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>UID</th>
            <th>Home Directory</th>
            <th>Actions</th>
        </tr>
        {% for user in users %}
        <tr>
            <td>{{ user.username }}</td>
            <td>{{ user.uid }}</td>
            <td>{{ user.home }}</td>
            <td>
                {% if user.username not in ['root', 'pi'] %}
                <a href="/delete_user/{{ user.username }}" class="btn btn-danger">Delete</a>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
EOF
    
    success "User Management UI created."
}

# Start User UI
start_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting User Management UI..." "🚀"
    
    local ui_dir="$PROJECT_DIR/user_ui"
    cd "$ui_dir"
    python3 app.py &
    cd - > /dev/null
    
    success "User Management UI started on port $USER_UI_PORT"
}

# Stop User UI
stop_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return
    
    log "yellow" "Stopping User Management UI..." "🛑"
    
    pkill -f "python3.*app.py" 2>/dev/null || true
    
    success "User Management UI stopped."
}
