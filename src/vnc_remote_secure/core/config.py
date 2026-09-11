#!/usr/bin/env python3
"""
Shared configuration loader for VNC Remote Secure Python components.
Reads .env file and provides environment variables with secure defaults.
NEVER hardcode credentials - always read from environment or .env file.
"""
import os
import sys
import secrets
import string


def _find_project_root():
    """Find project root by searching upward for .env or .env.example."""
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        if os.path.exists(os.path.join(current, '.env')):
            return current
        current = os.path.dirname(current)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_env_file(env_path=None):
    """Load .env file into os.environ without overriding existing vars."""
    if env_path is None:
        project_root = _find_project_root()
        env_path = os.path.join(project_root, '.env')
    if env_path is None or not os.path.exists(env_path):
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, _, val = line.partition('=')
                key = key.strip()
                val = val.strip()
                # Remove surrounding quotes
                if val and val[0] in '"\'' and val[-1] == val[0]:
                    val = val[1:-1]
                # Skip shell expansions like $(whoami)
                if val.startswith('$('):
                    continue
                # Only set if not already in environment
                if key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def generate_random_password(length=16):
    """Generate a strong random password."""
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_config():
    """Get configuration dictionary with all settings.
    Credentials are read from environment/.env, never hardcoded.
    If a required credential is missing, a random one is generated
    and printed to stderr so the user can see it.
    """
    load_env_file()

    # VNC password - generate random if not set
    vnc_password = os.environ.get('VNC_PASSWORD', '')
    if not vnc_password:
        vnc_password = generate_random_password(12)
        print(f"[CONFIG] WARNING: VNC_PASSWORD not set, generated random: {vnc_password}",
              file=sys.stderr)

    # Terminal credentials
    ttyd_username = os.environ.get('TTYD_USERNAME', 'admin')
    ttyd_password = os.environ.get('TTYD_PASSWD', '')
    if not ttyd_password:
        ttyd_password = generate_random_password(16)
        print(f"[CONFIG] WARNING: TTYD_PASSWD not set, generated random: {ttyd_password}",
              file=sys.stderr)

    # Ports
    config = {
        'vnc_port': int(os.environ.get('VNC_PORT', '5900')),
        'novnc_port': int(os.environ.get('NOVNC_PORT', '6080')),
        'ttyd_port': int(os.environ.get('TTYD_PORT', '5000')),
        'health_port': int(os.environ.get('HEALTH_WEB_PORT', '8090')),
        'landing_port': int(os.environ.get('LANDING_PORT', '8000')),
        'vnc_http_port': 5800,

        # Credentials (from .env, never hardcoded)
        'vnc_password': vnc_password,
        'ttyd_username': ttyd_username,
        'ttyd_password': ttyd_password,

        # SSL
        'ssl_cert': os.environ.get('SSL_CERT', ''),
        'ssl_key': os.environ.get('SSL_KEY', ''),

        # Hosts
        'health_host': os.environ.get('HEALTH_WEB_HOST', '0.0.0.0'),
        'landing_host': os.environ.get('LANDING_HOST', '0.0.0.0'),

        # Shell for web terminal
        'webterm_shell': os.environ.get('WEBTERM_SHELL', 'cmd.exe'),
    }

    # Fill SSL paths if not set but cert files exist in default location
    if not config['ssl_cert'] or not config['ssl_key']:
        project_root = _find_project_root()
        default_cert = os.path.join(project_root, 'data', 'ssl', 'fullchain.pem')
        default_key = os.path.join(project_root, 'data', 'ssl', 'privkey.pem')
        if os.path.exists(default_cert) and os.path.exists(default_key):
            config['ssl_cert'] = default_cert
            config['ssl_key'] = default_key

    return config
