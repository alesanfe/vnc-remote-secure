#!/usr/bin/env python3
"""
Shared configuration loader for VNC Remote Secure Python components.
Reads .env file and provides environment variables with secure defaults.
NEVER hardcode credentials - always read from environment or .env file.
"""
import os
import sys
import logging
import secrets
import string

from vnc_remote_secure.core.constants import (
    DEFAULT_VNC_PORT,
    DEFAULT_VNC_HTTP_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_TTYD_USERNAME,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_USER_UI_PORT,
    DEFAULT_VNC_GEOMETRY,
    DEFAULT_VNC_DEPTH,
    DEFAULT_VNC_DISPLAY,
    DEFAULT_WEBTERM_SHELL,
    DEFAULT_BIND_HOST,
)

logger = logging.getLogger(__name__)


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
    except Exception as e:
        logger.warning("Failed to load .env file '%s': %s", env_path, e)


def generate_random_password(length=16):
    """Generate a strong random password.

    Guarantees at least one uppercase, one lowercase, one digit, and
    one special character so the result always passes ``validate_password``.
    """
    specials = '!@#$%^&*'
    # Guarantee one of each required class, then fill the rest randomly.
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    alphabet = string.ascii_letters + string.digits + specials
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    pool = required + remaining
    secrets.SystemRandom().shuffle(pool)
    return ''.join(pool)


def get_config():
    """Get configuration dictionary with all settings.
    Credentials are read from environment/.env, never hardcoded.
    If a required credential is missing, a random one is generated
    and printed to stderr so the user can see it.
    """
    load_env_file()

    # VNC password - generate random if not set
    vnc_password_user_set = bool(os.environ.get('VNC_PASSWORD', ''))
    vnc_password = os.environ.get('VNC_PASSWORD', '')
    if not vnc_password:
        vnc_password = generate_random_password(12)
        os.environ['VNC_PASSWORD'] = vnc_password
        logger.warning("VNC_PASSWORD not set; generated a random password (not shown for security)")

    # Terminal credentials
    ttyd_username = os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME)
    ttyd_password_user_set = bool(os.environ.get('TTYD_PASSWD', ''))
    ttyd_password = os.environ.get('TTYD_PASSWD', '')
    if not ttyd_password:
        ttyd_password = generate_random_password(16)
        os.environ['TTYD_PASSWD'] = ttyd_password
        logger.warning("TTYD_PASSWD not set; generated a random password (not shown for security)")

    # User UI password (optional, only validated if set)
    user_ui_password = os.environ.get('USER_UI_PASSWORD', '')

    # Flask secret key - generate random if not set
    flask_secret_key = os.environ.get('FLASK_SECRET_KEY', '')
    if not flask_secret_key:
        flask_secret_key = secrets.token_hex(32)
        os.environ['FLASK_SECRET_KEY'] = flask_secret_key

    # Auth secret - generate random if not set
    auth_secret = os.environ.get('AUTH_SECRET', '')
    if not auth_secret:
        auth_secret = secrets.token_hex(32)
        os.environ['AUTH_SECRET'] = auth_secret

    # Landing page password (optional)
    landing_password = os.environ.get('LANDING_PASSWORD', '')

    # Health auth token (optional)
    health_auth_token = os.environ.get('HEALTH_AUTH_TOKEN', '')

    # Validate passwords when they are user-provided (not generated).
    # Generated passwords are always strong; user-provided ones may be weak.
    from vnc_remote_secure.core.validation import validate_password
    if vnc_password_user_set:
        validate_password(vnc_password, 'VNC_PASSWORD')
    if ttyd_password_user_set:
        validate_password(ttyd_password, 'TTYD_PASSWD')
    if user_ui_password:
        validate_password(user_ui_password, 'USER_UI_PASSWORD')
    if landing_password:
        validate_password(landing_password, 'LANDING_PASSWORD')

    # Ports (platform-aware defaults from constants.py)
    config = {
        'vnc_port': int(os.environ.get('VNC_PORT', str(DEFAULT_VNC_PORT))),
        'vnc_http_port': int(os.environ.get('VNC_HTTP_PORT', str(DEFAULT_VNC_HTTP_PORT))),
        'novnc_port': int(os.environ.get('NOVNC_PORT', str(DEFAULT_NOVNC_PORT))),
        'ttyd_port': int(os.environ.get('TTYD_PORT', str(DEFAULT_TTYD_PORT))),
        'health_port': int(os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT))),
        'landing_port': int(os.environ.get('LANDING_PORT', str(DEFAULT_LANDING_PORT))),
        'user_ui_port': int(os.environ.get('USER_UI_PORT', str(DEFAULT_USER_UI_PORT))),

        # Credentials (from .env, never hardcoded)
        'vnc_password': vnc_password,
        'ttyd_username': ttyd_username,
        'ttyd_password': ttyd_password,
        'user_ui_password': user_ui_password,

        # Secrets
        'flask_secret_key': flask_secret_key,
        'auth_secret': auth_secret,

        # SSL
        'ssl_cert': os.environ.get('SSL_CERT', ''),
        'ssl_key': os.environ.get('SSL_KEY', ''),

        # Hosts (secure default: localhost; set 0.0.0.0 for LAN access)
        'health_host': os.environ.get('HEALTH_WEB_HOST', DEFAULT_BIND_HOST),
        'landing_host': os.environ.get('LANDING_HOST', DEFAULT_BIND_HOST),
        'novnc_host': os.environ.get('SERVE_NOVNC_HOST', os.environ.get('NOVNC_HOST', DEFAULT_BIND_HOST)),
        'ttyd_host': os.environ.get('TTYD_HOST', DEFAULT_BIND_HOST),

        # Landing page auth
        'landing_password': os.environ.get('LANDING_PASSWORD', ''),

        # Health auth token (optional Bearer token for /health)
        'health_auth_token': os.environ.get('HEALTH_AUTH_TOKEN', ''),

        # Shell for web terminal
        'webterm_shell': os.environ.get('WEBTERM_SHELL', DEFAULT_WEBTERM_SHELL),

        # VNC display settings
        'vnc_geometry': os.environ.get('VNC_GEOMETRY', DEFAULT_VNC_GEOMETRY),
        'vnc_depth': int(os.environ.get('VNC_DEPTH', str(DEFAULT_VNC_DEPTH))),
        'vnc_display': os.environ.get('VNC_DISPLAY', DEFAULT_VNC_DISPLAY),

        # Feature toggles (mirrors .env.example; defaults are conservative)
        'nginx_enabled': os.environ.get('NGINX_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'fail2ban_enabled': os.environ.get('FAIL2BAN_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'monitoring_enabled': os.environ.get('MONITORING_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'healthcheck_enabled': os.environ.get('HEALTHCHECK_ENABLED', 'true').lower() in ('true', '1', 'yes'),
        'health_web_enabled': os.environ.get('HEALTH_WEB_ENABLED', 'true').lower() in ('true', '1', 'yes'),
        'recording_enabled': os.environ.get('RECORDING_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'user_ui_enabled': os.environ.get('USER_UI_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'alerts_enabled': os.environ.get('ALERTS_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'audio_stream_enabled': os.environ.get('AUDIO_STREAM_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'gamepad_enabled': os.environ.get('GAMEPAD_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'tls_enabled': os.environ.get('TLS_ENABLED', 'true').lower() in ('true', '1', 'yes'),
        'keep_temp_user': os.environ.get('KEEP_TEMP_USER', 'false').lower() in ('true', '1', 'yes'),
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
