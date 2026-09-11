"""Web application factory for VNC Remote Secure.

Creates and configures a Flask application with secure session
settings, registered route blueprints, and optional SSL. Falls back to
a minimal ``http.server``-based app when Flask is not installed.
"""
import os
import secrets

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.logging import setup_logging


def create_app(config=None):
    """Create and configure a web application.

    Args:
        config: Optional configuration dict (as returned by
            :func:`get_config`). When ``None`` the environment is loaded.

    Returns:
        A configured Flask application instance, or a
        :class:`SimpleWebApp` fallback when Flask is unavailable.
    """
    load_env_file()
    if config is None:
        config = get_config()
    setup_logging()

    try:
        from flask import Flask
    except ImportError:
        return _create_fallback_app(config)

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
    )
    app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true',
        PERMANENT_SESSION_LIFETIME=1800,
        VNC_CONFIG=config,
    )

    # Register blueprints.
    from vnc_remote_secure.web.routes.health import health_bp
    from vnc_remote_secure.web.routes.landing import landing_bp
    from vnc_remote_secure.web.routes.users import users_bp
    app.register_blueprint(health_bp)
    app.register_blueprint(landing_bp)
    app.register_blueprint(users_bp)

    return app


class SimpleWebApp:
    """Minimal fallback web app used when Flask is not installed.

    Implements a callable WSGI application that routes ``/health`` to a
    JSON status response and everything else to a simple text page.
    """

    def __init__(self, config):
        self.config = config

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '/')
        if path in ('/health', '/health_status', '/health_status.json'):
            from vnc_remote_secure.services.health import get_health_status
            import json
            body = json.dumps(get_health_status(), indent=2).encode('utf-8')
            start_response('200 OK', [('Content-Type', 'application/json'),
                                      ('Content-Length', str(len(body)))])
            return [body]
        body = b"VNC Remote Secure - Flask not installed. Install Flask for full UI."
        start_response('200 OK', [('Content-Type', 'text/plain'),
                                  ('Content-Length', str(len(body)))])
        return [body]


def _create_fallback_app(config):
    """Create the non-Flask fallback application."""
    return SimpleWebApp(config)
