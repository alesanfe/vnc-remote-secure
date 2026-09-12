"""Web application factory for VNC Remote Secure.

Creates and configures a Flask application with secure session
settings, registered route blueprints, and optional SSL. Falls back to
a minimal ``http.server``-based app when Flask is not installed.
"""
import logging
import os
import secrets

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.logging import setup_logging

logger = logging.getLogger(__name__)


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

    # Attach SSL context to the app config so callers (e.g. app.run())
    # can enable HTTPS consistently with other services.
    from vnc_remote_secure.security.certificates import create_ssl_context
    app.config['SSL_CONTEXT'] = create_ssl_context()

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
        auth_header = environ.get('HTTP_AUTHORIZATION', '')
        if path in ('/health', '/health_status', '/health_status.json'):
            from vnc_remote_secure.core.errors import error_json
            from vnc_remote_secure.security.http_auth import check_health_auth
            if not check_health_auth(auth_header):
                body, status = error_json('Unauthorized', 401)
                body = body.encode('utf-8')
                start_response(f'{status} Unauthorized',
                               [('Content-Type', 'application/json'),
                                ('WWW-Authenticate', 'Bearer realm="Health"'),
                                ('Content-Length', str(len(body)))])
                return [body]
            import json

            from vnc_remote_secure.services.health import get_health_status
            body = json.dumps(get_health_status(), indent=2).encode('utf-8')
            start_response('200 OK', [('Content-Type', 'application/json'),
                                      ('Content-Length', str(len(body)))])
            return [body]
        if path == '/health/all':
            from vnc_remote_secure.core.errors import error_json
            from vnc_remote_secure.security.http_auth import check_health_auth
            if not check_health_auth(auth_header):
                body, status = error_json('Unauthorized', 401)
                body = body.encode('utf-8')
                start_response(f'{status} Unauthorized',
                               [('Content-Type', 'application/json'),
                                ('WWW-Authenticate', 'Bearer realm="Health"'),
                                ('Content-Length', str(len(body)))])
                return [body]
            import json

            from vnc_remote_secure.monitoring.health import get_all_health
            try:
                body = json.dumps(get_all_health(), indent=2).encode('utf-8')
                start_response('200 OK', [('Content-Type', 'application/json'),
                                          ('Content-Length', str(len(body)))])
                return [body]
            except Exception:
                logger.exception("Health status generation failed")
                body, _ = error_json('Health status generation failed', 500)
                body = body.encode('utf-8')
                start_response('500 Internal Server Error',
                               [('Content-Type', 'application/json'),
                                ('Content-Length', str(len(body)))])
                return [body]
        from vnc_remote_secure.core.errors import error_json
        from vnc_remote_secure.security.http_auth import check_landing_auth
        if not check_landing_auth(auth_header):
            body, status = error_json('Unauthorized', 401)
            body = body.encode('utf-8')
            start_response(f'{status} Unauthorized',
                           [('Content-Type', 'application/json'),
                            ('WWW-Authenticate', 'Basic realm="VNC Remote Secure"'),
                            ('Content-Length', str(len(body)))])
            return [body]
        body = b"VNC Remote Secure - Flask not installed. Install Flask for full UI."
        start_response('200 OK', [('Content-Type', 'text/plain'),
                                  ('Content-Length', str(len(body)))])
        return [body]


def _create_fallback_app(config):
    """Create the non-Flask fallback application."""
    return SimpleWebApp(config)
