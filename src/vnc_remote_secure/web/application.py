"""Web application factory for VNC Remote Secure.

Creates and configures a Flask application with secure session
settings, registered route blueprints, and optional SSL. Falls back to
a minimal ``http.server``-based app when Flask is not installed.
"""
import logging
import os
import re

from vnc_remote_secure.core.config import (
    get_config,
    load_env_file,
    resolve_samesite,
)
from vnc_remote_secure.core.logging import setup_logging

logger = logging.getLogger(__name__)


def _safe_cookie_name(name) -> str:
    """Validate a cookie name for verbatim use in Set-Cookie.

    Returns 'vnc_flask_session' when the value is not a plain token or
    when it collides with 'vnc_session' — the name reserved for the
    raw HMAC session token consumed by the non-Flask services.
    """
    name = str(name or '')
    if re.fullmatch(r'[A-Za-z0-9_\-]+', name) and name != 'vnc_session':
        return name
    return 'vnc_flask_session'


def _resolved_tls(config) -> bool:
    """True when TLS will actually be active: flag enabled AND a cert
    pair resolvable via the same discovery the services use."""
    if not config.get('tls_enabled'):
        return False
    try:
        from vnc_remote_secure.security.certificates import create_ssl_context
        return create_ssl_context(
            config.get('ssl_cert') or None,
            config.get('ssl_key') or None) is not None
    except Exception:
        return False


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
        # In non-development profiles, Flask is required. The fallback
        # app lacks security features (no session middleware, no
        # after_request hooks, no blueprint auth). Legacy aliases
        # (home-lan, private-vpn, internet-hardened) must resolve to
        # their canonical names first or a hardened deployment via
        # alias would silently downgrade to the insecure fallback.
        from vnc_remote_secure.security.profiles import resolve_profile
        profile = resolve_profile()
        if profile in ('public-hardened', 'private-overlay', 'trusted-lan'):
            logger.error(
                "Flask is not installed but profile '%s' requires it. "
                "The fallback http.server app lacks security features. "
                "Install Flask: pip install flask",
                profile,
            )
            raise RuntimeError(
                f"Flask is required for security profile '{profile}'. "
                f"Install it with: pip install flask"
            )
        return _create_fallback_app(config)

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
    )

    # Flask secret key: must be set in non-development profiles.
    # In development, a random ephemeral key is acceptable.
    flask_secret = os.environ.get('FLASK_SECRET_KEY', '').strip()
    if flask_secret:
        app.secret_key = flask_secret
    else:
        from vnc_remote_secure.security.profiles import resolve_profile
        profile = resolve_profile()
        if profile in ('public-hardened', 'private-overlay', 'trusted-lan'):
            # Hardened profiles must not start with an ephemeral secret:
            # it invalidates sessions on every restart and breaks
            # multi-process deployments. ``get_blocking_findings()`` also
            # reports this, but we fail fast here to avoid a silently
            # insecure running instance.
            raise RuntimeError(
                f"FLASK_SECRET_KEY is required for security profile "
                f"'{profile}'. Set it in .env to a persistent random value."
            )
        # Development fallback: reuse the persisted auth secret
        # (auth_secret.key in the run dir) instead of an ephemeral
        # token — sessions then survive service restarts, matching
        # the behaviour operators expect from the bearer/ephemeral
        # token system, which already uses that same persisted key.
        from vnc_remote_secure.security.authentication import _get_secret
        app.secret_key = _get_secret().decode('utf-8')
    from vnc_remote_secure.security import sessions as _sessions
    app.config.update(
        # Cookie name lands verbatim in Set-Cookie — restrict to token
        # characters or a crafted SESSION_COOKIE_NAME could inject
        # extra attributes into the header.
        # This is Flask's OWN session cookie (itsdangerous blob holding
        # token/csrf/user). It must NOT be 'vnc_session' — that name
        # belongs to the raw HMAC session token the non-Flask services
        # (noVNC, terminal, audio, gamepad, landing) read directly via
        # check_authenticated/verify_session_cookie. Sharing the name
        # made WS cookie-auth unresolvable (a Flask blob never
        # verifies as an HMAC token).
        SESSION_COOKIE_NAME=(
            _safe_cookie_name(os.environ.get('SESSION_COOKIE_NAME',
                                             'vnc_flask_session'))),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=resolve_samesite(),
        # Default Secure flag follows the RESOLVED TLS state (env flag
        # plus actual cert resolution — same source of truth the
        # services use), not the flag alone: TLS_ENABLED=true with no
        # certs would emit a Secure cookie the browser never returns
        # over the resulting cleartext app. SESSION_COOKIE_SECURE can
        # still force the flag either way.
        SESSION_COOKIE_SECURE=os.environ.get(
            'SESSION_COOKIE_SECURE',
            'true' if _resolved_tls(config) else 'false').lower() == 'true',
        # Use the configured session timeouts from the security profile
        # (or .env) instead of a hardcoded 1800. This aligns Flask with
        # SESSION_IDLE_TIMEOUT and SESSION_MAX_LIFETIME consumed by the
        # auth gateway and ephemeral session subsystem.
        PERMANENT_SESSION_LIFETIME=int(
            os.environ.get(
                'SESSION_MAX_LIFETIME',
                str(_sessions.DEFAULT_MAX_LIFETIME))),
        SESSION_IDLE_TIMEOUT=int(
            os.environ.get(
                'SESSION_IDLE_TIMEOUT',
                str(_sessions.DEFAULT_IDLE_TIMEOUT))),
        VNC_CONFIG=config,
        # Request bodies are only small form fields (login/user mgmt)
        # — without a cap, a POST with a huge Content-Length is
        # buffered in memory (DoS). 64 KiB is generous; overridable via
        # env for exotic deployments.
        MAX_CONTENT_LENGTH=int(
            os.environ.get('WEB_MAX_CONTENT_LENGTH', str(64 * 1024))),
    )

    # Register blueprints.
    from vnc_remote_secure.web.routes.health import health_bp
    from vnc_remote_secure.web.routes.landing import landing_bp
    from vnc_remote_secure.web.routes.users import users_bp
    app.register_blueprint(health_bp)
    app.register_blueprint(landing_bp)
    app.register_blueprint(users_bp)

    # Apply security headers to all responses.
    from vnc_remote_secure.security.http_headers import get_security_headers
    from vnc_remote_secure.security.profiles import _is_tls_enabled

    @app.after_request
    def _apply_security_headers(response):
        headers = get_security_headers(_is_tls_enabled())
        for name, value in headers.items():
            response.headers[name] = value
        return response

    # Sliding idle timeout: re-issue the session cookie with an updated
    # last_seen on authenticated requests so SESSION_IDLE_TIMEOUT
    # measures inactivity rather than age since login.
    @app.after_request
    def _refresh_session_cookie(response):
        try:
            from flask import request as _req

            from vnc_remote_secure.security.sessions import (
                get_cookie_attributes,
                refresh_session_cookie,
            )
            # 'vnc_session' is the raw HMAC session token the other
            # services verify — NOT the Flask session cookie (renamed
            # 'vnc_flask_session' to avoid the collision).
            cookie_name = 'vnc_session'
            raw = _req.cookies.get(cookie_name, '')
            if not raw:
                return response
            new_value = refresh_session_cookie(raw)
            if new_value:
                attrs = get_cookie_attributes(
                    secure=app.config.get('SESSION_COOKIE_SECURE', True))
                # Same max_age as create_session_cookie:
                # min(idle, max_lifetime) — the idle window, not the
                # absolute cap, is what the cookie should outlive.
                # PERMANENT_SESSION_LIFETIME may surface as a timedelta
                # under Flask — read the env ints directly instead.
                from vnc_remote_secure.core.constants import (
                    DEFAULT_SESSION_IDLE_TIMEOUT,
                    DEFAULT_SESSION_MAX_LIFETIME,
                )
                from vnc_remote_secure.security.sessions import _get_env_int
                max_age = min(
                    _get_env_int('SESSION_IDLE_TIMEOUT',
                                 DEFAULT_SESSION_IDLE_TIMEOUT),
                    _get_env_int('SESSION_MAX_LIFETIME',
                                 DEFAULT_SESSION_MAX_LIFETIME))
                response.set_cookie(
                    cookie_name, new_value,
                    max_age=max_age,
                    httponly=True,
                    secure=attrs['secure'],
                    samesite=attrs['samesite'],
                    path=attrs['path'],
                )
        except Exception:  # noqa: BLE001 - refresh is best-effort
            pass
        return response

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
        # Apply the same security headers the Flask app emits via
        # after_request — the fallback must not weaken the surface.
        # TLS flag follows the resolved state (same as after_request):
        # hard-coding False would omit HSTS even when the server
        # terminates TLS.
        from vnc_remote_secure.security.http_headers import get_security_headers
        sec_headers = list(get_security_headers(
            tls_enabled=_resolved_tls(self.config)).items())
        original_start_response = start_response

        def _secure_start_response(status, headers, exc_info=None):
            if exc_info is None:
                # Some WSGI servers (and test doubles) don't accept the
                # optional third argument.
                return original_start_response(
                    status, headers + sec_headers)
            return original_start_response(
                status, headers + sec_headers, exc_info)

        start_response = _secure_start_response
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
        if not check_landing_auth(
                auth_header,
                client_ip=environ.get('REMOTE_ADDR')):
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


if __name__ == '__main__':
    # Entry point for ``python -m vnc_remote_secure.web.application``.
    # Used by the service manager to start the user-management UI.
    import argparse

    from vnc_remote_secure.core.constants import DEFAULT_USER_UI_PORT
    from vnc_remote_secure.security.certificates import create_ssl_context

    load_env_file()
    parser = argparse.ArgumentParser(description='VNC Remote Secure Web UI')
    parser.add_argument('--port', type=int,
                        default=int(os.environ.get('USER_UI_PORT',
                                                    str(DEFAULT_USER_UI_PORT))))
    # Same resolution chain as config._env_host: USER_UI_HOST →
    # BIND_HOST → loopback — the documented BIND_HOST knob must
    # control this backend's binding too.
    parser.add_argument('--host', type=str,
                        default=(os.environ.get('USER_UI_HOST', '').strip()
                                 or os.environ.get('BIND_HOST', '').strip()
                                 or '127.0.0.1'))
    args = parser.parse_args()

    app = create_app()
    ssl_ctx = create_ssl_context()
    logger.info("Web UI starting on %s:%s (%s)",
                args.host, args.port, 'https' if ssl_ctx else 'http')
    app.run(host=args.host, port=args.port, ssl_context=ssl_ctx)
