"""Web application factory for VNC Remote Secure.

The machine-facing surface (health/metrics/audit) is now a FastAPI
application served by uvicorn — Flask, the WSGI fallback and the
session middleware are gone; every user-facing page is the React SPA
served by the landing service, and the JSON surface lives behind
``/api/v1/*``.

``create_app`` remains the public entry point: it returns the ASGI
application so ``service_manager`` can spawn this module and tests
can mount it directly.
"""
import logging
import os

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.logging import setup_logging

logger = logging.getLogger(__name__)


def create_app(config=None):
    """Create the ASGI application for the user-ui/health process.

    Args:
        config: Optional configuration dict (as returned by
            :func:`get_config`). Accepted for call-site compatibility;
            the health app reads env lazily per request.

    Returns:
        A FastAPI application instance.
    """
    load_env_file()
    if config is None:
        config = get_config()
    setup_logging()
    from vnc_remote_secure.backend.health_app import create_health_app
    return create_health_app()


if __name__ == '__main__':
    # Entry point for ``python -m vnc_remote_secure.web.application``.
    # Used by the service manager to start the user-ui process.
    import argparse

    from vnc_remote_secure.core.constants import DEFAULT_USER_UI_PORT
    from vnc_remote_secure.security.certificates import create_ssl_context

    load_env_file()
    parser = argparse.ArgumentParser(description='VNC Remote Secure Web UI')
    parser.add_argument(
        '--port', type=int,
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

    ssl_ctx = create_ssl_context()
    kwargs = {}
    if ssl_ctx:
        kwargs = {'ssl_certfile': os.environ.get('SSL_CERT'),
                  'ssl_keyfile': os.environ.get('SSL_KEY')}
    logger.info("Web UI starting on %s:%s (%s)",
                args.host, args.port, 'https' if ssl_ctx else 'http')
    import uvicorn
    uvicorn.run(create_app(), host=args.host, port=args.port,
                log_level='warning', access_log=False,
                proxy_headers=False, **kwargs)
