"""Application lifecycle management for VNC Remote Secure.

Provides high-level ``startup``/``shutdown`` helpers that orchestrate
configuration loading, logging setup, directory creation, and graceful
teardown of running services.
"""
import logging
import threading

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.logging import setup_logging
from vnc_remote_secure.core.paths import ensure_dirs

_logger = logging.getLogger('vnc_remote_secure.lifecycle')
_lock = threading.Lock()
_state = {'running': False, 'config': None}


def startup(config=None):
    """Initialize the application.

    Loads environment configuration, applies the active security
    profile, sets up logging, creates the standard runtime directories,
    and stores the active configuration. Safe to call multiple times;
    subsequent calls are no-ops while running.

    The security profile is applied BEFORE reading ``get_config()`` so
    that profile defaults (TLS, MFA, nginx, BACKEND_BIND_HOST, session
    timeouts, ALLOWED_ORIGINS) materialize into ``os.environ`` and reach
    every consumer. This closes the F-002 finding where
    ``SECURITY_PROFILE=public-hardened`` alone did not enforce hardened
    defaults.
    """
    with _lock:
        if _state['running']:
            _logger.warning('startup() called while already running')
            return _state['config']
        load_env_file()
        # Apply the security profile so its defaults reach os.environ
        # before any service reads configuration. Existing user-set
        # values are preserved (apply_profile uses overwrite=False).
        from vnc_remote_secure.security.profiles import apply_profile
        apply_profile()
        setup_logging()
        if config is None:
            config = get_config()
        ensure_dirs()
        # Verify the audit chain eagerly on startup (the docstring in
        # security.audit promises verification "on every startup", and
        # early detection beats discovering tampering at first write).
        try:
            from vnc_remote_secure.security.audit import verify_chain_on_startup
            verify_chain_on_startup()
        except Exception as exc:  # noqa: BLE001 - audit init must not block startup
            _logger.warning('Audit chain verification skipped: %s', exc)
        _state['config'] = config
        _state['running'] = True
        _logger.info('VNC Remote Secure started (profile: %s)',
                     __import__('vnc_remote_secure.security.profiles',
                                fromlist=['get_profile']).get_profile())
        return config


def shutdown():
    """Gracefully shut down the application.

    Stops all managed services via the service manager (by PID, not by
    pattern), then clears the running state and active configuration.
    """
    with _lock:
        if not _state['running']:
            return
        _logger.info('VNC Remote Secure shutting down')
        # Stop services by PID to avoid killing unrelated processes.
        try:
            from vnc_remote_secure.core.service_manager import stop_all
            stop_all()
        except Exception as e:  # pragma: no cover - best-effort cleanup
            _logger.warning('service_manager.stop_all failed: %s', e)
        _state['running'] = False
        _state['config'] = None
