"""Application lifecycle management for VNC Remote Secure.

Provides high-level ``startup``/``shutdown``/``health_check`` helpers
that orchestrate configuration loading, logging setup, directory
creation, and graceful teardown of running services.
"""
import logging
import os
import signal
import sys
import threading

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.logging import setup_logging
from vnc_remote_secure.core.paths import ensure_dirs
from vnc_remote_secure.core.processes import find_process, is_port_available
from vnc_remote_secure.core.constants import (
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
)

_logger = logging.getLogger('vnc_remote_secure.lifecycle')
_state = {'running': False, 'config': None, 'lock': threading.Lock()}


def startup(config=None):
    """Initialize the application.

    Loads environment configuration, sets up logging, creates the
    standard runtime directories, and stores the active configuration.
    Safe to call multiple times; subsequent calls are no-ops while
    running.
    """
    with _state['lock']:
        if _state['running']:
            _logger.warning('startup() called while already running')
            return _state['config']
        load_env_file()
        setup_logging()
        if config is None:
            config = get_config()
        ensure_dirs()
        _state['config'] = config
        _state['running'] = True
        _logger.info('VNC Remote Secure started')
        return config


def shutdown():
    """Gracefully shut down the application.

    Clears the running state and active configuration. Subprocess
    termination of individual services is delegated to their own
    modules; this function only coordinates shared state.
    """
    with _state['lock']:
        if not _state['running']:
            return
        _logger.info('VNC Remote Secure shutting down')
        _state['running'] = False
        _state['config'] = None


def health_check():
    """Return a dict describing the health of core components.

    Checks whether the standard service ports are listening and reports
    the overall application state.
    """
    config = _state['config'] or {}
    ports = {
        'vnc': int(config.get('vnc_port', DEFAULT_VNC_PORT)),
        'novnc': int(config.get('novnc_port', DEFAULT_NOVNC_PORT)),
        'ttyd': int(config.get('ttyd_port', DEFAULT_TTYD_PORT)),
        'health': int(config.get('health_port', DEFAULT_HEALTH_PORT)),
        'landing': int(config.get('landing_port', DEFAULT_LANDING_PORT)),
    }
    services = {}
    for name, port in ports.items():
        services[name] = {
            'port': port,
            'listening': not is_port_available(port),
            'pid': find_process(port),
        }
    all_healthy = all(s['listening'] for s in services.values())
    return {
        'status': 'healthy' if all_healthy else 'degraded',
        'running': _state['running'],
        'services': services,
    }


def is_running():
    """Return ``True`` if the application has been started."""
    return _state['running']
