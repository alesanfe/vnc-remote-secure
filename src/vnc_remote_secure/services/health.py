"""Health check service — status aggregation and the server launcher.

The HTTP transport is FastAPI/uvicorn
(``vnc_remote_secure.backend.health_app``); this module keeps the
service-port inventory, the aggregate status computation and the
``start_health_server`` entry point other callers use.
"""
import logging
import os
import threading

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_NOVNC_WS_PORT,
    DEFAULT_TTYD_PORT,
)
from vnc_remote_secure.core.processes import is_port_available

logger = logging.getLogger(__name__)


def _service_ports():
    """Return the service-to-port mapping, honoring .env overrides.

    Reads ``NOVNC_PORT``, ``TTYD_PORT``, ``HEALTH_WEB_PORT`` and
    ``LANDING_PORT`` from the environment (falling back to the
    platform-aware ``DEFAULT_*`` constants); the VNC port comes from
    ``get_config()`` so the display-derived RFB port (5900+N) is
    probed on Linux.
    """
    from vnc_remote_secure.core.config import get_config, load_env_file
    from vnc_remote_secure.core.constants import (
        DEFAULT_AUDIO_STREAM_PORT,
        DEFAULT_GAMEPAD_PORT,
        DEFAULT_USER_UI_PORT,
    )
    load_env_file()
    # Use get_config() for the VNC port: on Linux the effective RFB
    # port is display-derived (5900+N), which the raw env read misses.
    # An explicit non-default VNC_PORT is still honoured by
    # get_config(), but TigerVNC binds 5900+N regardless — derive the
    # real port like services/vnc._vnc_port() does so the probe checks
    # where the server actually listens.
    _vnc_probe = get_config()['vnc_port']
    try:
        if os.name != 'nt':
            from vnc_remote_secure.services.vnc import _vnc_port
            _vnc_probe = _vnc_port(
                os.environ.get('VNC_DISPLAY', ':1'))
    except Exception:  # noqa: BLE001 - fall back to config value
        pass
    # Each entry is (host, port): services bind their own <SVC>_HOST,
    # so probing everything on loopback reports a LAN-bound service as
    # down forever (aggregate 'degraded'). Wildcard binds are probed on
    # loopback — connecting to '0.0.0.0' is unreliable on Windows.

    def _h(env, default='127.0.0.1'):
        host = (os.environ.get(env, '') or default).strip()
        # justification: detection, not a bind
        return '127.0.0.1' if host in ('0.0.0.0', '::', '') else host  # nosec B104

    def _p(env, default):
        # A malformed port env var must not crash every health request —
        # fall back to the same default get_config() would use.
        try:
            return int(os.environ.get(env, str(default)))
        except (ValueError, TypeError):
            return default

    ports = {
        'vnc': ('127.0.0.1', _vnc_probe),
        'novnc': (_h('NOVNC_HOST'), _p('NOVNC_PORT', DEFAULT_NOVNC_PORT)),
        'terminal': (_h('TTYD_HOST'), _p('TTYD_PORT', DEFAULT_TTYD_PORT)),
        'landing': (_h('LANDING_HOST'), _p('LANDING_PORT', DEFAULT_LANDING_PORT)),
        # Internal WebSocket->RFB bridge (loopback only, always runs
        # alongside noVNC — _start_websockify binds 127.0.0.1).
        'websockify': ('127.0.0.1', _p('NOVNC_WS_PORT', DEFAULT_NOVNC_WS_PORT)),
    }
    # Optional services are probed only when enabled, so a disabled
    # feature does not drag the aggregated status to 'degraded'.
    if env_flag('HEALTH_WEB_ENABLED', 'true'):
        ports['health'] = (_h('HEALTH_WEB_HOST'),
                           _p('HEALTH_WEB_PORT', DEFAULT_HEALTH_PORT))
    if env_flag('USER_UI_ENABLED', 'false'):
        ports['user_ui'] = (_h('USER_UI_HOST'),
                            _p('USER_UI_PORT', DEFAULT_USER_UI_PORT))
    if env_flag('AUDIO_STREAM_ENABLED', 'false'):
        ports['audio'] = (_h('AUDIO_STREAM_HOST'),
                          _p('AUDIO_STREAM_PORT', DEFAULT_AUDIO_STREAM_PORT))
    if env_flag('GAMEPAD_ENABLED', 'false'):
        ports['gamepad'] = (_h('GAMEPAD_HOST'),
                            _p('GAMEPAD_PORT', DEFAULT_GAMEPAD_PORT))
    return ports


def _check_port(port, host='127.0.0.1'):
    """Return True if ``port`` is listening on ``host``."""
    return not is_port_available(port, host=host)


def check_health():
    """Return a dict mapping service names to listening booleans."""
    return {name: _check_port(port, host)
            for name, (host, port) in _service_ports().items()}


def get_health_status():
    """Return an aggregated health status dict.

    The ``status`` field is ``healthy`` when every service is listening,
    ``degraded`` when some are down, and ``unknown`` when no data is
    available.
    """
    services = check_health()
    up = sum(1 for v in services.values() if v)
    total = len(services)
    if total == 0:
        status = 'unknown'
    elif up == total:
        status = 'healthy'
    elif up == 0:
        status = 'down'
    else:
        status = 'degraded'
    # Increment the Prometheus health-check counter (best-effort).
    from vnc_remote_secure.monitoring.prometheus import inc_counter
    inc_counter('vnc_remote_health_check_total', labels=status)
    return {
        'status': status,
        'services_up': up,
        'services_total': total,
        'services': services,
    }


def start_health_server(port=DEFAULT_HEALTH_PORT, host=DEFAULT_BIND_HOST,
                        ssl_context=None, ssl_certfile=None,
                        ssl_keyfile=None):
    """Start the health HTTP server (uvicorn) in a background thread.

    Args:
        port: Port to listen on.
        host: Bind address.
        ssl_context: Deprecated — kept for call-site compatibility;
            pass ``ssl_certfile``/``ssl_keyfile`` for TLS.
        ssl_certfile / ssl_keyfile: PEM paths when serving HTTPS.

    Returns a :class:`UvicornServerHandle` exposing
    ``server_address``, ``shutdown()`` and ``server_close()``.
    """
    from vnc_remote_secure.backend.health_app import start_health_server as _start
    return _start(port=port, host=host,
                  ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)


if __name__ == '__main__':
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    _port = int(os.environ.get('HEALTH_WEB_PORT', str(DEFAULT_HEALTH_PORT)))
    # Same resolution chain as config._env_host: HEALTH_WEB_HOST →
    # BIND_HOST → loopback — so the documented BIND_HOST knob actually
    # controls this backend's binding.
    _host = (os.environ.get('HEALTH_WEB_HOST', '').strip()
             or os.environ.get('BIND_HOST', '').strip()
             or DEFAULT_BIND_HOST)
    _cert = os.environ.get('SSL_CERT') or None
    _key = os.environ.get('SSL_KEY') or None
    srv = start_health_server(port=_port, host=_host,
                              ssl_certfile=_cert, ssl_keyfile=_key)
    logger.info("Health server on %s://%s:%s",
                'https' if _cert else 'http', _host, _port)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        srv.shutdown()
