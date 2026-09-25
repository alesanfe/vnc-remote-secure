"""Portal read-model inputs — transport-agnostic service inventory.

The portal page (React) and the /api/v1/portal read model consume
these helpers via ``engine.infrastructure.stores``; the landing
service itself also uses them for its own status endpoints. Kept in
``core`` so the engine never imports ``services.*`` (transport).
"""
import logging
import platform

from vnc_remote_secure.platform.detection import is_windows

logger = logging.getLogger(__name__)


def portal_config() -> dict:
    """Return the runtime config lazily so .env changes take effect
    on each call."""
    from vnc_remote_secure.core.config import get_config
    return get_config()


def check_port(port, host='127.0.0.1'):
    """Check if a port is listening on ``host``.

    Each service binds its own ``<SVC>_HOST`` — probing everything on
    loopback reports a service bound to a LAN IP as down. The doctor
    probes per-service hosts; the status JSON must agree. A wildcard
    bind (``0.0.0.0``/``::``) covers loopback too, and connecting to
    the wildcard address itself is unreliable on Windows.
    """
    # justification: detection, not a bind
    if host in ('0.0.0.0', '::', ''):  # nosec B104
        host = '127.0.0.1'
    # Delegate to the shared probe — it selects AF_INET6 for IPv6
    # literal hosts, which a hardcoded AF_INET socket cannot reach.
    try:
        from vnc_remote_secure.core.processes import is_port_available
        return not is_port_available(port, host=host)
    except Exception as e:
        logger.debug("Port check failed: %s", e)
        return False


def get_lan_ips():
    """Get real LAN IP addresses, filtering out virtual adapters.

    Delegates to the platform adapter for the OS-specific discovery.
    """
    try:
        from vnc_remote_secure.platform.base import get_adapter
        return get_adapter().get_lan_ips()
    except Exception as e:
        logger.debug("Platform LAN IP detection failed: %s", e)
        return []


def get_system_metrics():
    """Get quick system metrics for the portal page.

    Delegates CPU/memory/disk/uptime collection and OS display name
    detection to the platform adapter
    (``platform/{linux,windows}/metrics.py``) and adds hostname on top.
    """
    metrics = {
        'cpu': 'N/A', 'memory': 'N/A', 'disk': 'N/A',
        'uptime': 'N/A', 'hostname': platform.node(),
        'os': f'{platform.system()} {platform.release()}',
    }

    # Delegate core metrics and OS display name to the platform adapter.
    try:
        if is_windows():
            from vnc_remote_secure.platform.windows.metrics import (
                get_os_display_name as _os_name,
            )
            from vnc_remote_secure.platform.windows.metrics import (
                get_system_metrics as _get,
            )
        else:
            from vnc_remote_secure.platform.linux.metrics import (
                get_os_display_name as _os_name,
            )
            from vnc_remote_secure.platform.linux.metrics import (
                get_system_metrics as _get,
            )
        platform_metrics = _get()
        metrics.update(platform_metrics)
        # Override the os field with the platform-specific display name
        # (e.g. 'Windows 11' instead of 'Windows 10' on Win11).
        os_name = _os_name()
        if os_name:
            metrics['os'] = os_name
    except Exception as e:
        logger.debug("Platform metrics collection failed: %s", e)

    return metrics


def _service_descriptions():
    """Return platform-aware service descriptions.

    Returns a tuple (desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc).
    """
    win = is_windows()
    desktop_desc = (
        'Escritorio Windows completo en el navegador. Controla el ratón y teclado desde cualquier dispositivo.'
        if win else
        'Escritorio remoto completo en el navegador. Controla el ratón y teclado desde cualquier dispositivo.'
    )
    terminal_desc = (
        'Terminal de comandos (cmd.exe) en el navegador. Ejecuta comandos de Windows remotamente.'
        if win else
        'Terminal del sistema en el navegador. Ejecuta comandos de Linux remotamente.'
    )
    vnc_http_name = 'UltraVNC HTTP Viewer' if win else 'VNC HTTP Viewer'
    vnc_http_desc = (
        'Visor VNC Java legacy de UltraVNC. Alternativa al noVNC moderno.'
        if win else
        'Visor VNC HTTP legacy. Alternativa al noVNC moderno.'
    )
    return desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc


def build_service_list(protocol, external_base=None):
    """Build the list of service descriptor dicts.

    ``external_base`` is the public nginx base URL
    (``https://<forwarded-host>``) when the request arrived through the
    reverse proxy — backend ports are loopback-only, so the direct
    ``127.0.0.1:<port>`` links only work for clients on the server
    itself. Through nginx the services are reachable at well-known
    paths instead.
    """
    cfg = portal_config()
    desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc = (
        _service_descriptions())

    if external_base:
        novnc_url = f'{external_base}/vnc/vnc.html'
        terminal_url = f'{external_base}/terminal/'
        # nginx restricts /health to loopback (allow 127.0.0.1; deny all)
        # — remote clients would always get 403, so do not render a
        # public link for the health card through the proxy.
        health_url = ''
        health_all_url = ''
        audio_url = f'{external_base}/audio_receiver.html'
        gamepad_url = f'{external_base}/gamepad.html'
    else:
        novnc_url = f'{protocol}://127.0.0.1:{cfg["novnc_port"]}/vnc.html'
        terminal_url = f'{protocol}://127.0.0.1:{cfg["ttyd_port"]}/'
        health_url = f'{protocol}://127.0.0.1:{cfg["health_port"]}/health'
        health_all_url = (
            f'{protocol}://127.0.0.1:{cfg["health_port"]}/health/all')
        audio_url = (
            f'{protocol}://127.0.0.1:{cfg["landing_port"]}'
            '/audio_receiver.html')
        gamepad_url = (
            f'{protocol}://127.0.0.1:{cfg["landing_port"]}/gamepad.html')

    # All services with detailed info
    services = [
        {
            'name': 'VNC Desktop (noVNC)',
            'desc': desktop_desc,
            'features': ['Mouse y teclado completos', 'Portapapeles',
                         'Multi-monitor', 'Escalado automático'],
            'icon': '🖥️',
            'url': novnc_url,
            'port': cfg['novnc_port'],
            'running': check_port(
                cfg['novnc_port'], cfg.get('novnc_host', '127.0.0.1')),
            'color': '#4caf50',
            'category': 'remote-desktop',
        },
        {
            'name': 'Web Terminal',
            'desc': terminal_desc,
            'features': ['Historial de comandos', 'Tab completion',
                         'Ctrl+C interrupt', 'Colores ANSI'],
            'icon': '⌨️',
            'url': terminal_url,
            'port': cfg['ttyd_port'],
            'running': check_port(
                cfg['ttyd_port'], cfg.get('ttyd_host', '127.0.0.1')),
            'color': '#2196f3',
            'category': 'terminal',
        },
    ]
    # UltraVNC's built-in HTTP dir is Windows-only — on Linux nothing
    # ever listens on vnc_http_port, so the card would permanently show
    # a spurious "down" state (same reasoning as the status JSON).
    if is_windows():
        services.append({
            'name': vnc_http_name,
            'desc': vnc_http_desc,
            'features': ['Java applet', 'Conexión directa',
                         'Legacy support'],
            'icon': '🔌',
            'url': f'http://127.0.0.1:{cfg["vnc_http_port"]}/',
            'port': cfg['vnc_http_port'],
            'running': check_port(cfg['vnc_http_port']),
            'color': '#9c27b0',
            'category': 'remote-desktop',
        })
    # Optional features get a card only when enabled.
    if cfg.get('health_web_enabled', True):
        services.append({
            'name': 'Health Dashboard',
            'desc': ('Panel de monitorización con estado de servicios, '
                     'CPU, memoria, disco y red.'),
            'features': ['Estado por servicio', 'CPU/RAM/Disco',
                         'API JSON', 'Auto-refresh 30s'],
            'icon': '📊',
            'url': health_url,
            'url2': health_all_url,
            'url2_label': 'System + Services',
            'port': cfg['health_port'],
            'running': check_port(
                cfg['health_port'], cfg.get('health_host', '127.0.0.1')),
            'color': '#ff9800',
            'category': 'monitoring',
        })
    if cfg.get('audio_stream_enabled'):
        services.append({
            'name': 'Audio Stream',
            'desc': 'Audio del servidor en el navegador (WebSocket).',
            'features': ['Streaming en vivo', 'Sin plugins',
                         'Loopback seguro'],
            'icon': '🔊',
            'url': audio_url,
            'port': cfg['audio_stream_port'],
            'running': check_port(
                cfg['audio_stream_port'],
                cfg.get('audio_stream_host', '127.0.0.1')),
            'color': '#00bcd4',
            'category': 'remote-desktop',
        })
    if cfg.get('gamepad_enabled'):
        services.append({
            'name': 'Gamepad Forwarding',
            'desc': ('Reenvía el gamepad del cliente al servidor '
                     '(WebSocket).'),
            'features': ['HTML5 Gamepad API', 'Baja latencia',
                         'Sin drivers extra'],
            'icon': '🎮',
            'url': gamepad_url,
            'port': cfg['gamepad_port'],
            'running': check_port(
                cfg['gamepad_port'], cfg.get('gamepad_host', '127.0.0.1')),
            'color': '#8bc34a',
            'category': 'remote-desktop',
        })
    return services


def tls_available(cfg: dict) -> bool:
    """True when configured cert/key produce a usable TLS context."""
    try:
        from vnc_remote_secure.security.certificates import create_ssl_context
        return create_ssl_context(
            cfg['ssl_cert'], cfg['ssl_key']) is not None
    except Exception:  # noqa: BLE001 - no TLS is a valid answer
        return False


def vnc_base_port() -> int:
    """Configured VNC RFB base port (``VNC_PORT`` or the default)."""
    import os

    from vnc_remote_secure.core.constants import DEFAULT_VNC_PORT
    try:
        return int(portal_config()['vnc_port'])
    except (ValueError, KeyError):
        try:
            return int(os.environ.get('VNC_PORT', str(DEFAULT_VNC_PORT)))
        except ValueError:
            return DEFAULT_VNC_PORT


def vnc_display_port(display) -> int:
    """Return the RFB port a ``vncserver :N`` display binds.

    TigerVNC binds ``5900 + N`` for display ``:N`` — the adapter does
    not pass ``-rfbport``, so the port is the RFB convention, not
    ``VNC_PORT + N`` (VNC_PORT documents the expected port for the
    configured VNC_DISPLAY and feeds websockify/doctor checks).
    """
    from vnc_remote_secure.core.constants import TIGERVNC_BASE_PORT
    if display is None:
        return vnc_base_port()
    raw = str(display)
    # Strip at most ONE leading colon — '::1' must not silently
    # become display 1.
    s = raw[1:] if raw.startswith(':') else raw
    if not s.isdigit():
        raise ValueError(f'Invalid VNC display: {display!r}')
    num = int(s)
    port = TIGERVNC_BASE_PORT + num
    # A display whose RFB port exceeds 65535 is meaningless — fail
    # closed rather than let callers probe/bind a wrapped port.
    if port > 65535:
        raise ValueError(
            f'VNC display {display!r} maps to out-of-range port {port}')
    return port


def vnc_effective_port() -> int:
    """The RFB port actually bound — TigerVNC derives 5900+display on
    Linux regardless of an explicit VNC_PORT."""
    cfg = portal_config()
    port = cfg['vnc_port']
    if not is_windows():
        try:
            port = vnc_display_port(cfg.get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config port
            pass
    return port
