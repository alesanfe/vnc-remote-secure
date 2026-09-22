#!/usr/bin/env python3
"""
Landing page server for VNC Remote Secure.

Serves a portal page that links to all available services
and shows real-time system status.
Runs on port 8000 (or LANDING_PORT env var).

Security: Credentials are NOT displayed on the page. The landing page
shows service status and URLs only. Users must check the launcher output
or .env file for credentials.
"""
import html
import http.server
import json
import logging
import os
import platform

from vnc_remote_secure.core.errors import error_json, log_exception
from vnc_remote_secure.platform.detection import is_windows
from vnc_remote_secure.security.http_auth import (
    check_landing_auth,
    client_ip_from,
)

logger = logging.getLogger(__name__)

# Load configuration from .env file (never hardcode credentials)
from vnc_remote_secure.core.config import load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_AUDIO_STREAM_PORT,
    DEFAULT_GAMEPAD_PORT,
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_WS_PORT,
)

load_env_file()


def _config():
    """Return the runtime config lazily so .env changes take effect on each call."""
    from vnc_remote_secure.core.config import get_config
    return get_config()


def _samesite():
    """Whitelisted SameSite cookie value (shared whitelist in config)."""
    from vnc_remote_secure.core.config import resolve_samesite
    return resolve_samesite()


def check_port(port, host='127.0.0.1'):
    """Check if a port is listening on ``host``.

    Each service binds its own ``<SVC>_HOST`` — probing everything on
    loopback reports a service bound to a LAN IP as down. The doctor
    probes per-service hosts; the status JSON must agree. A wildcard
    bind (``0.0.0.0``/``::``) covers loopback too, and connecting to
    the wildcard address itself is unreliable on Windows.
    """
    # nosec rationale: detection, not a bind
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
    """Get quick system metrics for the landing page.

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


def _get_service_descriptions():
    """Return platform-aware service descriptions.

    Returns a tuple (desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc).
    """
    # Platform-aware descriptions
    is_windows_flag = is_windows()
    desktop_desc = (
        'Escritorio Windows completo en el navegador. Controla el ratón y teclado desde cualquier dispositivo.'
        if is_windows_flag else
        'Escritorio remoto completo en el navegador. Controla el ratón y teclado desde cualquier dispositivo.'
    )
    terminal_desc = (
        'Terminal de comandos (cmd.exe) en el navegador. Ejecuta comandos de Windows remotamente.'
        if is_windows_flag else
        'Terminal del sistema en el navegador. Ejecuta comandos de Linux remotamente.'
    )
    vnc_http_name = 'UltraVNC HTTP Viewer' if is_windows_flag else 'VNC HTTP Viewer'
    vnc_http_desc = (
        'Visor VNC Java legacy de UltraVNC. Alternativa al noVNC moderno.'
        if is_windows_flag else
        'Visor VNC HTTP legacy. Alternativa al noVNC moderno.'
    )
    return desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc


def _build_service_list(protocol, external_base=None):
    """Build the list of service descriptor dicts.

    ``external_base`` is the public nginx base URL
    (``https://<forwarded-host>``) when the request arrived through the
    reverse proxy — backend ports are loopback-only, so the direct
    ``127.0.0.1:<port>`` links only work for clients on the server
    itself. Through nginx the services are reachable at well-known
    paths instead.
    """
    desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc = _get_service_descriptions()

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
        novnc_url = f'{protocol}://127.0.0.1:{_config()["novnc_port"]}/vnc.html'
        terminal_url = f'{protocol}://127.0.0.1:{_config()["ttyd_port"]}/'
        health_url = f'{protocol}://127.0.0.1:{_config()["health_port"]}/health'
        health_all_url = f'{protocol}://127.0.0.1:{_config()["health_port"]}/health/all'
        audio_url = f'{protocol}://127.0.0.1:{_config()["landing_port"]}/audio_receiver.html'
        gamepad_url = f'{protocol}://127.0.0.1:{_config()["landing_port"]}/gamepad.html'

    # All services with detailed info
    services = [
        {
            'name': 'VNC Desktop (noVNC)',
            'desc': desktop_desc,
            'features': ['Mouse y teclado completos', 'Portapapeles', 'Multi-monitor', 'Escalado automático'],
            'icon': '🖥️',
            'url': novnc_url,
            'port': _config()['novnc_port'],
            'running': check_port(
                _config()['novnc_port'],
                _config().get('novnc_host', '127.0.0.1')),
            'color': '#4caf50',
            'category': 'remote-desktop',
        },
        {
            'name': 'Web Terminal',
            'desc': terminal_desc,
            'features': ['Historial de comandos', 'Tab completion', 'Ctrl+C interrupt', 'Colores ANSI'],
            'icon': '⌨️',
            'url': terminal_url,
            'port': _config()['ttyd_port'],
            'running': check_port(
                _config()['ttyd_port'],
                _config().get('ttyd_host', '127.0.0.1')),
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
            'features': ['Java applet', 'Conexión directa', 'Legacy support'],
            'icon': '🔌',
            'url': f'http://127.0.0.1:{_config()["vnc_http_port"]}/',
            'port': _config()['vnc_http_port'],
            'running': check_port(_config()['vnc_http_port']),
            'color': '#9c27b0',
            'category': 'remote-desktop',
        })
    # Optional features get a card only when enabled.
    if _config().get('health_web_enabled', True):
        services.append({
            'name': 'Health Dashboard',
            'desc': 'Panel de monitorización con estado de servicios, CPU, memoria, disco y red.',
            'features': ['Estado por servicio', 'CPU/RAM/Disco', 'API JSON', 'Auto-refresh 30s'],
            'icon': '📊',
            'url': health_url,
            'url2': health_all_url,
            'url2_label': 'System + Services',
            'port': _config()['health_port'],
            'running': check_port(
                _config()['health_port'],
                _config().get('health_host', '127.0.0.1')),
            'color': '#ff9800',
            'category': 'monitoring',
        })
    if _config().get('audio_stream_enabled'):
        services.append({
            'name': 'Audio Stream',
            'desc': 'Audio del servidor en el navegador (WebSocket).',
            'features': ['Streaming en vivo', 'Sin plugins', 'Loopback seguro'],
            'icon': '🔊',
            'url': audio_url,
            'port': _config()['audio_stream_port'],
            'running': check_port(
                _config()['audio_stream_port'],
                _config().get('audio_stream_host', '127.0.0.1')),
            'color': '#00bcd4',
            'category': 'remote-desktop',
        })
    if _config().get('gamepad_enabled'):
        services.append({
            'name': 'Gamepad Forwarding',
            'desc': 'Reenvía el gamepad del cliente al servidor (WebSocket).',
            'features': ['HTML5 Gamepad API', 'Baja latencia', 'Sin drivers extra'],
            'icon': '🎮',
            'url': gamepad_url,
            'port': _config()['gamepad_port'],
            'running': check_port(
                _config()['gamepad_port'],
                _config().get('gamepad_host', '127.0.0.1')),
            'color': '#8bc34a',
            'category': 'remote-desktop',
        })
    return services


def _build_service_cards_html(services):
    """Build the HTML for the service cards."""
    # Build service cards
    cards_html = ''
    for svc in services:
        status_text = 'ONLINE' if svc['running'] else 'OFFLINE'
        status_color = '#4caf50' if svc['running'] else '#f44336'
        disabled = '' if svc['running'] else 'disabled'
        opacity = '1' if svc['running'] else '0.5'

        features_html = ''
        for feat in svc.get('features', []):
            features_html += (
                f'<span class="feature-tag">{html.escape(str(feat))}</span>')

        extra_link = ''
        if svc.get('url2'):
            label = html.escape(str(svc.get('url2_label', 'Link')))
            extra_link = f'<a href="{svc["url2"]}" target="_blank" class="btn-sm {disabled}">{label}</a>'

        # Escape every interpolated field: the names/descriptions are
        # internal literals today, but the builder is a single choke
        # point — escaping here keeps a future dynamic card from
        # becoming reflected markup.
        cards_html += f"""
        <div class="service-card {status_text.lower()}" style="opacity:{opacity}">
            <div class="service-icon">{html.escape(str(svc['icon']))}</div>
            <div class="service-info">
                <h3>{html.escape(str(svc['name']))}</h3>
                <p>{html.escape(str(svc['desc']))}</p>
                <div class="features">{features_html}</div>
                <span class="service-port">Port {int(svc['port'])}</span>
            </div>
            <div class="service-action">
                <span class="status-badge" style="background:{status_color}">{status_text}</span>
                {f'<a href="{svc["url"]}" target="_blank" class="btn {disabled}">Abrir</a>' if svc.get('url') else ''}
                {extra_link}
            </div>
        </div>"""
    return cards_html


def _build_vnc_direct_html(lan_ips, vnc_rfb_running):
    """Build the direct VNC (RFB) connection info card."""
    # Direct VNC connection info card
    # The address must reflect the server's real bind: with nginx
    # enabled the adapter passes ``-localhost yes`` to the RFB server,
    # so a LAN IP in this card points at a port that is not reachable —
    # show loopback + a tunnel hint instead (same condition as
    # platform/linux/adapter.py's start_vnc_server).
    # The displayed port must be the EFFECTIVE one: on Linux TigerVNC
    # binds 5900+display regardless of an explicit VNC_PORT (same
    # derivation as the probe in generate_landing_page).
    vnc_port = _config()['vnc_port']
    if not is_windows():
        try:
            from vnc_remote_secure.services.vnc import _vnc_port
            vnc_port = _vnc_port(_config().get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config port
            pass
    if _config().get('nginx_enabled'):
        vnc_addr = f'127.0.0.1:{vnc_port}'
        vnc_note = ('<span class="cred-note">Solo loopback — acceda por '
                    'túnel SSH o noVNC</span>')
    else:
        vnc_addr = (f'{html.escape(lan_ips[0]) if lan_ips else "127.0.0.1"}'
                    f':{vnc_port}')
        vnc_note = ''
    vnc_direct_status = 'ONLINE' if vnc_rfb_running else 'OFFLINE'
    vnc_direct_color = '#4caf50' if vnc_rfb_running else '#f44336'
    vnc_direct_opacity = '1' if vnc_rfb_running else '0.5'
    return f"""
    <div class="service-card info-card" style="opacity:{vnc_direct_opacity}">
        <div class="service-icon">📡</div>
        <div class="service-info">
            <h3>VNC Directo (RFB)</h3>
            <p>Conexión directa con apps VNC nativas (TightVNC, RealVNC, TigerVNC, etc.)</p>
            <div class="features">
                <span class="feature-tag">Protocolo RFB 3.8</span>
                <span class="feature-tag">VNC Auth</span>
                <span class="feature-tag">Sin navegador</span>
            </div>
            <span class="service-port">Port {vnc_port}</span>
        </div>
        <div class="service-action">
            <span class="status-badge" style="background:{vnc_direct_color}">{vnc_direct_status}</span>
            <div class="connection-info">
                <code>{vnc_addr}</code>
                {vnc_note}
            </div>
        </div>
    </div>"""


def _build_metrics_html(metrics):
    """Build the system metrics bar HTML."""
    # System metrics bar
    return f"""
    <div class="metrics-bar">
        <div class="metric-item">
            <span class="metric-icon">💻</span>
            <span class="metric-label">Host</span>
            <span class="metric-value">{html.escape(metrics['hostname'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">🖥️</span>
            <span class="metric-label">OS</span>
            <span class="metric-value">{html.escape(metrics['os'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">⏱️</span>
            <span class="metric-label">Uptime</span>
            <span class="metric-value">{html.escape(metrics['uptime'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">📊</span>
            <span class="metric-label">CPU</span>
            <span class="metric-value">{html.escape(metrics['cpu'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">💾</span>
            <span class="metric-label">RAM</span>
            <span class="metric-value">{html.escape(metrics['memory'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">💿</span>
            <span class="metric-label">Disco</span>
            <span class="metric-value">{html.escape(metrics['disk'])}</span>
        </div>
    </div>"""


def _build_lan_html(lan_ips, protocol, external_base=None):
    """Build the LAN access section HTML.

    When the deployment runs behind nginx (``external_base`` is set),
    the raw backend ports are loopback-only — LAN clients must use the
    public nginx paths on the HTTPS port instead, or every link here
    is dead. Without nginx the direct per-service ports apply.
    """
    lan_html = ''
    if not lan_ips:
        return lan_html
    nginx = external_base is not None
    https_port = _config().get('nginx_https_port', DEFAULT_NGINX_HTTPS_PORT)
    lan_html = '<div class="lan-section"><h2>🌐 Acceso Remoto (LAN)</h2><p class="section-desc">Conecta desde otro dispositivo en la misma red:</p>'
    for ip in lan_ips:
        ip_escaped = html.escape(ip)
        if nginx:
            # https://<ip>[:<port>]/path — the default HTTPS port keeps a
            # bare host; a non-default NGINX_HTTPS_PORT must be explicit.
            port_suffix = '' if int(https_port) == DEFAULT_NGINX_HTTPS_PORT \
                else f':{https_port}'
            lan_html += f"""
            <div class="ip-card">
                <div class="ip-address">{ip_escaped}</div>
                <div class="ip-links">
                    <a href="https://{ip_escaped}{port_suffix}/vnc/vnc.html">🖥️ VNC Desktop</a>
                    <a href="https://{ip_escaped}{port_suffix}/terminal/">⌨️ Web Terminal</a>
                    <a href="https://{ip_escaped}{port_suffix}/">🏠 Portal</a>
                </div>
            </div>"""
        else:
            lan_html += f"""
            <div class="ip-card">
                <div class="ip-address">{ip_escaped}</div>
                <div class="ip-links">
                    <a href="{protocol}://{ip_escaped}:{_config()["novnc_port"]}/vnc.html">🖥️ VNC Desktop</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["ttyd_port"]}/">⌨️ Web Terminal</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["health_port"]}/health">📊 Health</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["health_port"]}/health/all">📋 Health (all)</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["landing_port"]}">🏠 Portal</a>
                </div>
            </div>"""
    lan_html += '</div>'
    return lan_html


def _build_credentials_html():
    """Build the credentials section HTML."""
    # Credentials section - NOT showing actual passwords for security
    # Users must check the launcher output or .env file
    return """
    <div class="credentials">
        <h2>🔐 Credenciales de Acceso</h2>
        <p class="section-desc">Por seguridad, las credenciales no se muestran en esta página.
        Revise el archivo <code>.env</code>, o <code>generated_credentials.env</code>
        en el directorio de ejecución si fueron autogeneradas.</p>
        <div class="cred-grid">
            <div class="cred-item">
                <span class="cred-icon">🖥️</span>
                <div class="cred-content">
                    <span class="cred-label">VNC Desktop (noVNC y RFB)</span>
                    <span class="cred-value">Password: <code>••••••••</code> (ver .env o generated_credentials.env)</span>
                    <span class="cred-note">VNC usa los primeros 8 caracteres del password</span>
                </div>
            </div>
            <div class="cred-item">
                <span class="cred-icon">⌨️</span>
                <div class="cred-content">
                    <span class="cred-label">Web Terminal</span>
                    <span class="cred-value">Usuario y password: ver <code>.env</code> o <code>generated_credentials.env</code></span>
                </div>
            </div>
        </div>
    </div>"""


def _build_features_section(use_ssl, is_windows):
    """Build the 'What you can do' features section HTML."""
    # What you can do section
    ssl_feature = ""
    if use_ssl:
        ssl_feature = """
            <div class="feature-card">
                <span class="feature-icon">🔒</span>
                <h3>Conexión cifrada</h3>
                <p>Todos los servicios web usan HTTPS con certificado SSL (self-signed). Acepta la advertencia del navegador.</p>
            </div>"""
    else:
        ssl_feature = """
            <div class="feature-card">
                <span class="feature-icon">⚠️</span>
                <h3>Sin cifrado SSL</h3>
                <p>Los servicios se ejecutan sin SSL (modo local). No expongas los puertos a Internet sin HTTPS.</p>
            </div>"""

    # Platform-aware wording: on Linux the desktop is TigerVNC/X11 and
    # the terminal runs the configured shell, not cmd.exe.
    os_label = 'Windows' if is_windows else 'Linux'
    shell_label = 'cmd.exe' if is_windows else 'el shell del sistema'
    # Effective RFB port: TigerVNC binds 5900+display regardless of an
    # explicit VNC_PORT (same derivation as _build_vnc_direct_html).
    vnc_port = _config()['vnc_port']
    if not is_windows:
        try:
            from vnc_remote_secure.services.vnc import _vnc_port
            vnc_port = _vnc_port(_config().get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config port
            pass

    return f"""
    <div class="features-section">
        <h2>✨ ¿Qué puedes hacer?</h2>
        <div class="feature-cards">
            <div class="feature-card">
                <span class="feature-icon">🖥️</span>
                <h3>Control remoto del escritorio</h3>
                <p>Accede al escritorio {os_label} completo desde cualquier navegador. Mueve el ratón, escribe con el teclado, abre aplicaciones.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">⌨️</span>
                <h3>Terminal remoto</h3>
                <p>Ejecuta comandos de {os_label} ({shell_label}) desde el navegador. Historial, tab completion y colores ANSI.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">📊</span>
                <h3>Monitorización</h3>
                <p>Consulta el estado de todos los servicios, CPU, memoria, disco y uptime en tiempo real.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">📡</span>
                <h3>VNC nativo</h3>
                <p>Conecta con apps VNC externas (TigerVNC, RealVNC) directamente al puerto {vnc_port} sin navegador.</p>
            </div>
            {ssl_feature}
            <div class="feature-card">
                <span class="feature-icon">🌐</span>
                <h3>Acceso LAN</h3>
                <p>Conecta desde cualquier dispositivo en tu red local: móvil, tablet, otro PC, etc.</p>
            </div>
        </div>
    </div>"""


def _build_firewall_html(is_windows, use_ssl):
    """Build the firewall notice HTML and the SSL self-signed note.

    Returns a tuple (firewall_html, ssl_note).
    """
    # Firewall note (platform-aware). Only the public entry point needs
    # a rule: backend services bind to 127.0.0.1 and are reached through
    # this portal (or nginx). Opening their ports would bypass the
    # auth-gateway model.
    firewall_html = ''
    public_port = _config()['landing_port']
    if is_windows:
        firewall_html = f"""
        <div class="notice">
            <strong>⚠️ Firewall de Windows:</strong> Solo el portal necesita acceso externo (los backends van por loopback):
            <code>New-NetFirewallRule -DisplayName "VncRemoteSecure-Portal" -Direction Inbound -LocalPort {public_port} -Protocol TCP -Action Allow</code>
        </div>"""
    else:
        firewall_html = f"""
        <div class="notice">
            <strong>⚠️ Firewall de Linux:</strong> Solo el portal necesita acceso externo (los backends van por loopback):
            <code>sudo ufw allow {public_port}/tcp</code>
        </div>"""

    ssl_note = ''
    if use_ssl:
        ssl_note = """
        <div class="notice">
            <strong>🔒 SSL Self-signed:</strong> El navegador mostrará una advertencia de seguridad.
            Click en "Advanced" → "Proceed" para aceptar el certificado en cada servicio HTTPS.
        </div>"""
    return firewall_html, ssl_note


def _landing_css() -> str:
    """Return the portal stylesheet as an inline ``<style>`` block.

    The CSS lives in ``static/landing.css`` (packaged as package-data)
    so it can be linted/versioned separately; it is inlined on each
    render because the stdlib http.server landing handler does not
    serve static files.
    """
    from importlib import resources
    css = resources.files('vnc_remote_secure').joinpath(
        'static/landing.css').read_text(encoding='utf-8')
    return f'    <style>\n{css}    </style>'


def _build_landing_page_template(metrics_html, cards_html, vnc_direct_html, features_section, lan_html, creds_html, ssl_note, firewall_html, metrics):
    """Assemble the final landing page HTML from its section components."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>VNC Remote Secure - Portal</title>
{_landing_css()}
</head>
<body>
    <div class="header">
        <h1>🔒 VNC Remote Secure</h1>
        <p>Portal de acceso a servicios - Actualización automática cada 30s</p>
    </div>

    {metrics_html}

    <div class="section-title">📡 Servicios Disponibles</div>
    <div class="services">
        {cards_html}
        {vnc_direct_html}
    </div>

    {features_section}

    {lan_html}

    {creds_html}

    {ssl_note}
    {firewall_html}

    <div class="footer">
        VNC Remote Secure | {html.escape(metrics['hostname'])} | {html.escape(metrics['os'])} | Uptime: {html.escape(metrics['uptime'])}
    </div>
</body>
</html>"""


def generate_landing_page(forwarded_host=None, forwarded_proto=None):
    """Generate the landing page HTML."""
    lan_ips = get_lan_ips()
    # Use create_ssl_context() as the single source of truth so that
    # links match the actual protocol the servers will use. This
    # requires both SSL_CERT and SSL_KEY to exist and TLS_ENABLED
    # to not be explicitly disabled.
    from vnc_remote_secure.security.certificates import create_ssl_context
    use_ssl = create_ssl_context(_config()['ssl_cert'], _config()['ssl_key']) is not None
    protocol = 'https' if use_ssl else 'http'
    metrics = get_system_metrics()
    is_windows_flag = is_windows()
    # Behind nginx the loopback-only backend ports are unreachable for
    # remote clients — the portal must link the public nginx paths.
    # The forwarded host/proto land inside href attributes in the
    # rendered page: reject anything outside a strict hostname set or
    # a crafted X-Forwarded-Host becomes reflected XSS (the header is
    # still attacker-influenced through nginx's $host).
    import re as _re
    external_base = None
    if forwarded_host:
        proto = (forwarded_proto or 'https').split(',')[0].strip()
        host = forwarded_host.split(',')[0].strip()
        if _re.fullmatch(r'[A-Za-z0-9.\-:\[\]]{1,253}', host) \
                and proto in ('http', 'https'):
            external_base = f'{proto}://{host}'
    services = _build_service_list(protocol, external_base)
    cards_html = _build_service_cards_html(services)
    # TigerVNC binds 5900+display on Linux regardless of an explicit
    # VNC_PORT — probe the same derivation services/vnc._vnc_port and
    # _start_websockify use or the "VNC direct" card lies when
    # VNC_DISPLAY is not :1. On Windows UltraVNC uses VNC_PORT directly.
    vnc_probe_port = _config()['vnc_port']
    if not is_windows_flag:
        try:
            from vnc_remote_secure.services.vnc import _vnc_port
            vnc_probe_port = _vnc_port(_config().get('vnc_display', ':1'))
        except Exception:  # noqa: BLE001 - fall back to config port
            pass
    vnc_rfb_running = check_port(vnc_probe_port)
    vnc_direct_html = _build_vnc_direct_html(lan_ips, vnc_rfb_running)
    metrics_html = _build_metrics_html(metrics)
    # NGINX_ENABLED alone (not just a forwarded request) decides the
    # LAN link shape: an operator browsing the portal directly on
    # LANDING_PORT has no X-Forwarded-Host, yet the backend ports are
    # still loopback-only and unreachable for LAN clients.
    lan_html = _build_lan_html(
        lan_ips, protocol,
        external_base if (external_base or _config().get('nginx_enabled'))
        else None)
    creds_html = _build_credentials_html()
    features_section = _build_features_section(use_ssl, is_windows_flag)
    firewall_html, ssl_note = _build_firewall_html(is_windows_flag, use_ssl)
    return _build_landing_page_template(metrics_html, cards_html, vnc_direct_html, features_section, lan_html, creds_html, ssl_note, firewall_html, metrics)


class LandingHandler(http.server.SimpleHTTPRequestHandler):
    """Landing Handler."""

    def end_headers(self):
        """End headers."""
        from vnc_remote_secure.security.http_headers import send_security_headers
        send_security_headers(self)
        super().end_headers()

    def _ephemeral_cookie(self) -> str:
        """Extract the ``vnc_ephemeral`` cookie value, if present."""
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_ephemeral='):
                return part.split('=', 1)[1].strip()
        return ''

    def _valid_ephemeral_cookie(self) -> bool:
        """Return True when the client holds an activated ephemeral session."""
        internal = self._ephemeral_cookie()
        if not internal:
            return False
        from vnc_remote_secure.security.ephemeral_sessions import check_session_permission
        # Portal access requires any valid permission; 'view' is the
        # base permission every role grants.
        client_ip = client_ip_from(
            self.headers,
            self.client_address[0] if self.client_address else None)
        return check_session_permission(
            internal, 'view', client_ip=client_ip)

    def _handle_session_exchange(self) -> bool:
        """Handle ``GET /?session=<signed_token>`` share links.

        Activates the ephemeral session once, issues the
        ``vnc_ephemeral`` cookie holding the internal session token and
        redirects to the portal without the token in the URL (avoids
        leaking it via Referer/history). Returns True when the request
        was fully handled.
        """
        from urllib.parse import parse_qs, urlparse
        query = parse_qs(urlparse(self.path).query)
        signed = (query.get('session') or [''])[0]
        if not signed:
            return False
        # Link scanners and browser prefetchers hit the activation URL
        # without user intent — each GET burns a use (single-use links
        # die before the recipient ever opens them). Prefetch requests
        # carry Sec-Purpose/Purpose hints; respond with an interstitial
        # so only a real navigation consumes the token.
        purpose = ' '.join(
            self.headers.get(h, '')
            for h in ('Sec-Purpose', 'Purpose', 'X-Moz')).lower()
        if 'prefetch' in purpose or 'preview' in purpose:
            from html import escape
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(
                b'<!doctype html><meta charset="utf-8">'
                b'<title>Open session</title>'
                b'<p><a href="'
                + escape(self.path, quote=True).encode()
                + b'">Click to open the shared session</a></p>')
            return True
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        # Forwarded-aware like check_session_permission: behind a
        # trusted proxy the peer is 127.0.0.1, so an allowed_ip-bound
        # session could never activate if we bound the raw peer.
        client_ip = client_ip_from(
            self.headers,
            self.client_address[0] if self.client_address else None)
        internal = activate_ephemeral_session(signed, client_ip=client_ip)
        if not internal:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body, _ = error_json(
                'Session link is invalid, expired, or already used', 403)
            self.wfile.write(body.encode())
            return True
        # Mark the cookie Secure when the response travels over TLS —
        # either behind a trusted nginx (X-Forwarded-Proto) or via
        # direct TLS on this service (the accepted socket is an
        # SSLSocket). X-Forwarded-Proto is honoured only under
        # TRUSTED_PROXY — a direct client claiming https would get a
        # Secure cookie the browser never returns over plain HTTP.
        import ssl as _ssl
        trusted = os.environ.get(
            'TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
        is_tls = ((trusted and
                   self.headers.get('X-Forwarded-Proto', '') == 'https')
                  or isinstance(self.connection, _ssl.SSLSocket))
        secure = ' Secure;' if is_tls else ''
        # The value lands verbatim inside Set-Cookie — a crafted
        # SESSION_SAMESITE containing ';' or CRLF would inject extra
        # cookie attributes / split the response. Whitelist it.
        samesite = _samesite()
        self.send_response(302)
        self.send_header('Location', '/')
        self.send_header(
            'Set-Cookie',
            f'vnc_ephemeral={internal};{secure} HttpOnly; Path=/; '
            f'SameSite={samesite}')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        return True

    def _require_portal_auth(self) -> bool:
        """Ephemeral cookie or landing Basic-auth gate; sends 401 on failure."""
        ephemeral_ok = self._valid_ephemeral_cookie()
        if not ephemeral_ok and not check_landing_auth(
                self.headers.get('Authorization', ''),
                client_ip=client_ip_from(
                    self.headers,
                    self.client_address[0] if self.client_address else None)):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="VNC Portal"')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body, _ = error_json('Unauthorized', 401)
            self.wfile.write(body.encode())
            return False
        return True

    def do_HEAD(self):  # noqa: N802 - stdlib API
        """Serve HEAD requests through the same auth gate as GET."""
        # HEAD must run the same gate — otherwise SimpleHTTPRequestHandler
        # leaks file metadata (and directory listings under some CPython
        # versions) without authentication.
        if not self._require_portal_auth():
            return
        path = self.path.split('?', 1)[0]
        if path in ('/', '/index.html', '/status.json',
                    '/audio_receiver.html', '/gamepad.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        """Do GET."""
        # Ephemeral share links exchange the signed token for a cookie
        # before any auth check (the link itself is the credential).
        if self._handle_session_exchange():
            return
        # An activated ephemeral session grants portal access without
        # the landing Basic-auth credentials.
        ephemeral_ok = self._valid_ephemeral_cookie()
        # Landing Basic-auth (fail-closed: an empty LANDING_PASSWORD
        # denies access — the startup blocker refuses to run in that
        # state anyway). client_ip feeds the shared auth rate limiter
        # so Basic-auth brute force is locked out like the
        # gateway-protected paths.
        if not ephemeral_ok and not check_landing_auth(
                self.headers.get('Authorization', ''),
                client_ip=client_ip_from(
                    self.headers,
                    self.client_address[0] if self.client_address else None)):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="VNC Portal"')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body, _ = error_json('Unauthorized', 401)
            self.wfile.write(body.encode())
            return
        # Strip the query string for routing: /status.json?ts=… must
        # resolve like the bare path (the Flask blueprint and nginx
        # both match path-only).
        path = self.path.split('?', 1)[0]
        if path == '/' or path == '/index.html':
            self._serve_landing()
        elif path == '/status.json':
            self._serve_status_json()
        elif path == '/audio_receiver.html':
            self._serve_template('audio_receiver.html')
        elif path == '/gamepad.html':
            self._serve_template('gamepad.html')
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body, _ = error_json('Not found', 404)
            self.wfile.write(body.encode())

    def _session_refresh_header(self):
        """Return a ``Set-Cookie`` value refreshing the session cookie.

        Re-issues ``vnc_session`` with an updated ``last_seen`` claim so
        SESSION_IDLE_TIMEOUT measures real inactivity. Returns ``None``
        when there is no session cookie or no refresh is due.
        """
        try:
            raw = ''
            for part in (self.headers.get('Cookie', '') or '').split(';'):
                part = part.strip()
                if part.startswith('vnc_session='):
                    raw = part.split('=', 1)[1].strip()
                    break
            if not raw:
                return None
            from vnc_remote_secure.security.sessions import (
                refresh_session_cookie,
            )
            new_value = refresh_session_cookie(raw)
            if not new_value:
                return None
            import ssl as _ssl
            # Same TLS detection as _handle_session_exchange: behind a
            # trusted proxy the backend socket is plain HTTP, so
            # X-Forwarded-Proto decides whether the refreshed cookie
            # keeps the Secure flag (a missing flag would downgrade
            # the attribute on re-issue).
            trusted = os.environ.get(
                'TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
            is_tls = ((trusted and
                       self.headers.get('X-Forwarded-Proto', '') == 'https')
                      or isinstance(self.connection, _ssl.SSLSocket))
            secure = ' Secure;' if is_tls else ''
            return (f'vnc_session={new_value};{secure} HttpOnly; Path=/; '
                    f'SameSite={_samesite()}')
        except Exception:  # noqa: BLE001 - refresh is best-effort
            return None

    def _serve_landing(self):
        try:
            # Honour X-Forwarded-* only behind a configured trusted
            # proxy — a direct client can spoof these headers and the
            # portal would render links pointing at the attacker's
            # host. Same TRUSTED_PROXY gate as client_ip_from().
            trusted = os.environ.get(
                'TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
            content = generate_landing_page(
                forwarded_host=(
                    self.headers.get('X-Forwarded-Host') if trusted else None),
                forwarded_proto=(
                    self.headers.get('X-Forwarded-Proto') if trusted else None))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            refresh = self._session_refresh_header()
            if refresh:
                self.send_header('Set-Cookie', refresh)
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            log_exception(e, 'Landing _serve_landing')
            body, code = error_json('Failed to render landing page', 500)
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body.encode())

    def _serve_template(self, template_name):
        """Serve an HTML template from the web templates directory.

        Performs minimal Jinja2-style substitution for port variables so
        the audio/gamepad pages honor configured ports instead of
        hardcoded values.
        """
        try:
            template_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'templates', template_name)
            if not os.path.isfile(template_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(f'Template {template_name} not found'.encode())
                return
            with open(template_path, encoding='utf-8') as f:
                content = f.read()
            # Minimal Jinja2 substitution for port variables. The env
            # values land verbatim in the page — coerce to int so a
            # malformed AUDIO_STREAM_PORT/GAMEPAD_PORT cannot inject
            # markup or break the URL.
            import re

            def _port_env(name, default):
                try:
                    return str(int(os.environ.get(name, default)))
                except (TypeError, ValueError):
                    return str(default)
            audio_port = _port_env('AUDIO_STREAM_PORT', DEFAULT_AUDIO_STREAM_PORT)
            gamepad_port = _port_env('GAMEPAD_PORT', DEFAULT_GAMEPAD_PORT)
            content = re.sub(r'\{\{\s*audio_port\s*\|\s*default\(\d+\)\s*\}\}', audio_port, content)
            content = re.sub(r'\{\{\s*gamepad_port\s*\|\s*default\(\d+\)\s*\}\}', gamepad_port, content)

            # WebSocket URLs: behind a trusted nginx the raw service
            # ports are loopback-only, so the pages must connect through
            # the proxied paths (/audio/, /gamepad/). Direct access uses
            # the browser-facing host with the configured port. The
            # ws/wss scheme follows the page's transport (X-Forwarded-
            # Proto for proxied, SSLSocket for direct TLS) so browsers
            # never get a mixed-content ws:// from an https:// page.
            trusted = os.environ.get(
                'TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
            fhost = self.headers.get('X-Forwarded-Host', '').split(',')[0].strip()
            fproto = self.headers.get('X-Forwarded-Proto', '').split(',')[0].strip()
            # The Host values land verbatim inside a JS string literal in
            # the rendered page — a crafted Host/X-Forwarded-Host header
            # containing quotes or markup would be reflected XSS on an
            # authenticated endpoint. Constrain to a strict hostname
            # character set and fall back to loopback on anything else.

            def _safe_host(raw):
                if re.fullmatch(r'[A-Za-z0-9.\-:\[\]]{1,253}', raw or ''):
                    return raw
                return '127.0.0.1'
            fhost = _safe_host(fhost)
            if trusted and fhost != '127.0.0.1' and self.headers.get(
                    'X-Forwarded-Host'):
                ws_scheme = 'wss' if fproto == 'https' else 'ws'
                audio_ws_url = f'{ws_scheme}://{fhost}/audio/'
                gamepad_ws_url = f'{ws_scheme}://{fhost}/gamepad/'
            else:
                import ssl as _ssl
                ws_scheme = ('wss' if isinstance(self.connection, _ssl.SSLSocket)
                             else 'ws')
                host = _safe_host(
                    self.headers.get('Host', '127.0.0.1').split(':')[0].strip())
                audio_ws_url = f'{ws_scheme}://{host}:{audio_port}/'
                gamepad_ws_url = f'{ws_scheme}://{host}:{gamepad_port}/'
            content = content.replace('{{ audio_ws_url }}', audio_ws_url)
            content = content.replace('{{ gamepad_ws_url }}', gamepad_ws_url)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            log_exception(e, 'Landing _serve_template')
            body, code = error_json(f'Failed to serve template {template_name}', 500)
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body.encode())

    def _serve_status_json(self):
        try:
            # On Linux TigerVNC binds 5900+N regardless of an explicit
            # VNC_PORT — probe the real RFB port (same derivation as
            # services/vnc._vnc_port and _start_websockify).
            vnc_port = _config()['vnc_port']
            if os.name != 'nt':
                try:
                    from vnc_remote_secure.services.vnc import _vnc_port
                    vnc_port = _vnc_port(
                        _config().get('vnc_display', ':1'))
                except Exception:  # noqa: BLE001 - fall back to config
                    pass
            cfg = _config()
            data = {
                'services': {
                    'vnc_desktop_novnc': check_port(
                        cfg['novnc_port'], cfg.get('novnc_host', '127.0.0.1')),
                    # websockify always binds loopback (_start_websockify
                    # forces 127.0.0.1 regardless of BIND_HOST).
                    'vnc_ws_bridge': check_port(
                        cfg.get('novnc_ws_port', DEFAULT_NOVNC_WS_PORT)),
                    'terminal': check_port(
                        cfg['ttyd_port'], cfg.get('ttyd_host', '127.0.0.1')),
                    'health_dashboard': check_port(
                        cfg['health_port'], cfg.get('health_host', '127.0.0.1')),
                    'vnc_rfb_direct': check_port(vnc_port),
                    'landing_page': True,
                } | (
                    # UltraVNC's built-in HTTP dir is Windows-only —
                    # on Linux nothing ever listens there and the card
                    # would permanently show a spurious "down" state.
                    {'ultravnc_http': check_port(cfg['vnc_http_port'])}
                    if os.name == 'nt' else {}
                ),
                'lan_ips': get_lan_ips(),
                'system': get_system_metrics(),
                # Credentials are NOT exposed in JSON for security
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
        except Exception as e:
            log_exception(e, 'Landing _serve_status_json')
            body, code = error_json('Failed to build status JSON', 500)
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body.encode())

    def setup(self):
        """Set up the request (bounded header-read window)."""
        super().setup()
        # Slowloris guard: bound the pre-auth header-read window.
        from vnc_remote_secure.services.bounded_server import (
            install_read_timeout,
        )
        install_read_timeout(self)

    def log_message(self, fmt, *args):
        """Log message."""
        # Route stdlib access logs to the module logger instead of
        # discarding — but NEVER verbatim: the request line carries
        # the share-link token (``GET /?session=<signed>``), which
        # would otherwise sit replayable in landing.log.
        import re as _re
        line = _re.sub(r'session=[^&\s"]+', 'session=<redacted>',
                       fmt % args)
        logger.info("%s - %s", self.client_address[0], line)


def main():
    """Start the landing page server."""
    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_options = create_ssl_context(_config()['ssl_cert'], _config()['ssl_key'])

    # Bounded threading server: daemon threads so a hung client cannot
    # block shutdown, and a hard cap so a pre-auth connection flood
    # (slowloris) cannot exhaust threads.
    from vnc_remote_secure.services.bounded_server import (
        BoundedThreadingTCPServer,
    )
    server = BoundedThreadingTCPServer(
        (_config()['landing_host'], _config()['landing_port']),
        LandingHandler)

    if ssl_options:
        server.socket = ssl_options.wrap_socket(server.socket, server_side=True)

    logger.info("Landing portal running on %s:%s", _config()['landing_host'], _config()['landing_port'])
    logger.info("URL: %s://127.0.0.1:%s", 'https' if ssl_options else 'http', _config()['landing_port'])

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
