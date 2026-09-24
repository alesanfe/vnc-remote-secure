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

from vnc_remote_secure.backend.api import is_api_path
from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.platform.detection import is_windows
from vnc_remote_secure.security.http_auth import client_ip_from, cookie_value
from vnc_remote_secure.services.bounded_server import SecuredHandlerMixin

logger = logging.getLogger(__name__)

# Self-hosted script for GET /share â€” kept out of the page so the CSP
# can run script-src 'self' with no 'unsafe-inline'. Reads the token
# from the URL fragment (never sent to the server), wipes it from the
# address bar, previews the grant and activates only on explicit
# consent. The token is never stored in web storage, state or logs.
_SHARE_JS = b"""'use strict';
(function () {
  // Read the token from the fragment and IMMEDIATELY wipe it from the
  // address bar - it must not linger in history or a screenshot.
  var hash = location.hash || '';
  var token = '';
  if (hash.indexOf('#t=') === 0) token = hash.slice(3);
  else if (hash.length > 1) token = hash.slice(1);
  history.replaceState(null, '', '/share');
  var info = document.getElementById('info');
  var actions = document.getElementById('actions');
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }
  function fail(msg) {
    info.innerHTML = '<p class="err">' + esc(msg) + '</p>';
  }
  if (!token) {
    fail('Enlace incompleto: falta el token.');
    return;
  }
  fetch('/session/preview', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin',
    body: JSON.stringify({token: token})
  }).then(function (r) {
    if (!r.ok) throw new Error('invalid');
    return r.json();
  }).then(function (p) {
    var mins = Math.floor(p.expires_in_seconds / 60);
    var secs = p.expires_in_seconds % 60;
    var flags = [];
    if (p.view_only) flags.push('solo visualizaci\\u00f3n');
    if (p.single_use) flags.push('uso \\u00fanico');
    if (p.no_terminal) flags.push('sin terminal');
    if (p.max_uses) flags.push('m\\u00e1x. ' + p.max_uses + ' usos');
    var rows = '<tr><td>Rol</td><td>' + esc(p.role) + '</td></tr>' +
      '<tr><td>Expira en</td><td>' + mins + 'm' +
      ('0' + secs).slice(-2) + 's</td></tr>' +
      (flags.length ? '<tr><td>Restricciones</td><td>' +
       esc(flags.join(', ')) + '</td></tr>' : '');
    info.innerHTML = '<p>Este enlace permitir\\u00e1 <strong>ver' +
      (p.view_only ? '' : ' y controlar') + '</strong> este equipo de ' +
      'forma remota.</p><table>' + rows + '</table>';
    var btn = document.createElement('button');
    btn.textContent = 'Aceptar y abrir sesi\\u00f3n';
    var cancel = document.createElement('button');
    cancel.textContent = 'Cancelar';
    cancel.className = 'ghost';
    cancel.style.cssText = 'background:#222c42;margin-top:8px';
    cancel.onclick = function () {
      // Cancelling must NOT consume the link - just clear the page.
      token = '';
      info.innerHTML = '<p>Enlace descartado. Puedes cerrar esta ' +
        'pesta\\u00f1a.</p>';
      actions.innerHTML = '';
    };
    btn.onclick = function () {
      btn.disabled = true;
      var body = 'token=' + encodeURIComponent(token);
      token = '';  // drop the only JS reference before activating
      fetch('/session/activate', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        credentials: 'same-origin',
        redirect: 'follow',
        body: body
      }).then(function (r) {
        if (r.redirected || r.ok) { location.href = '/'; return; }
        fail('El enlace ha caducado o ya ha sido utilizado.');
      }).catch(function () {
        fail('Error de red. Int\\u00e9ntalo de nuevo.');
      });
    };
    actions.appendChild(btn);
    actions.appendChild(cancel);
  }).catch(function () {
    token = '';
    fail('El enlace ha caducado o ya ha sido utilizado.');
  });
})();
"""

# Load configuration from .env file (never hardcode credentials)
from vnc_remote_secure.core.config import env_flag, load_env_file
from vnc_remote_secure.core.constants import (
    DEFAULT_AUDIO_STREAM_PORT,
    DEFAULT_GAMEPAD_PORT,
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_WS_PORT,
)

load_env_file()


def _safe_ws_host(raw: str) -> str:
    r"""Constrain a Host/X-Forwarded-Host value to a strict hostname set.

    These headers land inside JS string literals in rendered pages â€”
    anything outside ``[A-Za-z0-9.:\\-\\[\\]]`` (quotes, markup) falls
    back to loopback so a crafted header cannot become reflected XSS.
    """
    import re
    if re.fullmatch(r'[A-Za-z0-9.\-:\[\]]{1,253}', raw or ''):
        return raw
    return '127.0.0.1'


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

    Each service binds its own ``<SVC>_HOST`` â€” probing everything on
    loopback reports a service bound to a LAN IP as down. The doctor
    probes per-service hosts; the status JSON must agree. A wildcard
    bind (``0.0.0.0``/``::``) covers loopback too, and connecting to
    the wildcard address itself is unreliable on Windows.
    """
    # justification: detection, not a bind
    if host in ('0.0.0.0', '::', ''):  # nosec B104
        host = '127.0.0.1'
    # Delegate to the shared probe â€” it selects AF_INET6 for IPv6
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
        'Escritorio Windows completo en el navegador. Controla el ratÃ³n y teclado desde cualquier dispositivo.'
        if is_windows_flag else
        'Escritorio remoto completo en el navegador. Controla el ratÃ³n y teclado desde cualquier dispositivo.'
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
    reverse proxy â€” backend ports are loopback-only, so the direct
    ``127.0.0.1:<port>`` links only work for clients on the server
    itself. Through nginx the services are reachable at well-known
    paths instead.
    """
    desktop_desc, terminal_desc, vnc_http_name, vnc_http_desc = _get_service_descriptions()

    if external_base:
        novnc_url = f'{external_base}/vnc/vnc.html'
        terminal_url = f'{external_base}/terminal/'
        # nginx restricts /health to loopback (allow 127.0.0.1; deny all)
        # â€” remote clients would always get 403, so do not render a
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
            'features': ['Mouse y teclado completos', 'Portapapeles', 'Multi-monitor', 'Escalado automÃ¡tico'],
            'icon': 'ðŸ–¥ï¸',
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
            'icon': 'âŒ¨ï¸',
            'url': terminal_url,
            'port': _config()['ttyd_port'],
            'running': check_port(
                _config()['ttyd_port'],
                _config().get('ttyd_host', '127.0.0.1')),
            'color': '#2196f3',
            'category': 'terminal',
        },
    ]
    # UltraVNC's built-in HTTP dir is Windows-only â€” on Linux nothing
    # ever listens on vnc_http_port, so the card would permanently show
    # a spurious "down" state (same reasoning as the status JSON).
    if is_windows():
        services.append({
            'name': vnc_http_name,
            'desc': vnc_http_desc,
            'features': ['Java applet', 'ConexiÃ³n directa', 'Legacy support'],
            'icon': 'ðŸ”Œ',
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
            'desc': 'Panel de monitorizaciÃ³n con estado de servicios, CPU, memoria, disco y red.',
            'features': ['Estado por servicio', 'CPU/RAM/Disco', 'API JSON', 'Auto-refresh 30s'],
            'icon': 'ðŸ“Š',
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
            'icon': 'ðŸ”Š',
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
            'desc': 'ReenvÃ­a el gamepad del cliente al servidor (WebSocket).',
            'features': ['HTML5 Gamepad API', 'Baja latencia', 'Sin drivers extra'],
            'icon': 'ðŸŽ®',
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
        # point â€” escaping here keeps a future dynamic card from
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
    # so a LAN IP in this card points at a port that is not reachable â€”
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
        vnc_note = ('<span class="cred-note">Solo loopback â€” acceda por '
                    'tÃºnel SSH o noVNC</span>')
    else:
        vnc_addr = (f'{html.escape(lan_ips[0]) if lan_ips else "127.0.0.1"}'
                    f':{vnc_port}')
        vnc_note = ''
    vnc_direct_status = 'ONLINE' if vnc_rfb_running else 'OFFLINE'
    vnc_direct_color = '#4caf50' if vnc_rfb_running else '#f44336'
    vnc_direct_opacity = '1' if vnc_rfb_running else '0.5'
    return f"""
    <div class="service-card info-card" style="opacity:{vnc_direct_opacity}">
        <div class="service-icon">ðŸ“¡</div>
        <div class="service-info">
            <h3>VNC Directo (RFB)</h3>
            <p>ConexiÃ³n directa con apps VNC nativas (TightVNC, RealVNC, TigerVNC, etc.)</p>
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
            <span class="metric-icon">ðŸ’»</span>
            <span class="metric-label">Host</span>
            <span class="metric-value">{html.escape(metrics['hostname'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">ðŸ–¥ï¸</span>
            <span class="metric-label">OS</span>
            <span class="metric-value">{html.escape(metrics['os'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">â±ï¸</span>
            <span class="metric-label">Uptime</span>
            <span class="metric-value">{html.escape(metrics['uptime'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">ðŸ“Š</span>
            <span class="metric-label">CPU</span>
            <span class="metric-value">{html.escape(metrics['cpu'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">ðŸ’¾</span>
            <span class="metric-label">RAM</span>
            <span class="metric-value">{html.escape(metrics['memory'])}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">ðŸ’¿</span>
            <span class="metric-label">Disco</span>
            <span class="metric-value">{html.escape(metrics['disk'])}</span>
        </div>
    </div>"""


def _build_lan_html(lan_ips, protocol, external_base=None):
    """Build the LAN access section HTML.

    When the deployment runs behind nginx (``external_base`` is set),
    the raw backend ports are loopback-only â€” LAN clients must use the
    public nginx paths on the HTTPS port instead, or every link here
    is dead. Without nginx the direct per-service ports apply.
    """
    lan_html = ''
    if not lan_ips:
        return lan_html
    nginx = external_base is not None
    https_port = _config().get('nginx_https_port', DEFAULT_NGINX_HTTPS_PORT)
    lan_html = '<div class="lan-section"><h2>ðŸŒ Acceso Remoto (LAN)</h2><p class="section-desc">Conecta desde otro dispositivo en la misma red:</p>'
    for ip in lan_ips:
        ip_escaped = html.escape(ip)
        if nginx:
            # https://<ip>[:<port>]/path â€” the default HTTPS port keeps a
            # bare host; a non-default NGINX_HTTPS_PORT must be explicit.
            port_suffix = '' if int(https_port) == DEFAULT_NGINX_HTTPS_PORT \
                else f':{https_port}'
            lan_html += f"""
            <div class="ip-card">
                <div class="ip-address">{ip_escaped}</div>
                <div class="ip-links">
                    <a href="https://{ip_escaped}{port_suffix}/vnc/vnc.html">ðŸ–¥ï¸ VNC Desktop</a>
                    <a href="https://{ip_escaped}{port_suffix}/terminal/">âŒ¨ï¸ Web Terminal</a>
                    <a href="https://{ip_escaped}{port_suffix}/">ðŸ  Portal</a>
                </div>
            </div>"""
        else:
            lan_html += f"""
            <div class="ip-card">
                <div class="ip-address">{ip_escaped}</div>
                <div class="ip-links">
                    <a href="{protocol}://{ip_escaped}:{_config()["novnc_port"]}/vnc.html">ðŸ–¥ï¸ VNC Desktop</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["ttyd_port"]}/">âŒ¨ï¸ Web Terminal</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["health_port"]}/health">ðŸ“Š Health</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["health_port"]}/health/all">ðŸ“‹ Health (all)</a>
                    <a href="{protocol}://{ip_escaped}:{_config()["landing_port"]}">ðŸ  Portal</a>
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
        <h2>ðŸ” Credenciales de Acceso</h2>
        <p class="section-desc">Por seguridad, las credenciales no se muestran en esta pÃ¡gina.
        Revise el archivo <code>.env</code>, o <code>generated_credentials.env</code>
        en el directorio de ejecuciÃ³n si fueron autogeneradas.</p>
        <div class="cred-grid">
            <div class="cred-item">
                <span class="cred-icon">ðŸ–¥ï¸</span>
                <div class="cred-content">
                    <span class="cred-label">VNC Desktop (noVNC y RFB)</span>
                    <span class="cred-value">Password: <code>â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢</code> (ver .env o generated_credentials.env)</span>
                    <span class="cred-note">VNC usa los primeros 8 caracteres del password</span>
                </div>
            </div>
            <div class="cred-item">
                <span class="cred-icon">âŒ¨ï¸</span>
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
                <span class="feature-icon">ðŸ”’</span>
                <h3>ConexiÃ³n cifrada</h3>
                <p>Todos los servicios web usan HTTPS con certificado SSL (self-signed). Acepta la advertencia del navegador.</p>
            </div>"""
    else:
        ssl_feature = """
            <div class="feature-card">
                <span class="feature-icon">âš ï¸</span>
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
        <h2>âœ¨ Â¿QuÃ© puedes hacer?</h2>
        <div class="feature-cards">
            <div class="feature-card">
                <span class="feature-icon">ðŸ–¥ï¸</span>
                <h3>Control remoto del escritorio</h3>
                <p>Accede al escritorio {os_label} completo desde cualquier navegador. Mueve el ratÃ³n, escribe con el teclado, abre aplicaciones.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">âŒ¨ï¸</span>
                <h3>Terminal remoto</h3>
                <p>Ejecuta comandos de {os_label} ({shell_label}) desde el navegador. Historial, tab completion y colores ANSI.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">ðŸ“Š</span>
                <h3>MonitorizaciÃ³n</h3>
                <p>Consulta el estado de todos los servicios, CPU, memoria, disco y uptime en tiempo real.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">ðŸ“¡</span>
                <h3>VNC nativo</h3>
                <p>Conecta con apps VNC externas (TigerVNC, RealVNC) directamente al puerto {vnc_port} sin navegador.</p>
            </div>
            {ssl_feature}
            <div class="feature-card">
                <span class="feature-icon">ðŸŒ</span>
                <h3>Acceso LAN</h3>
                <p>Conecta desde cualquier dispositivo en tu red local: mÃ³vil, tablet, otro PC, etc.</p>
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
            <strong>âš ï¸ Firewall de Windows:</strong> Solo el portal necesita acceso externo (los backends van por loopback):
            <code>New-NetFirewallRule -DisplayName "VncRemoteSecure-Portal" -Direction Inbound -LocalPort {public_port} -Protocol TCP -Action Allow</code>
        </div>"""
    else:
        firewall_html = f"""
        <div class="notice">
            <strong>âš ï¸ Firewall de Linux:</strong> Solo el portal necesita acceso externo (los backends van por loopback):
            <code>sudo ufw allow {public_port}/tcp</code>
        </div>"""

    ssl_note = ''
    if use_ssl:
        ssl_note = """
        <div class="notice">
            <strong>ðŸ”’ SSL Self-signed:</strong> El navegador mostrarÃ¡ una advertencia de seguridad.
            Click en "Advanced" â†’ "Proceed" para aceptar el certificado en cada servicio HTTPS.
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


def _build_sessions_html():
    """Render the active ephemeral sessions panel with revoke buttons.

    The portal is the admin control surface: an operator should see
    WHO holds a share link (role, permissions, expiry) and be able to
    kill it without dropping to the CLI. Revocation is a POST to
    /sessions/revoke (Origin-checked, operator-auth). Best-effort â€”
    a store failure renders an empty panel, not a broken page.
    """
    try:
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store
        store = get_session_store()
        store._load_if_changed()
        sessions = store.list_active()
    except Exception:  # noqa: BLE001
        sessions = []
    if not sessions:
        return ''
    import time as _time
    rows = []
    for s in sessions:
        remaining = max(0, int(s['expires_at'] - _time.time()))
        mins, secs = divmod(remaining, 60)
        flags = []
        if s.get('view_only'):
            flags.append('view-only')
        if s.get('single_use'):
            flags.append('single-use')
        if s.get('no_terminal'):
            flags.append('no-terminal')
        perms = html.escape(', '.join(s.get('permissions', [])))
        rows.append(
            f'<tr><td><code>{html.escape(s["token_id"])}</code></td>'
            f'<td>{html.escape(s.get("role", ""))}</td>'
            f'<td title="{perms}">{html.escape(str(len(s.get("permissions", []))))} perm</td>'
            f'<td>{mins}m{secs:02d}s</td>'
            f'<td>{html.escape(", ".join(flags))}</td>'
            f'<td><button class="revoke-btn" '
            f'data-token="{html.escape(s["token_id"])}">Revocar</button></td></tr>')
    return f"""
    <div class="section-title">ðŸ”— Sesiones activas ({len(rows)})
    <button id="revoke-all-btn" style="margin-left:1em;font-size:0.8em;
    background:#c0392b;color:#fff;border:0;padding:4px 10px;
    border-radius:4px;cursor:pointer">Cerrar todas</button></div>
    <div class="info-card" style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse;font-size:0.9em">
    <tr><th>ID</th><th>Rol</th><th>Permisos</th><th>Expira</th><th>Flags</th><th></th></tr>
    {''.join(rows)}
    </table>
    </div>
    <script>
    var _CSRF = (document.querySelector('meta[name="csrf-token"]') || {{}}).content || '';
    document.getElementById('revoke-all-btn').addEventListener(
      'click', function(){{
      if (!confirm('Â¿Cerrar TODAS las sesiones activas? Las conexiones se cortarÃ¡n ahora.')) return;
      fetch('/sessions/revoke-all', {{method: 'POST',
        headers: {{'X-CSRF-Token': _CSRF}}}}).then(function(r){{
        if (r.ok) {{ location.reload(); }}
        else {{ alert('No se pudieron revocar'); }}
      }});
    }});
    document.querySelectorAll('.revoke-btn').forEach(function(b){{
      b.addEventListener('click', function(){{
        if (!confirm('Â¿Revocar esta sesiÃ³n? Sus conexiones se cerrarÃ¡n ahora.')) return;
        fetch('/sessions/revoke', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json',
                     'X-CSRF-Token': _CSRF}},
          body: JSON.stringify({{token_id: b.dataset.token}})
        }}).then(function(r){{
          if (r.ok) {{ b.closest('tr').style.opacity = '0.3'; b.disabled = true; }}
          else {{ alert('No se pudo revocar'); }}
        }});
      }});
    }});
    </script>"""


def _audio_capture_active() -> bool:
    """Return True while the audio service is capturing the mic."""
    try:
        from vnc_remote_secure.services.audio import audio_capture_active
        return audio_capture_active()
    except Exception:  # noqa: BLE001
        return False


def _build_gamepad_html():
    """Render the gamepad kill-switch card (stop/resume injection).

    The remote user drives a gamepad over a share link â€” the local
    operator needs a stop that does not depend on that session's
    cooperation: it flips a shared flag the gamepad service checks
    per-connection and per-message.
    """
    if not _config().get('gamepad_enabled'):
        return ''
    stopped = False
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        stopped = bool(get_backend().get('gamepad', 'stopped'))
    except Exception:  # noqa: BLE001
        pass
    if stopped:
        state = ('<strong style="color:#e53935">â›” InyecciÃ³n '
                 'detenida</strong> (local kill-switch activo)')
        btn = ('<button id="gamepad-resume-btn" '
               'style="font-size:0.85em;padding:5px 12px;cursor:pointer">'
               'Reanudar</button>')
        action = 'resume'
    else:
        state = '<strong style="color:#4caf50">ðŸŽ® InyecciÃ³n activa</strong>'
        btn = ('<button id="gamepad-stop-btn" style="font-size:0.85em;'
               'padding:5px 12px;background:#c0392b;color:#fff;border:0;'
               'cursor:pointer">Detener control</button>')
        action = 'stop'
    return f"""
    <div class="info-card"><strong>ðŸŽ® Gamepad:</strong> {state}
    {btn}
    <script>
    (function(){{
      var b = document.getElementById('gamepad-{action}-btn');
      if (!b) return;
      b.addEventListener('click', function(){{
        var _CSRF = (document.querySelector('meta[name="csrf-token"]') || {{}}).content || '';
        fetch('/gamepad/{action}', {{method: 'POST',
          headers: {{'X-CSRF-Token': _CSRF}}}}).then(function(r){{
          if (r.ok) {{ location.reload(); }}
          else {{ alert('No se pudo cambiar el estado del gamepad'); }}
        }});
      }});
    }})();
    </script></div>"""


def _build_audio_indicator_html():
    """Render a mic-capture privacy badge for the portal header.

    Audio streaming captures the machine's microphone/audio output â€”
    an operator or co-located user deserves an unmissable 'recording'
    indicator while it runs, not a buried service status.
    """
    if not _audio_capture_active():
        return ''
    return ('<div class="info-card" style="border-left:4px solid '
            '#e53935"><strong>ðŸŽ™ï¸ MicrÃ³fono activo</strong> â€” el '
            'servidor estÃ¡ capturando audio ahora mismo</div>')


def _build_backup_html():
    """Render backup status: newest backup name, age, and count.

    The portal is the admin control surface â€” 'when did a backup
    last succeed' is exactly the kind of operational fact that must
    be visible at a glance. Best-effort: an unreadable backup dir
    renders a warning, not an exception.
    """
    try:
        from vnc_remote_secure.core.backup import list_backups
        backups = list_backups()
    except Exception:  # noqa: BLE001
        return ('<div class="info-card"><strong>ðŸ’¾ Backups:</strong> '
                'no se pudo leer el directorio de backups</div>')
    if not backups:
        return ('<div class="info-card"><strong>ðŸ’¾ Backups:</strong> '
                'ninguno â€” ejecuta <code>vnc-remote backup</code></div>')
    import time as _time
    newest = backups[0]
    age_s = None
    try:
        age_s = int(_time.time() - os.path.getmtime(newest))
        if age_s < 3600:
            age = f'{age_s // 60}m'
        elif age_s < 86400:
            age = f'{age_s // 3600}h'
        else:
            age = f'{age_s // 86400}d'
    except OSError:
        age = '?'
    stale = age_s is not None and age_s > 7 * 86400
    warn = ' âš ï¸ antiguo (>7d)' if stale else ''
    # Certificate expiry: the metric exists in Prometheus â€” surface it
    # here too so the operator sees cert health without a scraper.
    cert_html = ''
    try:
        from vnc_remote_secure.security.tls_validation import cert_days_remaining
        days = cert_days_remaining()
        if days is not None:
            cert_warn = ' âš ï¸' if days < 30 else ''
            cert_html = (f'<br><strong>ðŸ” Certificado:</strong> '
                         f'{days} dÃ­as restantes{cert_warn}')
    except Exception:  # noqa: BLE001
        pass
    return (f'<div class="info-card"><strong>ðŸ’¾ Backups:</strong> '
            f'{len(backups)} â€” Ãºltimo: '
            f'<code>{html.escape(os.path.basename(newest))}</code> '
            f'({html.escape(age)}){warn}{cert_html}</div>')


def _build_landing_page_template(metrics_html, cards_html, vnc_direct_html, features_section, lan_html, creds_html, sessions_html, backups_html, audio_html, gamepad_html, ssl_note, firewall_html, metrics, maintenance_banner='', admin_link='', csrf_token=''):
    """Assemble the final landing page HTML from its section components."""
    csrf_meta = (f'<meta name="csrf-token" content="{csrf_token}">'
                 if csrf_token else '')
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    {csrf_meta}
    <title>VNC Remote Secure - Portal</title>
{_landing_css()}
</head>
<body>
    <a class="skip-link" href="#main">Saltar al contenido</a>
    <div class="header" role="banner">
        <h1>ðŸ”’ VNC Remote Secure</h1>
        <p>Portal de acceso a servicios - ActualizaciÃ³n automÃ¡tica cada 30s</p>
        {admin_link}
    </div>

    <main id="main">

    {maintenance_banner}

    {metrics_html}

    <div class="section-title">ðŸ“¡ Servicios Disponibles</div>
    <div class="services">
        {cards_html}
        {vnc_direct_html}
    </div>

    {features_section}

    {lan_html}

    {creds_html}

    {audio_html}
    {gamepad_html}
    {sessions_html}

    {backups_html}

    {ssl_note}
    {firewall_html}

    </main>

    <div class="footer" role="contentinfo">
        VNC Remote Secure | {html.escape(metrics['hostname'])} | {html.escape(metrics['os'])} | Uptime: {html.escape(metrics['uptime'])}
    </div>
</body>
</html>"""


def _maintenance_banner():
    """Render the maintenance-mode notice, or '' when inactive."""
    try:
        from vnc_remote_secure.security.maintenance import maintenance_active, maintenance_info
        if not maintenance_active():
            return ''
        info = maintenance_info() or {}
        reason = html.escape(info.get('reason') or '')
        detail = f' â€” {reason}' if reason else ''
    except Exception:  # noqa: BLE001 - never break the portal
        return ''
    return ('<div class="notice" role="alert" '
            'style="border-color:#e6a23c;color:#e6a23c">'
            f'âš ï¸ Modo mantenimiento activo{detail} â€” '
            'no se admiten nuevas sesiones.</div>')


def generate_landing_page(forwarded_host=None, forwarded_proto=None,
                          is_operator=True, csrf_token=''):
    """Generate the landing page HTML.

    ``is_operator`` distinguishes a credentialed operator from an
    ephemeral share-link session: the session inventory (who holds
    links, roles, expiry) and the gamepad kill-switch are operator
    information â€” a ``view``-only share recipient gets the page
    without them.
    """
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
    # remote clients â€” the portal must link the public nginx paths.
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
    # VNC_PORT â€” probe the same derivation services/vnc._vnc_port and
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
    sessions_html = _build_sessions_html() if is_operator else ''
    backups_html = _build_backup_html()
    audio_html = _build_audio_indicator_html()
    gamepad_html = _build_gamepad_html() if is_operator else ''
    features_section = _build_features_section(use_ssl, is_windows_flag)
    firewall_html, ssl_note = _build_firewall_html(is_windows_flag, use_ssl)
    admin_link = (
        '<p><a href="/admin/" style="color:#cfe0ff">ðŸ› ï¸ Panel de '
        'administraciÃ³n</a></p>' if is_operator else '')
    return _build_landing_page_template(
        metrics_html, cards_html, vnc_direct_html, features_section,
        lan_html, creds_html, sessions_html, backups_html, audio_html,
        gamepad_html, ssl_note, firewall_html, metrics,
        maintenance_banner=_maintenance_banner(), admin_link=admin_link,
        csrf_token=csrf_token)


class LandingHandler(SecuredHandlerMixin,
                     http.server.SimpleHTTPRequestHandler):
    """Landing Handler.

    The mixin installs the Slowloris read timeout and the security
    headers; ``log_message`` is overridden below to redact the
    share-link token from access logs.
    """

    def _ephemeral_cookie(self) -> str:
        """Extract the ``vnc_ephemeral`` cookie value, if present."""
        return cookie_value(
            self.headers.get('Cookie', ''), 'vnc_ephemeral')

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
            self.peer_ip())
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
        # A share link NEVER activates on GET: prefetchers, link
        # scanners and reloads must not burn a single-use token, and a
        # credential must not be consumed by a side-effecting GET.
        # The interstitial POSTs the token to /session/activate â€” a
        # real form, so it works with JavaScript disabled.
        self._render_share_interstitial(signed)
        return True

    def _session_preview(self, signed: str) -> dict | None:
        """Non-consuming preview of a share-link token.

        Returns what a recipient may see BEFORE accepting â€” role,
        expiry, coarse flags. Deliberately omits creator identity,
        bound IPs, hostnames and any infrastructure detail: the link
        grants access, not reconnaissance. Invalid/expired/revoked
        tokens all return None (uniform response, no enumeration).
        """
        import time as _time
        try:
            from vnc_remote_secure.security.ephemeral_sessions import (
                get_session_store,
                verify_ephemeral_token,
            )
            payload = verify_ephemeral_token(signed)
            if not payload:
                return None
            store = get_session_store()
            store._load_if_changed()
            session = store.get(payload['session_token'])
            if session is None or session.revoked:
                return None
            return {
                'role': session.role,
                'expires_in_seconds': max(
                    0, int(session.expires_at - _time.time())),
                'view_only': bool(session.view_only),
                'single_use': bool(session.single_use),
                'no_terminal': bool(session.no_terminal),
                'max_uses': session.max_uses,
                'resource': session.resource,
            }
        except Exception:  # noqa: BLE001 - preview is best-effort
            return None

    @staticmethod
    def _preview_rows(preview: dict) -> str:
        mins, secs = divmod(preview['expires_in_seconds'], 60)
        flags = []
        if preview['view_only']:
            flags.append('solo visualizaciÃ³n')
        if preview['single_use']:
            flags.append('uso Ãºnico')
        if preview['no_terminal']:
            flags.append('sin terminal')
        if preview['max_uses']:
            flags.append(f'mÃ¡x. {preview["max_uses"]} usos')
        return (
            f'<tr><td>Rol</td><td>{html.escape(str(preview["role"]))}</td></tr>'
            f'<tr><td>Expira en</td><td>{mins}m{secs:02d}s</td></tr>'
            + (f'<tr><td>Restricciones</td><td>'
               f'{html.escape(", ".join(flags))}</td></tr>'
               if flags else ''))

    def _render_share_interstitial(self, signed: str) -> None:
        """Render the share-link activation page (no state changes).

        Shows what the link grants (role, expiry, flags) so the
        recipient can make an informed click; the token is only
        consumed by the POST to /session/activate.
        """
        preview = self._session_preview(signed)
        rows = self._preview_rows(preview) if preview else ''
        if not preview:
            rows = ('<tr><td colspan="2">Este enlace ha caducado o ya '
                    'no es vÃ¡lido.</td></tr>')
        # NOTE: the token travels in the URL for these legacy links â€”
        # Referrer-Policy:no-referrer keeps it out of outbound
        # requests, and the CSP blocks anything that could exfiltrate
        # it (no external resources, no forms to foreign origins).
        body = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VNC Remote Secure â€” Abrir sesiÃ³n</title>
<style>
body {{ font-family: Arial, sans-serif; background: #0f1420;
       color: #e6e9f0; display: flex; justify-content: center;
       align-items: center; min-height: 100vh; margin: 0; }}
.card {{ background: #1a2233; border: 1px solid #2a3550;
        border-radius: 10px; padding: 2em; max-width: 420px; }}
table {{ border-collapse: collapse; margin: 1em 0; width: 100%; }}
td {{ padding: 6px 10px; border-bottom: 1px solid #2a3550; }}
td:first-child {{ color: #9aa7c0; }}
button {{ width: 100%; padding: 12px; font-size: 1em; border: 0;
         border-radius: 6px; background: #2f6fed; color: #fff;
         cursor: pointer; }}
button:hover {{ background: #245bcc; }}
</style></head><body>
<div class="card">
<h1>SesiÃ³n compartida</h1>
<p>Este enlace permitirÃ¡ <strong>ver{'' if (preview and preview['view_only']) else ' y controlar'}</strong>
este equipo de forma remota.</p>
{('<table>' + rows + '</table>') if rows else ''}
{'''<form method="post" action="/session/activate">
<input type="hidden" name="token" value="''' + html.escape(signed, quote=True) + '''">
<button type="submit">Aceptar y abrir sesiÃ³n</button>
</form>''' if preview else ''}
</div></body></html>"""
        data = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self'; base-uri 'none'")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_share_page(self) -> None:
        """Serve the fragment-token exchange page (GET /share).

        The signed token travels in the URL FRAGMENT (``#t=â€¦``), which
        browsers never send to the server â€” it cannot land in access
        logs, Referer headers, proxies or history entries. The inline
        script reads it, wipes the location bar, previews the grant
        via POST /session/preview and activates via POST
        /session/activate on explicit user consent.
        """
        body = b"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VNC Remote Secure \xe2\x80\x94 Abrir sesi\xc3\xb3n</title>
<style>
body { font-family: Arial, sans-serif; background: #0f1420;
       color: #e6e9f0; display: flex; justify-content: center;
       align-items: center; min-height: 100vh; margin: 0; }
.card { background: #1a2233; border: 1px solid #2a3550;
        border-radius: 10px; padding: 2em; max-width: 420px; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; }
td { padding: 6px 10px; border-bottom: 1px solid #2a3550; }
td:first-child { color: #9aa7c0; }
button { width: 100%; padding: 12px; font-size: 1em; border: 0;
         border-radius: 6px; background: #2f6fed; color: #fff;
         cursor: pointer; }
button:hover { background: #245bcc; }
.err { color: #e05b5b; }
</style></head><body>
<div class="card">
<h1>Sesi\xc3\xb3n compartida</h1>
<noscript><p>Se necesita JavaScript para este enlace. Pide al
administrador un enlace cl\xc3\xa1sico <code>/?session=\xe2\x80\xa6</code>.</p></noscript>
<div id="info"><p>Comprobando enlace\xe2\x80\xa6</p></div>
<div id="actions"></div>
</div>
<script src="/share.js" defer></script>
</body></html>"""
        data = body  # already bytes (b"""...""" with \xNN escapes)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; "
            "form-action 'self'; base-uri 'none'; "
            "frame-ancestors 'none'")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _post_session_preview(self) -> None:
        """POST /session/preview â€” non-consuming grant summary.

        The token IS the credential; knowing it already grants access,
        so the preview reveals only what the link does (role, expiry,
        coarse flags) â€” never creator, IPs, or host details.
        """
        from vnc_remote_secure.backend.api import _rate_limit
        if not _rate_limit(self, 'session.preview'):
            return
        token, error = self._read_activate_body()
        if error:
            self.send_json_error(error[0], error[1])
            return
        preview = self._session_preview(token)
        if preview is None:
            self.send_json_error(
                'Session link is invalid, expired, or already used',
                403)
            return
        self.send_json(preview, 200)

    def _read_activate_body(self):
        """Parse a share-link token from a POST body (form or JSON)."""
        from urllib.parse import parse_qs
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        if not 0 < length <= 4096:
            return None, ('Bad request', 400)
        raw = self.rfile.read(length)
        ctype = self.headers.get('Content-Type', '')
        if 'application/json' in ctype:
            try:
                return str(json.loads(raw).get('token', '')), None
            except (json.JSONDecodeError, ValueError):
                return None, ('Invalid JSON', 400)
        token = (parse_qs(
            raw.decode('utf-8', 'replace')).get('token') or [''])[0]
        if not token:
            return None, ('token required', 400)
        return token, None

    def _issue_ephemeral_cookie(self, internal: str) -> None:
        """Set the ``vnc_ephemeral`` cookie and redirect to '/'.

        The cookie is marked Secure when the response travels over TLS
        â€” either behind a trusted nginx (X-Forwarded-Proto) or via
        direct TLS on this service (the accepted socket is an
        SSLSocket). X-Forwarded-Proto is honoured only under
        TRUSTED_PROXY â€” a direct client claiming https would get a
        Secure cookie the browser never returns over plain HTTP.
        """
        import ssl as _ssl
        trusted = env_flag('TRUSTED_PROXY', 'false')
        is_tls = ((trusted and
                   self.headers.get('X-Forwarded-Proto', '') == 'https')
                  or isinstance(self.connection, _ssl.SSLSocket))
        secure = ' Secure;' if is_tls else ''
        # The value lands verbatim inside Set-Cookie â€” a crafted
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

    def _post_session_activate(self) -> None:
        """POST /session/activate â€” exchange a share-link token.

        The link itself is the credential, so no operator gate; the
        token arrives in the request BODY (form or JSON), never in a
        URL the server logs or a Referer could carry onward.
        """
        from vnc_remote_secure.backend.api import _rate_limit
        if not _rate_limit(self, 'session.activate'):
            return
        signed, error = self._read_activate_body()
        if error:
            self.send_json_error(error[0], error[1])
            return
        from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
        # Forwarded-aware like check_session_permission: behind a
        # trusted proxy the peer is 127.0.0.1, so an allowed_ip-bound
        # session could never activate if we bound the raw peer.
        client_ip = client_ip_from(self.headers, self.peer_ip())
        internal = activate_ephemeral_session(signed, client_ip=client_ip)
        if not internal:
            self.send_json_error(
                'Session link is invalid, expired, or already used',
                403)
            return
        self._issue_ephemeral_cookie(internal)

    def _portal_identity(self):
        """Resolve the portal request's auth identity.

        Returns ``(authenticated, operator)`` where ``operator`` is the
        RBAC record (env bootstrap admin or a stored operator account)
        or ``None`` when the request is an ephemeral share-link session.
        Read access is allowed to both; session inventory and
        mutations are operator-only (checked by the callers via the
        stashed ``self._portal_operator``).
        """
        if self._valid_ephemeral_cookie():
            return True, None
        ok, operator = self._resolve_operator()
        if ok and operator is not None:
            self._csrf_nonce()  # ensure the nonce cookie exists
        return ok, (operator if ok else None)

    # Operator session cookie lifetime (absolute).
    _OP_SESSION_TTL = 8 * 3600

    def _resolve_operator(self):
        """Authenticate an operator: ``vnc_op`` session cookie first,
        then Basic credentials (which mint a fresh session).

        Returns ``(ok, operator)``. On success the session id is
        stashed on ``self._portal_sid`` â€” the CSRF token is bound to
        it, and logout/revocation targets it.
        """
        cookie_header = self.headers.get('Cookie', '')
        # A duplicated vnc_op name is ambiguous â€” cookie parsing order
        # is not portable, so duplicated session cookies never auth.
        if self._cookie_occurrences(cookie_header, 'vnc_op') == 1:
            rec = self._verify_op_cookie(
                cookie_value(cookie_header, 'vnc_op'))
            if rec is not None:
                sid, operator = rec
                self._portal_sid = sid
                return True, operator
        from vnc_remote_secure.security.http_auth import authenticate_landing
        ok, operator = authenticate_landing(
            self.headers.get('Authorization', ''),
            client_ip=client_ip_from(
                self.headers,
                self.peer_ip()))
        if ok and operator is not None:
            username = operator.get('username', 'admin')
            self._portal_sid = self._issue_op_session(username)
            # A fresh credential check is a fresh authentication â€”
            # step-up-sensitive API actions (passkey register/revoke)
            # measure recency from this mark.
            try:
                from vnc_remote_secure.security.step_up_auth import record_auth_time
                record_auth_time(username)
            except Exception:  # noqa: BLE001 - best-effort marker
                pass
        return ok, (operator if ok else None)

    # Cap on simultaneous operator sessions per account â€” the oldest
    # is revoked when a new one is minted past the limit.
    _OP_SESSION_MAX_PER_USER = 10

    def _issue_op_session(self, username: str) -> str:
        """Mint a signed operator-session cookie; returns the sid.

        Format: ``<sid>.<b64url username>.<exp>.<hmac>`` â€” the
        username is base64url-encoded so dots in usernames can never
        confuse the positional parser.
        """
        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac
        import secrets
        import time as _time
        sid = secrets.token_urlsafe(16)
        exp = int(_time.time()) + self._OP_SESSION_TTL
        user64 = _b64.urlsafe_b64encode(
            username.encode('utf-8')).rstrip(b'=').decode('ascii')
        payload = f'{sid}.{user64}.{exp}'
        from vnc_remote_secure.security.authentication import _get_secret
        sig = _hmac.new(_get_secret(), f'op:{payload}'.encode(),
                        _hashlib.sha256).hexdigest()
        self._queue_cookie(
            f'vnc_op={payload}.{sig}; HttpOnly; Path=/; SameSite=Strict')
        self._index_op_session(username, sid, exp)
        # A fresh credential check mints the session â€” record it so
        # step-up-gated routes see this as a recent authentication.
        try:
            from vnc_remote_secure.security.step_up_auth import record_auth_time
            record_auth_time(username)
        except Exception:  # noqa: BLE001 - best-effort marker
            pass
        from vnc_remote_secure.security.audit import audit_event
        audit_event('operator_session_issued',
                    user=username, detail=f'sid={sid[:8]}â€¦')
        return sid

    def _index_op_session(self, username: str, sid: str, exp: int):
        """Track live sids per operator; revoke the oldest past the cap."""
        import time as _time
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            be = get_backend()
            ns = 'op_sessions'
            now = int(_time.time())
            active = []
            for k in be.list_keys(ns):
                try:
                    exp_i = int(be.get(ns, k) or 0)
                except (TypeError, ValueError):
                    be.delete(ns, k)
                    continue
                if exp_i <= now:
                    be.delete(ns, k)
                    continue
                user, _, ksid = k.partition('\x00')
                if user == username:
                    active.append((exp_i, ksid))
            while len(active) >= self._OP_SESSION_MAX_PER_USER:
                oldest_exp, oldest_sid = min(active)
                self._revoke_op_session(oldest_sid, oldest_exp)
                be.delete(ns, f'{username}\x00{oldest_sid}')
                active.remove((oldest_exp, oldest_sid))
            be.set_ttl(ns, f'{username}\x00{sid}', str(exp),
                       self._OP_SESSION_TTL)
        except Exception:  # noqa: BLE001 - indexing is best-effort
            pass

    @staticmethod
    def _cookie_occurrences(cookie_header: str, name: str) -> int:
        """Count ``name=`` appearances â€” a duplicated cookie name makes
        parsing order-dependent, so verifiers reject it outright."""
        return sum(
            1 for p in (cookie_header or '').split(';')
            if p.strip().startswith(name + '='))

    def _verify_op_cookie(self, value: str):
        """Verify a ``vnc_op`` cookie; returns ``(sid, operator)``.

        Format: ``<sid>.<b64user>.<exp>.<hmac>``. Strict checks: exact
        part count, bounded size, no control chars, field shapes,
        finite future expiry within the TTL window, constant-time
        signature, shared-state revocation (per-sid and per-user
        marks), and account disabled state.
        """
        import base64 as _b64
        import hashlib as _hashlib
        import hmac
        import re as _re
        import time as _time
        if not value or len(value) > 256:
            return None
        if any(ord(c) < 0x21 or ord(c) == 0x7f for c in value):
            return None
        parts = value.split('.')
        if len(parts) != 4:
            return None
        sid, user64, exp_s, sig = parts
        if not _re.fullmatch(r'[A-Za-z0-9_-]{8,64}', sid):
            return None
        if not _re.fullmatch(r'[0-9]{1,12}', exp_s) \
                or not _re.fullmatch(r'[0-9a-f]{64}', sig):
            return None
        try:
            username = _b64.urlsafe_b64decode(
                user64 + '=' * (-len(user64) % 4)).decode('utf-8')
        except Exception:  # noqa: BLE001 - malformed b64
            return None
        if not username or len(username) > 64:
            return None
        now = _time.time()
        exp = int(exp_s)
        if exp <= now or exp > now + self._OP_SESSION_TTL + 60:
            return None
        from vnc_remote_secure.security.authentication import _get_secret
        expected = hmac.new(
            _get_secret(),
            f'op:{sid}.{user64}.{exp_s}'.encode(),
            _hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            backend = get_backend()
            if backend.get('op_revoked_sessions', sid):
                return None
            # Per-user revocation mark: password/role/disable/delete
            # kill sessions issued before the mark (issue time is
            # exp - TTL).
            revoked_at = backend.get('op_revoked_users', username)
            if revoked_at and (exp - self._OP_SESSION_TTL) <= int(
                    float(revoked_at)):
                return None
        except Exception:  # noqa: BLE001 - fail closed
            return None
        # Resolve the operator record: store users first, env
        # bootstrap 'admin' as the fallback.
        try:
            from vnc_remote_secure.security.operator_users import (
                get_permissions,
                load_store,
            )
            store = load_store()
            if username in store:
                if store[username].get('disabled'):
                    return None
                return sid, {
                    'username': username,
                    'role': store[username].get('role', 'operator'),
                    'permissions': sorted(get_permissions(username)),
                }
        except Exception:  # noqa: BLE001
            return None
        if username == 'admin':
            return sid, {'username': 'admin', 'role': 'admin',
                         'permissions': ['admin:*']}
        return None

    def _queue_cookie(self, cookie: str) -> None:
        """Queue a Set-Cookie for this response (emitted by
        end_headers so every code path is covered once)."""
        self.__dict__.setdefault('_pending_cookies', []).append(cookie)

    def _revoke_op_session(self, sid: str, exp: int) -> None:
        """Mark an operator session id as revoked for its remaining TTL."""
        import time as _time
        ttl = max(1, exp - int(_time.time()))
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().set_ttl('op_revoked_sessions', sid, '1', ttl)

    def _csrf_nonce(self) -> str:
        """Return this session's CSRF nonce, issuing a cookie if needed.

        The nonce lives in an HttpOnly cookie (``vnc_csrf``); the
        matching token â€” HMAC(secret, 'csrf:' + nonce) â€” is exposed to
        pages via a meta tag / the /api/v1/me payload, and mutations
        must present it as X-CSRF-Token or a 'csrf' form field.
        Revoking/rotating the cookie invalidates every token minted
        for it, and two sessions of the same user hold different
        tokens.
        """
        nonce = cookie_value(self.headers.get('Cookie', ''), 'vnc_csrf')
        if nonce and 16 <= len(nonce) <= 128 \
                and all(c.isalnum() or c in '-_' for c in nonce):
            return nonce
        # Reuse the nonce already minted for THIS response â€” calling
        # twice (e.g. /me emits the token, end_headers emits the
        # cookie) must agree on one value.
        pending = getattr(self, '_pending_csrf_nonce', None)
        if pending:
            return pending
        import secrets
        nonce = secrets.token_urlsafe(32)
        self._pending_csrf_nonce = nonce
        self._queue_cookie(
            f'vnc_csrf={nonce}; HttpOnly; Path=/; SameSite=Strict')
        return nonce

    def _csrf_token(self) -> str:
        """The token a mutation must present for this session â€”
        bound to BOTH the operator session id and the CSRF nonce, so a
        copied nonce cookie alone cannot mint a usable token."""
        from vnc_remote_secure.backend.api import _csrf_token
        return _csrf_token(getattr(self, '_portal_sid', ''),
                           self._csrf_nonce())

    def _check_csrf(self) -> bool:
        """Verify the CSRF token on a mutating request.

        The expected token is HMAC(secret, 'csrf:' + <vnc_csrf nonce>),
        presented via the X-CSRF-Token header. SameSite=Strict on the
        nonce cookie plus this token are two CSRF layers; Origin and
        Sec-Fetch-Site are checked separately in _operator_gate.
        """
        import hmac as _hmac

        from vnc_remote_secure.backend.api import _csrf_token
        nonce = cookie_value(self.headers.get('Cookie', ''), 'vnc_csrf')
        sid = getattr(self, '_portal_sid', '')
        if not nonce or not sid:
            return False
        presented = self.headers.get('X-CSRF-Token', '')
        if not presented:
            return False
        return _hmac.compare_digest(presented, _csrf_token(sid, nonce))

    def end_headers(self):  # noqa: N802 - stdlib API
        # Deliver queued cookies (vnc_op session, vnc_csrf nonce,
        # logout expirations) exactly once per response â€” emitting
        # here covers every code path without per-handler plumbing.
        cookies = self.__dict__.pop('_pending_cookies', None) or []
        if cookies:
            import ssl as _ssl
            trusted = env_flag('TRUSTED_PROXY', 'false')
            is_tls = ((trusted and
                       self.headers.get('X-Forwarded-Proto', '') == 'https')
                      or isinstance(self.connection, _ssl.SSLSocket))
            for cookie in cookies:
                if is_tls and ' Secure' not in cookie:
                    cookie = cookie.replace('; HttpOnly', '; Secure; HttpOnly', 1)
                self.send_header('Set-Cookie', cookie)
        super().end_headers()

    def _require_portal_auth(self) -> bool:
        """Ephemeral cookie or operator Basic-auth gate; sends 401."""
        authed, operator = self._portal_identity()
        if not authed:
            self.send_json_error('Unauthorized', 401, www_authenticate='Basic realm="VNC Portal"')
            return False
        self._portal_operator = operator
        return True

    def do_HEAD(self):  # noqa: N802 - stdlib API
        """Serve HEAD requests through the same auth gate as GET."""
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(self.headers):
            self.send_response(400)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        # HEAD must run the same gate â€” otherwise SimpleHTTPRequestHandler
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
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(self.headers):
            self.send_json_error('Ambiguous request framing', 400)
            return
        # Ephemeral share links exchange the signed token for a cookie
        # before any auth check (the link itself is the credential).
        if self._handle_session_exchange():
            return
        # Fragment-carried share links (â€¦/share#t=<token>) keep the
        # token out of the URL entirely â€” the page is public and its
        # JS POSTs the token to /session/activate. The script is
        # self-hosted at /share.js so the CSP needs no unsafe-inline.
        _share_path = self.path.split('?', 1)[0]
        if _share_path == '/share':
            self._serve_share_page()
            return
        if _share_path == '/share.js':
            self.send_response(200)
            self.send_header('Content-Type',
                             'text/javascript; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Length', str(len(_SHARE_JS)))
            self.end_headers()
            self.wfile.write(_SHARE_JS)
            return
        # Ephemeral share sessions or operator Basic-auth (env
        # bootstrap admin or a stored operator account â€” fail closed
        # either way). client_ip feeds the shared auth rate limiter
        # so Basic-auth brute force is locked out like the
        # gateway-protected paths.
        authed, operator = self._portal_identity()
        if not authed:
            self.send_json_error('Unauthorized', 401, www_authenticate='Basic realm="VNC Portal"')
            return
        self._portal_operator = operator
        # Strip the query string for routing: /status.json?ts=â€¦ must
        # resolve like the bare path (the Flask blueprint and nginx
        # both match path-only).
        path = self.path.split('?', 1)[0]
        if path == '/' or path == '/index.html':
            self._serve_landing()
        elif path == '/status.json':
            self._serve_status_json()
        elif path == '/sessions.json':
            self._serve_sessions_json()
        elif path == '/audio_receiver.html':
            self._serve_template('audio_receiver.html')
        elif path == '/gamepad.html':
            self._serve_template('gamepad.html')
        elif path == '/admin' or path.startswith('/admin/'):
            self._serve_admin(path)
        elif is_api_path(path):
            self._serve_api_get(path)
        else:
            self.send_json_error('Not found', 404)

    def _serve_api_get(self, path: str) -> None:
        """Dispatch a GET under /api/v1/ to the api_v1 module."""
        from urllib.parse import parse_qs, urlparse

        from vnc_remote_secure.backend.api import handle_get
        query = parse_qs(urlparse(self.path).query)
        try:
            if not handle_get(self, path, query):
                self.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001 - never take the portal down
            log_exception(e, 'api GET')
            self.send_json_error('Internal error', 500)

    _ADMIN_DIR = os.path.normpath(os.path.join(
        os.path.dirname(__file__), '..', 'web', 'static', 'admin'))
    _ADMIN_TYPES = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'text/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.map': 'application/json',
        '.json': 'application/json',
        '.svg': 'image/svg+xml',
        '.png': 'image/png',
        '.ico': 'image/x-icon',
        '.woff': 'font/woff',
        '.woff2': 'font/woff2',
    }

    def _serve_admin(self, path: str) -> None:
        """Serve the React admin SPA (operator-only).

        Static assets live in ``web/static/admin`` (the Vite build
        output). Paths without a file extension fall back to
        index.html so client-side routing works on reload. Ephemeral
        share-link sessions get 403 â€” the admin surface is
        operator-only.
        """
        if self._portal_operator is None:
            self.send_json_error('Operator access required', 403)
            return
        rel = path[len('/admin'):].lstrip('/') or 'index.html'
        # SPA fallback: extensionless client routes serve index.html.
        if '.' not in os.path.basename(rel):
            rel = 'index.html'
        # Path traversal: resolve and require containment.
        full = os.path.normpath(os.path.join(self._ADMIN_DIR, rel))
        if not full.startswith(self._ADMIN_DIR + os.sep) and \
                full != self._ADMIN_DIR:
            self.send_json_error('Not found', 404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = self._ADMIN_TYPES.get(ext)
        if ctype is None or not os.path.isfile(full):
            self.send_json_error('Not found', 404)
            return
        try:
            with open(full, 'rb') as f:
                body = f.read()
        except OSError:
            self.send_json_error('Not found', 404)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        # HTML is the SPA shell â€” never cache it so a new deploy is
        # picked up; hashed assets may be cached safely.
        if ext == '.html':
            self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _session_refresh_header(self):
        """Return a ``Set-Cookie`` value refreshing the session cookie.

        Re-issues ``vnc_session`` with an updated ``last_seen`` claim so
        SESSION_IDLE_TIMEOUT measures real inactivity. Returns ``None``
        when there is no session cookie or no refresh is due.
        """
        try:
            raw = cookie_value(
                self.headers.get('Cookie', ''), 'vnc_session')
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
            trusted = env_flag('TRUSTED_PROXY', 'false')
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
            # proxy â€” a direct client can spoof these headers and the
            # portal would render links pointing at the attacker's
            # host. Same TRUSTED_PROXY gate as client_ip_from().
            trusted = env_flag('TRUSTED_PROXY', 'false')
            content = generate_landing_page(
                forwarded_host=(
                    self.headers.get('X-Forwarded-Host') if trusted else None),
                forwarded_proto=(
                    self.headers.get('X-Forwarded-Proto') if trusted else None),
                is_operator=getattr(
                    self, '_portal_operator', None) is not None,
                csrf_token=(self._csrf_token()
                            if getattr(self, '_portal_operator', None)
                            else ''))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            refresh = self._session_refresh_header()
            if refresh:
                self.send_header('Set-Cookie', refresh)
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            log_exception(e, 'Landing _serve_landing')
            self.send_json_error('Failed to render landing page', 500)

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
            # values land verbatim in the page â€” coerce to int so a
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
            trusted = env_flag('TRUSTED_PROXY', 'false')
            fhost = self.headers.get('X-Forwarded-Host', '').split(',')[0].strip()
            fproto = self.headers.get('X-Forwarded-Proto', '').split(',')[0].strip()
            # The Host values land verbatim inside a JS string literal in
            # the rendered page â€” a crafted Host/X-Forwarded-Host header
            # containing quotes or markup would be reflected XSS on an
            # authenticated endpoint. Constrain to a strict hostname
            # character set and fall back to loopback on anything else.
            fhost = _safe_ws_host(fhost)
            if trusted and fhost != '127.0.0.1' and self.headers.get(
                    'X-Forwarded-Host'):
                ws_scheme = 'wss' if fproto == 'https' else 'ws'
                audio_ws_url = f'{ws_scheme}://{fhost}/audio/'
                gamepad_ws_url = f'{ws_scheme}://{fhost}/gamepad/'
            else:
                import ssl as _ssl
                ws_scheme = ('wss' if isinstance(self.connection, _ssl.SSLSocket)
                             else 'ws')
                host = _safe_ws_host(
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
            self.send_json_error(f'Failed to serve template {template_name}', 500)

    def _status_payload(self) -> dict:
        """Build the service-status payload shared by /status.json and
        the /api/v1/status endpoint."""
        # On Linux TigerVNC binds 5900+N regardless of an explicit
        # VNC_PORT â€” probe the real RFB port (same derivation as
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
                # UltraVNC's built-in HTTP dir is Windows-only â€”
                # on Linux nothing ever listens there and the card
                # would permanently show a spurious "down" state.
                {'ultravnc_http': check_port(cfg['vnc_http_port'])}
                if os.name == 'nt' else {}
            ),
            # Microphone privacy indicator: true while ffmpeg is
            # capturing (shared-state flag, self-clearing TTL).
            'audio_capture': _audio_capture_active(),
            # Credentials are NOT exposed in JSON for security
        }
        # Internal topology + LAN IPs + resource usage are
        # operator-grade telemetry. An ephemeral view-only link
        # holder gets service states only â€” enough for the portal
        # cards, not enough to map the host.
        if getattr(self, '_portal_operator', None) is not None:
            data['lan_ips'] = get_lan_ips()
            data['system'] = get_system_metrics()
        return data

    def _serve_status_json(self):
        try:
            self.send_json(self._status_payload(), 200, indent=2)
        except Exception as e:
            log_exception(e, 'Landing _serve_status_json')
            self.send_json_error('Failed to build status JSON', 500)

    def _serve_api_post(self, path: str) -> None:
        """Dispatch a POST under /api/v1/ to the api_v1 module."""
        from vnc_remote_secure.backend.api import handle_post
        try:
            if not handle_post(self, path):
                self.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001 - never take the portal down
            log_exception(e, 'api POST')
            self.send_json_error('Internal error', 500)

    def _serve_api_mutation(self, method: str) -> None:
        """PATCH/DELETE reach only /api/v1/* â€” anything else is 404.
        Body framing is validated before the dispatcher runs."""
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(self.headers):
            self.send_json_error('Ambiguous request framing', 400)
            return
        path = self.path.split('?', 1)[0]
        if not is_api_path(path):
            self.send_json_error('Not found', 404)
            return
        from vnc_remote_secure.backend.api import _dispatch
        try:
            if not _dispatch(self, method, path, {}):
                self.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001
            log_exception(e, f'api {method}')
            self.send_json_error('Internal error', 500)

    def do_PATCH(self):  # noqa: N802 - stdlib API
        self._serve_api_mutation('PATCH')

    def do_DELETE(self):  # noqa: N802 - stdlib API
        self._serve_api_mutation('DELETE')

    def _serve_sessions_json(self):
        """List active ephemeral sessions â€” operator-only.

        The outer auth gate lets activated ephemeral cookies reach
        portal routes; enumerating OTHER people's sessions is an
        operator privilege, so this endpoint re-checks the landing
        Basic credential itself (stateless, no session required).
        Session data comes from to_dict() â€” token fingerprints and
        metadata only, never raw tokens or passwords.
        """
        from vnc_remote_secure.security.http_auth import authenticate_landing
        ok, operator = authenticate_landing(
            self.headers.get('Authorization', ''),
            client_ip=client_ip_from(
                self.headers,
                self.peer_ip()))
        perms = set((operator or {}).get('permissions') or [])
        if not ok or (
                'admin_sessions' not in perms
                and 'admin:*' not in perms):
            self.send_json_error('Operator credentials required' if not ok else 'Insufficient role for this action', 401 if not ok else 403, www_authenticate='Basic realm="VNC Portal"')
            return
        try:
            from vnc_remote_secure.security.ephemeral_sessions import get_session_store
            store = get_session_store()
            store._load_if_changed()
            self.send_json({'sessions': store.list_active()}, 200, indent=2)
        except Exception as e:
            log_exception(e, 'Landing _serve_sessions_json')
            self.send_json_error('Failed to list sessions', 500)

    def do_POST(self):
        """Handle POST â€” only /sessions/revoke is mutating.

        Basic auth travels automatically in the browser, so the
        endpoint is CSRF-able in principle: reject requests whose
        Origin header is present but not in the allowlist (cross-site
        forms always send Origin; curl/API clients legitimately omit
        it).
        """
        from vnc_remote_secure.security.http_auth import request_headers_safe
        if not request_headers_safe(self.headers):
            # Ambiguous body framing (Transfer-Encoding or duplicate
            # Content-Length) â€” reject before touching the body.
            self.send_json_error('Ambiguous request framing', 400)
            return
        path = self.path.split('?', 1)[0]
        # Share-link preview + activation: the token is the credential,
        # so both routes precede the operator-gated mutations.
        if path == '/session/preview':
            self._post_session_preview()
            return
        if path == '/session/activate':
            self._post_session_activate()
            return
        if is_api_path(path):
            self._serve_api_post(path)
            return
        if path == '/sessions/revoke-all':
            self._post_revoke_all()
            return
        if path in ('/gamepad/stop', '/gamepad/resume'):
            self._post_gamepad_control(path.endswith('/stop'))
            return
        if path != '/sessions/revoke':
            self.send_json_error('Not found', 404)
            return

        operator = self._operator_gate('admin_sessions')
        if operator is None:
            return

        # Bounded body read: Content-Length beyond 4 KiB is not a
        # revoke request, it is padding â€” reject before reading.
        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        if not 0 < length <= 4096:
            self.send_json_error('Bad request', 400)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            payload = {}
        token_id = str(payload.get('token_id', '')).strip()
        if not token_id:
            self.send_json_error('token_id required', 400)
            return

        from vnc_remote_secure.security.ephemeral_sessions import revoke_session
        revoked = revoke_session(token_id)
        from vnc_remote_secure.security.audit import audit_event
        audit_event(
            'portal_session_revoke',
            user=operator.get('username', 'unknown'),
            result='success' if revoked else 'failure',
            detail=f'token_id={token_id}')
        # Uniform response whether the token existed or not â€” the
        # caller is already authorized; a 404 here would only help
        # enumerate live session ids.
        self.send_json({'revoked': bool(revoked)}, 200)

    def _operator_gate(self, permission):
        """Authenticate and authorize a mutating endpoint call.

        Runs operator auth (env bootstrap or operator store), the
        Origin check, and the per-role permission check. Returns the
        operator dict ``{'username', 'role', 'permissions'}`` on
        success; on failure it has already written the error response
        (401/403) and returns ``None``.
        """
        ok, operator = self._resolve_operator()
        if not ok:
            self.send_json_error('Operator credentials required', 401, www_authenticate='Basic realm="VNC Portal"')
            return None

        from vnc_remote_secure.security.auth_gateway import check_origin, get_allowed_origins
        origin = self.headers.get('Origin', '')
        if origin and not check_origin(origin, get_allowed_origins()):
            self.send_json_error('Invalid origin', 403)
            return None

        # Fetch Metadata CSRF defense-in-depth: browsers mark every
        # cross-site-initiated request with ``Sec-Fetch-Site:
        # cross-site`` â€” a forbidden header a malicious page cannot
        # strip or forge. It protects the case where Origin is absent
        # (some form posts, redirects). Non-browser clients (curl,
        # scripts) never send it, so automation is unaffected.
        if self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
            self.send_json_error('Cross-site request rejected', 403)
            return None

        # CSRF token bound to the vnc_csrf nonce cookie â€” required on
        # every mutation (portal legacy POSTs and /api/v1 alike).
        if not self._check_csrf():
            self.send_json_error('CSRF token missing or invalid', 403)
            return None

        perms = set(operator.get('permissions') or [])
        if permission and permission not in perms \
                and 'admin:*' not in perms:
            from vnc_remote_secure.security.audit import audit_event
            audit_event('portal_permission_denied',
                      user=operator.get('username', '?'),
                      detail=f'required={permission}')
            self.send_json_error('Insufficient role for this action', 403)
            return None
        return operator

    def _post_revoke_all(self):
        """POST /sessions/revoke-all â€” emergency kill-switch.

        Revokes every active ephemeral session in one call; live
        WebSockets close via shared-state propagation. Operator-only
        with the same Origin check as the single-revoke endpoint.
        """
        operator = self._operator_gate('admin_sessions')
        if operator is None:
            return
        from vnc_remote_secure.security.ephemeral_sessions import get_session_store, revoke_session
        store = get_session_store()
        store._load_if_changed()
        count = 0
        for s in list(store.list_active()):
            if revoke_session(s['token_id']):
                count += 1
        from vnc_remote_secure.security.audit import audit_event
        audit_event('portal_session_revoke_all',
                  user=operator.get('username', 'unknown'),
                  detail=f'count={count}')
        self.send_json({'revoked': count}, 200)

    def _post_gamepad_control(self, stop: bool):
        """POST /gamepad/{stop,resume} â€” local kill-switch.

        Sets/clears the shared ``gamepad:stopped`` flag that the
        gamepad service checks per-connection and per-message â€” the
        operator at the machine can cut remote control injection even
        while a session holds it. Same operator-auth + Origin gate as
        the session endpoints.
        """
        operator = self._operator_gate('admin_sessions')
        if operator is None:
            return
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            if stop:
                get_backend().set_ttl('gamepad', 'stopped', '1',
                                      86400 * 365)
            else:
                get_backend().delete('gamepad', 'stopped')
        except Exception as e:  # noqa: BLE001
            self.send_json({'error': str(e)}, 500)
            return
        from vnc_remote_secure.security.audit import audit_event
        audit_event(
            'portal_gamepad_' + ('stop' if stop else 'resume'),
            user=operator.get('username', 'unknown'))
        self.send_json({'gamepad_stopped': stop}, 200)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # pylint: disable=redefined-builtin
        """Log message."""
        # Route stdlib access logs to the module logger instead of
        # discarding â€” but NEVER verbatim: the request line carries
        # the share-link token (``GET /?session=<signed>``), which
        # would otherwise sit replayable in landing.log.
        import re as _re
        line = _re.sub(r'session=[^&\s"]+', 'session=<redacted>',
                       format % args)
        logger.info("%s - %s", self.peer_ip(), line)


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
