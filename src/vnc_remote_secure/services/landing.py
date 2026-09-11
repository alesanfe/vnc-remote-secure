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
import os
import sys
import ssl
import json
import socket
import platform
import subprocess
import urllib.request
import re
import html
import base64
import hmac
from datetime import datetime

import http.server
import socketserver

# Load configuration from .env file (never hardcode credentials)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vnc_remote_secure.core.config import load_env_file

load_env_file()

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

PORT = int(os.environ.get('LANDING_PORT', '8000'))
HOST = os.environ.get('LANDING_HOST', '0.0.0.0')
CERT_FILE = os.environ.get('SSL_CERT', '')
KEY_FILE = os.environ.get('SSL_KEY', '')

VNC_PORT = int(os.environ.get('VNC_PORT', '5900'))
NOVNC_PORT = int(os.environ.get('NOVNC_PORT', '6080'))
TTYD_PORT = int(os.environ.get('TTYD_PORT', '5000'))
HEALTH_PORT = int(os.environ.get('HEALTH_WEB_PORT', '8090'))
VNC_HTTP_PORT = 5800

# Credentials are read from env but NOT displayed on the page
# They are only used internally, never exposed in HTML or JSON
VNC_PASSWORD = os.environ.get('VNC_PASSWORD', '')
TTYD_USERNAME = os.environ.get('TTYD_USERNAME', 'admin')
TTYD_PASSWORD = os.environ.get('TTYD_PASSWD', '')

# Optional auth for the landing page itself (set LANDING_PASSWORD to enable)
LANDING_PASSWORD = os.environ.get('LANDING_PASSWORD', '')


def check_port(port):
    """Check if a port is listening."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex(('localhost', port))
        s.close()
        return result == 0
    except Exception:
        return False


def get_lan_ips():
    """Get all LAN IP addresses."""
    ips = []
    try:
        result = subprocess.run(
            ['ipconfig'] if platform.system() == 'Windows' else ['ip', 'addr'],
            capture_output=True, text=True, timeout=10, check=False
        )
        if platform.system() == 'Windows':
            for line in result.stdout.split('\n'):
                if 'IPv4' in line:
                    ip = line.split(':')[-1].strip()
                    if ip and not ip.startswith('169.254'):
                        ips.append(ip)
        else:
            # Linux: parse 'ip addr' output correctly
            # Lines look like: "    inet 192.168.1.100/24 brd ..."
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    for part in parts:
                        if part.startswith('inet ') or part == 'inet':
                            continue
                        if part.startswith('inet') and '/' in part:
                            ip = part.split('/')[0].replace('inet', '').strip()
                            if ip and not ip.startswith('127'):
                                ips.append(ip)
                        elif part.startswith('inet') and '/' not in part:
                            # 'inet' is separate from the IP, find next token
                            idx = parts.index(part)
                            if idx + 1 < len(parts):
                                ip = parts[idx + 1].split('/')[0]
                                if ip and not ip.startswith('127'):
                                    ips.append(ip)
    except Exception:
        pass
    return ips


def get_system_metrics():
    """Get quick system metrics for the landing page."""
    metrics = {
        'cpu': 'N/A', 'memory': 'N/A', 'disk': 'N/A',
        'uptime': 'N/A', 'hostname': platform.node(),
        'os': f'{platform.system()} {platform.release()}',
    }

    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'loadpercentage', '/value'],
                capture_output=True, text=True, timeout=5, check=False
            )
            match = re.search(r'LoadPercentage=(\d+)', result.stdout)
            if match:
                metrics['cpu'] = f"{match.group(1)}%"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/value'],
                capture_output=True, text=True, timeout=5, check=False
            )
            total_match = re.search(r'TotalVisibleMemorySize=(\d+)', result.stdout)
            free_match = re.search(r'FreePhysicalMemory=(\d+)', result.stdout)
            if total_match and free_match:
                total_kb = int(total_match.group(1))
                free_kb = int(free_match.group(1))
                used_kb = total_kb - free_kb
                pct = (used_kb / total_kb) * 100 if total_kb > 0 else 0
                metrics['memory'] = f"{pct:.0f}% ({used_kb // 1024} MB / {total_kb // 1024} MB)"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'size,freespace,caption', '/value'],
                capture_output=True, text=True, timeout=5, check=False
            )
            current = {}
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    key, val = key.strip(), val.strip()
                    if key == 'Caption':
                        if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
                            size_gb = int(current['Size']) / (1024**3)
                            free_gb = int(current['FreeSpace']) / (1024**3)
                            pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
                            if metrics['disk'] == 'N/A':
                                metrics['disk'] = f"{current['Caption']} {pct:.0f}% ({free_gb:.0f} GB free)"
                        current = {'Caption': val}
                    elif key == 'Size':
                        try: current['Size'] = int(val)
                        except ValueError: pass
                    elif key == 'FreeSpace':
                        try: current['FreeSpace'] = int(val)
                        except ValueError: pass
            if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
                size_gb = int(current['Size']) / (1024**3)
                free_gb = int(current['FreeSpace']) / (1024**3)
                pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
                if metrics['disk'] == 'N/A':
                    metrics['disk'] = f"{current['Caption']} {pct:.0f}% ({free_gb:.0f} GB free)"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['wmic', 'os', 'get', 'LastBootUpTime', '/value'],
                capture_output=True, text=True, timeout=5, check=False
            )
            match = re.search(r'LastBootUpTime=(.+)', result.stdout)
            if match:
                boot_str = match.group(1).strip()
                if '.' in boot_str:
                    boot_dt = datetime.strptime(boot_str.split('.')[0], '%Y%m%d%H%M%S')
                    delta = datetime.now() - boot_dt
                    hours = int(delta.total_seconds() // 3600)
                    minutes = int((delta.total_seconds() % 3600) // 60)
                    metrics['uptime'] = f"{hours}h {minutes}m"
        except Exception:
            pass
    else:
        # Linux
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_sec = float(f.readline().split()[0])
                hours = int(uptime_sec // 3600)
                minutes = int((uptime_sec % 3600) // 60)
                metrics['uptime'] = f"{hours}h {minutes}m"
        except Exception:
            pass
        try:
            with open('/proc/loadavg', 'r') as f:
                metrics['cpu'] = f"Load: {f.readline().split()[0]}"
        except Exception:
            pass
        # Linux memory (was missing)
        try:
            result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if line.startswith('Mem:'):
                    parts = line.split()
                    total = int(parts[1])
                    used = int(parts[2])
                    pct = (used / total) * 100 if total > 0 else 0
                    metrics['memory'] = f"{pct:.0f}% ({used} MB / {total} MB)"
                    break
        except Exception:
            pass
        # Linux disk
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                metrics['disk'] = f"/ {parts[4]} ({parts[3]} used)" if len(parts) > 4 else 'N/A'
        except Exception:
            pass

    return metrics


def generate_landing_page():
    """Generate the landing page HTML."""
    lan_ips = get_lan_ips()
    use_ssl = bool(CERT_FILE and os.path.exists(CERT_FILE))
    protocol = 'https' if use_ssl else 'http'
    metrics = get_system_metrics()

    # All services with detailed info
    services = [
        {
            'name': 'VNC Desktop (noVNC)',
            'desc': 'Escritorio Windows completo en el navegador. Controla el ratón y teclado desde cualquier dispositivo.',
            'features': ['Mouse y teclado completos', 'Portapapeles', 'Multi-monitor', 'Escalado automático'],
            'icon': '🖥️',
            'url': f'{protocol}://localhost:{NOVNC_PORT}/vnc.html',
            'port': NOVNC_PORT,
            'running': check_port(NOVNC_PORT),
            'color': '#4caf50',
            'category': 'remote-desktop',
        },
        {
            'name': 'Web Terminal',
            'desc': 'Terminal de comandos (cmd.exe) en el navegador. Ejecuta comandos de Windows remotamente.',
            'features': ['Historial de comandos', 'Tab completion', 'Ctrl+C interrupt', 'Colores ANSI'],
            'icon': '⌨️',
            'url': f'{protocol}://localhost:{TTYD_PORT}/',
            'port': TTYD_PORT,
            'running': check_port(TTYD_PORT),
            'color': '#2196f3',
            'category': 'terminal',
        },
        {
            'name': 'Health Dashboard',
            'desc': 'Panel de monitorización con estado de servicios, CPU, memoria, disco y red.',
            'features': ['Estado por servicio', 'CPU/RAM/Disco', 'API JSON', 'Auto-refresh 30s'],
            'icon': '📊',
            'url': f'http://localhost:{HEALTH_PORT}/health_status',
            'url2': f'http://localhost:{HEALTH_PORT}/health_status.json',
            'url2_label': 'API JSON',
            'port': HEALTH_PORT,
            'running': check_port(HEALTH_PORT),
            'color': '#ff9800',
            'category': 'monitoring',
        },
        {
            'name': 'UltraVNC HTTP Viewer',
            'desc': 'Visor VNC Java legacy de UltraVNC. Alternativa al noVNC moderno.',
            'features': ['Java applet', 'Conexión directa', 'Legacy support'],
            'icon': '🔌',
            'url': f'http://localhost:{VNC_HTTP_PORT}/',
            'port': VNC_HTTP_PORT,
            'running': check_port(VNC_HTTP_PORT),
            'color': '#9c27b0',
            'category': 'remote-desktop',
        },
    ]

    # Direct VNC connection (not a web service, but useful info)
    vnc_rfb_running = check_port(VNC_PORT)

    # Build service cards
    cards_html = ''
    for svc in services:
        status_text = 'ONLINE' if svc['running'] else 'OFFLINE'
        status_color = '#4caf50' if svc['running'] else '#f44336'
        disabled = '' if svc['running'] else 'disabled'
        opacity = '1' if svc['running'] else '0.5'

        features_html = ''
        for feat in svc.get('features', []):
            features_html += f'<span class="feature-tag">{feat}</span>'

        extra_link = ''
        if svc.get('url2'):
            label = svc.get('url2_label', 'Link')
            extra_link = f'<a href="{svc["url2"]}" target="_blank" class="btn-sm {disabled}">{label}</a>'

        cards_html += f"""
        <div class="service-card {status_text.lower()}" style="opacity:{opacity}">
            <div class="service-icon">{svc['icon']}</div>
            <div class="service-info">
                <h3>{svc['name']}</h3>
                <p>{svc['desc']}</p>
                <div class="features">{features_html}</div>
                <span class="service-port">Port {svc['port']}</span>
            </div>
            <div class="service-action">
                <span class="status-badge" style="background:{status_color}">{status_text}</span>
                <a href="{svc['url']}" target="_blank" class="btn {disabled}">Abrir</a>
                {extra_link}
            </div>
        </div>"""

    # Direct VNC connection info card
    vnc_direct_status = 'ONLINE' if vnc_rfb_running else 'OFFLINE'
    vnc_direct_color = '#4caf50' if vnc_rfb_running else '#f44336'
    vnc_direct_opacity = '1' if vnc_rfb_running else '0.5'
    vnc_direct_html = f"""
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
            <span class="service-port">Port {VNC_PORT}</span>
        </div>
        <div class="service-action">
            <span class="status-badge" style="background:{vnc_direct_color}">{vnc_direct_status}</span>
            <div class="connection-info">
                <code>{lan_ips[0] if lan_ips else 'localhost'}:{VNC_PORT}</code>
            </div>
        </div>
    </div>"""

    # System metrics bar
    metrics_html = f"""
    <div class="metrics-bar">
        <div class="metric-item">
            <span class="metric-icon">💻</span>
            <span class="metric-label">Host</span>
            <span class="metric-value">{metrics['hostname']}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">🖥️</span>
            <span class="metric-label">OS</span>
            <span class="metric-value">{metrics['os']}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">⏱️</span>
            <span class="metric-label">Uptime</span>
            <span class="metric-value">{metrics['uptime']}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">📊</span>
            <span class="metric-label">CPU</span>
            <span class="metric-value">{metrics['cpu']}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">💾</span>
            <span class="metric-label">RAM</span>
            <span class="metric-value">{metrics['memory']}</span>
        </div>
        <div class="metric-item">
            <span class="metric-icon">💿</span>
            <span class="metric-label">Disco</span>
            <span class="metric-value">{metrics['disk']}</span>
        </div>
    </div>"""

    # Build LAN access section
    lan_html = ''
    if lan_ips:
        lan_html = '<div class="lan-section"><h2>🌐 Acceso Remoto (LAN)</h2><p class="section-desc">Conecta desde otro dispositivo en la misma red:</p>'
        for ip in lan_ips:
            lan_html += f"""
            <div class="ip-card">
                <div class="ip-address">{ip}</div>
                <div class="ip-links">
                    <a href="{protocol}://{ip}:{NOVNC_PORT}/vnc.html">🖥️ VNC Desktop</a>
                    <a href="{protocol}://{ip}:{TTYD_PORT}/">⌨️ Terminal</a>
                    <a href="http://{ip}:{HEALTH_PORT}/health_status">📊 Health</a>
                    <a href="{protocol}://{ip}:{PORT}">🏠 Portal</a>
                </div>
            </div>"""
        lan_html += '</div>'

    # Credentials section - NOT showing actual passwords for security
    # Users must check the launcher output or .env file
    creds_html = """
    <div class="credentials">
        <h2>🔐 Credenciales de Acceso</h2>
        <p class="section-desc">Por seguridad, las credenciales no se muestran en esta página.
        Revise la salida del launcher o el archivo <code>.env</code>.</p>
        <div class="cred-grid">
            <div class="cred-item">
                <span class="cred-icon">🖥️</span>
                <div class="cred-content">
                    <span class="cred-label">VNC Desktop (noVNC y RFB)</span>
                    <span class="cred-value">Password: <code>••••••••</code> (ver launcher)</span>
                    <span class="cred-note">VNC usa los primeros 8 caracteres del password</span>
                </div>
            </div>
            <div class="cred-item">
                <span class="cred-icon">⌨️</span>
                <div class="cred-content">
                    <span class="cred-label">Web Terminal</span>
                    <span class="cred-value">Usuario y password: ver launcher o <code>.env</code></span>
                </div>
            </div>
        </div>
    </div>"""

    # What you can do section
    features_section = """
    <div class="features-section">
        <h2>✨ ¿Qué puedes hacer?</h2>
        <div class="feature-cards">
            <div class="feature-card">
                <span class="feature-icon">🖥️</span>
                <h3>Control remoto del escritorio</h3>
                <p>Accede al escritorio Windows completo desde cualquier navegador. Mueve el ratón, escribe con el teclado, abre aplicaciones.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">⌨️</span>
                <h3>Terminal remoto</h3>
                <p>Ejecuta comandos de Windows (cmd.exe) desde el navegador. Historial, tab completion y colores ANSI.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">📊</span>
                <h3>Monitorización</h3>
                <p>Consulta el estado de todos los servicios, CPU, memoria, disco y uptime en tiempo real.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">📡</span>
                <h3>VNC nativo</h3>
                <p>Conecta con apps VNC externas (TigerVNC, RealVNC) directamente al puerto 5900 sin navegador.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">🔒</span>
                <h3>Conexión cifrada</h3>
                <p>Todos los servicios web usan HTTPS con certificado SSL (self-signed). Acepta la advertencia del navegador.</p>
            </div>
            <div class="feature-card">
                <span class="feature-icon">🌐</span>
                <h3>Acceso LAN</h3>
                <p>Conecta desde cualquier dispositivo en tu red local: móvil, tablet, otro PC, etc.</p>
            </div>
        </div>
    </div>"""

    # Firewall note
    firewall_html = ''
    if platform.system() == 'Windows':
        firewall_html = """
        <div class="notice">
            <strong>⚠️ Firewall de Windows:</strong> Para acceso remoto, ejecuta como administrador:
            <code>New-NetFirewallRule -DisplayName "VNC Remote" -Direction Inbound -LocalPort 5000,6080,8090,5900,5800,8000 -Protocol TCP -Action Allow</code>
        </div>"""

    ssl_note = ''
    if use_ssl:
        ssl_note = """
        <div class="notice">
            <strong>🔒 SSL Self-signed:</strong> El navegador mostrará una advertencia de seguridad.
            Click en "Advanced" → "Proceed" para aceptar el certificado en cada servicio HTTPS.
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>VNC Remote Secure - Portal</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: #e0e0e0; font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh; padding: 20px;
        }}
        .header {{ text-align: center; padding: 30px 0; }}
        .header h1 {{
            font-size: 36px; color: #fff; margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(100, 181, 246, 0.5);
        }}
        .header p {{ color: #aaa; font-size: 16px; }}
        .metrics-bar {{
            max-width: 900px; margin: 20px auto;
            display: flex; flex-wrap: wrap; gap: 10px; justify-content: center;
            background: rgba(255,255,255,0.05); border-radius: 12px; padding: 15px;
        }}
        .metric-item {{
            display: flex; flex-direction: column; align-items: center;
            padding: 8px 16px; min-width: 100px;
        }}
        .metric-icon {{ font-size: 20px; margin-bottom: 4px; }}
        .metric-label {{ font-size: 11px; color: #888; text-transform: uppercase; }}
        .metric-value {{ font-size: 14px; color: #64b5f6; font-family: monospace; margin-top: 2px; }}
        .section-title {{
            max-width: 900px; margin: 30px auto 15px;
            color: #fff; font-size: 22px;
        }}
        .section-desc {{ color: #aaa; font-size: 14px; margin-bottom: 15px; }}
        .services {{
            max-width: 900px; margin: 15px auto;
            display: grid; gap: 15px;
        }}
        .service-card {{
            background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px; padding: 20px; display: flex;
            align-items: center; gap: 20px; transition: all 0.3s;
        }}
        .service-card:hover {{
            background: rgba(255,255,255,0.08); border-color: rgba(100,181,246,0.3);
            transform: translateX(5px);
        }}
        .service-card.info-card {{ border-color: rgba(156,39,176,0.3); }}
        .service-icon {{ font-size: 40px; flex-shrink: 0; }}
        .service-info {{ flex: 1; }}
        .service-info h3 {{ color: #fff; font-size: 18px; margin-bottom: 5px; }}
        .service-info p {{ color: #aaa; font-size: 14px; margin-bottom: 8px; }}
        .features {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }}
        .feature-tag {{
            font-size: 11px; color: #90caf9; background: rgba(33,150,243,0.1);
            padding: 2px 8px; border-radius: 10px; border: 1px solid rgba(33,150,243,0.2);
        }}
        .service-port {{
            font-size: 12px; color: #666; background: rgba(255,255,255,0.05);
            padding: 2px 8px; border-radius: 4px;
        }}
        .service-action {{ display: flex; flex-direction: column; gap: 8px; align-items: flex-end; flex-shrink: 0; }}
        .status-badge {{
            font-size: 11px; font-weight: bold; padding: 3px 10px;
            border-radius: 12px; color: #fff;
        }}
        .btn {{
            display: inline-block; padding: 8px 24px; background: #2196f3;
            color: #fff; text-decoration: none; border-radius: 6px;
            font-size: 14px; font-weight: 600; transition: background 0.3s;
        }}
        .btn:hover {{ background: #1976d2; }}
        .btn.disabled {{ background: #555; pointer-events: none; opacity: 0.5; }}
        .btn-sm {{
            display: inline-block; padding: 4px 12px; background: #607d8b;
            color: #fff; text-decoration: none; border-radius: 4px;
            font-size: 12px; transition: background 0.3s;
        }}
        .btn-sm:hover {{ background: #455a64; }}
        .btn-sm.disabled {{ background: #555; pointer-events: none; opacity: 0.5; }}
        .connection-info {{ margin-top: 5px; }}
        .connection-info code {{
            background: rgba(0,0,0,0.3); padding: 4px 10px; border-radius: 4px;
            color: #64b5f6; font-size: 13px;
        }}
        .features-section {{
            max-width: 900px; margin: 30px auto;
        }}
        .features-section h2 {{ color: #fff; margin-bottom: 15px; font-size: 22px; }}
        .feature-cards {{
            display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px;
        }}
        .feature-card {{
            background: rgba(255,255,255,0.03); border-radius: 10px; padding: 20px;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        .feature-card .feature-icon {{ font-size: 30px; margin-bottom: 10px; display: block; }}
        .feature-card h3 {{ color: #fff; font-size: 16px; margin-bottom: 8px; }}
        .feature-card p {{ color: #aaa; font-size: 13px; line-height: 1.5; }}
        .lan-section {{
            max-width: 900px; margin: 30px auto;
            background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px;
        }}
        .lan-section h2 {{ color: #fff; margin-bottom: 5px; font-size: 20px; }}
        .ip-card {{
            background: rgba(255,255,255,0.03); border-radius: 8px;
            padding: 15px; margin-bottom: 10px;
        }}
        .ip-address {{
            font-size: 18px; color: #64b5f6; font-family: monospace; margin-bottom: 8px;
        }}
        .ip-links {{ display: flex; gap: 10px; flex-wrap: wrap; }}
        .ip-links a {{
            color: #90caf9; text-decoration: none; font-size: 14px;
            padding: 6px 14px; background: rgba(33,150,243,0.1); border-radius: 6px;
            transition: background 0.3s;
        }}
        .ip-links a:hover {{ background: rgba(33,150,243,0.2); }}
        .credentials {{
            max-width: 900px; margin: 30px auto;
            background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px;
        }}
        .credentials h2 {{ color: #fff; margin-bottom: 15px; font-size: 20px; }}
        .cred-grid {{ display: grid; gap: 15px; }}
        .cred-item {{
            background: rgba(255,255,255,0.03); padding: 15px; border-radius: 8px;
            display: flex; gap: 15px; align-items: flex-start;
        }}
        .cred-icon {{ font-size: 24px; }}
        .cred-content {{ flex: 1; }}
        .cred-label {{ display: block; color: #aaa; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }}
        .cred-value {{ display: block; color: #e0e0e0; font-size: 14px; }}
        .cred-value code {{ background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px; color: #64b5f6; }}
        .cred-note {{ display: block; color: #888; font-size: 12px; margin-top: 4px; }}
        .cred-note code {{ background: rgba(0,0,0,0.3); padding: 1px 6px; border-radius: 3px; color: #ffb74d; }}
        .notice {{
            max-width: 900px; margin: 15px auto; padding: 15px;
            background: rgba(255,152,0,0.1); border: 1px solid rgba(255,152,0,0.3);
            border-radius: 8px; color: #ffb74d; font-size: 14px;
        }}
        .notice code {{
            display: block; margin-top: 8px; padding: 8px;
            background: rgba(0,0,0,0.3); border-radius: 4px;
            font-size: 12px; color: #ccc; word-break: break-all;
        }}
        .footer {{
            text-align: center; margin-top: 40px; padding: 20px; color: #666; font-size: 12px;
        }}
        .footer a {{ color: #64b5f6; text-decoration: none; }}
    </style>
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
        VNC Remote Secure | {metrics['hostname']} | {metrics['os']} | Uptime: {metrics['uptime']}
    </div>
</body>
</html>"""


class LandingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Check auth if LANDING_PASSWORD is set
        if LANDING_PASSWORD:
            auth = self.request.headers.get('Authorization')
            if not self._check_auth(auth):
                self.send_response(401)
                self.set_header('WWW-Authenticate', 'Basic realm="VNC Portal"')
                self.end_headers()
                return
        if self.path == '/' or self.path == '/index.html':
            self._serve_landing()
        elif self.path == '/status.json':
            self._serve_status_json()
        elif self.path == '/audio_receiver.html':
            self._serve_template('audio_receiver.html')
        elif self.path == '/gamepad.html':
            self._serve_template('gamepad.html')
        else:
            self.send_response(404)
            self.end_headers()

    def _check_auth(self, auth):
        try:
            if not auth or not auth.startswith('Basic '):
                return False
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            expected = f'admin:{LANDING_PASSWORD}'
            return hmac.compare_digest(decoded, expected)
        except Exception:
            return False

    def _serve_landing(self):
        try:
            content = generate_landing_page()
            self.send_response(200)
            self.set_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {e}'.encode())

    def _serve_template(self, template_name):
        """Serve an HTML template from src/templates/."""
        try:
            template_path = os.path.join(PROJECT_DIR, 'src', 'templates', template_name)
            if not os.path.isfile(template_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(f'Template {template_name} not found'.encode())
                return
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.send_response(200)
            self.set_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {e}'.encode())

    def _serve_status_json(self):
        try:
            data = {
                'services': {
                    'vnc_desktop_novnc': check_port(NOVNC_PORT),
                    'web_terminal': check_port(TTYD_PORT),
                    'health_dashboard': check_port(HEALTH_PORT),
                    'ultravnc_http': check_port(VNC_HTTP_PORT),
                    'vnc_rfb_direct': check_port(VNC_PORT),
                    'landing_page': True,
                },
                'lan_ips': get_lan_ips(),
                'system': get_system_metrics(),
                # Credentials are NOT exposed in JSON for security
            }
            self.send_response(200)
            self.set_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {e}'.encode())

    def log_message(self, fmt, *args):
        del fmt, args


def main():
    ssl_options = None
    if CERT_FILE and KEY_FILE and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ssl_options = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_options.load_cert_chain(CERT_FILE, KEY_FILE)
        print(f"[Landing] SSL enabled")

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((HOST, PORT), LandingHandler)

    if ssl_options:
        server.socket = ssl_options.wrap_socket(server.socket, server_side=True)

    print(f"[Landing] Portal running on {HOST}:{PORT}")
    print(f"[Landing] URL: {'https' if ssl_options else 'http'}://localhost:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Landing] Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
