#!/usr/bin/env python3
"""
Health Web Server for VNC Remote Secure.
Provides HTTP endpoint for health status monitoring.

Works on both Linux and Windows. On Windows, uses Windows-native
commands (tasklist, netstat, wmic) instead of Linux equivalents.
"""

import http.server
import socketserver
import os
import sys
import signal
import subprocess
import platform
import json
import time
import re
import html
from datetime import datetime


def is_windows():
    """Check if running on Windows."""
    return platform.system() == 'Windows'


def get_process_info(name):
    """Get process info by name. Returns (running, pid_list)."""
    if is_windows():
        try:
            result = subprocess.run(
                ['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, timeout=10, check=False
            )
            pids = []
            for line in result.stdout.strip().split('\n'):
                if name.lower() in line.lower():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        pid = parts[1].strip('"')
                        if pid.isdigit():
                            pids.append(int(pid))
            return (len(pids) > 0, pids)
        except Exception:
            return (False, [])
    else:
        try:
            result = subprocess.run(
                ['pgrep', '-f', name],
                capture_output=True, text=True, timeout=10, check=False
            )
            pids = [int(p) for p in result.stdout.strip().split('\n') if p.strip().isdigit()]
            return (len(pids) > 0, pids)
        except Exception:
            return (False, [])


def check_port(port):
    """Check if a port is listening. Returns (listening, pid)."""
    if is_windows():
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, text=True, timeout=10, check=False
            )
            for line in result.stdout.split('\n'):
                if f':{port} ' in line and 'LISTENING' in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        return (True, pid)
            return (False, None)
        except Exception:
            return (False, None)
    else:
        try:
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True, text=True, timeout=10, check=False
            )
            for line in result.stdout.split('\n'):
                if f':{port} ' in line and 'LISTEN' in line:
                    return (True, None)
            return (False, None)
        except Exception:
            return (False, None)


def http_check(url, timeout=5):
    """Check if an HTTP endpoint responds. Returns (ok, status_code)."""
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return (True, resp.status)
    except Exception as e:
        return (False, str(e)[:100])


def get_system_info():
    """Get system information."""
    info = {
        'hostname': platform.node(),
        'os': f"{platform.system()} {platform.release()}",
        'python': platform.python_version(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }

    if is_windows():
        try:
            result = subprocess.run(
                ['wmic', 'os', 'get', 'LastBootUpTime', '/value'],
                capture_output=True, text=True, timeout=10, check=False
            )
            match = re.search(r'LastBootUpTime=(.+)', result.stdout)
            if match:
                boot_str = match.group(1).strip()
                # WMI format: 20240101120000.000000+000
                if '.' in boot_str:
                    boot_dt = datetime.strptime(boot_str.split('.')[0], '%Y%m%d%H%M%S')
                    uptime_delta = datetime.now() - boot_dt
                    hours = int(uptime_delta.total_seconds() // 3600)
                    minutes = int((uptime_delta.total_seconds() % 3600) // 60)
                    info['uptime'] = f"{hours}h {minutes}m"
                else:
                    info['uptime'] = boot_str
            else:
                info['uptime'] = 'Unknown'
        except Exception:
            info['uptime'] = 'Unknown'

        # CPU and memory
        try:
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'loadpercentage', '/value'],
                capture_output=True, text=True, timeout=10, check=False
            )
            match = re.search(r'LoadPercentage=(\d+)', result.stdout)
            info['cpu_usage'] = f"{match.group(1)}%" if match else 'N/A'
        except Exception:
            info['cpu_usage'] = 'N/A'

        try:
            result = subprocess.run(
                ['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/value'],
                capture_output=True, text=True, timeout=10, check=False
            )
            total_match = re.search(r'TotalVisibleMemorySize=(\d+)', result.stdout)
            free_match = re.search(r'FreePhysicalMemory=(\d+)', result.stdout)
            if total_match and free_match:
                total_kb = int(total_match.group(1))
                free_kb = int(free_match.group(1))
                used_kb = total_kb - free_kb
                usage_pct = (used_kb / total_kb) * 100 if total_kb > 0 else 0
                info['memory_usage'] = f"{usage_pct:.1f}%"
                info['memory_detail'] = f"{used_kb // 1024} MB / {total_kb // 1024} MB"
            else:
                info['memory_usage'] = 'N/A'
                info['memory_detail'] = ''
        except Exception:
            info['memory_usage'] = 'N/A'
            info['memory_detail'] = ''

        try:
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'size,freespace,caption', '/value'],
                capture_output=True, text=True, timeout=10, check=False
            )
            disks = []
            # wmic outputs each property on its own line with blank lines between
            # properties of the same disk. We collect all key=value pairs and
            # group them into disks whenever we see a Caption= (new disk starts).
            current = {}
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    key = key.strip()
                    val = val.strip()
                    if key == 'Caption':
                        # New disk starts - save previous if complete
                        if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
                            size_gb = int(current['Size']) / (1024**3)
                            free_gb = int(current['FreeSpace']) / (1024**3)
                            used_pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
                            disks.append(f"{current['Caption']} {used_pct:.0f}% ({free_gb:.0f} GB free)")
                        current = {'Caption': val}
                    elif key == 'Size':
                        try:
                            current['Size'] = int(val)
                        except ValueError:
                            pass
                    elif key == 'FreeSpace':
                        try:
                            current['FreeSpace'] = int(val)
                        except ValueError:
                            pass
            # Save last disk
            if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
                size_gb = int(current['Size']) / (1024**3)
                free_gb = int(current['FreeSpace']) / (1024**3)
                used_pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
                disks.append(f"{current['Caption']} {used_pct:.0f}% ({free_gb:.0f} GB free)")
            info['disk_usage'] = '; '.join(disks) if disks else 'N/A'
        except Exception:
            info['disk_usage'] = 'N/A'
    else:
        # Linux
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_sec = float(f.readline().split()[0])
                hours = int(uptime_sec // 3600)
                minutes = int((uptime_sec % 3600) // 60)
                info['uptime'] = f"{hours}h {minutes}m"
        except Exception:
            info['uptime'] = 'Unknown'

        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                # df -h / output: Filesystem Size Used Avail Use% Mounted on
                # parts[3] = Avail, parts[4] = Use%, parts[2] = Used
                if len(parts) > 4:
                    info['disk_usage'] = f"/ {parts[4]} ({parts[2]} used, {parts[3]} free)"
                else:
                    info['disk_usage'] = 'N/A'
        except Exception:
            info['disk_usage'] = 'N/A'

        try:
            with open('/proc/loadavg', 'r') as f:
                # This is load average, not CPU usage percentage
                load = f.readline().split()[0]
                info['cpu_usage'] = f"Load avg: {load}"
        except Exception:
            info['cpu_usage'] = 'N/A'

        try:
            result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if line.startswith('Mem:'):
                    parts = line.split()
                    total = int(parts[1])
                    used = int(parts[2])
                    pct = (used / total) * 100 if total > 0 else 0
                    info['memory_usage'] = f"{pct:.1f}%"
                    info['memory_detail'] = f"{used} MB / {total} MB"
                    break
        except Exception:
            info['memory_usage'] = 'N/A'
            info['memory_detail'] = ''

    return info


def check_services():
    """Check all services and return structured status."""
    vnc_port = int(os.environ.get('VNC_PORT', '5900'))
    novnc_port = int(os.environ.get('NOVNC_PORT', '6080'))
    ttyd_port = int(os.environ.get('TTYD_PORT', '5000'))
    health_port = int(os.environ.get('HEALTH_WEB_PORT', '8090'))

    services = []

    # UltraVNC / TigerVNC
    vnc_running, vnc_pids = get_process_info('winvnc.exe') if is_windows() else get_process_info('tigervnc')
    vnc_port_ok, vnc_port_pid = check_port(vnc_port)
    services.append({
        'name': 'VNC Server',
        'process': 'winvnc.exe' if is_windows() else 'tigervncserver',
        'pid': vnc_pids[0] if vnc_pids else None,
        'port': vnc_port,
        'port_listening': vnc_port_ok,
        'process_running': vnc_running,
        'status': 'healthy' if (vnc_running and vnc_port_ok) else ('warning' if vnc_port_ok else 'error'),
        'message': 'Running' if vnc_running and vnc_port_ok else ('Port open but process not found' if vnc_port_ok else 'Not running'),
    })

    # noVNC / websockify
    ws_running, ws_pids = get_process_info('python') if is_windows() else get_process_info('websockify')
    ws_port_ok, ws_port_pid = check_port(novnc_port)
    # On Windows, websockify runs as python, so we need to check more carefully
    if is_windows() and ws_port_ok:
        ws_running = True
    services.append({
        'name': 'noVNC (websockify)',
        'process': 'python3 (websockify)',
        'pid': ws_port_pid if ws_port_ok else (ws_pids[0] if ws_pids else None),
        'port': novnc_port,
        'port_listening': ws_port_ok,
        'process_running': ws_running,
        'status': 'healthy' if (ws_port_ok) else 'error',
        'message': f'Listening on :{novnc_port}' if ws_port_ok else 'Not running',
        'url': f'https://localhost:{novnc_port}/vnc.html',
    })

    # Web Terminal (ttyd or web_terminal.py)
    term_port_ok, term_port_pid = check_port(ttyd_port)
    services.append({
        'name': 'Web Terminal',
        'process': 'web_terminal.py' if is_windows() else 'ttyd',
        'pid': term_port_pid,
        'port': ttyd_port,
        'port_listening': term_port_ok,
        'process_running': term_port_ok,
        'status': 'healthy' if term_port_ok else 'error',
        'message': f'Listening on :{ttyd_port}' if term_port_ok else 'Not running',
        'url': f'https://localhost:{ttyd_port}/',
    })

    # Health Server (self)
    health_port_ok, _ = check_port(health_port)
    services.append({
        'name': 'Health Dashboard',
        'process': 'health_web_server.py',
        'pid': os.getpid(),
        'port': health_port,
        'port_listening': health_port_ok,
        'process_running': True,
        'status': 'healthy' if health_port_ok else 'warning',
        'message': f'Listening on :{health_port}' if health_port_ok else 'Starting...',
        'url': f'http://localhost:{health_port}/health_status',
    })

    return services


def generate_html():
    """Generate the health status HTML page."""
    sys_info = get_system_info()
    services = check_services()

    # Count statuses
    healthy = sum(1 for s in services if s['status'] == 'healthy')
    warnings = sum(1 for s in services if s['status'] == 'warning')
    errors = sum(1 for s in services if s['status'] == 'error')

    # Overall status
    if errors > 0:
        overall_status = 'ERROR'
        overall_color = '#f44336'
        overall_icon = 'x-circle'
    elif warnings > 0:
        overall_status = 'WARNING'
        overall_color = '#ff9800'
        overall_icon = 'alert-triangle'
    else:
        overall_status = 'HEALTHY'
        overall_color = '#4caf50'
        overall_icon = 'check-circle'

    # Build service cards
    service_cards = []
    for s in services:
        status_color = {
            'healthy': '#4caf50',
            'warning': '#ff9800',
            'error': '#f44336',
        }.get(s['status'], '#9e9e9e')

        status_bg = {
            'healthy': '#1b3a1b',
            'warning': '#3a2e1b',
            'error': '#3a1b1b',
        }.get(s['status'], '#2a2a2a')

        pid_text = f"PID: {s['pid']}" if s.get('pid') else 'PID: N/A'
        port_text = f"Port: {s['port']} ({'LISTENING' if s.get('port_listening') else 'CLOSED'})"
        url_link = f'<a href="{html.escape(s["url"])}" target="_blank" style="color:#64b5f6;text-decoration:none;">Open</a>' if s.get('url') else ''

        service_cards.append(f"""
        <div class="service-card" style="background:{status_bg};border-left:4px solid {status_color};">
            <div class="service-header">
                <span class="service-name">{html.escape(s['name'])}</span>
                <span class="service-status" style="color:{status_color};">{s['status'].upper()}</span>
            </div>
            <div class="service-details">
                <div class="detail-line">{html.escape(s['process'])} &middot; {pid_text}</div>
                <div class="detail-line">{port_text}</div>
                <div class="detail-line">{html.escape(s['message'])} {url_link}</div>
            </div>
        </div>""")

    # Build the full HTML page
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>VNC Remote - Health Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #1a1a2e; color: #e0e0e0;
            font-family: 'Segoe UI', 'Consolas', monospace;
            padding: 20px; min-height: 100vh;
        }}
        .header {{
            text-align: center; margin-bottom: 30px;
        }}
        .header h1 {{
            color: #fff; font-size: 28px; margin-bottom: 10px;
        }}
        .overall-status {{
            display: inline-block; padding: 8px 24px;
            border-radius: 20px; font-size: 18px; font-weight: bold;
            background: {overall_color}; color: #fff;
        }}
        .summary-bar {{
            display: flex; justify-content: center; gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-item {{
            padding: 10px 20px; border-radius: 8px; text-align: center;
        }}
        .summary-item.healthy {{ background: #1b3a1b; color: #4caf50; }}
        .summary-item.warning {{ background: #3a2e1b; color: #ff9800; }}
        .summary-item.error {{ background: #3a1b1b; color: #f44336; }}
        .summary-item .count {{ font-size: 32px; font-weight: bold; }}
        .summary-item .label {{ font-size: 12px; text-transform: uppercase; }}
        .services-grid {{
            display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 15px; max-width: 1200px; margin: 0 auto 30px;
        }}
        .service-card {{
            padding: 15px; border-radius: 8px;
        }}
        .service-header {{
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 10px;
        }}
        .service-name {{ font-size: 16px; font-weight: bold; color: #fff; }}
        .service-status {{ font-size: 12px; font-weight: bold; }}
        .service-details {{ font-size: 13px; color: #b0b0b0; }}
        .detail-line {{ margin: 4px 0; }}
        .system-info {{
            max-width: 1200px; margin: 0 auto;
            background: #16213e; padding: 20px; border-radius: 8px;
        }}
        .system-info h2 {{ color: #fff; margin-bottom: 15px; font-size: 18px; }}
        .info-grid {{
            display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
        }}
        .info-item {{
            background: #0f3460; padding: 10px; border-radius: 6px;
        }}
        .info-item .key {{ font-size: 11px; color: #888; text-transform: uppercase; }}
        .info-item .val {{ font-size: 14px; color: #e0e0e0; margin-top: 4px; }}
        .footer {{
            text-align: center; margin-top: 20px; color: #666; font-size: 12px;
        }}
        a {{ color: #64b5f6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>VNC Remote Secure - Health Dashboard</h1>
        <div class="overall-status" style="background:{overall_color};">
            {overall_status}
        </div>
    </div>

    <div class="summary-bar">
        <div class="summary-item healthy">
            <div class="count">{healthy}</div>
            <div class="label">Healthy</div>
        </div>
        <div class="summary-item warning">
            <div class="count">{warnings}</div>
            <div class="label">Warning</div>
        </div>
        <div class="summary-item error">
            <div class="count">{errors}</div>
            <div class="label">Error</div>
        </div>
    </div>

    <div class="services-grid">
        {''.join(service_cards)}
    </div>

    <div class="system-info">
        <h2>System Information</h2>
        <div class="info-grid">
            <div class="info-item"><div class="key">Hostname</div><div class="val">{html.escape(sys_info['hostname'])}</div></div>
            <div class="info-item"><div class="key">OS</div><div class="val">{html.escape(sys_info['os'])}</div></div>
            <div class="info-item"><div class="key">Uptime</div><div class="val">{html.escape(sys_info['uptime'])}</div></div>
            <div class="info-item"><div class="key">CPU</div><div class="val">{html.escape(sys_info['cpu_usage'])}</div></div>
            <div class="info-item"><div class="key">Memory</div><div class="val">{html.escape(sys_info['memory_usage'])} {html.escape(sys_info.get('memory_detail', ''))}</div></div>
            <div class="info-item"><div class="key">Disk</div><div class="val">{html.escape(sys_info['disk_usage'])}</div></div>
            <div class="info-item"><div class="key">Python</div><div class="val">{html.escape(sys_info['python'])}</div></div>
            <div class="info-item"><div class="key">Updated</div><div class="val">{html.escape(sys_info['timestamp'])}</div></div>
        </div>
    </div>

    <div class="footer">
        Auto-refresh: 30s &middot; VNC Remote Secure Health Dashboard
    </div>
</body>
</html>"""
    return page


def generate_json():
    """Generate health status as JSON."""
    sys_info = get_system_info()
    services = check_services()
    return json.dumps({
        'system': sys_info,
        'services': services,
        'summary': {
            'healthy': sum(1 for s in services if s['status'] == 'healthy'),
            'warning': sum(1 for s in services if s['status'] == 'warning'),
            'error': sum(1 for s in services if s['status'] == 'error'),
        },
    }, indent=2)


class HealthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for health status endpoints."""

    def do_GET(self):
        if self.path == '/health_status':
            self._serve_health_status()
        elif self.path == '/health_status.json':
            self._serve_health_json()
        elif self.path == '/':
            self.send_response(302)
            self.send_header('Location', '/health_status')
            self.end_headers()
        else:
            self._serve_not_found()

    def _serve_health_status(self):
        try:
            content = generate_html()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(content.encode('utf-8'))
            except BrokenPipeError:
                pass
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(f'Health status generation failed: {e}'.encode())
            except BrokenPipeError:
                pass

    def _serve_health_json(self):
        try:
            content = generate_json()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(content.encode('utf-8'))
            except BrokenPipeError:
                pass
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(f'JSON generation failed: {e}'.encode())
            except BrokenPipeError:
                pass

    def _send_security_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'no-referrer')

    def _serve_not_found(self):
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        try:
            self.wfile.write(b'Not Found')
        except BrokenPipeError:
            pass

    def log_message(self, fmt, *args):
        del fmt, args


def signal_handler(signum, frame):
    del signum, frame
    print('Health web server shutting down...')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    port = int(os.environ.get('HEALTH_WEB_PORT', '8090'))
    # Default to 127.0.0.1 for security; set HEALTH_WEB_HOST=0.0.0.0 to expose
    host = os.environ.get('HEALTH_WEB_HOST', '127.0.0.1')

    try:
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer((host, port), HealthHandler) as httpd:
            print(f'Health web server running on {host}:{port}')
            print(f'  Dashboard: http://localhost:{port}/health_status')
            print(f'  JSON API:  http://localhost:{port}/health_status.json')
            httpd.serve_forever()
    except OSError as exc:
        if 'Address already in use' in str(exc):
            print(f'ERROR: Port {port} is already in use')
        else:
            print(f'Health web server error: {exc}')
        sys.exit(1)
    except KeyboardInterrupt:
        print('Health web server stopped')


if __name__ == '__main__':
    main()
