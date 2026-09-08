#!/usr/bin/env python3
"""
Health Web Server for Raspberry Pi VNC Remote
Provides HTTP endpoint for health status monitoring
"""

import http.server
import socketserver
import os
import signal
import sys

class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health_status':
            # Generate health status HTML
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'health_web_server.sh')
            os.system(f'bash {script_path} generate_html > /tmp/health_status.html')
            try:
                with open('/tmp/health_status.html', 'r') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                try:
                    self.wfile.write(content.encode())
                except BrokenPipeError:
                    # Client disconnected, ignore error
                    pass
            except FileNotFoundError:
                self.send_response(500)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                try:
                    self.wfile.write(b'Health status generation failed')
                except BrokenPipeError:
                    pass
        else:
            self.send_response(404)
            self.end_headers()
            try:
                self.wfile.write(b'Not Found')
            except BrokenPipeError:
                pass
    
    def log_message(self, format, *args):
        # Suppress log messages
        pass

# Handle shutdown gracefully
def signal_handler(sig, frame):
    print('Health web server shutting down...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Main server execution
def main():
    port = int(os.environ.get('HEALTH_WEB_PORT', 8080))
    
    try:
        # Try to bind to port, if fails show detailed error
        with socketserver.TCPServer(('127.0.0.1', port), HealthHandler) as httpd:
            print(f'Health web server running on port {port}')
            httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f'ERROR: Port {port} is already in use')
            print(f'ERROR: Another process is using port {port}')
            print(f'SOLUTION: Kill process using port {port} and try again')
            print(f'COMMAND: sudo lsof -ti:{port} | xargs kill -9')
            sys.exit(1)
        else:
            print(f'Health web server error: {e}')
            sys.exit(1)
    except KeyboardInterrupt:
        print('Health web server stopped')
    except Exception as e:
        print(f'Health web server error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()