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
                self.wfile.write(content.encode())
            except FileNotFoundError:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Health status generation failed')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
    
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
        with socketserver.TCPServer(('127.0.0.1', port), HealthHandler) as httpd:
            print(f'Health web server running on port {port}')
            httpd.serve_forever()
    except KeyboardInterrupt:
        print('Health web server stopped')
    except Exception as e:
        print(f'Health web server error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
