#!/usr/bin/env python3
"""
Health Web Server for Raspberry Pi VNC Remote.
Provides HTTP endpoint for health status monitoring.
"""

import http.server
import socketserver
import os
import signal
import sys
import subprocess


class HealthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for health status endpoints."""

    def do_GET(self):
        if self.path == '/health_status':
            self._serve_health_status()
        else:
            self._serve_not_found()

    def _serve_health_status(self):
        # Generate health status HTML using subprocess (safe, no shell)
        script_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'health_web_server.sh',
        )
        try:
            result = subprocess.run(
                ['bash', script_path, 'generate_html'],
                capture_output=True, text=True, timeout=30,
                check=False,
            )
            content = result.stdout
            if result.returncode != 0:
                self.send_response(503)
                self.send_header('Content-Type', 'text/plain')
                self._send_security_headers()
                self.end_headers()
                try:
                    self.wfile.write(b'Health status generation failed')
                except BrokenPipeError:
                    pass
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(content.encode())
            except BrokenPipeError:
                pass  # Client disconnected
        except Exception:  # pylint: disable=broad-except
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self._send_security_headers()
            self.end_headers()
            try:
                self.wfile.write(b'Health status generation failed')
            except BrokenPipeError:
                pass

    def _send_security_headers(self):
        """Send standard security headers for the response."""
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'no-referrer')

    def _serve_not_found(self):
        self.send_response(404)
        self.end_headers()
        try:
            self.wfile.write(b'Not Found')
        except BrokenPipeError:
            pass

    def log_message(self, fmt, *args):
        """Suppress default log messages."""
        del fmt, args  # Unused but required by base class signature


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    del signum, frame  # Unused but required by signal API
    print('Health web server shutting down...')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Run the health web server."""
    port = int(os.environ.get('HEALTH_WEB_PORT', 8080))

    try:
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer(('127.0.0.1', port), HealthHandler) as httpd:
            print(f'Health web server running on port {port}')
            httpd.serve_forever()
    except OSError as exc:
        if 'Address already in use' in str(exc):
            print(f'ERROR: Port {port} is already in use')
            print(f'SOLUTION: sudo lsof -ti:{port} | xargs kill -9')
        else:
            print(f'Health web server error: {exc}')
        sys.exit(1)
    except KeyboardInterrupt:
        print('Health web server stopped')


if __name__ == '__main__':
    main()
