#!/usr/bin/env python3
"""Simple HTTP server to serve noVNC static files.
Usage: python3 -m vnc_remote_secure.services.novnc [novnc_dir] [port]
"""
import http.server
import logging
import os
import signal
import socketserver
import sys

logger = logging.getLogger(__name__)

from vnc_remote_secure.core.constants import DEFAULT_NOVNC_PORT

novnc_dir = sys.argv[1] if len(sys.argv) > 1 else "."
try:
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_NOVNC_PORT
except ValueError:
    logger.error("Invalid port '%s'", sys.argv[2])
    sys.exit(1)

if not os.path.isdir(novnc_dir):
    logger.error("Directory '%s' does not exist", novnc_dir)
    sys.exit(1)

os.chdir(novnc_dir)
handler = http.server.SimpleHTTPRequestHandler
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.daemon_threads = True

# Default to localhost for security; set SERVE_NOVNC_HOST=0.0.0.0 to expose
host = os.environ.get('SERVE_NOVNC_HOST', '127.0.0.1')

# Graceful shutdown
def signal_handler(sig, frame):
    logger.info("Shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)

with socketserver.ThreadingTCPServer((host, port), handler) as httpd:
    # Optional TLS via shared SSL context builder.
    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_ctx = create_ssl_context()
    if ssl_ctx:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    scheme = 'https' if ssl_ctx else 'http'
    logger.info("noVNC web server running on %s://%s:%s", scheme, host, port)
    httpd.serve_forever()
