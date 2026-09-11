#!/usr/bin/env python3
"""Simple HTTP server to serve noVNC static files.
Usage: python3 serve_novnc.py [novnc_dir] [port]
"""
import http.server
import socketserver
import os
import sys
import signal

novnc_dir = sys.argv[1] if len(sys.argv) > 1 else "."
try:
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 6080
except ValueError:
    print(f"Error: invalid port '{sys.argv[2]}'", file=sys.stderr)
    sys.exit(1)

if not os.path.isdir(novnc_dir):
    print(f"Error: directory '{novnc_dir}' does not exist", file=sys.stderr)
    sys.exit(1)

os.chdir(novnc_dir)
handler = http.server.SimpleHTTPRequestHandler
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer.daemon_threads = True

# Default to localhost for security; set SERVE_NOVNC_HOST=0.0.0.0 to expose
host = os.environ.get('SERVE_NOVNC_HOST', '127.0.0.1')

# Graceful shutdown
def signal_handler(sig, frame):
    print("\nShutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)

with socketserver.ThreadingTCPServer((host, port), handler) as httpd:
    print(f"noVNC web server running on {host}:{port}")
    httpd.serve_forever()
