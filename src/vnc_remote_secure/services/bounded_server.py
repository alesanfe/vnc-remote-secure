"""Bounded threading HTTP servers for the http.server-based services.

``ThreadingMixIn`` spawns one thread per accepted socket with no cap —
an unauthenticated client dribbling partial request headers (slowloris)
pins a thread per connection until a read timeout fires, and enough
connections exhaust process threads/memory entirely. Two defences live
here:

- :class:`BoundedThreadingTCPServer` / :class:`BoundedThreadingHTTPServer`
  cap in-flight connections with a semaphore; once full, the accept loop
  back-pressures instead of spawning more threads.
- :func:`install_read_timeout` sets a socket read timeout so a stalled
  pre-auth connection is reaped quickly. Call sites that upgrade the
  socket to a long-lived stream (the noVNC websocket relay) must call
  ``self.connection.settimeout(None)`` before entering the relay — the
  relay enforces its own idle timeout.
"""

import http.server
import socketserver
import threading

MAX_CONNECTIONS = 128
READ_TIMEOUT_SECONDS = 15


class _BoundedMixin:
    """Semaphore-bounded request threads for ThreadingMixIn servers."""

    def __init__(self, *args, max_connections=MAX_CONNECTIONS, **kwargs):
        self._conn_semaphore = threading.BoundedSemaphore(max_connections)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Acquire BEFORE spawning the thread — a full pool makes the
        # accept loop wait, which is the desired back-pressure.
        self._conn_semaphore.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_semaphore.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_semaphore.release()


class BoundedThreadingTCPServer(_BoundedMixin,
                                socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class BoundedThreadingHTTPServer(_BoundedMixin,
                                 http.server.ThreadingHTTPServer):
    daemon_threads = True


def install_read_timeout(handler, seconds=READ_TIMEOUT_SECONDS):
    """Set a socket read timeout inside a ``BaseHTTPRequestHandler``.

    Intended for ``setup()``: bounds the time a client can stall the
    request-line/header read (the pre-auth slowloris window) and any
    keep-alive idle gap. Failures are ignored — a socket that cannot
    take a timeout is still usable.
    """
    try:
        handler.connection.settimeout(seconds)
    except OSError:
        pass
