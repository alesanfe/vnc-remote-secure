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

import contextlib
import http.server
import logging
import socketserver
import threading

logger = logging.getLogger(__name__)

MAX_CONNECTIONS = 128
# Per-source-IP cap: a single client must not be able to hold the
# whole connection pool — slowloris needs many sockets, and they all
# come from one address. Generous enough for a browser's parallel
# connections plus keep-alives behind one NAT.
MAX_CONNECTIONS_PER_IP = 16
READ_TIMEOUT_SECONDS = 15


class _BoundedMixin:
    """Semaphore-bounded request threads for ThreadingMixIn servers."""

    def __init__(self, *args, max_connections=MAX_CONNECTIONS,
                 max_per_ip=MAX_CONNECTIONS_PER_IP, **kwargs):
        self._conn_semaphore = threading.BoundedSemaphore(max_connections)
        self._max_per_ip = max_per_ip
        self._per_ip: dict = {}
        self._per_ip_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def _ip_acquire(self, ip: str) -> bool:
        """Reserve a slot for ``ip``; False when at the per-IP cap."""
        with self._per_ip_lock:
            count = self._per_ip.get(ip, 0)
            if count >= self._max_per_ip:
                return False
            self._per_ip[ip] = count + 1
            return True

    def _ip_release(self, ip: str) -> None:
        with self._per_ip_lock:
            count = self._per_ip.get(ip, 0)
            if count <= 1:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = count - 1

    def process_request(self, request, client_address):
        # Acquire BEFORE spawning the thread — a full pool makes the
        # accept loop wait, which is the desired back-pressure.
        ip = client_address[0] if client_address else ''
        self._conn_semaphore.acquire()
        if not self._ip_acquire(ip):
            # Per-IP cap hit: refuse the socket instead of queuing a
            # thread that would stall on the global semaphore anyway.
            self._conn_semaphore.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_semaphore.release()
            self._ip_release(ip)
            raise

    def process_request_thread(self, request, client_address):
        ip = client_address[0] if client_address else ''
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_semaphore.release()
            self._ip_release(ip)


class BoundedThreadingTCPServer(_BoundedMixin,
                                socketserver.ThreadingTCPServer):
    """Bounded Threading TCPServer."""

    daemon_threads = True
    allow_reuse_address = True


class BoundedThreadingHTTPServer(_BoundedMixin,
                                 http.server.ThreadingHTTPServer):
    """Bounded Threading HTTPServer."""

    daemon_threads = True


def install_read_timeout(handler, seconds=READ_TIMEOUT_SECONDS):
    """Set a socket read timeout inside a ``BaseHTTPRequestHandler``.

    Intended for ``setup()``: bounds the time a client can stall the
    request-line/header read (the pre-auth slowloris window) and any
    keep-alive idle gap. Failures are ignored — a socket that cannot
    take a timeout is still usable.
    """
    with contextlib.suppress(OSError):
        handler.connection.settimeout(seconds)


class SecuredHandlerMixin:
    """Shared ``http.server`` handler boilerplate (pull-up).

    The health, landing, and noVNC handlers all installed the same
    Slowloris read timeout in ``setup()`` and emitted the same
    security headers in ``end_headers()``; health and noVNC also
    routed access logs to the module logger identically. Inherit
    BEFORE the stdlib handler class. A service needing different
    access-log treatment (the landing redacts share-link tokens)
    overrides ``log_message``.
    """

    def setup(self):
        super().setup()
        install_read_timeout(self)

    def end_headers(self):
        from vnc_remote_secure.security.http_headers import (
            send_security_headers,
        )
        send_security_headers(self)
        super().end_headers()

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # pylint: disable=redefined-builtin
        logger.info("%s - %s", self.client_address[0],
                    format % args)  # noqa: PIE803 - stdlib log format
