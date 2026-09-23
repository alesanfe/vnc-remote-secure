"""Unit tests for bounded_server — the connection semaphore is the
anti-slowloris control; if it stops limiting or stops releasing, the
server either exhausts threads or deadlocks."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import bounded_server as bs  # noqa: E402


def _server(max_conn=2, max_per_ip=16):
    """Instantiate the mixin without binding a real socket."""
    srv = object.__new__(bs.BoundedThreadingTCPServer)
    srv._conn_semaphore = threading.BoundedSemaphore(max_conn)
    srv._max_per_ip = max_per_ip
    srv._per_ip = {}
    srv._per_ip_lock = threading.Lock()
    # process_request_thread bottom half: the semaphore release is in
    # the mixin's finally; the super() call we stub out below.
    return srv


class TestSemaphoreBounds:
    def test_semaphore_initialized(self):
        srv = _server(3)
        assert srv._conn_semaphore._initial_value == 3

    def test_release_on_spawn_failure(self, monkeypatch):
        """If process_request raises after acquire, the slot MUST be
        returned — a leaked slot permanently reduces capacity."""
        srv = _server(1)
        monkeypatch.setattr(
            'socketserver.ThreadingMixIn.process_request',
            lambda self, r, a: (_ for _ in ()).throw(RuntimeError('boom')),
            raising=False)
        # First call drains the only slot and must release it on error.
        try:
            bs._BoundedMixin.process_request(srv, 'req', 'addr')
        except RuntimeError:
            pass
        # Semaphore back to full — a second acquire must not block.
        assert srv._conn_semaphore.acquire(blocking=False)

    def test_release_after_thread_done(self, monkeypatch):
        """process_request_thread must release even when the handler
        raised — otherwise the server wedges after N failures."""
        srv = _server(1)
        monkeypatch.setattr(
            'socketserver.ThreadingMixIn.process_request_thread',
            lambda self, r, a: (_ for _ in ()).throw(RuntimeError('x')),
            raising=False)
        # Take the slot first — in production process_request does the
        # acquire before spawning this thread.
        assert srv._conn_semaphore.acquire(blocking=False)
        try:
            bs._BoundedMixin.process_request_thread(srv, 'req', 'addr')
        except RuntimeError:
            pass
        assert srv._conn_semaphore.acquire(blocking=False)


class TestReadTimeout:
    def test_installs_timeout(self):
        class H:
            connection = None
        h = H()
        set_with = []

        class Conn:
            def settimeout(self, s):
                set_with.append(s)
        h.connection = Conn()
        bs.install_read_timeout(h)
        assert set_with == [bs.READ_TIMEOUT_SECONDS]

    def test_oserror_suppressed(self):
        """A socket that rejects settimeout must not kill the handler."""
        from unittest.mock import MagicMock
        h = MagicMock()
        h.connection.settimeout.side_effect = OSError('not supported')
        bs.install_read_timeout(h)  # must not raise


class TestBackpressure:
    def test_acquire_blocks_when_full(self):
        """With the pool exhausted, process_request must block — that
        IS the back-pressure contract against slowloris."""
        srv = _server(1)
        assert srv._conn_semaphore.acquire(blocking=False)
        done = []

        def _call():
            # super().process_request is unreachable without a real
            # server; stub it so the acquire path is the thing tested.
            import socketserver
            orig = socketserver.ThreadingMixIn.process_request
            try:
                socketserver.ThreadingMixIn.process_request = (
                    lambda self, r, a: done.append('spawned'))
                bs._BoundedMixin.process_request(srv, 'req', 'addr')
            finally:
                socketserver.ThreadingMixIn.process_request = orig
        t = threading.Thread(target=_call, daemon=True)
        t.start()
        time.sleep(0.15)
        assert done == []  # blocked on the semaphore
        srv._conn_semaphore.release()
        t.join(timeout=2)
        assert done == ['spawned']


class TestPerIpCap:
    """A single source IP must not hold the whole pool — slowloris
    sockets all come from one address."""

    def _server(self, per_ip=3):
        import socketserver
        from vnc_remote_secure.services.bounded_server import _BoundedMixin

        class S(_BoundedMixin, socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        class HoldHandler(socketserver.BaseRequestHandler):
            def handle(self):
                # Hold the connection — without this the handler
                # returns instantly and the slot frees before the
                # assertion runs.
                self.request.settimeout(5)
                try:
                    self.request.recv(64)
                except OSError:
                    pass
        return S(('127.0.0.1', 0), HoldHandler, max_per_ip=per_ip)

    def test_cap_blocks_n_plus_one(self):
        """After N held connections, N+1 from the same IP is refused
        at accept time."""
        import socket
        import threading
        s = self._server(per_ip=2)
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()
        socks = [socket.create_connection(s.server_address)
                 for _ in range(2)]
        # Third connection: accept loop still accepts the socket but
        # closes it immediately — the client sees an instant EOF.
        third = socket.create_connection(s.server_address)
        third.settimeout(2)
        assert third.recv(1) == b''
        s.shutdown()
        for sk in socks:
            sk.close()
        s.server_close()

    def test_release_frees_slot(self):
        s = self._server(per_ip=2)
        assert s._ip_acquire('10.0.0.1') is True
        assert s._ip_acquire('10.0.0.1') is True
        assert s._ip_acquire('10.0.0.1') is False
        s._ip_release('10.0.0.1')
        assert s._ip_acquire('10.0.0.1') is True
        s.server_close()

    def test_different_ips_independent(self):
        s = self._server(per_ip=1)
        assert s._ip_acquire('10.0.0.1') is True
        assert s._ip_acquire('10.0.0.2') is True
        assert s._ip_acquire('10.0.0.1') is False
        s.server_close()

    def test_empty_counter_cleanup(self):
        """Released-to-zero IPs must not leak dict entries."""
        s = self._server(per_ip=2)
        s._ip_acquire('10.0.0.1')
        s._ip_release('10.0.0.1')
        assert s._per_ip == {}
        s.server_close()
