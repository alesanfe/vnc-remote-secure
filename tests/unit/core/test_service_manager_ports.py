"""Regression tests for service-manager port pre/post checks.

A service whose port is already occupied must not be reported as
"started": either the port holder is an orphaned copy of our own
service (reaped when psutil is available) or a foreign process
(fail loudly, never kill). After spawn, the process must actually
bind the port within the grace window.
"""
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vnc_remote_secure.core import service_manager as sm


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _hold_port(port, stop_evt):
    """Hold a listening socket, accepting connections so probes don't
    fill the backlog (a full backlog makes connect_ex flap)."""
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))
        s.listen(8)
        s.settimeout(0.1)
        while not stop_evt.is_set():
            try:
                conn, _ = s.accept()
                conn.close()
            except socket.timeout:
                pass


class TestPortInUse:
    def test_free_port_reports_false(self):
        assert sm._port_in_use(_free_port()) is False

    def test_held_port_reports_true(self):
        port = _free_port()
        stop = threading.Event()
        t = threading.Thread(target=_hold_port, args=(port, stop),
                             daemon=True)
        t.start()
        try:
            time.sleep(0.2)
            assert sm._port_in_use(port) is True
        finally:
            stop.set()
            t.join(timeout=2)


class TestPreStartPortCheck:
    def test_occupied_port_fails_start(self, monkeypatch):
        """A port held by a foreign process must abort the start."""
        monkeypatch.setattr(sm, '_read_pid', lambda s: None)
        monkeypatch.setattr(sm, '_reap_stale_service',
                            lambda *a, **k: None)
        port = _free_port()
        stop = threading.Event()
        t = threading.Thread(target=_hold_port, args=(port, stop),
                             daemon=True)
        t.start()
        try:
            time.sleep(0.2)
            assert sm._start_python_service(
                'vnc_remote_secure.services.terminal', 'terminal',
                port=port) is None
        finally:
            stop.set()
            t.join(timeout=2)


class TestPostStartBindVerification:
    def test_child_that_never_binds_is_reported_failed(
            self, monkeypatch, tmp_path):
        """A process that exits without binding must fail the start."""
        monkeypatch.setattr(sm, '_read_pid', lambda s: None)
        monkeypatch.setattr(sm, '_port_in_use', lambda p, h='127.0.0.1': False)
        monkeypatch.setattr('vnc_remote_secure.core.paths.get_log_dir',
                            lambda: str(tmp_path))
        # A module that exits instantly without binding anything.
        monkeypatch.setattr(sm, '_write_pid', lambda *a: None)
        pid = sm._start_python_service(
            'vnc_remote_secure.services.nonexistent_module',
            'nonexistent_module', port=_free_port())
        assert pid is None

    def test_binding_child_passes(self, monkeypatch, tmp_path):
        """A process that binds its port within the window passes."""
        monkeypatch.setattr(sm, '_read_pid', lambda s: None)
        monkeypatch.setattr('vnc_remote_secure.core.paths.get_log_dir',
                            lambda: str(tmp_path))
        monkeypatch.setattr(sm, '_write_pid', lambda *a: None)
        port = _free_port()
        # Simulate the child binding shortly after spawn: the listener
        # accepts connections so the probe's backlog slot is drained.
        bind_err = []
        def delayed_bind():
            try:
                time.sleep(0.3)
                with socket.socket() as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('127.0.0.1', port))
                    s.listen(8)
                    s.settimeout(0.1)
                    end = time.time() + 10
                    while time.time() < end:
                        try:
                            conn, _ = s.accept()
                            conn.close()
                        except socket.timeout:
                            pass
            except OSError as e:
                bind_err.append(repr(e))
        t = threading.Thread(target=delayed_bind, daemon=True)
        t.start()
        calls = []
        orig = sm._port_in_use
        def wrapped(p, h='127.0.0.1'):
            calls.append(p)
            return orig(p, h)
        monkeypatch.setattr(sm, '_port_in_use', wrapped)
        # Use a real long-running module-free child: python -c sleep
        # via a fake Popen? Instead patch Popen to a sleeping process.
        import subprocess
        real_popen = subprocess.Popen
        def fake_popen(cmd, **kw):
            return real_popen(
                [sys.executable, '-c', 'import time;time.sleep(10)'],
                **kw)
        monkeypatch.setattr(subprocess, 'Popen', fake_popen)
        pid = sm._start_python_service(
            'vnc_remote_secure.services.terminal', 'terminal', port=port)
        assert pid is not None, f"bind errors: {bind_err}"
        sm._kill_pid(pid)
