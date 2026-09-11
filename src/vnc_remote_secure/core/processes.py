"""Process management utilities for VNC Remote Secure.

Cross-platform helpers for finding processes bound to a port, killing
processes by PID, checking port availability, and allocating free
ports. On Linux ``ss``/``lsof`` are used; on Windows ``netstat`` and
``taskkill`` are used.
"""
import os
import socket
import subprocess
import sys

from vnc_remote_secure.platform.detection import is_windows


def find_process(port):
    """Find the PID of the process listening on ``port``.

    Returns the PID as an ``int`` or ``None`` if no process is bound to
    the port or the lookup tools are unavailable.
    """
    if is_windows():
        try:
            result = subprocess.run(
                ['netstat', '-ano', '-p', 'TCP'],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith(f':{port}'):
                    if parts[3] == 'LISTENING':
                        try:
                            return int(parts[4])
                        except ValueError:
                            continue
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        return None

    # Linux: prefer ss, fall back to lsof.
    for cmd in (['ss', '-tlnp'], ['lsof', '-i', f':{port}', '-t']):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if cmd[0] == 'ss':
            for line in result.stdout.splitlines():
                if f':{port} ' in line or line.rstrip().endswith(f':{port}'):
                    # Extract pid=NNN from the users column.
                    if 'pid=' in line:
                        pid_part = line.split('pid=', 1)[1]
                        pid_str = pid_part.split(',')[0].split(')')[0]
                        try:
                            return int(pid_str)
                        except ValueError:
                            continue
        else:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    return int(line)
    return None


def kill_process(pid):
    """Terminate a process by PID.

    Returns ``True`` if the process was terminated (or was already gone)
    and ``False`` if it could not be killed.
    """
    if not pid:
        return False
    try:
        if is_windows():
            result = subprocess.run(
                ['taskkill', '/PID', str(pid), '/F'],
                capture_output=True, timeout=10,
            )
        else:
            result = subprocess.run(
                ['kill', '-TERM', str(pid)],
                capture_output=True, timeout=10,
            )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def is_port_available(port, host='127.0.0.1'):
    """Return ``True`` if ``port`` is free to bind on ``host``."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def get_free_port(host='127.0.0.1', start_range=(49152, 65535)):
    """Find and return a free TCP port on ``host``.

    ``start_range`` is an inclusive ``(low, high)`` tuple constraining
    the search. Returns ``None`` if no free port is found.
    """
    low, high = start_range
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        for _ in range(50):
            s.bind((host, 0))
            port = s.getsockname()[1]
            s.close()
            if low <= port <= high:
                return port
            # Reopen for next iteration.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return None
