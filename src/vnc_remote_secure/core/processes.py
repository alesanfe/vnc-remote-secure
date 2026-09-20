"""Process management utilities for VNC Remote Secure.

Cross-platform helpers for checking port availability.
"""
import socket


def is_port_available(port, host='127.0.0.1'):
    """Return ``True`` if ``port`` is free to bind on ``host``.

    Uses a connect-based probe rather than bind-based because Windows
    ``SO_REUSEADDR`` allows multiple sockets to bind the same port,
    producing false negatives (reporting a port as available when it
    is actively listening).
    """
    # AF_INET6 for literal IPv6 hosts ('::1') — an AF_INET socket
    # cannot reach them and would falsely report the port free.
    family = socket.AF_INET6 if ':' in str(host) else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((host, port))
        # Connection succeeded → something is listening → port NOT available
        return False
    except (OSError, ConnectionRefusedError, socket.timeout):
        # Nothing listening → port IS available
        return True


def run_cmd(cmd, timeout=30, check=False, **kwargs):
    """``subprocess.run`` with a hard timeout by default.

    A hung ``systemctl``, ``netsh``, ``taskkill`` or ``certbot`` must
    not wedge the service manager or installer forever. On timeout the
    child is killed and a ``CompletedProcess`` with ``returncode=-1``
    is returned so ``check=False`` callers see a normal failure. With
    ``check=True`` the timeout is re-raised as ``TimeoutExpired``
    (still an exception, matching the contract that failure is
    exceptional).
    """
    import subprocess
    try:
        return subprocess.run(cmd, timeout=timeout, check=check,
                              **kwargs)
    except subprocess.TimeoutExpired as e:
        if check:
            raise
        return subprocess.CompletedProcess(
            cmd, returncode=-1,
            stdout=e.stdout or b'',
            stderr=e.stderr or b'command timed out')
