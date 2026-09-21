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

    Unless the caller passes ``env`` explicitly, the child gets a
    credential-scrubbed environment: a PATH-shadowed helper binary
    must not harvest ``VNC_PASSWORD``/``DUCKDNS_TOKEN``/etc. through
    inherited env vars.
    """
    import subprocess
    if 'env' not in kwargs:
        from vnc_remote_secure.security.redaction import (
            sanitized_child_env,
        )
        kwargs['env'] = sanitized_child_env()
    try:
        return subprocess.run(cmd, timeout=timeout, check=check,
                              **kwargs)
    except subprocess.TimeoutExpired as e:
        if check:
            raise
        # Honour text mode on the synthetic result: TimeoutExpired.stdout
        # is always bytes, but callers that passed text=True expect str.
        text_mode = kwargs.get('text') or kwargs.get('universal_newlines')
        out, err = e.stdout or b'', e.stderr or b'command timed out'
        if text_mode:
            enc = kwargs.get('encoding') or 'utf-8'
            out = out.decode(enc, 'replace') if isinstance(out, bytes) else out
            err = err.decode(enc, 'replace') if isinstance(err, bytes) else err
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout=out, stderr=err)
