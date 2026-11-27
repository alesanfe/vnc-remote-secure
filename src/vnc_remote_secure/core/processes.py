"""Process management utilities for VNC Remote Secure.

Cross-platform helpers for checking port availability.
"""

import socket


def is_port_available(port, host="127.0.0.1"):
    """Return ``True`` if ``port`` is free to bind on ``host``.

    Uses a connect-based probe rather than bind-based because Windows
    ``SO_REUSEADDR`` allows multiple sockets to bind the same port,
    producing false negatives (reporting a port as available when it
    is actively listening).
    """
    # AF_INET6 for literal IPv6 hosts ('::1') — an AF_INET socket
    # cannot reach them and would falsely report the port free.
    family = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((host, port))
        # Connection succeeded → something is listening → port NOT available
        return False
    except OSError:  # ConnectionRefusedError/TimeoutError subclass OSError
        # Nothing listening → port IS available
        return True


def port_in_listen_state(port):
    """Return ``True`` if ``port`` has a LISTEN socket on this host.

    Reads ``/proc/net/tcp{,6}`` instead of opening a connection — a
    connect+close is not free for every listener: TigerVNC counts it
    as an unauthenticated attempt toward ``-BlacklistThreshold``, and
    once blacklisted each further attempt extends the (exponentially
    growing) timeout, so a periodic connect probe locks the host out
    of the RFB server permanently. ``None`` when the socket table is
    unavailable (non-Linux, restricted /proc) so callers can fall back
    to a connect probe.
    """
    seen = False
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, encoding="ascii") as fh:
                seen = True
                next(fh, None)  # header line
                for line in fh:
                    fields = line.split()
                    # fields[1] is "hexIP:hexPort"; state 0A = LISTEN
                    if len(fields) > 3 and fields[3] == "0A":
                        try:
                            if int(fields[1].rsplit(":", 1)[-1], 16) == port:
                                return True
                        except ValueError:
                            continue
        except OSError:
            continue
    return False if seen else None


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
    inherited env vars. ``env=None`` is treated as absent — in
    ``subprocess.run`` it means "inherit everything", which is exactly
    the leak this guard exists to prevent; a caller wanting the full
    environment must pass ``os.environ.copy()`` deliberately.
    """
    import subprocess

    if kwargs.get("env") is None:
        from vnc_remote_secure.security.redaction import (
            sanitized_child_env,
        )

        kwargs["env"] = sanitized_child_env()
    try:
        return subprocess.run(cmd, timeout=timeout, check=check, **kwargs)
    except subprocess.TimeoutExpired as e:
        if check:
            raise
        # Honour text mode on the synthetic result: TimeoutExpired.stdout
        # is always bytes, but callers that passed text=True expect str.
        text_mode = kwargs.get("text") or kwargs.get("universal_newlines")
        out, err = e.stdout or b"", e.stderr or b"command timed out"
        if text_mode:
            enc = kwargs.get("encoding") or "utf-8"
            out = out.decode(enc, "replace") if isinstance(out, bytes) else out
            err = err.decode(enc, "replace") if isinstance(err, bytes) else err
        return subprocess.CompletedProcess(cmd, returncode=-1, stdout=out, stderr=err)
