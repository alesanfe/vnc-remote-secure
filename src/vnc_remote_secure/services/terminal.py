#!/usr/bin/env python3
"""
Web Terminal server using FastAPI/Starlette WebSocket + xterm.js.

Canonical web terminal on both platforms (replaced ttyd; ConPTY has
issues on Windows 11 25H2).

Instead of using a PTY/ConPTY, this implements a command executor:
each command sent via WebSocket is executed as a subprocess and the
output is sent back.

Features:
  - Command history (arrow up/down)
  - Tab completion for files/dirs and basic commands
  - Multi-line paste support
  - Ctrl+C interrupt
  - cd/pwd/cls/exit/help built-in commands
  - ANSI color support
  - PowerShell/cmd.exe backend on Windows; POSIX shell (WEBTERM_SHELL,
    default bash) on Linux — the service manager runs this module on
    both platforms
"""
import asyncio
import glob
import json
import logging
import os
import subprocess
import sys
import threading

from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import (
    check_terminal_auth,
    client_ip_from,
    cookie_value,
    extract_bearer_token,
)

logger = logging.getLogger(__name__)

# Load configuration from .env file (never hardcode credentials)
from vnc_remote_secure.core.config import env_flag, load_env_file

load_env_file()

# Configuration - credentials read from environment, never hardcoded
from contextlib import suppress

from vnc_remote_secure.core.constants import (
    DEFAULT_CMD_TIMEOUT,
    DEFAULT_MAX_OUTPUT,
)


def _config():
    """Return the runtime config lazily so .env changes take effect on each call."""
    from vnc_remote_secure.core.config import get_config
    return get_config()


# Common commands for tab completion (no duplicates)
if os.name == 'posix':
    COMMON_COMMANDS = [
        'ls', 'cd', 'echo', 'cat', 'cp', 'rm', 'mv', 'mkdir', 'rmdir',
        'ps', 'kill', 'ip', 'ss', 'netstat', 'ping', 'traceroute', 'uname',
        'python', 'python3', 'pip', 'git', 'node', 'npm', 'which', 'grep',
        'find', 'sort', 'env', 'export', 'hostname', 'whoami', 'clear',
        'head', 'tail', 'df', 'du', 'top', 'systemctl', 'curl', 'wget',
        'tar', 'chmod', 'chown', 'ssh', 'scp', 'bash', 'sh', 'exit', 'help',
    ]
else:
    COMMON_COMMANDS = [
        'dir', 'cd', 'echo', 'type', 'copy', 'del', 'move', 'ren', 'mkdir', 'rmdir',
        'tasklist', 'taskkill', 'ipconfig', 'netstat', 'ping', 'tracert', 'systeminfo',
        'python', 'python3', 'pip', 'git', 'node', 'npm', 'where', 'findstr', 'sort',
        'set', 'setx', 'hostname', 'whoami', 'ver', 'vol', 'tree', 'attrib', 'fc',
        'powershell', 'cmd', 'cls', 'exit', 'help', 'color', 'title', 'prompt',
        'netsh', 'sc', 'wmic', 'chkdsk', 'format', 'label', 'subst',
    ]


def _portal_terminal_url(host_header: str) -> str:
    """Landing-portal URL of the React terminal page."""
    cfg = _config()
    from vnc_remote_secure.security.certificates import create_ssl_context
    proto = ('https' if create_ssl_context(
        cfg.get('ssl_cert'), cfg.get('ssl_key')) else 'http')
    host = (host_header or '').split(':')[0] or '127.0.0.1'
    return f'{proto}://{host}:{cfg["landing_port"]}/terminal'


def _root_security_headers(tls_enabled: bool) -> dict:
    """Security headers for the redirect response."""
    from vnc_remote_secure.security.http_headers import get_security_headers
    headers = get_security_headers(tls_enabled=tls_enabled)
    # The only response this route emits is a redirect to the React
    # terminal page — the strict 'self' CSP applies (an explicit
    # CSP_POLICY env override still wins).
    if not os.environ.get('CSP_POLICY'):
        headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' wss: ws:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
    return headers


def _basic_auth_enabled() -> bool:
    """Whether the legacy TTYD_* Basic credential surface is enabled.

    ``TERMINAL_BASIC_AUTH=false`` removes it: Basic is the broadest
    credential type the terminal accepts (a reusable shared password
    with no expiry/revocation), so hardened deployments can force
    token-only auth (ephemeral cookie, bearer, operator session).
    """
    return env_flag('TERMINAL_BASIC_AUTH', 'true')


def _is_origin_allowed(origin):
    """Reject WebSocket connections from unknown origins (prevents CSWSH).

    Delegates to the canonical auth-gateway origin list so every
    WebSocket service enforces the same policy (ALLOWED_ORIGINS +
    DUCK_DOMAIN + local service ports + LAN IPs).
    """
    if not origin:
        return False
    from vnc_remote_secure.security.auth_gateway import (
        check_origin as _gw_check_origin,
    )
    from vnc_remote_secure.security.auth_gateway import (
        get_allowed_origins as _gw_get_allowed_origins,
    )
    # The gateway check covers the allowlist AND the ALLOWED_LAN_IPS
    # exception — the same policy every other service enforces.
    if _gw_check_origin(origin, _gw_get_allowed_origins()):
        return True
    logger.warning("Rejected WebSocket from origin: %s", origin)
    return False


def _complete_windows_command(prefix):
    """Complete a command prefix using common commands and PATH lookup."""
    suggestions = [c for c in COMMON_COMMANDS if c.startswith(prefix.lower())]
    # Also match executables in PATH ('where' is Windows-only; on POSIX
    # 'which' works but COMMON_COMMANDS already covers the usual verbs)
    if os.name != 'posix' and _config()['webterm_shell'] == 'cmd.exe':
        try:
            from vnc_remote_secure.core.processes import run_cmd
            result = run_cmd(
                ['where', prefix + '*'],
                capture_output=True, text=True, timeout=5, check=False
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    name = os.path.basename(line.strip()).replace('.exe', '').replace('.EXE', '')
                    if name and name not in suggestions:
                        suggestions.append(name)
        except Exception as e:
            logger.debug("Tab completion via 'where' failed: %s", e)
    return suggestions


def _complete_path_glob(input_str, cwd):
    """Complete a file/directory argument via glob, constrained to cwd tree.

    Returns a list of suggestions, or None when the input is rejected
    (contains null/control characters) so the caller can send an empty
    completion response.
    """
    parts = input_str.split()
    last_word = parts[-1]
    # Sanitize: reject null bytes and control characters
    if '\x00' in last_word or any(ord(c) < 32 for c in last_word):
        return None
    # Determine the directory to search
    if os.path.isabs(last_word):
        search_dir = os.path.dirname(last_word)
        prefix = os.path.basename(last_word)
    else:
        search_dir = cwd
        prefix = last_word

    if not os.path.isdir(search_dir):
        search_dir = cwd

    # Resolve and constrain to cwd tree to prevent arbitrary traversal.
    # Use ``real_cwd + os.sep`` so sibling directories sharing a prefix
    # (e.g. /home/app and /home/apple) are not matched.
    try:
        real_search = os.path.realpath(search_dir)
        real_cwd = os.path.realpath(cwd)
        if real_search != real_cwd and not real_search.startswith(real_cwd + os.sep):
            search_dir = cwd
    except (OSError, ValueError) as e:
        logger.debug("Path validation failed: %s", e)
        search_dir = cwd

    suggestions = []
    try:
        pattern = os.path.join(search_dir, prefix + '*')
        for entry in glob.glob(pattern):
            name = os.path.basename(entry)
            if os.path.isdir(entry):
                name += os.sep
            suggestions.append(name)
    except Exception as e:
        logger.debug("Tab completion via glob failed: %s", e)
    return suggestions


def _build_child_env():
    """Build a sanitized environment for the child process.

    All credential variables (the canonical ``SECRET_VARS`` list —
    VNC_PASSWORD, TTYD_PASSWD, TOTP_SECRET, HEALTH_AUTH_TOKEN,
    BACKUP_PASSWORD, webhook URLs, SMTP passwords, etc.) are removed
    so they are not exfiltrable via `set`/`env` commands.
    """
    from vnc_remote_secure.security.redaction import SECRET_VARS
    return {
        k: v for k, v in os.environ.items()
        if k not in SECRET_VARS
    }


def _child_rlimits():
    """Return a ``preexec_fn`` bounding a terminal child's resources.

    POSIX only. Limits inherited across exec (setpriv/runuser/exec),
    so they apply to the shell and its descendants:

    - ``RLIMIT_NPROC`` — per-uid process count (fork bombs).
    - ``RLIMIT_AS`` — address space (memory exhaustion).
    - ``RLIMIT_CPU`` — CPU seconds (a cmd can outpace CMD_TIMEOUT
      wall-clock only up to this).
    - ``RLIMIT_NOFILE`` — descriptor count.
    - ``RLIMIT_FSIZE`` — a runaway `> file` cannot fill the disk.
    - ``RLIMIT_CORE`` — core dumps disabled (they can embed secrets).
    """
    def _apply():
        # POSIX-only module; unreachable on Windows (guarded above).
        import resource  # pylint: disable=import-error
        limits = (
            (resource.RLIMIT_NPROC, 128),
            (resource.RLIMIT_AS, 1 << 30),       # 1 GiB
            (resource.RLIMIT_CPU, 300),
            (resource.RLIMIT_NOFILE, 256),
            (resource.RLIMIT_FSIZE, 256 << 20),  # 256 MiB
            (resource.RLIMIT_CORE, 0),
        )
        for res, soft in limits:
            try:
                hard = resource.getrlimit(res)[1]
                cap = soft if hard == resource.RLIM_INFINITY else min(
                    soft, hard)
                resource.setrlimit(res, (cap, cap))
            except (OSError, ValueError):
                # A limit the platform lacks must not abort the spawn.
                pass
    return _apply


def _restricted_user_prefix():
    """Return argv prefix to drop privileges to ``WEBTERM_USER``.

    When ``WEBTERM_USER`` names an existing account and this process
    runs as root, terminal commands are spawned as that user instead
    of the service account — the shell can no longer read the
    service's secrets, PID files or other services' state. Prefers
    ``setpriv`` (no PAM), falls back to ``runuser``. Returns ``None``
    when privilege dropping is unavailable or not configured.
    """
    import pwd  # pylint: disable=import-error
    import shutil as _shutil

    user = os.environ.get('WEBTERM_USER', '').strip()
    if not user:
        return None
    if os.geteuid() != 0:  # pylint: disable=no-member
        logger.warning(
            "WEBTERM_USER=%s ignored — not running as root; terminal "
            "commands execute as the service user", user)
        return None
    try:
        from vnc_remote_secure.core.validation import validate_username
        validate_username(user)
    except (ImportError, ValueError) as exc:
        logger.warning("WEBTERM_USER rejected: %s", exc)
        return None
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        logger.warning("WEBTERM_USER=%s does not exist — ignoring", user)
        return None
    setpriv = _shutil.which('setpriv')
    if setpriv:
        return [setpriv, '--reuid', str(pw.pw_uid),
                '--regid', str(pw.pw_gid), '--clear-groups', '--']
    runuser = _shutil.which('runuser')
    if runuser:
        return [runuser, '-u', user, '--']
    logger.warning(
        "WEBTERM_USER=%s configured but neither setpriv nor runuser "
        "found — terminal runs as the service user", user)
    return None


_BWRAP_USABLE = None


def _bwrap_usable(bwrap: str) -> bool:
    """Probe once whether unprivileged user namespaces work.

    ``bwrap --dev-bind / / -- true`` is the minimal namespace setup —
    when the kernel forbids unprivileged userns (e.g.
    ``kernel.unprivileged_userns_clone=0``) the probe fails and we fall
    back instead of erroring every terminal command.
    """
    global _BWRAP_USABLE
    if _BWRAP_USABLE is not None:
        return _BWRAP_USABLE
    try:
        from vnc_remote_secure.core.processes import run_cmd
        res = run_cmd([bwrap, '--dev-bind', '/', '/', '--', 'true'],
                      capture_output=True, timeout=5)
        _BWRAP_USABLE = res.returncode == 0
    except Exception:  # noqa: BLE001 - probe is best-effort
        _BWRAP_USABLE = False
    if not _BWRAP_USABLE:
        logger.warning(
            "bubblewrap present but unprivileged user namespaces are "
            "disabled — terminal sandbox unavailable")
    return _BWRAP_USABLE


def _sandbox_prefix():
    """Return a bubblewrap argv prefix masking secret dirs, or None.

    When the WEBTERM_USER privilege drop is unavailable (the packaged
    systemd unit runs as the unprivileged ``vnc-remote`` user, where
    setpriv/runuser are impossible), unprivileged user namespaces still
    let us hide the directories holding service secrets — auth_secret.
    key, shared_state.db, generated_credentials.env, config.env, SSL
    keys and backups — from the spawned shell. The shell keeps a full
    view of the rest of the filesystem; only the service-owned state
    is masked with tmpfs.
    """
    import shutil as _shutil
    bwrap = _shutil.which('bwrap')
    if not bwrap or not _bwrap_usable(bwrap):
        return None
    try:
        from vnc_remote_secure.core.paths import (
            get_config_dir,
            get_data_dir,
            get_log_dir,
            get_run_dir,
            get_ssl_dir,
        )
        sensitive = [get_run_dir(), get_ssl_dir(), get_config_dir(),
                     get_data_dir(), get_log_dir()]
    except Exception:  # noqa: BLE001 - paths module unavailable
        sensitive = []
    args = [bwrap, '--dev-bind', '/', '/']
    # Mask every sensitive dir — even the shell's cwd. A cwd inside a
    # masked dir resolves to the empty tmpfs (confusing but secure);
    # skipping the mask would leave the service state readable.
    for d in sensitive:
        args += ['--tmpfs', os.path.realpath(d)]
    args.append('--')
    return args


# Shell allowlist for WEBTERM_SHELL (§6): an arbitrary binary as
# "shell" would execute `binary -c <remote command>` — restricting
# to real shells keeps the env var from becoming a code-exec
# primitive via configuration.
_ALLOWED_SHELLS = frozenset({
    'bash', 'sh', 'zsh', 'dash', 'ksh',
    'cmd.exe', 'cmd', 'powershell.exe', 'powershell', 'pwsh.exe', 'pwsh',
})


def _shell_allowed(shell: str) -> bool:
    """Return True when ``shell`` is in the terminal shell allowlist."""
    return os.path.basename(shell).lower() in _ALLOWED_SHELLS


def _build_subprocess_args(cmd, shell, cwd):
    """Build the subprocess argument list for the configured shell."""
    import shutil as _shutil
    if os.name == 'posix':
        # POSIX shell (bash/sh/zsh): the configured WEBTERM_SHELL or a
        # sane fallback — cmd.exe does not exist here.
        if shell and not _shell_allowed(shell):
            logger.warning(
                "WEBTERM_SHELL=%r not in the shell allowlist — "
                "falling back to bash/sh", shell)
            shell = ''
        resolved = (_shutil.which(shell) if shell else None) \
            or _shutil.which('bash') or '/bin/sh'
        # Prefer a real uid drop (strongest); fall back to the
        # bubblewrap filesystem sandbox when the service is non-root.
        prefix = (_restricted_user_prefix()
                  or _sandbox_prefix() or [])
        return prefix + [resolved, '-c', cmd]
    if shell == 'powershell.exe':
        ps_exe = (_shutil.which('powershell.exe')
                  or _shutil.which('powershell')
                  or r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
        return [ps_exe, '-NoProfile', '-NonInteractive', '-Command', cmd]
    cmd_exe = _shutil.which('cmd.exe') or os.environ.get('ComSpec', r'C:\Windows\System32\cmd.exe')
    # NOTE: cmd.exe /c has notoriously inconsistent quote handling
    # (inner quotes may be stripped depending on the command). This is
    # a cmd.exe behaviour, not something this layer can safely fix —
    # wrapping the whole command in quotes breaks paths containing
    # spaces. Users needing complex quoting should set
    # WEBTERM_SHELL=powershell.exe, which takes -Command verbatim.
    return [cmd_exe, '/c', cmd]


_kill_job_handle = None


def _assign_to_kill_job(proc) -> None:
    """Windows: assign ``proc`` to a Job Object with KILL_ON_JOB_CLOSE.

    When the last handle to the job closes — i.e. when this terminal
    service process exits, even abruptly — Windows kills every
    assigned process. Without it, a crashed/killed terminal service
    orphans cmd/powershell children that keep an interactive shell
    alive after the remote command that spawned them is gone. POSIX
    children share the service's process group and are covered by
    the manager's killpg path. Best-effort: nested-job hosts (and
    AppContainer, which uses its own job) can reject the
    assignment — taskkill /T remains the fallback.
    """
    global _kill_job_handle
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        if _kill_job_handle is None:
            _kill_job_handle = k32.CreateJobObjectW(None, None)
            if not _kill_job_handle:
                return

            class _Basic(ctypes.Structure):
                _fields_ = [
                    ('PerProcessUserTimeLimit', ctypes.c_int64),
                    ('PerJobUserTimeLimit', ctypes.c_int64),
                    ('LimitFlags', ctypes.c_uint32),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', ctypes.c_uint32),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', ctypes.c_uint32),
                    ('SchedulingClass', ctypes.c_uint32)]

            class _Io(ctypes.Structure):
                _fields_ = [(k, ctypes.c_uint64) for k in (
                    'ReadOperationCount', 'WriteOperationCount',
                    'OtherOperationCount', 'ReadTransferCount',
                    'WriteTransferCount', 'OtherTransferCount')]

            class _Ext(ctypes.Structure):
                _fields_ = [
                    ('BasicLimitInformation', _Basic),
                    ('IoInfo', _Io),
                    ('ProcessMemoryLimit', ctypes.c_size_t),
                    ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t),
                    ('PeakJobMemoryUsed', ctypes.c_size_t)]

            # JobObjectExtendedLimitInformation = 9,
            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000.
            info = _Ext()
            info.BasicLimitInformation.LimitFlags = 0x2000
            if not k32.SetInformationJobObject(
                    _kill_job_handle, 9, ctypes.byref(info),
                    ctypes.sizeof(info)):
                _kill_job_handle = None
                return
        # Resolve a HANDLE: subprocess.Popen exposes _handle; an
        # asyncio subprocess Process carries it under
        # _transport._proc; a bare pid needs OpenProcess
        # (PROCESS_SET_QUOTA|PROCESS_TERMINATE = 0x0101).
        handle = getattr(proc, '_handle', None)
        opened = False
        if handle is None:
            inner = getattr(getattr(proc, '_transport', None),
                            '_proc', None)
            handle = getattr(inner, '_handle', None)
        if handle is None:
            pid = getattr(proc, 'pid', None) or (
                proc if isinstance(proc, int) else None)
            if not pid:
                return
            handle = k32.OpenProcess(0x0101, False, int(pid))
            opened = bool(handle)
            if not handle:
                return
        try:
            if not k32.AssignProcessToJobObject(
                    _kill_job_handle, int(handle)):
                logger.debug(
                    'Job assignment refused for pid %s (nested job?)',
                    getattr(proc, 'pid', proc))
        finally:
            if opened:
                k32.CloseHandle(handle)
    except Exception as e:  # noqa: BLE001
        logger.debug('Kill-job unavailable: %s', e)


def _kill_process_tree(proc):
    """Kill ``proc`` and its whole process tree.

    ``proc.kill()`` alone kills only the shell — grandchildren
    (``cmd /c ping``, ``bash -c 'tail -f'``) keep running and keep the
    stdout/stderr pipes open, so the drain threads would block until
    the grandchild exits. On Windows use ``taskkill /T`` (tree kill);
    on POSIX send SIGKILL to the process group.
    """
    try:
        if os.name == 'nt':
            from vnc_remote_secure.core.processes import run_cmd
            run_cmd(
                ['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                capture_output=True, timeout=10, check=False)
        else:
            import signal
            try:
                # POSIX-only path — pylint: disable=no-member
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:  # ProcessLookupError/PermissionError subclass OSError
                proc.kill()
    except Exception:  # noqa: BLE001 - kill is best-effort
        with suppress(Exception):
            proc.kill()


def _help_text():
    """Return the help text shown by the 'help' built-in command."""
    return (
        '\r\n\x1b[36mAvailable commands:\x1b[0m\r\n'
        '  \x1b[33mAny system command\x1b[0m  - dir, echo, python, etc.\r\n'
        '  \x1b[33mcls/clear\x1b[0m          - Clear screen\r\n'
        '  \x1b[33mhistory\x1b[0m            - Show command history\r\n'
        '  \x1b[33mexit/quit\x1b[0m          - Disconnect\r\n'
        '  \x1b[33mhelp\x1b[0m               - Show this help\r\n'
        '\r\n\x1b[90mTips: Arrow Up/Down for history, Tab for completion\x1b[0m\r\n'
    )


def _history_text(history):
    """Return the text shown by the 'history' built-in command."""
    if not history:
        return '\r\n\x1b[90mNo commands in history.\x1b[0m\r\n'
    lines = ['\r\n']
    for i, cmd in enumerate(history, 1):
        lines.append(f'  \x1b[90m{i:4d}\x1b[0m  {cmd}\r\n')
    return ''.join(lines)


def _clear_text():
    """Return the escape sequence that clears the screen."""
    return '\x1b[2J\x1b[H'


def _interrupt_text():
    """Return the text emitted on Ctrl+C interrupt."""
    return '\r\n\x1b[31m^C\x1b[0m\r\n'


class _WSRequest:
    """Duck-typed request shim over a Starlette WebSocket.

    Exposes ``headers``, ``remote_ip`` and ``host`` — the attributes
    the terminal auth path read off ``self.request``.
    """

    def __init__(self, websocket):
        self.headers = websocket.headers
        self.remote_ip = (
            websocket.client.host if websocket.client else '')
        self.host = websocket.headers.get('host', '')


class _LoopAdapter:
    """Callback-scheduling shim over an asyncio loop.

    The drain threads call ``add_callback(fn, *args)``;
    ``call_soon_threadsafe`` is the asyncio equivalent. ``time()``
    returns the loop's monotonic clock — the idle watchdog compares
    it against ``_last_activity``.
    """

    def __init__(self, loop):
        self._loop = loop

    def add_callback(self, fn, *args, **kwargs):
        self._loop.call_soon_threadsafe(fn, *args, **kwargs)

    def time(self):
        return self._loop.time()


class _IdleWatcher:
    """Periodic idle check, framework-free (thread + Event)."""

    def __init__(self, check, interval=30.0):
        self._check = check
        self._interval = interval
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.wait(self._interval):
            try:
                self._check()
            except Exception:  # noqa: BLE001 - watchdog never dies loud
                pass

    def stop(self):
        self._stop.set()


class TerminalWebSocket:
    """Command executor terminal — one instance per WebSocket.

    Not a framework handler anymore: the FastAPI route in
    :func:`make_app` owns the socket lifecycle and delegates to this
    session object, which keeps the same method surface the tests and
    drain threads use (``write_message``/``close`` schedule onto the
    running loop, so they are callable from any thread).
    """

    main_loop = None
    # Terminal commands are short JSON envelopes — a multi-MB frame is
    # only a memory-exhaustion attempt.
    max_message_size = 64 * 1024

    def __init__(self, websocket):
        self.websocket = websocket
        self.request = _WSRequest(websocket)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - outside a loop
            loop = None
        self._loop = loop
        self.current_process = None

    # -- transport primitives ----------------------------------------
    def write_message(self, message, binary=False):
        """Send a frame — callable from any thread (drain threads
        produce output off-loop)."""
        self._touch_activity()
        ws = self.websocket
        loop = self._loop
        if ws is None or loop is None:
            return
        coro = (ws.send_bytes(message) if binary
                else ws.send_text(message))
        fut = asyncio.run_coroutine_threadsafe(coro, loop)

        def _discard(f):
            try:
                f.result()
            except Exception as e:  # noqa: BLE001 - socket may be closed
                logger.debug('Terminal send failed: %s', e)

        fut.add_done_callback(_discard)
        return fut

    def close(self, code=1000, reason=''):
        """Close the socket — callable pre- or post-accept."""
        ws = self.websocket
        loop = self._loop
        if ws is None or loop is None:
            return
        fut = asyncio.run_coroutine_threadsafe(
            ws.close(code=code, reason=reason), loop)

        def _discard(f):
            try:
                f.result()
            except Exception as e:  # noqa: BLE001
                logger.debug('Terminal close failed: %s', e)

        fut.add_done_callback(_discard)
        return fut

    def _step_up_required(self, session_cookie, bearer):
        """Enforce step-up auth for operator sessions.

        Applies to operator sessions — skipped only when the ephemeral
        cookie is the SOLE credential (the previous behavior): a session
        that is already permission-bound has no username for step-up to
        challenge.
        """
        if not (bearer or session_cookie):
            return True
        from vnc_remote_secure.security.auth_gateway import check_authenticated
        from vnc_remote_secure.security.step_up_auth import require_step_up
        _authed, ws_user = check_authenticated(session_cookie, bearer)
        if ws_user:
            step_up_err = require_step_up(ws_user, 'open_terminal')
            if step_up_err:
                self.close(code=1008, reason=step_up_err)
                return False
            from vnc_remote_secure.security.auth_policy import (
                auth_context_for,
                evaluate,
                session_id_for_cookie,
            )
            sid = session_id_for_cookie(session_cookie) if session_cookie else None
            decision = evaluate('open_terminal',
                                auth_context_for(sid or ''))
            if not decision.allowed:
                self.close(code=1008,
                           reason=f'Auth policy: {decision.reason_code}')
                return False
        return True

    def _authenticate(self):
        """Authenticate the WebSocket upgrade. Returns True when allowed.

        Token credentials (ephemeral cookie, bearer, session cookie)
        resolve through the gateway's single enforcement tree; the
        legacy basic-auth path falls back to ``check_terminal_auth``.
        """
        auth = self.request.headers.get('Authorization', '')
        bearer = extract_bearer_token(auth)
        cookie = self.request.headers.get('Cookie', '')
        session_cookie = cookie_value(cookie, 'vnc_session')
        eph = cookie_value(cookie, 'vnc_ephemeral')
        if not (eph or bearer or session_cookie):
            if not _basic_auth_enabled():
                # TERMINAL_BASIC_AUTH=false: the legacy TTYD_*
                # credential surface is disabled — only token
                # credentials (ephemeral/bearer/session) authenticate.
                self.close(code=1008, reason='Basic auth disabled')
                return False
            if not check_terminal_auth(
                    auth, client_ip=client_ip_from(
                        self.request.headers, self.request.remote_ip)):
                self.close(code=1008, reason='Unauthorized')
                return False
            self._ws_conn_id = None
            return True

        from vnc_remote_secure.security.auth_gateway import (
            check_websocket_upgrade,
            register_websocket_connection,
        )
        allowed, reason = check_websocket_upgrade(
            origin=self.request.headers.get('Origin', ''),
            cookie_value=session_cookie,
            bearer_token=bearer,
            resource='terminal',
            # terminal_view admits view-only sessions; command
            # execution is gated separately by terminal_write.
            required_permission='terminal_view',
            client_ip=client_ip_from(
                self.request.headers, self.request.remote_ip),
            ephemeral_cookie=eph,
        )
        if not allowed:
            self.close(code=1008, reason=reason)
            return False
        # RBAC split: an ephemeral session needs terminal_write to run
        # commands; terminal_view only opens a read-only terminal
        # (builtins work, subprocesses don't). Operator sessions
        # (cookie/bearer/Basic) are not permission-bound.
        self._terminal_write = True
        if eph:
            from vnc_remote_secure.security.ephemeral_sessions import check_session_permission
            self._terminal_write = check_session_permission(
                eph, 'terminal_write', resource='terminal',
                client_ip=client_ip_from(
                    self.request.headers, self.request.remote_ip))
        if not self._step_up_required(session_cookie, bearer):
            return False
        # Register the connection so revocation can close it live.
        token = eph or bearer or session_cookie
        self._ws_conn_id = register_websocket_connection(
            token, self.close, resource='terminal',
            client_ip=self.request.remote_ip or '',
        )
        if self._ws_conn_id is None:
            self.close(code=1008, reason='Session revoked')
            return False
        # Cross-process revocation watcher — a CLI-issued revoke
        # only marks shared state; this closes the live socket.
        from vnc_remote_secure.security.websocket_registry import (
            start_revocation_watcher,
        )
        start_revocation_watcher(token)
        return True

    def open(self):
        """Open."""
        if not self._authenticate():
            return

        self.current_process = None
        import time as _time
        self._opened_at = _time.time()
        home = os.environ.get('USERPROFILE') or os.path.expanduser('~')
        self.cwd = home if os.path.isdir(home) else (
            'C:\\' if os.name == 'nt' else '/')
        self.history = []
        logger.info("Client connected from %s", self.request.remote_ip)
        # A terminal is remote code execution — its open/close must
        # land in the audit trail (identity, duration; never commands).
        from vnc_remote_secure.security.audit import audit_event
        audit_event('terminal_open',
                  detail='web terminal session started')

        # Idle timeout: an unattended terminal is an open shell on the
        # server — close it rather than leave it authenticated forever.
        # Activity = client input AND server output (a user watching a
        # long-running tail stays connected). 0 disables.
        try:
            self._idle_timeout = int(
                os.environ.get('TERMINAL_IDLE_TIMEOUT', '900'))
        except ValueError:
            self._idle_timeout = 900
        self._last_activity = self._now()
        self._idle_cb = None
        if self._idle_timeout > 0:
            self._idle_cb = _IdleWatcher(self._check_idle, 30.0)
            self._idle_cb.start()
        # Message rate cap: nobody types 30 commands/s — a flood is a
        # fork/spawn DoS against the shell channel, not usage.
        import collections
        self._msg_times = collections.deque()
        try:
            self._msg_rate = int(
                os.environ.get('TERMINAL_MSG_RATE', '30'))
        except ValueError:
            self._msg_rate = 30

        self.write_message("\x1b[36m\r\n  VNC Remote Secure - Web Terminal\r\n\x1b[0m")
        self.write_message(
            f"\x1b[90m  Shell: {_config()['webterm_shell']} | "
            f"OS: {os.name}\r\n\x1b[0m")
        self.write_message(f"\x1b[90m  Working directory: {self.cwd}\r\n\x1b[0m")
        self.write_message("\x1b[90m  Type 'help' for commands, 'exit' to disconnect.\r\n\x1b[0m")
        self.write_message("\r\n")
        self._send_prompt()

    def _now(self) -> float:
        """Monotonic clock for the idle watchdog."""
        try:
            if self._loop is not None:
                return self._loop.time()
        except Exception:  # noqa: BLE001
            pass
        import time as _time
        return _time.monotonic()

    def _touch_activity(self):
        try:
            self._last_activity = self._now()
        except Exception:  # noqa: BLE001
            pass

    def _check_idle(self):
        """Close the socket when no input/output for idle_timeout s."""
        if (self._now()
                - getattr(self, '_last_activity', 0)
                > self._idle_timeout):
            logger.info("Terminal idle for %ss — closing",
                        self._idle_timeout)
            try:
                self.write_message(
                    "\r\n\x1b[33m[session closed: idle timeout]\x1b[0m\r\n")
            except Exception:  # noqa: BLE001
                pass
            self.close(code=1000, reason='idle timeout')

    def on_close(self):
        """Clean up on WebSocket close.

        Unregisters the connection from the revocation registry (so
        revoked sessions stop receiving terminal output) and terminates
        any running child process.
        """
        conn_id = getattr(self, '_ws_conn_id', None)
        if conn_id:
            from vnc_remote_secure.security.auth_gateway import (
                unregister_websocket_quiet,
            )
            unregister_websocket_quiet(conn_id)
            self._ws_conn_id = None
        idle_cb = getattr(self, '_idle_cb', None)
        if idle_cb is not None:
            idle_cb.stop()
            self._idle_cb = None
        opened_at = getattr(self, '_opened_at', None)
        if opened_at:
            import time as _time

            from vnc_remote_secure.security.audit import audit_event
            audit_event('terminal_close',
                        detail=f'duration={_time.time() - opened_at:.0f}s')
            self._opened_at = None
        logger.info("Client disconnected")
        # current_process is only assigned after successful auth —
        # sockets rejected in open() raise AttributeError noise here.
        proc = getattr(self, 'current_process', None)
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception as e:
                logger.warning("Failed to terminate process on close: %s", e)
            self.current_process = None

    def _send_prompt(self):
        """Send the shell prompt with ANSI color."""
        if _config()['webterm_shell'] == 'powershell.exe':
            prompt = f"\x1b[33mPS {self.cwd}>\x1b[0m "
        else:
            short_cwd = self.cwd
            if len(short_cwd) > 35:
                short_cwd = "..." + os.sep + os.path.basename(short_cwd)
            prompt = f"\x1b[33m{short_cwd}>\x1b[0m"
        self.write_message(prompt)

    def _rate_limited(self) -> bool:
        """Sliding 1s-window message cap — a burst of input is fine, a
        sustained flood gets the socket closed."""
        import time as _time
        now = _time.monotonic()
        times = getattr(self, '_msg_times', None)
        if times is None or self._msg_rate <= 0:
            return False
        times.append(now)
        while times and times[0] < now - 1.0:
            times.popleft()
        if len(times) > self._msg_rate:
            logger.warning("Terminal message flood from %s — "
                           "closing", self.request.remote_ip)
            self.close(code=1008, reason='rate limit')
            return True
        return False

    def _builtin_command(self, cmd: str) -> bool:
        """Handle read-only builtins; True when ``cmd`` was one."""
        low = cmd.lower()
        if low in ('exit', 'quit'):
            self.write_message('\r\n\x1b[90mGoodbye.\x1b[0m\r\n')
            self.close()
            return True
        if low in ('cls', 'clear'):
            self.write_message(_clear_text())
        elif low == 'help':
            self.write_message(_help_text())
        elif low == 'history':
            self.write_message(_history_text(self.history))
        else:
            return False
        self._send_prompt()
        self._set_busy(False)
        return True

    def _command_allowed(self, cmd: str) -> bool:
        """TERMINAL_COMMAND_ALLOWLIST gate (comma-separated regexes).

        A defense-in-depth knob for deployments where the shell cannot
        drop privileges and terminal access should be scoped to a few
        diagnostics commands.
        """
        allowlist = os.environ.get(
            'TERMINAL_COMMAND_ALLOWLIST', '').strip()
        if not allowlist:
            return True
        import re
        patterns = [p.strip() for p in allowlist.split(',') if p.strip()]
        try:
            return any(re.fullmatch(p, cmd) for p in patterns)
        except re.error:
            logger.exception(
                "Invalid TERMINAL_COMMAND_ALLOWLIST regex — "
                "denying command")
            return False

    def _on_command(self, msg):
        """Handle a ``command`` terminal message."""
        cmd = msg.get('cmd', '').strip()
        if not cmd:
            self.write_message('\r\n')
            self._send_prompt()
            self._set_busy(False)
            return
        self.history.append(cmd)
        if self._builtin_command(cmd):
            return
        # RBAC split: terminal_view connects and uses read-only
        # builtins, but only terminal_write spawns subprocesses.
        # Operator sessions (no ephemeral cookie) are not
        # permission-bound — _terminal_write stays True for them.
        if not getattr(self, '_terminal_write', True):
            self.write_message(
                '\r\n\x1b[31mView-only terminal session — '
                'command execution requires the terminal_write '
                'permission.\x1b[0m\r\n')
            self._send_prompt()
            self._set_busy(False)
            return
        if not self._command_allowed(cmd):
            self.write_message(
                '\r\n\x1b[31mCommand not allowed by '
                'TERMINAL_COMMAND_ALLOWLIST\x1b[0m\r\n')
            self._send_prompt()
            self._set_busy(False)
            return
        self._execute_command(cmd)

    def on_message(self, message):
        """On message."""
        self._touch_activity()
        if self._rate_limited():
            return
        try:
            msg = json.loads(message)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Ignoring malformed terminal message: %s", exc)
            return

        msg_type = msg.get('type')

        if msg_type == 'command':
            self._on_command(msg)

        elif msg_type == 'interrupt':
            if self.current_process and self.current_process.poll() is None:
                try:
                    self.current_process.terminate()
                    self.current_process.wait(timeout=2)
                    self.write_message(_interrupt_text())
                    self._send_prompt()
                    self._set_busy(False)
                except Exception as e:
                    logger.warning("Failed to terminate process on interrupt: %s", e)
            else:
                self.write_message('\r\n')
                self._send_prompt()
                self._set_busy(False)

        elif msg_type == 'complete':
            # Path completion globs the server filesystem — a
            # view-only session could enumerate filenames under the
            # cwd even though it cannot run commands. Gate it behind
            # the same permission as execution.
            if getattr(self, '_terminal_write', True):
                self._handle_completion(msg.get('input', ''))

    def _set_busy(self, busy):
        """Send busy state to client."""
        self.write_message(json.dumps({"type": "busy", "value": busy}))

    def _handle_completion(self, input_str):
        """Handle tab completion request."""
        suggestions = []

        parts = input_str.split()
        if len(parts) <= 1:
            # Completing the command itself
            prefix = parts[0] if parts else input_str
            suggestions = _complete_windows_command(prefix)
        else:
            # Completing a file/directory argument
            path_suggestions = _complete_path_glob(input_str, self.cwd)
            if path_suggestions is None:
                self.write_message(json.dumps({
                    "type": "completion",
                    "suggestions": [],
                    "input": input_str
                }))
                return
            suggestions = path_suggestions

        # Limit suggestions
        suggestions = suggestions[:20]

        self.write_message(json.dumps({
            "type": "completion",
            "suggestions": suggestions,
            "input": input_str
        }))

    def _execute_command(self, cmd):
        """Execute a command and stream output.

        SECURITY NOTE:
            This is a full interactive web terminal. Authenticated WebSocket
            clients can execute arbitrary shell commands, including command
            chaining (&&, ||, ;, |). This is intentional — the terminal
            provides full shell access, not a restricted command set.

            Security relies on:
              1. WebSocket authentication (Basic auth on the upgrade request)
              2. Origin checking (rejects cross-origin connections)
              3. ALLOWED_LAN_IPS filtering (optional IP allowlist)
              4. SSL/TLS encryption (when SSL_CERT/SSL_KEY are configured)

            If authentication is compromised, an attacker gains full shell
            access. Ensure strong credentials and network-level controls
            (firewall, VPN) are in place before exposing the terminal.
        """
        self.write_message('\r\n')
        self._set_busy(True)

        # Command timeout (seconds) - prevents infinite-running commands
        CMD_TIMEOUT = DEFAULT_CMD_TIMEOUT
        # Max output size (bytes) - prevents memory exhaustion
        MAX_OUTPUT = DEFAULT_MAX_OUTPUT

        args = _build_subprocess_args(cmd, _config()['webterm_shell'], self.cwd)

        try:
            # Build a sanitized environment for the child process so that
            # secrets loaded from .env (VNC_PASSWORD, TTYD_PASSWD, tokens, etc.)
            # are not exfiltrable via `set`/`env` commands run in the terminal.
            # NOTE: this only hides secrets from the environment — the
            # shell still runs as the service account, which owns
            # .env, <run_dir>/auth_secret.key and the session stores.
            # Real isolation: WEBTERM_USER uid drop or the bwrap
            # filesystem sandbox on POSIX (see _restricted_user_prefix
            # / _sandbox_prefix); AppContainer on Windows (see
            # platform/windows/sandbox.py, TERMINAL_WINDOWS_SANDBOX).
            child_env = _build_child_env()
            # CREATE_NO_WINDOW is Windows-only; on Linux the attribute does
            # not exist and passing it raises AttributeError.
            kwargs = {}
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            else:
                # Own process group so _kill_process_tree can SIGKILL
                # the shell AND its children without hitting ours.
                kwargs['start_new_session'] = True
                # Resource limits bound a single command's blast
                # radius — a fork bomb or memory hog can otherwise
                # exhaust the host inside CMD_TIMEOUT seconds.
                kwargs['preexec_fn'] = _child_rlimits()
            # A previous command may still be running if two 'command'
            # messages raced — overwriting current_process here would
            # orphan it from interrupt/on_close cleanup.
            prev = self.current_process
            if prev is not None and prev.poll() is None:
                with suppress(Exception):  # best-effort cleanup
                    prev.terminate()
            # Windows: spawn inside an AppContainer when enabled —
            # the shell then cannot read the user profile holding the
            # service secrets (F-035 mitigation). 'auto' falls back to
            # an unsandboxed spawn on failure; 'strict' propagates;
            # 'off' skips the sandbox entirely.
            proc = None
            if sys.platform == 'win32':
                from vnc_remote_secure.platform.windows.sandbox import sandbox_mode, spawn_sandboxed
                mode = sandbox_mode()
                if mode != 'off':
                    try:
                        proc = spawn_sandboxed(
                            args, cwd=self.cwd, env=child_env)
                    except Exception as e:  # noqa: BLE001
                        if mode == 'strict':
                            raise
                        logger.warning(
                            "AppContainer spawn failed (%s) — terminal "
                            "command runs unsandboxed", e)
            if proc is None:
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    cwd=self.cwd,
                    env=child_env,
                    **kwargs
                )
            if sys.platform == 'win32':
                # Orphan guard: shells die with this service even if
                # the service dies before running cleanup.
                _assign_to_kill_job(proc)
            self.current_process = proc
        except Exception as e:
            log_exception(e, 'Web Terminal subprocess start')
            self.write_message(f"\x1b[31mError: {e}\x1b[0m\r\n")
            self._send_prompt()
            self._set_busy(False)
            return

        def read_output():
            proc = self.current_process
            if proc is None:
                return
            ioloop = TerminalWebSocket.main_loop

            try:
                # Drain stdout/stderr incrementally on helper threads so
                # BOTH limits actually hold: wait(timeout) alone cannot
                # fire while a blocking read() is still consuming a
                # never-ending stream (e.g. `yes`, `tail -f`), and an
                # uncapped buffer would grow without bound. The readers
                # kill the process once MAX_OUTPUT is exceeded.
                out_chunks, err_chunks = [], []
                overflow = {'hit': False}

                def _drain(stream, chunks):
                    try:
                        while True:
                            data = stream.read(65536)
                            if not data:
                                break
                            chunks.append(data)
                            if sum(len(c) for c in chunks) > MAX_OUTPUT:
                                overflow['hit'] = True
                                _kill_process_tree(proc)
                                break
                    except Exception:  # noqa: BLE001 - best-effort drain
                        pass

                t_out = threading.Thread(
                    target=_drain, args=(proc.stdout, out_chunks),
                    daemon=True)
                t_err = threading.Thread(
                    target=_drain, args=(proc.stderr, err_chunks),
                    daemon=True)
                t_out.start()
                t_err.start()

                timed_out = False
                try:
                    proc.wait(timeout=CMD_TIMEOUT)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_process_tree(proc)
                    with suppress(Exception):  # best-effort reap
                        proc.wait(timeout=5)
                t_out.join(timeout=5)
                t_err.join(timeout=5)

                output = b''.join(out_chunks)
                stderr_data = b''.join(err_chunks)
                if stderr_data:
                    if output:
                        output += b'\r\n'
                    output += stderr_data

                truncated = overflow['hit'] or len(output) > MAX_OUTPUT
                output = output[:MAX_OUTPUT]

                text = output.decode('utf-8', errors='replace') if output else ''
                if truncated:
                    text += '\r\n\x1b[33m[output truncated at 1MB]\x1b[0m\r\n'
                if timed_out:
                    text += ("\r\n\x1b[33m[command timed out after "
                             f"{CMD_TIMEOUT}s]\x1b[0m\r\n")
                ioloop.add_callback(self._send_output, text)
                ioloop.add_callback(
                    self._after_command, cmd,
                    -1 if timed_out else proc.returncode)
            except Exception as e:
                log_exception(e, 'Web Terminal read output')
                ioloop.add_callback(self._send_output, f"\r\n\x1b[31mError: {e}\x1b[0m\r\n")
                ioloop.add_callback(self._after_command, cmd, -1)

        t = threading.Thread(target=read_output, daemon=True)
        t.start()

    def _send_output(self, text):
        """Send command output to client."""
        if text:
            text = text.replace('\n', '\r\n')
            try:
                self.write_message(text)
            except Exception as e:
                logger.warning("Failed to send terminal output: %s", e)
            if not text.endswith('\r\n'):
                self.write_message('\r\n')

    def _after_command(self, cmd, returncode):
        """Send final output after the command completes."""
        # Handle cd command
        parts = cmd.strip().split()
        if parts and parts[0].lower() == 'cd':
            if len(parts) > 1:
                target = ' '.join(parts[1:])
                if target == '..':
                    new_cwd = os.path.dirname(self.cwd)
                elif os.path.isabs(target):
                    new_cwd = target
                else:
                    new_cwd = os.path.join(self.cwd, target)
                if os.path.isdir(new_cwd):
                    self.cwd = os.path.normpath(new_cwd)
            else:
                home = os.environ.get('USERPROFILE') or os.path.expanduser('~')
                self.cwd = home if os.path.isdir(home) else (
                    'C:\\' if os.name == 'nt' else '/')

        self.current_process = None
        self._send_prompt()
        self._set_busy(False)


def make_app():
    """Build the FastAPI terminal application.

    ``GET /`` redirects to the React terminal page on the portal;
    ``/ws`` carries the command-executor WebSocket.
    """
    from fastapi import FastAPI
    from starlette.requests import Request
    from starlette.responses import RedirectResponse
    from starlette.websockets import WebSocket
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get('/')
    def root(request: Request):
        """The terminal UI is a React page on the portal — redirect.

        The WebSocket endpoint (/ws) is unchanged: the React client
        connects cross-port with the same vnc_session/vnc_ephemeral
        cookie this page used to require.
        """
        host = request.headers.get('host', '')
        resp = RedirectResponse(_portal_terminal_url(host))
        for name, value in _root_security_headers(
                tls_enabled=request.url.scheme == 'https').items():
            resp.headers[name] = value
        return resp

    @app.websocket('/ws')
    async def ws(websocket: WebSocket):
        origin = websocket.headers.get('origin', '')
        if not _is_origin_allowed(origin):
            await websocket.close(code=1008)
            return
        session = TerminalWebSocket(websocket)
        # Auth runs BEFORE accept — a rejected upgrade must not look
        # like an open socket to the client.
        if not session._authenticate():
            return
        await websocket.accept()
        loop = asyncio.get_running_loop()
        TerminalWebSocket.main_loop = _LoopAdapter(loop)
        session._loop = loop
        session.open()
        try:
            while True:
                message = await websocket.receive()
                if message['type'] == 'websocket.disconnect':
                    break
                if message['type'] != 'websocket.receive':
                    continue
                data = message.get('text')
                if data is None:
                    data = message.get('bytes') or b''
                    data = data.decode('utf-8', errors='replace')
                if len(data) > session.max_message_size:
                    await websocket.close(
                        code=1009, reason='message too large')
                    break
                session.on_message(data)
        except Exception as e:  # noqa: BLE001 - disconnect mid-recv
            logger.debug('Terminal receive ended: %s', e)
        finally:
            session.on_close()

    return app


def main():
    """Start the web terminal server (uvicorn)."""
    import uvicorn

    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_options = create_ssl_context(_config()['ssl_cert'], _config()['ssl_key'])
    if ssl_options:
        logger.info("SSL enabled: %s", _config()['ssl_cert'])
    else:
        logger.warning("No SSL (HTTP mode)")
    kwargs = {}
    if ssl_options:
        kwargs = {'ssl_certfile': _config()['ssl_cert'],
                  'ssl_keyfile': _config()['ssl_key']}

    logger.info("Web Terminal running on %s:%s",
                _config()['ttyd_host'], _config()['ttyd_port'])
    logger.info("URL: %s://127.0.0.1:%s",
                'https' if ssl_options else 'http',
                _config()['ttyd_port'])
    logger.info("Auth: %s:***", _config()['ttyd_username'])
    logger.info("Shell: %s", _config()['webterm_shell'])

    uvicorn.run(make_app(),
                host=_config()['ttyd_host'],
                port=_config()['ttyd_port'],
                log_level='warning', access_log=False,
                proxy_headers=False, **kwargs)


if __name__ == '__main__':
    main()
