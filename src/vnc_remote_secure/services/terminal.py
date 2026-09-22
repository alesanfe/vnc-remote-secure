#!/usr/bin/env python3
"""
Web Terminal server using tornado + xterm.js.
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
import glob
import json
import logging
import os
import subprocess
import sys
import threading

import tornado.ioloop
import tornado.web
import tornado.websocket

from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import (
    check_terminal_auth,
    client_ip_from,
)

logger = logging.getLogger(__name__)

# Load configuration from .env file (never hardcode credentials)
from vnc_remote_secure.core.config import load_env_file

load_env_file()

# Configuration - credentials read from environment, never hardcoded
from vnc_remote_secure.core.constants import (
    DEFAULT_CMD_TIMEOUT,
    DEFAULT_MAX_OUTPUT,
)


def _config():
    """Lazy config accessor — reads get_config() on each call so .env changes take effect."""
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


def _html_page() -> str:
    """Return the terminal HTML page.

    The markup lives in ``static/terminal.html`` (package-data) so it
    can be linted/versioned separately; loaded lazily so a missing
    asset raises at request time, not at import.
    """
    from importlib import resources
    return resources.files('vnc_remote_secure').joinpath(
        'static/terminal.html').read_text(encoding='utf-8')


class MainHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        from vnc_remote_secure.security.http_headers import get_security_headers
        # HSTS only when this app was started with an SSL context —
        # main() stores it so per-request handlers don't rebuild it.
        tls = getattr(self.application, '_vnc_tls_enabled', False)
        headers = get_security_headers(tls_enabled=tls)
        # The terminal page loads xterm.js from the vendored /xterm/
        # static route — no CDN dependency, so the strict 'self' CSP
        # applies (the page's inline handlers still need
        # 'unsafe-inline'). An explicit CSP_POLICY env override wins
        # over this default.
        if not os.environ.get('CSP_POLICY'):
            headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; "
                "connect-src 'self' wss: ws:; "
                "font-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'"
            )
        for name, value in headers.items():
            self.set_header(name, value)

    def _ephemeral_authorized(self) -> bool:
        """True when the vnc_ephemeral cookie grants terminal access."""
        cookie = self.request.headers.get('Cookie', '')
        eph = ''
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_ephemeral='):
                eph = part.split('=', 1)[1].strip()
                break
        if not eph:
            return False
        from vnc_remote_secure.security.ephemeral_sessions import check_session_permission
        return check_session_permission(
            eph, 'terminal:use', resource='terminal',
            client_ip=client_ip_from(
                    self.request.headers, self.request.remote_ip))

    def _session_authorized(self) -> bool:
        """True when a valid ``vnc_session`` cookie authenticates the
        request — the WebSocket upgrade already accepts the session
        cookie, so the page must too or a portal-authenticated user is
        double-challenged with Basic credentials the WS does not need.
        """
        cookie = self.request.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_session='):
                raw = part.split('=', 1)[1].strip()
                from vnc_remote_secure.security.auth_gateway import (
                    check_authenticated,
                )
                allowed, _user = check_authenticated(raw, '')
                return bool(allowed)
        return False

    def get(self):
        auth = self.request.headers.get('Authorization', '')
        if not (self._ephemeral_authorized()
                or self._session_authorized()
                or check_terminal_auth(
                    auth, client_ip=client_ip_from(
                        self.request.headers, self.request.remote_ip))):
            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Unauthorized', 401)
            self.set_status(status)
            self.set_header('WWW-Authenticate', 'Basic realm="Web Terminal"')
            self.set_header('Content-Type', 'application/json')
            self.write(body)
            return
        self.set_header('Content-Type', 'text/html')
        self.write(_html_page())


def _is_origin_allowed(origin):
    """Reject WebSocket connections from unknown origins (prevents CSWSH).

    Delegates to the canonical auth-gateway origin list so Tornado and
    the rest of the stack enforce the same policy (ALLOWED_ORIGINS +
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


def _restricted_user_prefix():
    """Return argv prefix to drop privileges to ``WEBTERM_USER``.

    When ``WEBTERM_USER`` names an existing account and this process
    runs as root, terminal commands are spawned as that user instead
    of the service account — the shell can no longer read the
    service's secrets, PID files or other services' state. Prefers
    ``setpriv`` (no PAM), falls back to ``runuser``. Returns ``None``
    when privilege dropping is unavailable or not configured.
    """
    import pwd
    import shutil as _shutil

    user = os.environ.get('WEBTERM_USER', '').strip()
    if not user:
        return None
    if os.geteuid() != 0:
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


def _build_subprocess_args(cmd, shell, cwd):
    """Build the subprocess argument list for the configured shell."""
    import shutil as _shutil
    if os.name == 'posix':
        # POSIX shell (bash/sh/zsh): the configured WEBTERM_SHELL or a
        # sane fallback — cmd.exe does not exist here.
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
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
    except Exception:  # noqa: BLE001 - kill is best-effort
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


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


class TerminalWebSocket(tornado.websocket.WebSocketHandler):
    """Command executor terminal - runs each command as a subprocess."""

    main_ioloop = None
    # Terminal commands are short JSON envelopes — a multi-MB frame is
    # only a memory-exhaustion attempt (Tornado default is 10 MiB).
    max_message_size = 64 * 1024

    def check_origin(self, origin):
        """Reject WebSocket connections from unknown origins (prevents CSWSH)."""
        return _is_origin_allowed(origin)

    def open(self):
        auth = self.request.headers.get('Authorization', '')
        # First, try ephemeral session token (Bearer) via auth_gateway
        # so that revocation and per-action permissions are enforced.
        bearer = ''
        if auth.lower().startswith('bearer '):
            bearer = auth[7:].strip()
        cookie = self.request.headers.get('Cookie', '')
        # Extract session cookie value if present.
        cookie_value = ''
        eph = ''
        if cookie:
            for part in cookie.split(';'):
                part = part.strip()
                if part.startswith('vnc_session='):
                    cookie_value = part.split('=', 1)[1].strip()
                elif part.startswith('vnc_ephemeral='):
                    eph = part.split('=', 1)[1].strip()
        origin = self.request.headers.get('Origin', '')
        # Token credentials (ephemeral cookie, bearer, session cookie)
        # all resolve through the gateway's single enforcement tree.
        if eph or bearer or cookie_value:
            from vnc_remote_secure.security.auth_gateway import (
                check_websocket_upgrade,
                register_websocket_connection,
            )
            allowed, reason = check_websocket_upgrade(
                origin=origin,
                cookie_value=cookie_value,
                bearer_token=bearer,
                resource='terminal',
                required_permission='terminal:use',
                client_ip=client_ip_from(
                    self.request.headers, self.request.remote_ip),
                ephemeral_cookie=eph,
            )
            if not allowed:
                self.close(code=1008, reason=reason)
                return
            # Step-up auth applies to operator sessions — skip it only
            # when the ephemeral cookie is the SOLE credential (the
            # previous behavior): a session that is already
            # permission-bound has no username for step-up to challenge.
            if bearer or cookie_value:
                from vnc_remote_secure.security.auth_gateway import check_authenticated
                from vnc_remote_secure.security.step_up_auth import require_step_up
                _authed, ws_user = check_authenticated(cookie_value, bearer)
                if ws_user:
                    step_up_err = require_step_up(ws_user, 'open_terminal')
                    if step_up_err:
                        self.close(code=1008, reason=step_up_err)
                        return
            # Register the connection so revocation can close it live.
            token = eph or bearer or cookie_value
            self._ws_conn_id = register_websocket_connection(
                token, self.close, resource='terminal',
            )
            if self._ws_conn_id is None:
                self.close(code=1008, reason='Session revoked')
                return
            # Cross-process revocation watcher — a CLI-issued revoke
            # only marks shared state; this closes the live socket.
            from vnc_remote_secure.security.websocket_registry import (
                start_revocation_watcher,
            )
            start_revocation_watcher(token)
        elif not check_terminal_auth(
                auth, client_ip=client_ip_from(
                    self.request.headers, self.request.remote_ip)):
            self.close(code=1008, reason='Unauthorized')
            return
        else:
            self._ws_conn_id = None

        self.current_process = None
        home = os.environ.get('USERPROFILE') or os.path.expanduser('~')
        self.cwd = home if os.path.isdir(home) else (
            'C:\\' if os.name == 'nt' else '/')
        self.history = []
        logger.info("Client connected from %s", self.request.remote_ip)

        self.write_message("\x1b[36m\r\n  VNC Remote Secure - Web Terminal\r\n\x1b[0m")
        self.write_message(
            f"\x1b[90m  Shell: {_config()['webterm_shell']} | "
            f"OS: {os.name}\r\n\x1b[0m")
        self.write_message(f"\x1b[90m  Working directory: {self.cwd}\r\n\x1b[0m")
        self.write_message("\x1b[90m  Type 'help' for commands, 'exit' to disconnect.\r\n\x1b[0m")
        self.write_message("\r\n")
        self._send_prompt()

    def on_close(self):
        """Clean up on WebSocket close.

        Unregisters the connection from the revocation registry (so
        revoked sessions stop receiving terminal output) and terminates
        any running child process.
        """
        conn_id = getattr(self, '_ws_conn_id', None)
        if conn_id:
            try:
                from vnc_remote_secure.security.auth_gateway import (
                    unregister_websocket_connection,
                )
                unregister_websocket_connection(conn_id)
            except Exception as e:
                logger.debug("Failed to unregister WebSocket: %s", e)
            self._ws_conn_id = None
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

    def on_message(self, message):
        try:
            msg = json.loads(message)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Ignoring malformed terminal message: %s", exc)
            return

        msg_type = msg.get('type')

        if msg_type == 'command':
            cmd = msg.get('cmd', '').strip()
            if not cmd:
                self.write_message('\r\n')
                self._send_prompt()
                self._set_busy(False)
                return

            # Add to history
            self.history.append(cmd)

            # Handle built-in commands
            if cmd.lower() in ('exit', 'quit'):
                self.write_message('\r\n\x1b[90mGoodbye.\x1b[0m\r\n')
                self.close()
                return

            if cmd.lower() in ('cls', 'clear'):
                self.write_message(_clear_text())
                self._send_prompt()
                self._set_busy(False)
                return

            if cmd.lower() == 'help':
                self.write_message(_help_text())
                self._send_prompt()
                self._set_busy(False)
                return

            if cmd.lower() == 'history':
                self.write_message(_history_text(self.history))
                self._send_prompt()
                self._set_busy(False)
                return

            # TERMINAL_COMMAND_ALLOWLIST: comma-separated regexes. When
            # set, only matching commands may spawn — a defense-in-depth
            # knob for deployments where the shell cannot drop
            # privileges (non-root service user) and terminal access
            # should be scoped to a few diagnostics commands.
            allowlist = os.environ.get(
                'TERMINAL_COMMAND_ALLOWLIST', '').strip()
            if allowlist:
                import re
                patterns = [p.strip() for p in allowlist.split(',')
                            if p.strip()]
                try:
                    allowed = any(re.fullmatch(p, cmd) for p in patterns)
                except re.error:
                    logger.error(
                        "Invalid TERMINAL_COMMAND_ALLOWLIST regex — "
                        "denying command")
                    allowed = False
                if not allowed:
                    self.write_message(
                        '\r\n\x1b[31mCommand not allowed by '
                        'TERMINAL_COMMAND_ALLOWLIST\x1b[0m\r\n')
                    self._send_prompt()
                    self._set_busy(False)
                    return

            self._execute_command(cmd)

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
            # A previous command may still be running if two 'command'
            # messages raced — overwriting current_process here would
            # orphan it from interrupt/on_close cleanup.
            prev = self.current_process
            if prev is not None and prev.poll() is None:
                try:
                    prev.terminate()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass
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
            ioloop = TerminalWebSocket.main_ioloop

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
                    try:
                        proc.wait(timeout=5)
                    except Exception:  # noqa: BLE001 - best-effort reap
                        pass
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
        """Called after command completes."""
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


class XtermStaticHandler(tornado.web.StaticFileHandler):
    """Static handler for the vendored xterm assets, auth-gated.

    The rest of the terminal service requires authentication — an
    unauthenticated static route would fingerprint the deployment and
    violate the everything-behind-the-gateway posture. Same checks as
    the terminal page itself (Basic auth or ephemeral cookie).
    """

    def _authorized(self) -> bool:
        cookie = self.request.headers.get('Cookie', '')
        eph = ''
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_ephemeral='):
                eph = part.split('=', 1)[1].strip()
                break
        if eph:
            from vnc_remote_secure.security.ephemeral_sessions import (
                check_session_permission,
            )
            return check_session_permission(
                eph, 'terminal:use', resource='terminal',
                client_ip=client_ip_from(
                    self.request.headers, self.request.remote_ip))
        # A valid vnc_session cookie authorizes the terminal — the
        # WebSocket upgrade already accepts it, so the page's static
        # assets must too or session-authenticated users break on
        # xterm.js fetches (401 JS = blank terminal).
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('vnc_session='):
                raw = part.split('=', 1)[1].strip()
                from vnc_remote_secure.security.auth_gateway import (
                    check_authenticated,
                )
                allowed, _user = check_authenticated(raw, '')
                if allowed:
                    return True
                break
        auth = self.request.headers.get('Authorization', '')
        return check_terminal_auth(
            auth, client_ip=client_ip_from(
                self.request.headers, self.request.remote_ip))

    async def get(self, path, include_body=True):
        if not self._authorized():
            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Unauthorized', 401)
            self.set_status(status)
            self.set_header('WWW-Authenticate', 'Basic realm="Web Terminal"')
            self.set_header('Content-Type', 'application/json')
            self.write(body)
            return
        await super().get(path, include_body)


def _xterm_static_dir() -> str:
    """Return the vendored xterm.js assets directory.

    The terminal page must be self-hosted: loading xterm.js from a CDN
    would break offline deployments and ship an unaudited third-party
    script into an authenticated session. The assets live under the
    package so they resolve in both source and installed layouts.
    """
    try:
        from importlib.resources import files
        return str(files('vnc_remote_secure') / 'static' / 'xterm')
    except Exception:  # noqa: BLE001 - source-tree fallback
        import os as _os
        return _os.path.join(
            _os.path.dirname(_os.path.dirname(
                _os.path.abspath(__file__))), 'static', 'xterm')


def make_app():
    return tornado.web.Application([
        (r'/', MainHandler),
        (r'/ws', TerminalWebSocket),
        (r'/xterm/(.*)', XtermStaticHandler,
         {'path': _xterm_static_dir()}),
    ])


def main():
    app = make_app()
    TerminalWebSocket.main_ioloop = tornado.ioloop.IOLoop.current()

    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_options = create_ssl_context(_config()['ssl_cert'], _config()['ssl_key'])
    if ssl_options:
        logger.info("SSL enabled: %s", _config()['ssl_cert'])
    else:
        logger.warning("No SSL (HTTP mode)")
    # Per-request handlers read this flag to decide whether HSTS
    # applies (see MainHandler.set_default_headers).
    app._vnc_tls_enabled = ssl_options is not None

    app.listen(_config()['ttyd_port'], _config()['ttyd_host'],
               ssl_options=ssl_options)
    logger.info("Web Terminal running on %s:%s",
                _config()['ttyd_host'], _config()['ttyd_port'])
    logger.info("URL: %s://127.0.0.1:%s",
                'https' if ssl_options else 'http',
                _config()['ttyd_port'])
    logger.info("Auth: %s:***", _config()['ttyd_username'])
    logger.info("Shell: %s", _config()['webterm_shell'])

    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        logger.info("Web Terminal shutting down...")
        tornado.ioloop.IOLoop.current().stop()


if __name__ == '__main__':
    main()
