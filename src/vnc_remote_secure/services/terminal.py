#!/usr/bin/env python3
"""
Web terminal server using tornado + xterm.js.
Replaces ttyd on Windows where ConPTY has issues.

Instead of using a PTY/ConPTY (which fails on Windows 11 25H2),
this implements a command executor: each command sent via WebSocket
is executed as a subprocess and the output is sent back.

Features:
  - Command history (arrow up/down)
  - Tab completion for files/dirs and basic commands
  - Multi-line paste support
  - Ctrl+C interrupt
  - cd/pwd/cls/exit/help built-in commands
  - ANSI color support
  - PowerShell or cmd.exe backend
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

from vnc_remote_secure.core.constants import DEFAULT_BIND_HOST, DEFAULT_WEBTERM_SHELL
from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import check_terminal_auth

logger = logging.getLogger(__name__)

# Load configuration from .env file (never hardcode credentials)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vnc_remote_secure.core.config import generate_random_password, load_env_file

load_env_file()

# Configuration - credentials read from environment, never hardcoded
from vnc_remote_secure.core.constants import (
    DEFAULT_CMD_TIMEOUT,
    DEFAULT_MAX_OUTPUT,
)
from vnc_remote_secure.core.constants import (
    DEFAULT_TTYD_PORT as _DEFAULT_TTYD_PORT,
)
from vnc_remote_secure.core.constants import (
    DEFAULT_TTYD_USERNAME as _DEFAULT_TTYD_USERNAME,
)

PORT = int(os.environ.get('TTYD_PORT', str(_DEFAULT_TTYD_PORT)))
HOST = os.environ.get('TTYD_HOST', DEFAULT_BIND_HOST)
USERNAME = os.environ.get('TTYD_USERNAME', _DEFAULT_TTYD_USERNAME)
PASSWORD = os.environ.get('TTYD_PASSWD', '')
if not PASSWORD:
    PASSWORD = generate_random_password(16)
    logger.warning("TTYD_PASSWD not set; generated a random password (not shown for security)")
CERT_FILE = os.environ.get('SSL_CERT', '')
KEY_FILE = os.environ.get('SSL_KEY', '')
SHELL = os.environ.get('WEBTERM_SHELL', DEFAULT_WEBTERM_SHELL)

# Common commands for tab completion (no duplicates)
COMMON_COMMANDS = [
    'dir', 'cd', 'echo', 'type', 'copy', 'del', 'move', 'ren', 'mkdir', 'rmdir',
    'tasklist', 'taskkill', 'ipconfig', 'netstat', 'ping', 'tracert', 'systeminfo',
    'python', 'python3', 'pip', 'git', 'node', 'npm', 'where', 'findstr', 'sort',
    'set', 'setx', 'hostname', 'whoami', 'ver', 'vol', 'tree', 'attrib', 'fc',
    'powershell', 'cmd', 'cls', 'exit', 'help', 'color', 'title', 'prompt',
    'netsh', 'sc', 'wmic', 'chkdsk', 'format', 'label', 'subst',
]

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Web Terminal</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
    <style>
        body { margin: 0; padding: 0; background: #1e1e1e; }
        #terminal { width: 100vw; height: 100vh; }
        #status { position: fixed; top: 5px; right: 10px; color: #888; font-family: monospace; font-size: 12px; z-index: 100; }
        #reconnect { position: fixed; bottom: 10px; right: 10px; z-index: 100; }
        #reconnect button { background: #333; color: #ccc; border: 1px solid #555; padding: 5px 15px; cursor: pointer; border-radius: 4px; }
        #reconnect button:hover { background: #444; }
    </style>
</head>
<body>
    <div id="status">Connecting...</div>
    <div id="reconnect" style="display:none;"><button onclick="location.reload()">Reconnect</button></div>
    <div id="terminal"></div>
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.js"></script>
    <script>
        const term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Consolas, "Courier New", monospace',
            theme: {
                background: '#1e1e1e',
                foreground: '#cccccc',
                cursor: '#ffffff',
                selection: 'rgba(255,255,255,0.3)',
            },
            scrollback: 5000,
            allowProposedApi: true,
        });
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        const linksAddon = new WebLinksAddon.WebLinksAddon();
        term.loadAddon(linksAddon);
        term.open(document.getElementById('terminal'));
        fitAddon.fit();

        const statusEl = document.getElementById('status');
        const reconnectEl = document.getElementById('reconnect');
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = protocol + '//' + location.host + '/ws';

        let ws = null;
        let inputBuffer = '';
        let history = [];
        let historyIndex = -1;
        let busy = false;

        function setStatus(text, color) {
            statusEl.textContent = text;
            statusEl.style.color = color || '#888';
        }

        function connect() {
            setStatus('Connecting...', '#ff9800');
            ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';

            ws.onopen = function() {
                setStatus('Connected', '#4caf50');
                reconnectEl.style.display = 'none';
            };
            ws.onmessage = function(event) {
                if (event.data instanceof ArrayBuffer) {
                    term.write(new Uint8Array(event.data));
                } else {
                    // Try to parse as JSON control message
                    try {
                        const msg = JSON.parse(event.data);
                        if (msg.type === 'busy') {
                            busy = msg.value;
                        } else if (msg.type === 'completion') {
                            handleCompletion(msg.suggestions, msg.input);
                        }
                    } catch (e) {
                        term.write(event.data);
                    }
                }
            };
            ws.onerror = function() {
                setStatus('Error', '#f44336');
            };
            ws.onclose = function() {
                setStatus('Disconnected', '#f44336');
                reconnectEl.style.display = 'block';
                setTimeout(connect, 3000);
            };
        }

        function clearCurrentLine() {
            // Clear the current input line
            term.write('\\r\\x1b[K');  // Carriage return + clear line
        }

        function redrawPrompt(input) {
            // Redraw prompt + input
            const prompt = window._currentPrompt || '>';
            term.write('\\r\\x1b[K' + prompt + input);
        }

        term.onData(function(data) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                if (busy) return;  // Ignore input while command is running

                // Handle special keys
                if (data === '\\r') {  // Enter
                    term.write('\\r\\n');
                    if (inputBuffer.trim()) {
                        history.push(inputBuffer);
                        if (history.length > 100) history.shift();
                    }
                    historyIndex = -1;
                    ws.send(JSON.stringify({ type: 'command', cmd: inputBuffer }));
                    inputBuffer = '';
                    busy = true;
                } else if (data === '\\u007f') {  // Backspace
                    if (inputBuffer.length > 0) {
                        inputBuffer = inputBuffer.slice(0, -1);
                        term.write('\\b \\b');
                    }
                } else if (data === '\\u0003') {  // Ctrl+C
                    term.write('^C\\r\\n');
                    ws.send(JSON.stringify({ type: 'interrupt' }));
                    inputBuffer = '';
                    historyIndex = -1;
                } else if (data === '\\u001b[A') {  // Arrow Up - history
                    if (history.length > 0) {
                        if (historyIndex === -1) {
                            historyIndex = history.length - 1;
                        } else if (historyIndex > 0) {
                            historyIndex--;
                        }
                        // Clear current line and show history entry
                        term.write('\\r\\x1b[K');
                        const prompt = window._currentPrompt || '>';
                        term.write(prompt + history[historyIndex]);
                        inputBuffer = history[historyIndex];
                    }
                } else if (data === '\\u001b[B') {  // Arrow Down - history
                    if (historyIndex !== -1) {
                        if (historyIndex < history.length - 1) {
                            historyIndex++;
                        } else {
                            historyIndex = -1;
                        }
                        term.write('\\r\\x1b[K');
                        const prompt = window._currentPrompt || '>';
                        if (historyIndex === -1) {
                            term.write(prompt);
                            inputBuffer = '';
                        } else {
                            term.write(prompt + history[historyIndex]);
                            inputBuffer = history[historyIndex];
                        }
                    }
                } else if (data === '\\u0009') {  // Tab - completion
                    if (inputBuffer) {
                        ws.send(JSON.stringify({ type: 'complete', input: inputBuffer }));
                    }
                } else if (data === '\\u001b[D') {  // Left arrow - ignore (no cursor movement)
                    // No-op: we don't support cursor movement in this simple terminal
                } else if (data === '\\u001b[C') {  // Right arrow - ignore
                    // No-op
                } else if (data === '\\u001b[H') {  // Home - ignore
                    // No-op
                } else if (data === '\\u001b[F') {  // End - ignore
                    // No-op
                } else if (data.charCodeAt(0) >= 32) {  // Printable chars
                    inputBuffer += data;
                    term.write(data);
                }
            }
        });

        function handleCompletion(suggestions, input) {
            if (!suggestions || suggestions.length === 0) {
                return;  // No completions, do nothing
            }
            if (suggestions.length === 1) {
                // Single match - complete it
                const completed = suggestions[0];
                // Replace the last word with the completion
                const parts = input.split(' ');
                parts[parts.length - 1] = completed;
                const newInput = parts.join(' ');
                // Clear line and rewrite
                term.write('\\r\\x1b[K');
                const prompt = window._currentPrompt || '>';
                term.write(prompt + newInput);
                inputBuffer = newInput;
            } else {
                // Multiple matches - show them
                term.write('\\r\\n');
                const line = suggestions.join('  ');
                term.write(line + '\\r\\n');
                const prompt = window._currentPrompt || '>';
                term.write(prompt + inputBuffer);
            }
        }

        window.addEventListener('resize', function() { fitAddon.fit(); });
        connect();
    </script>
</body>
</html>"""


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        auth = self.request.headers.get('Authorization', '')
        if not check_terminal_auth(auth):
            from vnc_remote_secure.core.errors import error_json
            body, status = error_json('Unauthorized', 401)
            self.set_status(status)
            self.set_header('WWW-Authenticate', 'Basic realm="Terminal"')
            self.set_header('Content-Type', 'application/json')
            self.write(body)
            return
        self.set_header('Content-Type', 'text/html')
        self.write(HTML_PAGE)


class TerminalWebSocket(tornado.websocket.WebSocketHandler):
    """Command executor terminal - runs each command as a subprocess."""

    main_ioloop = None

    # Allowed origins for WebSocket connections (prevents CSWSH)
    # Accept localhost, 127.0.0.1, and any configured LAN IP
    ALLOWED_ORIGINS = None  # Lazy-initialized

    def _get_allowed_origins(self):
        """Build set of allowed origins dynamically."""
        if self.ALLOWED_ORIGINS is not None:
            return self.ALLOWED_ORIGINS
        origins = set()
        for host in ['localhost', '127.0.0.1', '0.0.0.0']:
            origins.add(f'https://{host}:{PORT}')
            origins.add(f'http://{host}:{PORT}')
        # Add LAN IPs from environment
        lan_ips = os.environ.get('ALLOWED_LAN_IPS', '')
        if lan_ips:
            for ip in lan_ips.split(','):
                ip = ip.strip()
                if ip:
                    origins.add(f'https://{ip}:{PORT}')
                    origins.add(f'http://{ip}:{PORT}')
        TerminalWebSocket.ALLOWED_ORIGINS = origins
        return origins

    def check_origin(self, origin):
        """Reject WebSocket connections from unknown origins (prevents CSWSH)."""
        if not origin:
            return False
        allowed = self._get_allowed_origins()
        if origin in allowed:
            return True
        # Also allow same-host origins (any port)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(origin)
            host = parsed.hostname
            if host in ('localhost', '127.0.0.1', '::1'):
                return True
        except Exception as e:
            logger.debug("Origin parsing failed for '%s': %s", origin, e)
        logger.warning("Rejected WebSocket from origin: %s", origin)
        return False

    def open(self):
        auth = self.request.headers.get('Authorization', '')
        if not check_terminal_auth(auth):
            self.close(code=1008, reason='Unauthorized')
            return

        self.current_process = None
        self.cwd = os.environ.get('USERPROFILE', 'C:\\')
        self.history = []
        logger.info("Client connected from %s", self.request.remote_ip)

        self.write_message("\x1b[36m\r\n  VNC Remote Secure - Web Terminal\r\n\x1b[0m")
        self.write_message(f"\x1b[90m  Shell: {SHELL} | OS: {os.name}\r\n\x1b[0m")
        self.write_message(f"\x1b[90m  Working directory: {self.cwd}\r\n\x1b[0m")
        self.write_message("\x1b[90m  Type 'help' for commands, 'exit' to disconnect.\r\n\x1b[0m")
        self.write_message("\r\n")
        self._send_prompt()

    def _send_prompt(self):
        """Send the shell prompt with ANSI color."""
        if SHELL == 'powershell.exe':
            prompt = f"\x1b[33mPS {self.cwd}>\x1b[0m "
        else:
            short_cwd = self.cwd
            if len(short_cwd) > 35:
                short_cwd = "...\\" + os.path.basename(short_cwd)
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
                self.write_message('\x1b[2J\x1b[H')
                self._send_prompt()
                self._set_busy(False)
                return

            if cmd.lower() == 'help':
                self._show_help()
                self._send_prompt()
                self._set_busy(False)
                return

            if cmd.lower() == 'history':
                self._show_history()
                self._send_prompt()
                self._set_busy(False)
                return

            self._execute_command(cmd)

        elif msg_type == 'interrupt':
            if self.current_process and self.current_process.poll() is None:
                try:
                    self.current_process.terminate()
                    self.write_message('\r\n\x1b[31m^C\x1b[0m\r\n')
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

    def _show_help(self):
        """Show help text."""
        self.write_message('\r\n\x1b[36mAvailable commands:\x1b[0m\r\n')
        self.write_message('  \x1b[33mAny system command\x1b[0m  - dir, echo, python, etc.\r\n')
        self.write_message('  \x1b[33mcls/clear\x1b[0m          - Clear screen\r\n')
        self.write_message('  \x1b[33mhistory\x1b[0m            - Show command history\r\n')
        self.write_message('  \x1b[33mexit/quit\x1b[0m          - Disconnect\r\n')
        self.write_message('  \x1b[33mhelp\x1b[0m               - Show this help\r\n')
        self.write_message('\r\n\x1b[90mTips: Arrow Up/Down for history, Tab for completion\x1b[0m\r\n')

    def _show_history(self):
        """Show command history."""
        if not self.history:
            self.write_message('\r\n\x1b[90mNo commands in history.\x1b[0m\r\n')
        else:
            self.write_message('\r\n')
            for i, cmd in enumerate(self.history, 1):
                self.write_message(f'  \x1b[90m{i:4d}\x1b[0m  {cmd}\r\n')

    def _handle_completion(self, input_str):
        """Handle tab completion request."""
        suggestions = []

        parts = input_str.split()
        if len(parts) <= 1:
            # Completing the command itself
            prefix = parts[0] if parts else input_str
            # Match common commands
            suggestions = [c for c in COMMON_COMMANDS if c.startswith(prefix.lower())]
            # Also match executables in PATH
            if SHELL == 'cmd.exe':
                try:
                    result = subprocess.run(
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
        else:
            # Completing a file/directory argument
            last_word = parts[-1]
            # Sanitize: reject null bytes and control characters
            if '\x00' in last_word or any(ord(c) < 32 for c in last_word):
                self.write_message(json.dumps({
                    "type": "completion",
                    "suggestions": [],
                    "input": input_str
                }))
                return
            # Determine the directory to search
            if os.path.isabs(last_word):
                search_dir = os.path.dirname(last_word)
                prefix = os.path.basename(last_word)
            else:
                search_dir = self.cwd
                prefix = last_word

            if not os.path.isdir(search_dir):
                search_dir = self.cwd

            # Resolve and constrain to cwd tree to prevent arbitrary traversal
            try:
                real_search = os.path.realpath(search_dir)
                real_cwd = os.path.realpath(self.cwd)
                if not real_search.startswith(real_cwd):
                    search_dir = self.cwd
            except (OSError, ValueError) as e:
                logger.debug("Path validation failed: %s", e)
                search_dir = self.cwd

            try:
                pattern = os.path.join(search_dir, prefix + '*')
                for entry in glob.glob(pattern):
                    name = os.path.basename(entry)
                    if os.path.isdir(entry):
                        name += '\\'
                    suggestions.append(name)
            except Exception as e:
                logger.debug("Tab completion via glob failed: %s", e)

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

        if SHELL == 'powershell.exe':
            args = [
                'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                '-NoProfile', '-NonInteractive', '-Command', cmd
            ]
        else:
            args = ['C:\\Windows\\System32\\cmd.exe', '/c', cmd]

        try:
            # Build a sanitized environment for the child process so that
            # secrets loaded from .env (VNC_PASSWORD, TTYD_PASSWD, tokens, etc.)
            # are not exfiltrable via `set`/`env` commands run in the terminal.
            child_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    'VNC_PASSWORD', 'TTYD_PASSWD',
                    'LANDING_PASSWORD', 'DUCKDNS_TOKEN', 'FLASK_SECRET_KEY',
                    'AUTH_SECRET', 'SSL_KEY', 'USER_UI_PASSWORD',
                )
            }
            # CREATE_NO_WINDOW is Windows-only; on Linux the attribute does
            # not exist and passing it raises AttributeError.
            kwargs = {}
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            self.current_process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=self.cwd,
                env=child_env,
                **kwargs
            )
        except Exception as e:
            log_exception(e, 'Terminal subprocess start')
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
                stdout_data = proc.stdout.read()
                stderr_data = proc.stderr.read()
                proc.wait(timeout=CMD_TIMEOUT)

                output = b''
                if stdout_data:
                    output += stdout_data
                if stderr_data:
                    if output:
                        output += b'\r\n'
                    output += stderr_data

                # Truncate output to prevent memory exhaustion
                truncated = False
                if len(output) > MAX_OUTPUT:
                    output = output[:MAX_OUTPUT]
                    truncated = True

                text = output.decode('utf-8', errors='replace') if output else ''
                if truncated:
                    text += '\r\n\x1b[33m[output truncated at 1MB]\x1b[0m\r\n'
                ioloop.add_callback(self._send_output, text)
                ioloop.add_callback(self._after_command, cmd, proc.returncode)
            except subprocess.TimeoutExpired:
                proc.kill()
                ioloop.add_callback(self._send_output,
                    f"\r\n\x1b[33m[command timed out after {CMD_TIMEOUT}s]\x1b[0m\r\n")
                ioloop.add_callback(self._after_command, cmd, -1)
            except Exception as e:
                log_exception(e, 'Terminal read output')
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
                self.cwd = os.environ.get('USERPROFILE', 'C:\\')

        self.current_process = None
        self._send_prompt()
        self._set_busy(False)

    def on_close(self):
        logger.info("Client disconnected")
        if self.current_process:
            try:
                self.current_process.terminate()
            except Exception as e:
                logger.warning("Failed to terminate process on close: %s", e)
            self.current_process = None


def make_app():
    return tornado.web.Application([
        (r'/', MainHandler),
        (r'/ws', TerminalWebSocket),
    ])


def main():
    app = make_app()
    TerminalWebSocket.main_ioloop = tornado.ioloop.IOLoop.current()

    from vnc_remote_secure.security.certificates import create_ssl_context
    ssl_options = create_ssl_context(CERT_FILE, KEY_FILE)
    if ssl_options:
        logger.info("SSL enabled: %s", CERT_FILE)
    else:
        logger.warning("No SSL (HTTP mode)")

    app.listen(PORT, HOST, ssl_options=ssl_options)
    logger.info("Web terminal running on %s:%s", HOST, PORT)
    logger.info("URL: %s://localhost:%s", 'https' if ssl_options else 'http', PORT)
    logger.info("Auth: %s:***", USERNAME)
    logger.info("Shell: %s", SHELL)

    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        print("\n[Terminal] Shutting down...")
        tornado.ioloop.IOLoop.current().stop()


if __name__ == '__main__':
    main()
