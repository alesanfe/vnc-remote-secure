"""System readiness diagnostics for VNC Remote Secure.

The canonical Python doctor replaces the legacy Bash/PowerShell
``doctor`` commands. It checks configuration consistency, dependency
availability, and service readiness without delegating to shell
scripts.
"""
import logging
import os
import shutil
import sys

from vnc_remote_secure.core.config import get_config, load_env_file
from vnc_remote_secure.core.paths import (
    get_config_dir,
    get_data_dir,
    get_log_dir,
    get_run_dir,
    get_ssl_dir,
)
from vnc_remote_secure.security.profiles import (
    get_blocking_findings,
    validate_profile_consistency,
)

logger = logging.getLogger(__name__)


def _check_port(host: str, port: int) -> bool:
    """Return True if ``port`` is listening on ``host``.

    A wildcard bind (``0.0.0.0``/``::``) covers loopback too — connecting
    to the wildcard address itself is unreliable on Windows.
    """
    # justification: detection, not a bind
    if host in ('0.0.0.0', '::', ''):  # nosec B104
        host = '127.0.0.1'
    # Delegate to the shared probe — it selects AF_INET6 for IPv6
    # literal hosts, which a hardcoded AF_INET socket cannot reach.
    try:
        from vnc_remote_secure.core.processes import is_port_available
        return not is_port_available(port, host=host)
    except Exception:  # noqa: BLE001 - a probe failure means "not listening"
        return False


def _check_binary(name: str) -> bool:
    """Return True if a binary is on PATH."""
    return shutil.which(name) is not None


def _ok(checks, name, msg=''):
    checks.append({'name': name, 'status': 'ok', 'message': msg})


def _warn(checks, name, msg):
    checks.append({'name': name, 'status': 'warn', 'message': msg})


def _fail(checks, name, msg):
    checks.append({'name': name, 'status': 'fail', 'message': msg})


def _skip(checks, name, msg=''):
    checks.append({'name': name, 'status': 'skip', 'message': msg})


def _check_config(checks, config):
    """Add configuration checks (blockers, consistency, profile)."""
    # --- Configuration ---
    blockers = get_blocking_findings()
    if blockers:
        _fail(checks, 'config.blockers',
              f"{len(blockers)} blocking finding(s): " +
              '; '.join(b.get('message', '') for b in blockers))
    else:
        _ok(checks, 'config.blockers', 'No blocking security findings')

    warnings = validate_profile_consistency()
    if warnings:
        for w in warnings:
            _warn(checks, 'config.consistency', w)
    else:
        _ok(checks, 'config.consistency', 'Profile configuration is consistent')


def _check_directories(checks):
    """Add directory checks (config, data, logs, run, ssl)."""
    # --- Directories ---
    for name, path in [('config', get_config_dir()), ('data', get_data_dir()),
                       ('logs', get_log_dir()), ('run', get_run_dir()),
                       ('ssl', get_ssl_dir())]:
        if os.path.isdir(path):
            _ok(checks, f'dirs.{name}', path)
        else:
            _warn(checks, f'dirs.{name}', f'Directory does not exist: {path}')


def _check_secrets(checks, config):
    """Add secret checks (flask_key, auth_secret, vnc_password)."""
    # --- Secrets ---
    if config.get('vnc_password') and config['vnc_password'] not in (
            'changeme', 'admin123', 'password'):
        _ok(checks, 'secrets.vnc_password', 'Set and non-default')
    else:
        _fail(checks, 'secrets.vnc_password', 'VNC_PASSWORD is empty or default')

    # Flask secret key and auth secret are persisted to auth_secret.key
    # by _get_secret() when not set in the environment. Report as set
    # when either the env var or the persisted file is present.
    try:
        from vnc_remote_secure.security.authentication import _secret_file_path
        secret_file = _secret_file_path()
        secret_persisted = os.path.exists(secret_file)
    except (ImportError, OSError):
        secret_persisted = False

    if config.get('flask_secret_key') or secret_persisted:
        _ok(checks, 'secrets.flask_key', 'Set')
    else:
        _warn(checks, 'secrets.flask_key', 'FLASK_SECRET_KEY not set')

    if config.get('auth_secret') or secret_persisted:
        _ok(checks, 'secrets.auth_secret', 'Set')
    else:
        _warn(checks, 'secrets.auth_secret', 'AUTH_SECRET not set')


def _check_ssl(checks, config):
    """Add SSL/TLS checks (cert, key, tls validation)."""
    # --- TLS ---
    if config.get('tls_enabled'):
        cert = config.get('ssl_cert', '')
        key = config.get('ssl_key', '')
        # Fall back to the canonical ssl-dir discovery — the same
        # resolution create_ssl_context() uses — or the check warns
        # "certificates not found" on deployments actually serving TLS.
        if not (cert and key and os.path.isfile(cert) and os.path.isfile(key)):
            try:
                ssl_dir = get_ssl_dir()
                d_cert = os.path.join(ssl_dir, 'fullchain.pem')
                d_key = os.path.join(ssl_dir, 'privkey.pem')
                if os.path.isfile(d_cert) and os.path.isfile(d_key):
                    cert, key = d_cert, d_key
            except Exception:  # noqa: BLE001
                pass
        if cert and key and os.path.isfile(cert) and os.path.isfile(key):
            _ok(checks, 'tls.certificates', f'{cert}')
        else:
            _warn(checks, 'tls.certificates',
                  'TLS enabled but certificate files not found')
    else:
        _skip(checks, 'tls.certificates', 'TLS disabled')


def _check_webauthn(checks):
    """WebAuthn: enabled-but-unavailable, or unsafe inferred config."""
    try:
        from vnc_remote_secure.security.webauthn import rp_config_error, webauthn_available
    except ImportError:
        _skip(checks, 'webauthn', 'module unavailable')
        return
    if not os.environ.get('WEBAUTHN_ENABLED', '').strip():
        try:
            from vnc_remote_secure.security.profiles import get_profile
            if get_profile() in ('public-hardened', 'private-overlay'):
                _fail(checks, 'webauthn',
                      'disabled — hardened profile enforces '
                      'phishing-resistant policies no method can '
                      'satisfy')
                return
        except Exception:  # noqa: BLE001
            pass
        _skip(checks, 'webauthn', 'disabled')
        return
    if not webauthn_available():
        _warn(checks, 'webauthn',
              'WEBAUTHN_ENABLED=true but the webauthn package is not '
              'installed (pip install vnc-remote-secure[webauthn])')
        return
    err = rp_config_error()
    if err:
        _fail(checks, 'webauthn.origin', err)
    else:
        _ok(checks, 'webauthn.origin',
            'origin/RP ID explicit or deployment is direct')

    # State-based satisfiability: config validate proves the config
    # COULD satisfy strong-auth policies; only doctor can check the
    # deployment actually can (a credential must exist).
    try:
        from vnc_remote_secure.security.profiles import get_profile
        from vnc_remote_secure.security.webauthn import _load_store
        if get_profile() in ('public-hardened', 'private-overlay'):
            if not _load_store():
                _fail(checks, 'webauthn.credentials',
                      'Hardened profile enforces phishing-resistant '
                      'auth policies but no passkey is registered — '
                      'register an admin credential before relying on '
                      'this profile')
            else:
                _ok(checks, 'webauthn.credentials',
                    f"{len(_load_store())} passkey(s) registered")
    except Exception:  # noqa: BLE001 - best-effort diagnostic
        _skip(checks, 'webauthn.credentials', 'store unreadable')


def _check_shared_state(checks):
    """Add shared-state backend check.

    The service manager runs each service as a separate process, so
    single-use claims, rate limiting and revocation propagation need
    the cross-process SQLite backend. ``memory`` is only acceptable
    for development/test runs.
    """
    backend = os.environ.get('SHARED_STATE_BACKEND', 'sqlite').lower()
    try:
        profile = os.environ.get('SECURITY_PROFILE', 'development').lower()
    except Exception:  # noqa: BLE001
        profile = 'development'
    if backend == 'sqlite':
        _ok(checks, 'state.backend',
            'SQLite shared state (cross-process guarantees)')
    elif backend == 'memory':
        if profile in ('development', 'test'):
            _warn(checks, 'state.backend',
                  'In-memory backend — single-use claims, revocation '
                  'and rate limiting are process-local (dev only)')
        else:
            _fail(checks, 'state.backend',
                  'In-memory backend in a hardened profile — revoked '
                  'sessions and TOTP claims do not propagate across '
                  'service processes. Set SHARED_STATE_BACKEND=sqlite')
    else:
        _warn(checks, 'state.backend',
              f'Unknown backend {backend!r} — falling back to memory')
    # Detect silent degradation: SHARED_STATE_BACKEND=sqlite is set but
    # SQLiteBackend init failed and get_backend() fell back to memory.
    # Cross-process revocation, TOTP replay protection and single-use
    # claims would silently become per-process.
    if backend == 'sqlite':
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            actual = type(get_backend()).__name__
            if actual == 'MemoryBackend':
                _fail(checks, 'state.backend.effective',
                      'SQLite backend failed to initialize — running on '
                      'in-memory fallback. Revocations and single-use '
                      'claims do NOT propagate across processes. '
                      'Check logs for the SQLite init error.')
            else:
                _ok(checks, 'state.backend.effective',
                    f'Effective backend: {actual}')
        except Exception as e:  # noqa: BLE001 - probe is best-effort
            _warn(checks, 'state.backend.effective',
                  f'Could not probe effective backend: {e}')
    # Integrity check: the DB carries security state (revocations,
    # TOTP claims, rate limits) — a torn DB after a crash or AV
    # quarantine must surface here, not as silent auth anomalies.
    if backend == 'sqlite':
        try:
            import sqlite3 as _sq

            from vnc_remote_secure.core.paths import get_run_dir
            db_path = os.environ.get(
                'SHARED_STATE_DB_PATH',
                os.path.join(get_run_dir(), 'shared_state.db'))
            if os.path.isfile(db_path):
                conn = _sq.connect(
                    f'file:{db_path}?mode=ro', uri=True)
                try:
                    row = conn.execute(
                        'PRAGMA integrity_check').fetchone()
                finally:
                    conn.close()
                if row and row[0] == 'ok':
                    _ok(checks, 'state.integrity',
                        'shared_state.db integrity_check ok')
                else:
                    _fail(checks, 'state.integrity',
                          f'shared_state.db corrupt: '
                          f'{row[0] if row else "integrity_check failed"} '
                          '— see docs/runbook/recovery.md §2')
        except Exception as e:  # noqa: BLE001
            _warn(checks, 'state.integrity',
                  f'Could not run integrity_check: {e}')


def _check_runtime_deps(checks):
    """Optional-runtime dependencies whose absence silently disables features."""
    try:
        import psutil  # noqa: F401  # pylint: disable=unused-import
        _ok(checks, 'deps.psutil',
            'psutil present — stale-process reaping enabled')
    except ImportError:
        _warn(checks, 'deps.psutil',
              'psutil not installed — orphaned service processes are '
              'not reaped on restart. Install with: '
              'pip install "vnc-remote-secure[ops]"')
    try:
        import uvicorn  # noqa: F401  # pylint: disable=unused-import
        _ok(checks, 'deps.uvicorn',
            'uvicorn present — web surfaces served by the ASGI '
            'server')
    except ImportError:
        _warn(checks, 'deps.uvicorn',
              'uvicorn not installed — the web services cannot start. '
              'Install with: pip install "vnc-remote-secure"')


def _check_terminal_isolation(checks):
    """Warn when web-terminal shells run as the service account.

    The terminal service strips secret env vars from children, but the
    shell it spawns inherits the service's filesystem identity: it can
    read auth_secret.key, generated_credentials.env and config.env, and
    WRITE shared_state.db (erasing rate-limit lockouts, TOTP step
    claims and revocation markers). On Linux the privilege drop only
    applies when the service runs as root and WEBTERM_USER is set —
    the packaged systemd unit runs as the unprivileged 'vnc-remote'
    user, where setpriv is unavailable. In that case the bubblewrap
    sandbox (unprivileged user namespaces) is the second line of
    defence: it masks the secret dirs from the spawned shell.
    """
    if sys.platform == 'win32':
        try:
            from vnc_remote_secure.platform.windows.sandbox import _get_sid, sandbox_mode
            mode = sandbox_mode()
            if mode == 'off':
                _warn(checks, 'terminal.isolation',
                      'TERMINAL_WINDOWS_SANDBOX=off — terminal shells '
                      'can read the service data dir (auth_secret.key, '
                      'shared_state.db)')
            elif _get_sid() is not None:
                _ok(checks, 'terminal.isolation',
                    f'AppContainer sandbox ({mode}) — terminal shells '
                    'cannot read the user profile or service secrets')
            else:
                _warn(checks, 'terminal.isolation',
                      'AppContainer SID derivation failed — terminal '
                      'shells run unsandboxed')
        except Exception:  # noqa: BLE001 - probe is best-effort
            _warn(checks, 'terminal.isolation',
                  'Could not verify AppContainer sandbox availability')
        return
    try:
        euid = os.geteuid()  # pylint: disable=no-member
    except AttributeError:
        return
    webterm_user = os.environ.get('WEBTERM_USER', '').strip()
    if euid == 0 and webterm_user:
        _ok(checks, 'terminal.isolation',
            f'WEBTERM_USER={webterm_user} — shell drops privileges')
        return
    if euid == 0:
        _warn(checks, 'terminal.isolation',
              'Running as root without WEBTERM_USER — terminal shells '
              'spawn as root. Set WEBTERM_USER to an unprivileged user')
        return
    # Non-root service: a real uid drop is impossible, but the
    # bubblewrap sandbox still hides the service state dirs from the
    # spawned shell when unprivileged user namespaces are enabled.
    bwrap = shutil.which('bwrap')
    if bwrap:
        try:
            from vnc_remote_secure.services.terminal import _bwrap_usable
            usable = _bwrap_usable(bwrap)
        except Exception:  # noqa: BLE001 - probe is best-effort
            usable = False
        if usable:
            _ok(checks, 'terminal.isolation',
                'bubblewrap sandbox active — secret dirs (run, config, '
                'ssl, data, log) are masked from terminal shells')
            return
        _warn(checks, 'terminal.isolation',
              'bubblewrap installed but unprivileged user namespaces '
              'are disabled — terminal shells can read the service '
              'state dirs (auth_secret.key, shared_state.db)')
        return
    _warn(checks, 'terminal.isolation',
          'Not running as root and no bubblewrap — terminal shells '
          'run as the service account and can read auth_secret.key / '
          'write shared_state.db. Install bubblewrap, set '
          'TERMINAL_COMMAND_ALLOWLIST, or restrict terminal access')


def _check_gamepad_capability(checks):
    """Verify the platform can actually inject gamepad input.

    Only runs when GAMEPAD_ENABLED — an idle optional service failing
    a doctor check would be noise. Linux needs uinput (evdev device
    creation); Windows uses SendInput, which is a no-op from
    Session 0 — the check reports whether an interactive session is
    reachable, since 'driver' per se does not apply to SendInput.
    """
    from vnc_remote_secure.core.config import env_flag
    if not env_flag('GAMEPAD_ENABLED'):
        return
    if sys.platform == 'win32':
        # Best backend first: ViGEmBus gives a REAL XInput controller —
        # with it the SendInput/Session-0 caveat stops applying.
        try:
            import vgamepad  # noqa: F401  # pylint: disable=unused-import
            _ok(checks, 'gamepad.capability',
                'ViGEm available — real X360 XInput virtual '
                'controller (works even without an interactive '
                'session)')
            return
        except ImportError:
            pass
        try:
            import ctypes
            # WTSGetActiveConsoleSessionId: 0xFFFFFFFF when no
            # interactive console is attached — SendInput would
            # silently drop every injected event.
            session = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
            if session == 0xFFFFFFFF:
                _fail(checks, 'gamepad.capability',
                      'GAMEPAD_ENABLED but no interactive console '
                      'session and no ViGEmBus driver — SendInput '
                      'cannot inject from Session 0. Install ViGEmBus '
                      '+ `pip install vgamepad` or run the service in '
                      'the user session')
            else:
                _warn(checks, 'gamepad.capability',
                      'SendInput injection only (interactive session '
                      'present) — injects keyboard/mouse events, NOT '
                      'an XInput gamepad. Install ViGEmBus + '
                      '`pip install vgamepad` for real controller '
                      'emulation')
        except Exception:  # noqa: BLE001 - probe is best-effort
            _warn(checks, 'gamepad.capability',
                  'Could not verify interactive session for SendInput')
        return
    # Linux: uinput device creation requires evdev + /dev/uinput
    try:
        import evdev  # noqa: F401  # pylint: disable=unused-import
    except ImportError:
        _warn(checks, 'gamepad.capability',
              'GAMEPAD_ENABLED but evdev not installed — gamepad '
              'forwarding disabled. pip install evdev')
        return
    if os.path.exists('/dev/uinput'):
        _ok(checks, 'gamepad.capability',
            'uinput available — virtual gamepad can be created')
    else:
        _warn(checks, 'gamepad.capability',
              '/dev/uinput missing — load the uinput module '
              '(modprobe uinput) or gamepad injection will fail')


def _check_firewall(checks):
    """Add firewall checks (platform-aware)."""
    # --- Firewall (Windows only) ---
    # Rules are only required when something binds to a public
    # interface — a fully loopback deployment never traverses the
    # firewall, so missing rules are not a problem worth warning about.
    if sys.platform == 'win32':
        public_bind = os.environ.get(
            'PUBLIC_BIND_HOST', os.environ.get('BIND_HOST', '127.0.0.1'))
        needs_rules = public_bind not in ('127.0.0.1', 'localhost', '::1')
        try:
            from vnc_remote_secure.platform.windows.firewall import list_firewall_rules
            rules = list_firewall_rules()
            if rules:
                _ok(checks, 'firewall.rules', f'{len(rules)} VncRemoteSecure rule(s) found')
            elif needs_rules:
                _warn(checks, 'firewall.rules',
                      'No VncRemoteSecure firewall rules found '
                      f'(public bind {public_bind} configured)')
            else:
                _ok(checks, 'firewall.rules',
                    'Not needed (loopback-only deployment)')
        except (ImportError, OSError, RuntimeError) as e:
            _skip(checks, 'firewall.rules', f'Firewall check unavailable: {e}')


def _list_listeners():
    """Return [(address, port)] of TCP listeners, best-effort.

    psutil is preferred (works on every OS); falls back to parsing
    ``netstat -an`` — no admin rights needed for a socket listing.
    Returns ``None`` when enumeration is impossible, so callers can
    report ``skip`` rather than a false pass.
    """
    try:
        import psutil
        out = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN' and conn.laddr:
                out.append((conn.laddr.ip, conn.laddr.port))
        return out
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 - permission/platform errors
        return None
    import re
    import subprocess
    try:
        proc = subprocess.run(
            ['netstat', '-an'], capture_output=True, text=True,
            timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    out = []
    for line in proc.stdout.splitlines():
        if 'LISTEN' not in line.upper():
            continue
        m = re.search(r'(\S+):(\d+)\s+\S+:\S+\s+LISTEN', line)
        if m:
            out.append((m.group(1), int(m.group(2))))
    return out or None


def _is_loopback_addr(addr: str) -> bool:
    """Return True for loopback binds (127.x, ::1)."""
    return (addr.startswith('127.') or addr in ('::1', '[::1]'))


def _check_public_listeners(checks, config):
    """Fail if an internal-only service listens on a public address.

    The RFB port and the websockify bridge must NEVER be reachable
    off-host — RFB auth is 8-char DES and the bridge is the auth
    gateway's trust boundary. Other backend ports are only public when
    nginx is disabled and the operator explicitly bound them so —
    reported as ``warn`` then, ``fail`` when nginx is the entry point.
    """
    listeners = _list_listeners()
    if listeners is None:
        _skip(checks, 'security.public_listeners',
              'Could not enumerate listening sockets')
        return
    from vnc_remote_secure.core.service_manager import _service_port_map
    ports = _service_port_map(config)
    nginx = bool(config.get('nginx_enabled'))
    from vnc_remote_secure.security.profiles import get_profile
    hardened = get_profile() in (
        'public-hardened', 'private-overlay')
    ws_port = ports.get('websockify')
    rfb_port = ports.get('vnc')
    public = []
    rfb_public = False
    for addr, port in listeners:
        if _is_loopback_addr(addr):
            continue
        if port == ws_port:
            # The WebSocket→RFB bridge is the auth gateway's trust
            # boundary — it is never meant to be reachable off-host.
            _fail(checks, 'security.public_listeners',
                  f'websockify bridge listening on {addr}:{port} — '
                  'the auth gateway can be bypassed directly')
            return
        if port == rfb_port:
            rfb_public = addr
            continue
        if port in set(ports.values()):
            public.append(f'{addr}:{port}')
    if rfb_public and (nginx or hardened):
        _fail(checks, 'security.public_listeners',
              f'RFB port {rfb_port} listening publicly — the 8-char '
              'DES credential is the only barrier; set LoopbackOnly '
              'or keep the profile honest')
        return
    if public:
        if nginx:
            _fail(checks, 'security.public_listeners',
                  'Backend ports public while nginx is the entry '
                  f'point — gateway bypass possible: '
                  f'{", ".join(sorted(public))}')
        else:
            _warn(checks, 'security.public_listeners',
                  'Backend ports bound publicly (no nginx): '
                  f'{", ".join(sorted(public))}')
    elif rfb_public:
        _warn(checks, 'security.public_listeners',
              f'RFB port public on {rfb_public} — direct VNC clients '
              'rely on an 8-char DES password; prefer nginx+websockify')
    else:
        _ok(checks, 'security.public_listeners',
            'No internal service port bound publicly')


def _check_services(checks):
    """Add service checks (ports listening)."""
    # --- Service ports ---
    # Each service binds to its own host key (landing_host, ttyd_host,
    # ...) — probing every port on health_host would report false
    # "not listening" results whenever the per-service hosts diverge.
    config = get_config()
    checks_spec = [
        ('vnc', 'vnc_port', None),  # VNC binds loopback/its own socket
        ('novnc', 'novnc_port', 'novnc_host'),
        # websockify always binds 127.0.0.1 (_start_websockify forces
        # loopback regardless of BIND_HOST) — probe loopback, not
        # novnc_host, which may be a public bind.
        ('websockify', 'novnc_ws_port', None),
        ('terminal', 'ttyd_port', 'ttyd_host'),
        ('health', 'health_port', 'health_host'),
        ('landing', 'landing_port', 'landing_host'),
        ('user_ui', 'user_ui_port', 'user_ui_host'),
        ('audio', 'audio_stream_port', 'audio_stream_host'),
        ('gamepad', 'gamepad_port', 'gamepad_host'),
    ]
    # Optional services are reported as skipped (not silently absent)
    # so the operator can see they were intentionally not probed.
    _enabled_flag = {
        'health': 'health_web_enabled',
        'user_ui': 'user_ui_enabled',
        'audio': 'audio_stream_enabled',
        'gamepad': 'gamepad_enabled',
    }
    for name, port_key, host_key in checks_spec:
        flag = _enabled_flag.get(name)
        if flag and not config.get(flag, True):
            env_name = flag.upper()
            _skip(checks, f'ports.{name}',
                  f'Disabled via {env_name}=false')
            continue
        host = '127.0.0.1' if host_key is None else config.get(host_key, '127.0.0.1')
        port = config.get(port_key)
        if name == 'vnc' and sys.platform != 'win32':
            # TigerVNC binds 5900+N regardless of an explicit VNC_PORT —
            # probe where the server actually listens (same derivation
            # as services/vnc._vnc_port and _start_websockify).
            try:
                from vnc_remote_secure.services.vnc import _vnc_port
                port = _vnc_port(config.get('vnc_display', ':1'))
            except Exception:  # noqa: BLE001 - fall back to config
                pass
        if port and _check_port(host, int(port)):
            _ok(checks, f'ports.{name}', f'Listening on {host}:{port}')
        else:
            _skip(checks, f'ports.{name}', f'Not listening on {host}:{port}')
    # nginx is the public entry point when enabled — a dead proxy with
    # healthy backends still means a dead deployment, so probe it too.
    if config.get('nginx_enabled'):
        from vnc_remote_secure.core.constants import DEFAULT_NGINX_HTTPS_PORT
        ngx_port = config.get('nginx_https_port', DEFAULT_NGINX_HTTPS_PORT)
        if _check_port('127.0.0.1', int(ngx_port)):
            _ok(checks, 'ports.nginx', f'Listening on 127.0.0.1:{ngx_port}')
        else:
            _fail(checks, 'ports.nginx',
                  f'NGINX_ENABLED=true but nothing listens on {ngx_port} '
                  '— the public entry point is down')

    _check_public_listeners(checks, config)


def run_doctor(as_json: bool = False) -> dict:
    """Run all diagnostic checks and return a results dict.

    Args:
        as_json: When True the return dict is suitable for JSON output.

    Returns:
        A dict with ``checks`` (list of {name, status, message}) and
        ``summary`` (counts). ``status`` is one of ``ok``, ``warn``,
        ``fail``, ``skip``.
    """
    load_env_file()
    config = get_config()

    checks: list = []

    _check_config(checks, config)
    _check_directories(checks)
    _check_secrets(checks, config)
    _check_ssl(checks, config)
    _check_webauthn(checks)

    # --- Dependencies ---
    for binary in ('python3' if sys.platform != 'win32' else 'python',):
        if _check_binary(binary):
            _ok(checks, f'deps.{binary}', 'Found')
        else:
            _fail(checks, f'deps.{binary}', 'Not found on PATH')

    # VNC server binary — on Windows use the same discovery as the
    # adapter (ULTRAVNC_PATH, install dir, PATH, project bin/).
    if sys.platform == 'win32':
        try:
            from vnc_remote_secure.platform.windows.installer import _find_ultravnc
            found = _find_ultravnc()
        except (ImportError, OSError):
            found = None
        if found:
            _ok(checks, 'deps.vnc_server', found)
        else:
            _warn(checks, 'deps.vnc_server',
                  'winvnc.exe not found (may still work)')
    else:
        if _check_binary('vncserver'):
            _ok(checks, 'deps.vnc_server', 'vncserver')
        else:
            _warn(checks, 'deps.vnc_server',
                  'vncserver not on PATH (may still work)')

    # Python module dependencies required at runtime.
    import importlib.util
    for module, critical, pip_name in (
            ('websockify', True, 'websockify'),   # WebSocket->RFB bridge (desktop access)
            ('fastapi', True, 'fastapi'),         # all HTTP/WS surfaces
            ('uvicorn', True, 'uvicorn'),         # ASGI server
            ('websockets', True, 'websockets'),   # noVNC upstream client
            ('cryptography', True, 'cryptography'),  # TLS, backup encryption
            ('Crypto', True, 'pycryptodome'),     # VNC DES password handling (vendor/d3des)
    ):
        if importlib.util.find_spec(module) is not None:
            _ok(checks, f'deps.py.{module}', 'Installed')
        elif critical:
            _fail(checks, f'deps.py.{module}',
                  f'Missing — install with: pip install {pip_name}')

    _check_services(checks)
    _check_firewall(checks)
    _check_shared_state(checks)
    _check_runtime_deps(checks)
    _check_terminal_isolation(checks)
    _check_gamepad_capability(checks)

    # --- Summary ---
    counts = {'ok': 0, 'warn': 0, 'fail': 0, 'skip': 0}
    for c in checks:
        counts[c['status']] += 1

    return {
        'checks': checks,
        'summary': counts,
        'healthy': counts['fail'] == 0,
    }


def format_doctor(result: dict) -> str:
    """Format doctor results for terminal output."""
    lines = []
    for c in result['checks']:
        symbol = {'ok': '[OK]', 'warn': '[WARN]', 'fail': '[FAIL]',
                  'skip': '[SKIP]'}[c['status']]
        lines.append(f"  {symbol:<7} {c['name']:<25} {c['message']}")
    s = result['summary']
    lines.append('')
    lines.append(f"  Summary: {s['ok']} ok, {s['warn']} warnings, "
                 f"{s['fail']} failures, {s['skip']} skipped")
    return '\n'.join(lines)
