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
    if host in ('0.0.0.0', '::', ''):
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
        import os as _os
        secret_persisted = _os.path.exists(secret_file)
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
                from vnc_remote_secure.core.paths import get_ssl_dir
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
                  f'— the public entry point is down')


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

    checks = []

    _check_config(checks, config)
    _check_directories(checks)
    _check_secrets(checks, config)
    _check_ssl(checks, config)

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
            ('flask', True, 'Flask'),             # user UI / hardened profiles require it
            ('tornado', True, 'tornado'),         # web terminal
            ('websockets', True, 'websockets'),   # audio/gamepad services
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

    # --- Summary ---
    counts = {'ok': 0, 'warn': 0, 'fail': 0, 'skip': 0}
    for c in checks:
        counts[c['status']] += 1

    result = {
        'checks': checks,
        'summary': counts,
        'healthy': counts['fail'] == 0,
    }
    return result


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
