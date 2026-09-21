#!/usr/bin/env python3
"""
Shared configuration loader for VNC Remote Secure Python components.
Reads .env file and provides environment variables with secure defaults.
NEVER hardcode credentials - always read from environment or .env file.
"""
import logging
import os
import secrets
import string

from vnc_remote_secure.core.constants import (
    DEFAULT_AUDIO_STREAM_PORT,
    DEFAULT_BIND_HOST,
    DEFAULT_GAMEPAD_PORT,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NGINX_HTTP_PORT,
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_NOVNC_WS_PORT,
    DEFAULT_SESSION_IDLE_TIMEOUT,
    DEFAULT_SESSION_MAX_LIFETIME,
    DEFAULT_SESSION_SAMESITE,
    DEFAULT_TTYD_PORT,
    DEFAULT_TTYD_USERNAME,
    DEFAULT_USER_UI_PORT,
    DEFAULT_VNC_DEPTH,
    DEFAULT_VNC_DISPLAY,
    DEFAULT_VNC_GEOMETRY,
    DEFAULT_VNC_HTTP_PORT,
    DEFAULT_VNC_PORT,
    DEFAULT_WEBTERM_SHELL,
    TIGERVNC_BASE_PORT,
)

logger = logging.getLogger(__name__)


def _find_project_root():
    """Find project root by searching upward for .env or .env.example.

    Delegates to the canonical helper in ``core.paths``.
    """
    from vnc_remote_secure.core.paths import find_project_root
    return find_project_root()


def normalize_duck_domain(value: str = '') -> str:
    """Normalize ``DUCK_DOMAIN`` to a full hostname.

    Operators enter both forms — ``mysub`` (the DuckDNS "subdomain")
    and ``mysub.duckdns.org``. DuckDNS update API calls want the bare
    token (duckdns_update.py strips the suffix), but every consumer
    that builds a hostname — nginx ``server_name``, share-link URLs,
    auto-generated ALLOWED_ORIGINS — needs the FQDN. A bare value is
    interpreted as a DuckDNS subdomain; anything containing a dot is
    returned as-is (real custom domains pass through untouched).
    """
    d = (value or '').strip()
    if not d:
        return ''
    if '.' not in d:
        return f'{d}.duckdns.org'
    return d


def _is_tls_enabled_env() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    ``DISABLE_SSL=true`` is an explicit kill-switch and wins over
    ``TLS_ENABLED``: .env.example ships ``TLS_ENABLED=true``, so an
    operator adding ``DISABLE_SSL=true`` on top must actually get plain
    HTTP — otherwise the documented "both are equivalent" claim is
    false and the kill-switch is silently ignored.
    """
    disable_val = os.environ.get('DISABLE_SSL', '').strip()
    if disable_val.lower() in ('true', '1', 'yes'):
        return False
    tls_val = os.environ.get('TLS_ENABLED', '').strip()
    if tls_val:
        return tls_val.lower() in ('true', '1', 'yes')
    if disable_val:
        return disable_val.lower() not in ('true', '1', 'yes')
    return True


def _parse_env_file(path):
    """Parse a .env-style file and yield (key, value) pairs."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, _, val = line.partition('=')
                key = key.strip()
                val = val.strip()
                # Remove surrounding quotes
                if val and val[0] in '"\'' and val[-1] == val[0]:
                    val = val[1:-1]
                # Skip shell command substitutions — `$(` ANYWHERE in
                # the value (and backticks) evaluates when a wrapper
                # does `source .env` (duckdns_update.sh, rpi wrapper).
                # startswith() alone missed `FOO=x$(id)`.
                if '$(' in val or '`' in val:
                    logger.warning(
                        "Skipping %s: value contains shell substitution",
                        key)
                    continue
                # Expand ${VAR} references from the current environment.
                # Unknown variables expand to an empty string, mirroring
                # the behavior of most shells when `set -u` is off.
                if '${' in val:
                    import re
                    val = re.sub(
                        r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',
                        lambda m: os.environ.get(m.group(1), ''),
                        val,
                    )
                yield key, val
    except Exception as e:
        logger.warning("Failed to load env file '%s': %s", path, e)


def _load_platform_defaults(project_root):
    """Load platform-aware defaults from config/defaults/.

    Loads ``common.env`` first, then ``{linux,windows}.env`` based on
    the current platform. Existing environment variables are NOT
    overridden — these are only defaults.

    Resolution order:
      1. ``<project_root>/src/vnc_remote_secure/config/defaults/``
         (post-consolidation development checkout).
      2. ``<project_root>/config/defaults/`` (legacy layout).
      3. ``importlib.resources`` from the installed package (wheel install).
    """
    # Candidate directories: package-relative, legacy project root, then
    # importlib.resources (works for pip-installed wheels).
    candidates = []
    if project_root:
        candidates.append(os.path.join(
            project_root, 'src', 'vnc_remote_secure', 'config', 'defaults'))
        candidates.append(os.path.join(project_root, 'config', 'defaults'))
    # Package-relative fallback (works for pip-installed wheels).
    try:
        from importlib.resources import files

        pkg_defaults = os.path.join(str(files('vnc_remote_secure') / 'config' / 'defaults'))
        candidates.append(pkg_defaults)
    except Exception:  # noqa: BLE001 - importlib.resources not available or package missing
        pass

    defaults_dir = next((d for d in candidates if d and os.path.isdir(d)), None)
    if not defaults_dir:
        return
    # Load common.env, then platform-specific.
    import platform as _platform
    is_windows = _platform.system() == 'Windows'
    platform_file = 'windows.env' if is_windows else 'linux.env'
    for name in ('common.env', platform_file):
        path = os.path.join(defaults_dir, name)
        if not os.path.isfile(path):
            continue
        for key, val in _parse_env_file(path):
            if key not in os.environ:
                os.environ[key] = val


_ENV_LOADED = False


def _system_env_path():
    """Return the system config.env path for this platform, or None."""
    from vnc_remote_secure.platform.detection import is_windows
    if is_windows():
        return os.path.join(
            os.environ.get('ProgramData', r'C:\ProgramData'),
            'VncRemoteSecure', 'config.env')
    return '/etc/vnc-remote-secure/config.env'


def set_env_persistent(name: str, value: str) -> bool:
    """Update ``name=value`` in the effective env file and ``os.environ``.

    Used by secret rotation and by one-shot credential consumption
    (e.g. used recovery codes) so runtime state changes survive the
    process. The write goes to whichever file actually holds the key —
    an installed deployment keeps secrets in the system ``config.env``
    (``/etc/vnc-remote-secure`` or ``%ProgramData%``); writing only to
    the project ``.env`` would leave the stale value active for the
    service (which reads config.env via EnvironmentFile). Falls back
    to the project ``.env`` when the key lives nowhere else; applies
    ``0o600`` to the file afterwards.

    Returns ``True`` on success.
    """
    # The value lands as a raw line in the env file — a CR/LF would
    # inject additional variables. Reject rather than sanitise so a
    # caller bug surfaces loudly instead of silently mangling config.
    if '\r' in str(value) or '\n' in str(value):
        logger.error("Refusing to persist env value containing CR/LF")
        return False
    if not name or '=' in name or '\r' in name or '\n' in name:
        logger.error("Refusing to persist invalid env var name %r", name)
        return False
    env_path = os.path.join(_find_project_root(), '.env')
    # Prefer the file that already defines the key.
    for candidate in (_system_env_path(), env_path):
        if candidate and os.path.isfile(candidate):
            try:
                with open(candidate, encoding='utf-8') as f:
                    content = f.read()
            except OSError:
                continue
            for ln in content.splitlines():
                s = ln.strip()
                if (s and not s.startswith('#') and '=' in ln
                        and ln.split('=', 1)[0].strip() == name):
                    env_path = candidate
                    break
            else:
                continue
            break
    lines = []
    if os.path.isfile(env_path):
        try:
            with open(env_path, encoding='utf-8') as f:
                lines = f.read().splitlines()
        except OSError:
            return False
    out, found = [], False
    for ln in lines:
        stripped = ln.strip()
        if stripped and not stripped.startswith('#') and '=' in ln:
            if ln.split('=', 1)[0].strip() == name:
                out.append(f'{name}={value}')
                found = True
                continue
        out.append(ln)
    if not found:
        out.append(f'{name}={value}')
    try:
        # Write to a temp file then os.replace() — a crash mid-write
        # of the target file would truncate the .env in place and lose
        # every other variable.
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(env_path) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write('\n'.join(out) + '\n')
            os.replace(tmp, env_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass
    except OSError:
        return False
    os.environ[name] = value
    return True


def load_env_file(env_path=None):
    """Load .env file into os.environ.

    Precedence (highest wins):
        real env > project ``.env`` > system ``config.env``
        (``/etc/vnc-remote-secure/config.env`` or
        ``%ProgramData%\\VncRemoteSecure\\config.env``)
        > platform-aware defaults (``config/defaults/``).

    The default merge runs once per process — hot paths (per-request
    auth checks) call this function on every request, so re-parsing
    the env files each time would add pointless disk I/O. Passing an
    explicit ``env_path`` always performs the load.
    """
    global _ENV_LOADED
    if env_path is None and _ENV_LOADED:
        return

    # Snapshot the REAL environment before any defaults are merged in.
    # Keys present here must never be overridden by .env or defaults —
    # even when the same key also appears in a defaults file.
    real_env_keys = set(os.environ)

    project_root = _find_project_root()
    # Precedence (highest wins):
    #   real env > project .env > system config.env > platform defaults
    #
    # The system config file (/etc/vnc-remote-secure/config.env on
    # Linux, %ProgramData%\VncRemoteSecure\config.env on Windows) is
    # what the packaged installer writes. systemd injects it for the
    # service via EnvironmentFile=, but manual CLI invocations must
    # read it explicitly or they would silently run with defaults.
    system_env = {}
    for candidate in (
            '/etc/vnc-remote-secure/config.env',
            os.path.join(os.environ.get(
                'ProgramData', r'C:\ProgramData'),
                'VncRemoteSecure', 'config.env'),
    ):
        if os.path.isfile(candidate):
            system_env = dict(_parse_env_file(candidate))
            break

    if env_path is None:
        env_path = os.path.join(project_root, '.env')
    proj_env = {}
    if env_path and os.path.exists(env_path):
        proj_env = dict(_parse_env_file(env_path))

    # 1. Platform-aware defaults (common.env + {linux,windows}.env).
    #    These only set keys that are not already in the real environment.
    _load_platform_defaults(project_root)
    # 2. System config.env — fills keys absent from real env AND from
    #    the project .env (which outranks it).
    for key, val in system_env.items():
        if key not in real_env_keys and key not in proj_env:
            os.environ[key] = val
    # 3. Project .env — overrides system config and platform defaults
    #    but never real env vars.
    for key, val in proj_env.items():
        if key not in real_env_keys:
            os.environ[key] = val

    if env_path is None:
        _ENV_LOADED = True


def generate_random_password(length=16):
    """Generate a strong random password.

    Guarantees at least one uppercase, one lowercase, one digit, and
    one special character so the result always passes ``validate_password``.
    """
    specials = '!@#$%^&*'
    # Guarantee one of each required class, then fill the rest randomly.
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    alphabet = string.ascii_letters + string.digits + specials
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    pool = required + remaining
    secrets.SystemRandom().shuffle(pool)
    return ''.join(pool)


def _load_generated_credential(name):
    """Return a previously generated credential from run_dir, if any.

    Reading the persisted value before generating a new one keeps
    auto-generated credentials stable across restarts — otherwise the
    file would only help until the next start (which would silently
    rotate the password the operator copied).
    """
    try:
        from vnc_remote_secure.core.paths import get_run_dir
        cred_file = os.path.join(get_run_dir(), 'generated_credentials.env')
        if os.path.isfile(cred_file):
            with open(cred_file, encoding='utf-8') as f:
                for line in f:
                    if line.startswith(name + '='):
                        return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return ''


def _persist_generated_credential(name, value):
    """Write a generated credential to an owner-only file in run_dir.

    Auto-generated passwords are never printed to logs or stdout —
    but they would be unrecoverable otherwise (a regenerated value on
    every restart would lock the operator out of the terminal/VNC).
    Persisting to ``<run_dir>/generated_credentials.env`` with 0600
    lets the operator retrieve it locally while keeping it out of
    logs. Persisted values are reused on the next start via
    :func:`_load_generated_credential`.
    """
    try:
        from vnc_remote_secure.core.paths import get_run_dir
        cred_file = os.path.join(get_run_dir(), 'generated_credentials.env')
        # The run dir is normally created by ensure_dirs() during
        # startup(), but get_config() can run before it (bare CLI
        # invocations) — mkstemp would fail and the credential would
        # silently regenerate on every start.
        os.makedirs(os.path.dirname(cred_file), exist_ok=True)
        lines = {}
        if os.path.isfile(cred_file):
            with open(cred_file, encoding='utf-8') as f:
                for line in f:
                    if '=' in line:
                        k, v = line.rstrip('\n').split('=', 1)
                        lines[k] = v
        lines[name] = value
        # Atomic write: an in-place O_TRUNC write that crashes midway
        # loses every persisted credential and the next start would
        # silently rotate them all (locking the operator out — exactly
        # what this file exists to prevent). Same tmp+os.replace
        # treatment as set_env_persistent().
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(cred_file) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                for k, v in lines.items():
                    f.write(f'{k}={v}\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, cred_file)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.chmod(cred_file, 0o600)
        except OSError:
            pass
        logger.warning(
            "%s not set; generated a random password — stored in %s "
            "(owner-only). Set it explicitly in .env to control it.",
            name, cred_file)
    except Exception as exc:  # noqa: BLE001 - persistence is best-effort
        logger.warning(
            "%s not set; generated a random password (not shown for "
            "security; persistence failed: %s)", name, exc)


def _remove_generated_credential(name):
    """Drop ``name`` from generated_credentials.env.

    Called when the operator sets an explicit value (e.g.
    ``secrets rotate``): leaving the stale generated entry means that
    deleting the env var later silently resurrects the OLD generated
    password — the "rotated" secret would come back from the dead.
    """
    try:
        from vnc_remote_secure.core.paths import get_run_dir
        cred_file = os.path.join(get_run_dir(), 'generated_credentials.env')
        if not os.path.isfile(cred_file):
            return
        lines = {}
        with open(cred_file, encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    k, v = line.rstrip('\n').split('=', 1)
                    lines[k] = v
        if name not in lines:
            return
        del lines[name]
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(cred_file) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                for k, v in lines.items():
                    f.write(f'{k}={v}\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, cred_file)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


def _get_vnc_password():
    """Generate a VNC password if not set; return (password, was_user_set).

    Credentials are read from environment/.env, never hardcoded.
    If the password is missing, a random one is generated and persisted
    to ``<run_dir>/generated_credentials.env`` (0600) so the operator
    can retrieve it locally — it is never printed to logs.
    """
    was_user_set = bool(os.environ.get('VNC_PASSWORD', ''))
    vnc_password = os.environ.get('VNC_PASSWORD', '')
    if not vnc_password:
        # Reuse the previously persisted generated credential so the
        # password stays stable across restarts.
        vnc_password = _load_generated_credential('VNC_PASSWORD')
        if vnc_password:
            os.environ['VNC_PASSWORD'] = vnc_password
        else:
            # VNC legacy DES auth truncates to 8 bytes — generating 12
            # would make the last 4 dead entropy and trigger the
            # "only first 8 used" warning on every start.
            vnc_password = generate_random_password(8)
            os.environ['VNC_PASSWORD'] = vnc_password
            _persist_generated_credential('VNC_PASSWORD', vnc_password)
    return vnc_password, was_user_set


def _get_ttyd_credentials():
    """Generate TTYD credentials if not set; return (username, password, was_user_set).

    Credentials are read from environment/.env, never hardcoded.
    If the password is missing, a random one is generated and persisted
    to ``<run_dir>/generated_credentials.env`` (0600) so the operator
    can retrieve it locally — it is never printed to logs.
    """
    ttyd_username = os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME)
    was_user_set = bool(os.environ.get('TTYD_PASSWD', ''))
    ttyd_password = os.environ.get('TTYD_PASSWD', '')
    if not ttyd_password:
        ttyd_password = _load_generated_credential('TTYD_PASSWD')
        if ttyd_password:
            os.environ['TTYD_PASSWD'] = ttyd_password
        else:
            ttyd_password = generate_random_password(16)
            os.environ['TTYD_PASSWD'] = ttyd_password
            _persist_generated_credential('TTYD_PASSWD', ttyd_password)
    return ttyd_username, ttyd_password, was_user_set


def _get_landing_password():
    """Resolve LANDING_PASSWORD like the other generated credentials.

    The portal is fail-closed and the startup blocker rejects an empty
    LANDING_PASSWORD, so an operator without one could never start at
    all — the same chicken-and-egg TTYD_PASSWD solved by persisting a
    generated value to ``generated_credentials.env``. Generated values
    are always strong (``was_user_set=False`` skips weak-password
    validation).
    """
    was_user_set = bool(os.environ.get('LANDING_PASSWORD', ''))
    landing_password = os.environ.get('LANDING_PASSWORD', '')
    if not landing_password:
        landing_password = _load_generated_credential('LANDING_PASSWORD')
        if landing_password:
            os.environ['LANDING_PASSWORD'] = landing_password
        else:
            landing_password = generate_random_password(16)
            os.environ['LANDING_PASSWORD'] = landing_password
            _persist_generated_credential('LANDING_PASSWORD', landing_password)
    return landing_password, was_user_set


def _validate_user_passwords(vnc_password, vnc_user_set, ttyd_password, ttyd_user_set,
                             user_ui_password, landing_password):
    """Validate user-provided passwords (generated ones are always strong).

    Validates VNC_PASSWORD, TTYD_PASSWD, USER_UI_PASSWORD, and
    LANDING_PASSWORD. Generated passwords are always strong; user-provided
    ones may be weak, so only the latter are validated.
    """
    from vnc_remote_secure.core.validation import validate_password
    if vnc_user_set:
        validate_password(vnc_password, 'VNC_PASSWORD')
    if ttyd_user_set:
        validate_password(ttyd_password, 'TTYD_PASSWD')
    if user_ui_password:
        validate_password(user_ui_password, 'USER_UI_PASSWORD')
    if landing_password:
        validate_password(landing_password, 'LANDING_PASSWORD')


def _safe_int(env_name: str, default: int, minimum: int = None, maximum: int = None) -> int:
    """Parse an integer env var with a fallback and optional range check.

    Returns ``default`` when the env var is unset or not a valid integer.
    When ``minimum``/``maximum`` are set, out-of-range values fall back
    to ``default`` and log a warning, so a malformed ``.env`` never
    crashes ``get_config()``.
    """
    raw = os.environ.get(env_name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        logger.warning("Invalid integer for %s=%r; using default %d", env_name, raw, default)
        return default
    if minimum is not None and value < minimum:
        logger.warning("%s=%d below minimum %d; using default %d", env_name, value, minimum, default)
        return default
    if maximum is not None and value > maximum:
        logger.warning("%s=%d above maximum %d; using default %d", env_name, value, maximum, default)
        return default
    return value


def _env_host(*names, default=DEFAULT_BIND_HOST):
    """Return the first non-empty env var among ``names``, else ``default``.

    Per-service bind hosts resolve ``<SERVICE>_HOST`` → ``BIND_HOST`` →
    the loopback constant, so the documented ``BIND_HOST`` knob
    actually controls backend binding (it was previously ignored by
    the per-service resolution even though .env.example presents it as
    the backend bind switch).
    """
    for name in names:
        val = os.environ.get(name, '').strip()
        if val:
            return val
    return default


def _get_ports_config():
    """Return the ports configuration dict (platform-aware defaults)."""
    vnc_port = _safe_int('VNC_PORT', DEFAULT_VNC_PORT, 1, 65535)
    # On Linux the RFB port is display-derived (TigerVNC binds 5900+N
    # for display :N). When the configured VNC_PORT still equals the
    # platform default but the configured display would bind elsewhere,
    # prefer the display-derived port so websockify/doctor target the
    # port the server actually binds — otherwise changing VNC_DISPLAY
    # alone leaves consumers probing a stale default. An explicit
    # non-default VNC_PORT is honoured as documented (operator intent).
    from vnc_remote_secure.platform.detection import is_windows
    if not is_windows() and vnc_port == DEFAULT_VNC_PORT:
        try:
            display = os.environ.get('VNC_DISPLAY', DEFAULT_VNC_DISPLAY)
            display_port = TIGERVNC_BASE_PORT + int(str(display).lstrip(':'))
            if display_port != DEFAULT_VNC_PORT:
                vnc_port = display_port
        except ValueError:
            pass
    return {
        'vnc_port': vnc_port,
        'vnc_http_port': _safe_int('VNC_HTTP_PORT', DEFAULT_VNC_HTTP_PORT, 1, 65535),
        'novnc_port': _safe_int('NOVNC_PORT', DEFAULT_NOVNC_PORT, 1, 65535),
        'ttyd_port': _safe_int('TTYD_PORT', DEFAULT_TTYD_PORT, 1, 65535),
        'health_port': _safe_int('HEALTH_WEB_PORT', DEFAULT_HEALTH_PORT, 1, 65535),
        'landing_port': _safe_int('LANDING_PORT', DEFAULT_LANDING_PORT, 1, 65535),
        'user_ui_port': _safe_int('USER_UI_PORT', DEFAULT_USER_UI_PORT, 1, 65535),
        'novnc_ws_port': _safe_int('NOVNC_WS_PORT', DEFAULT_NOVNC_WS_PORT, 1, 65535),
        'audio_stream_port': _safe_int('AUDIO_STREAM_PORT', DEFAULT_AUDIO_STREAM_PORT, 1, 65535),
        'audio_stream_host': _env_host('AUDIO_STREAM_HOST', 'BIND_HOST'),
        'gamepad_port': _safe_int('GAMEPAD_PORT', DEFAULT_GAMEPAD_PORT, 1, 65535),
        'gamepad_host': _env_host('GAMEPAD_HOST', 'BIND_HOST'),
    }


def _get_credentials_config(vnc_password, ttyd_username, ttyd_password, user_ui_password):
    """Return the credentials dict (from .env, never hardcoded).

    Flask secret key and auth secret: do NOT generate random values
    here. _get_secret() in authentication.py handles persistent
    generation to a file so tokens remain valid across CLI/service
    processes. Setting random per-process secrets here would break
    cross-process token validation.
    """
    return {
        # Credentials (from .env, never hardcoded)
        'vnc_password': vnc_password,
        'ttyd_username': ttyd_username,
        'ttyd_password': ttyd_password,
        'user_ui_password': user_ui_password,

        # Secrets
        'flask_secret_key': os.environ.get('FLASK_SECRET_KEY', ''),
        'auth_secret': os.environ.get('AUTH_SECRET', ''),
    }


def _get_ssl_config():
    """Return the SSL configuration dict, filling default paths if needed."""
    ssl_cert = os.environ.get('SSL_CERT', '')
    ssl_key = os.environ.get('SSL_KEY', '')
    # Fill SSL paths if not set but cert files exist in the canonical
    # platform SSL dir (ProgramData on Windows, XDG/FHS on Linux), or in
    # the legacy <project>/data/ssl location used by older checkouts.
    if not ssl_cert or not ssl_key:
        from vnc_remote_secure.core.paths import get_ssl_dir
        project_root = _find_project_root()
        for cert_dir in (get_ssl_dir(),
                         os.path.join(project_root, 'data', 'ssl')):
            default_cert = os.path.join(cert_dir, 'fullchain.pem')
            default_key = os.path.join(cert_dir, 'privkey.pem')
            if os.path.exists(default_cert) and os.path.exists(default_key):
                ssl_cert = default_cert
                ssl_key = default_key
                break
    return {
        # SSL
        'ssl_cert': ssl_cert,
        'ssl_key': ssl_key,
    }


def _get_hosts_config():
    """Return the hosts dict (secure default: 127.0.0.1; set 0.0.0.0 for LAN access).

    The landing portal is the public entry point on Windows (there is no
    nginx), so ``PUBLIC_BIND_HOST`` — not ``BIND_HOST`` — is its second
    fallback there. On Linux the portal stays loopback behind nginx.
    """
    from vnc_remote_secure.platform.detection import is_windows
    landing_fallback = 'PUBLIC_BIND_HOST' if is_windows() else 'BIND_HOST'
    return {
        'health_host': _env_host('HEALTH_WEB_HOST', 'BIND_HOST'),
        'landing_host': _env_host('LANDING_HOST', landing_fallback),
        'novnc_host': _env_host('SERVE_NOVNC_HOST', 'NOVNC_HOST', 'BIND_HOST'),
        'ttyd_host': _env_host('TTYD_HOST', 'BIND_HOST'),
    }


def _get_feature_toggles():
    """Return the feature toggles dict (mirrors .env.example; defaults are conservative)."""
    return {
        'nginx_enabled': os.environ.get('NGINX_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'fail2ban_enabled': os.environ.get('FAIL2BAN_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'healthcheck_enabled': os.environ.get('HEALTHCHECK_ENABLED', 'true').lower() in ('true', '1', 'yes'),
        'health_web_enabled': os.environ.get('HEALTH_WEB_ENABLED', 'true').lower() in ('true', '1', 'yes'),
        'user_ui_enabled': os.environ.get('USER_UI_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'alerts_enabled': os.environ.get('ALERTS_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'audio_stream_enabled': os.environ.get('AUDIO_STREAM_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'gamepad_enabled': os.environ.get('GAMEPAD_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'tls_enabled': _is_tls_enabled_env(),
        'keep_temp_user': os.environ.get('KEEP_TEMP_USER', 'false').lower() in ('true', '1', 'yes'),
    }


def _profile_name() -> str:
    """Active profile honouring the VNC_REMOTE_PROFILE fallback."""
    from vnc_remote_secure.security.profiles import get_profile
    return get_profile()


def _get_security_config():
    """Return the security dict (profile, binding, auth, hardening, temp user)."""
    return {
        # Security profile and binding (consumed by profiles, auth, nginx).
        # get_profile() honours the VNC_REMOTE_PROFILE fallback.
        'security_profile': _profile_name(),
        'bind_host': os.environ.get('BIND_HOST', '127.0.0.1'),
        'backend_bind_host': os.environ.get('BACKEND_BIND_HOST', '127.0.0.1'),
        'allowed_origins': os.environ.get('ALLOWED_ORIGINS', ''),

        # Temp user management
        'temp_user': os.environ.get('TEMP_USER', 'remote'),
        'temp_user_pass': os.environ.get('TEMP_USER_PASS', ''),

        # Landing page auth
        'landing_password': os.environ.get('LANDING_PASSWORD', ''),

        # Health auth token (optional Bearer token for /health)
        'health_auth_token': os.environ.get('HEALTH_AUTH_TOKEN', ''),

        # Auth rate limiting
        'auth_max_attempts': _safe_int('AUTH_MAX_ATTEMPTS', 5, 1),
        'auth_lockout_seconds': _safe_int('AUTH_LOCKOUT_SECONDS', 900, 1),
        'auth_window_seconds': _safe_int('AUTH_WINDOW_SECONDS', 600, 1),

        # Security hardening
        'csp_policy': os.environ.get('CSP_POLICY', ''),
        'ssl_ciphers': os.environ.get('SSL_CIPHERS', ''),
        'audit_log_file': os.environ.get('AUDIT_LOG_FILE', ''),
        'allowed_lan_ips': os.environ.get('ALLOWED_LAN_IPS', ''),
        'trusted_proxy': os.environ.get('TRUSTED_PROXY', ''),

        # MFA secrets (optional, set by user)
        'totp_secret': os.environ.get('TOTP_SECRET', ''),
        'recovery_codes_hashes': os.environ.get('RECOVERY_CODES_HASHES', ''),
    }


def _get_session_config():
    """Return the session security dict (timeouts, cookie settings)."""
    return {
        # Session security
        'session_idle_timeout': _safe_int(
            'SESSION_IDLE_TIMEOUT', DEFAULT_SESSION_IDLE_TIMEOUT, 1),
        'session_max_lifetime': _safe_int(
            'SESSION_MAX_LIFETIME', DEFAULT_SESSION_MAX_LIFETIME, 1),
        'session_cookie_secure': os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() in ('true', '1', 'yes'),
        # Flask's own session cookie — 'vnc_session' is reserved for the
        # raw HMAC session token the non-Flask services verify.
        'session_cookie_name': os.environ.get(
            'SESSION_COOKIE_NAME', 'vnc_flask_session'),
        'session_samesite': resolve_samesite(),
    }


def resolve_samesite() -> str:
    """Return a whitelisted SameSite cookie value for SESSION_SAMESITE.

    The value lands verbatim in ``Set-Cookie`` headers — a crafted value
    containing ';' or CRLF would inject extra attributes or split the
    response, so anything outside (Lax, Strict, None) falls back to the
    default. Single source for the whitelist shared by Flask sessions,
    the stdlib landing server and profile checks.
    """
    v = os.environ.get('SESSION_SAMESITE', DEFAULT_SESSION_SAMESITE)
    return v if v in ('Lax', 'Strict', 'None') else DEFAULT_SESSION_SAMESITE


def _get_optional_features_config():
    """Return the optional-features dict (audio, gamepad, MFA, DuckDNS, alerts, etc.)."""
    return {
        # Shell for web terminal
        'webterm_shell': os.environ.get('WEBTERM_SHELL', DEFAULT_WEBTERM_SHELL),

        # VNC display settings
        'vnc_geometry': os.environ.get('VNC_GEOMETRY', DEFAULT_VNC_GEOMETRY),
        'vnc_depth': _safe_int('VNC_DEPTH', DEFAULT_VNC_DEPTH, 8, 32),
        'vnc_display': os.environ.get('VNC_DISPLAY', DEFAULT_VNC_DISPLAY),

        # nginx ports (for reverse proxy configuration)
        'nginx_http_port': _safe_int('NGINX_HTTP_PORT', DEFAULT_NGINX_HTTP_PORT, 1, 65535),
        'nginx_https_port': _safe_int('NGINX_HTTPS_PORT', DEFAULT_NGINX_HTTPS_PORT, 1, 65535),

        # Audio settings
        'audio_device': os.environ.get('AUDIO_DEVICE', ''),
        'audio_bitrate': _safe_int('AUDIO_BITRATE', 128, 1),

        # MFA
        'mfa_required': os.environ.get('MFA_REQUIRED', 'false').lower() in ('true', '1', 'yes'),

        # DuckDNS (optional dynamic DNS)
        'duck_domain': os.environ.get('DUCK_DOMAIN', ''),
        'duckdns_token': os.environ.get('DUCKDNS_TOKEN', ''),

        # Logging
        'log_dir': os.environ.get('LOG_DIR', ''),
        'log_level': os.environ.get('LOG_LEVEL', 'INFO'),

        # UltraVNC path (Windows)
        'ultravnc_path': os.environ.get('ULTRAVNC_PATH', ''),
        'ultravnc_url': os.environ.get('ULTRAVNC_URL', ''),

        # Shared state backend (multi-worker deployments). Default is
        # 'sqlite' — same as shared_state.get_backend() and the schema
        # default; 'memory' is for single-process test/dev only.
        'shared_state_backend': os.environ.get('SHARED_STATE_BACKEND', 'sqlite'),
        'shared_state_db_path': os.environ.get('SHARED_STATE_DB_PATH', ''),

        # Alerts (optional)
        'alert_webhook_url': os.environ.get('ALERT_WEBHOOK_URL', ''),

        # Fail2ban tuning (read by installer)
        'fail2ban_max_retry': os.environ.get('FAIL2BAN_MAX_RETRY', '5'),
        'fail2ban_findtime': os.environ.get('FAIL2BAN_FINDTIME', '600'),
        'fail2ban_bantime': os.environ.get('FAIL2BAN_BANTIME', '3600'),

        # Email contact (optional, for Let's Encrypt and alerts)
        'email': os.environ.get('EMAIL', ''),

        # DuckDNS update interval (seconds). .env.example documents this in
        # minutes for readability; we multiply by 60 to honour that contract.
        'duckdns_update_interval': _safe_int('DUCKDNS_UPDATE_INTERVAL', 5, 1) * 60,

        # Discord notifications (optional)
        'discord_enabled': os.environ.get('DISCORD_ENABLED', 'false').lower() in ('true', '1', 'yes'),
        'discord_webhook_url': os.environ.get('DISCORD_WEBHOOK_URL', ''),

        # Healthcheck / auto-restart (systemd)
        'healthcheck_interval': _safe_int('HEALTHCHECK_INTERVAL', 30, 1),
        'auto_restart': os.environ.get('AUTO_RESTART', 'false').lower() in ('true', '1', 'yes'),

        # User UI host
        'user_ui_host': _env_host('USER_UI_HOST', 'BIND_HOST'),

        # Email alerts (optional)
        'alert_email_to': os.environ.get('ALERT_EMAIL_TO', ''),
        'alert_email_from': os.environ.get('ALERT_EMAIL_FROM', ''),
        'alert_smtp_server': os.environ.get('ALERT_SMTP_SERVER', ''),
        'alert_smtp_user': os.environ.get('ALERT_SMTP_USER', ''),
        'alert_smtp_pass': os.environ.get('ALERT_SMTP_PASS', ''),

        # Reserved / informational
        'vnc_remote_profile': os.environ.get('VNC_REMOTE_PROFILE', ''),
        'verbose': os.environ.get('VERBOSE', 'false').lower() in ('true', '1', 'yes'),
    }


def get_config():
    """Get configuration dictionary with all settings.

    Credentials are read from environment/.env, never hardcoded.
    If a required credential is missing, a random one is generated
    and persisted to ``<run_dir>/generated_credentials.env`` (0600)
    so the operator can retrieve it locally — it is never printed.
    """
    load_env_file()

    # VNC password - generate random if not set
    vnc_password, vnc_user_set = _get_vnc_password()
    # Terminal credentials
    ttyd_username, ttyd_password, ttyd_user_set = _get_ttyd_credentials()
    # User UI password (optional, only validated if set)
    user_ui_password = os.environ.get('USER_UI_PASSWORD', '')
    # Landing page password — auto-generated when unset (fail-closed
    # portal + startup blocker make an empty value unusable).
    landing_password, _landing_user_set = _get_landing_password()

    # Validate passwords when they are user-provided (not generated).
    _validate_user_passwords(vnc_password, vnc_user_set, ttyd_password, ttyd_user_set,
                             user_ui_password, landing_password)

    # A user-set credential makes the persisted generated copy stale:
    # leaving it means deleting the env var later silently resurrects
    # the OLD generated password. ``secrets rotate`` removes the entry
    # too, but a plain .env edit hits the same trap — purge here.
    for _cred_name, _cred_user_set in (
            ('VNC_PASSWORD', vnc_user_set),
            ('TTYD_PASSWD', ttyd_user_set),
            ('LANDING_PASSWORD', _landing_user_set)):
        if _cred_user_set:
            _remove_generated_credential(_cred_name)

    # Merge all configuration sections into a single dict.
    config = {}
    config.update(_get_ports_config())
    config.update(_get_credentials_config(vnc_password, ttyd_username, ttyd_password, user_ui_password))
    config.update(_get_ssl_config())
    config.update(_get_hosts_config())
    config.update(_get_feature_toggles())
    config.update(_get_security_config())
    config.update(_get_session_config())
    config.update(_get_optional_features_config())

    return config
