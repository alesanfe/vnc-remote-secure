r"""Path resolution utilities for VNC Remote Secure.

Provides platform-aware directory locations for configuration, data,
logs, runtime state, and SSL certificates.

On Linux the standard FHS locations (``/etc``, ``/var/lib``,
``/var/log``, ``/run``) are used for system-wide installs (root).
For non-root or user-session deployments, XDG Base Directory
specification paths (``XDG_CONFIG_HOME``, ``XDG_DATA_HOME``,
``XDG_RUNTIME_DIR``) are honoured so the application works without
write access to ``/etc`` or ``/var``.

On Windows, elevated processes (installer, Windows Service running as
SYSTEM) use ``%ProgramData%``; non-elevated runs fall back to
``%LOCALAPPDATA%`` because ProgramData is not writable without
elevation — or to ``%USERPROFILE%\\AppData\\LocalLow`` when running
under an MSIX-packaged interpreter (Store Python), where
``%LOCALAPPDATA%`` is virtualized per package and would split shared
state between interpreters.
"""
import contextlib
import os

from vnc_remote_secure.platform.detection import is_windows

_APP_DIR_NAME = 'vnc-remote-secure'
_APP_DIR_NAME_WIN = 'VncRemoteSecure'


def find_project_root():
    """Find the project root by searching upward for ``.env.example``.

    Falls back to the package's grandparent directory when no marker
    file is found.
    """
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        if os.path.exists(os.path.join(current, '.env')):
            return current
        current = os.path.dirname(current)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _is_elevated_windows() -> bool:
    """Return True when the process runs elevated on Windows."""
    if os.name != 'nt':
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - best-effort elevation probe
        return False


def _is_msix_packaged() -> bool:
    r"""Return True when running under an MSIX-packaged interpreter.

    Microsoft Store Python (and other packaged interpreters) get file
    system virtualization: writes to ``%LOCALAPPDATA%`` are redirected
    to ``Packages\\<pkg>\\LocalCache\\Local`` *per package*. Two
    interpreters (Store 3.11 vs a venv, or Store 3.9 vs 3.11) would see
    different directories, silently splitting the shared state
    (``shared_state.db``, ``auth_secret.key``, generated credentials,
    PID/lock files) that the architecture requires to be common.

    Detection is based on ``sys.executable`` (not ``sys.base_prefix``):
    a venv created from Store Python runs its own un-packaged
    interpreter and is not virtualized.
    """
    if os.name != 'nt':
        return False
    try:
        import sys
        exe = os.path.realpath(sys.executable).lower()
        return 'windowsapps' in exe
    except Exception:  # noqa: BLE001 - best-effort probe
        return False


def _win_base():
    r"""Return the Windows base directory for app state.

    Elevated processes (the installed Windows Service runs as SYSTEM,
    and the installer/CLI run elevated) use ``ProgramData`` — the
    documented installed layout. A non-elevated invocation cannot write
    there at all: without a fallback every dev-mode ``vnc-remote`` run
    fails with AccessDenied on pid files, generated credentials and
    logs. Non-elevated runs therefore use ``%LOCALAPPDATA%`` — except
    under MSIX-packaged interpreters (Store Python), where that path is
    virtualized per package; ``AppData\\LocalLow`` is outside the MSIX
    VFS mapping and stays stable across interpreters.
    """
    if not _is_elevated_windows():
        local = os.environ.get('LOCALAPPDATA')
        if local:
            if _is_msix_packaged():
                locallow = os.path.join(os.path.dirname(local), 'LocalLow')
                if os.path.isdir(locallow):
                    return locallow
            return local
    return os.environ.get('ProgramData', r'C:\ProgramData')


def _is_root():
    """Return True if running as root (UID 0) on Linux."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _xdg_path(env_var, default_subdir):
    """Return an XDG base directory, falling back to the default."""
    value = os.environ.get(env_var)
    if value:
        return os.path.join(value, _APP_DIR_NAME)
    home = os.path.expanduser('~')
    return os.path.join(home, default_subdir, _APP_DIR_NAME)


def get_config_dir():
    """Return the configuration directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'config')
    if _is_root():
        return os.path.join('/etc', _APP_DIR_NAME)
    return _xdg_path('XDG_CONFIG_HOME', '.config')


def get_data_dir():
    """Return the data directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'data')
    if _is_root():
        return os.path.join('/var/lib', _APP_DIR_NAME)
    return _xdg_path('XDG_DATA_HOME', '.local/share')


def get_log_dir():
    """Return the log directory for the current platform.

    ``LOG_DIR`` is honoured as an operator override when set — the
    maintenance scripts (cleanup.sh, update.sh) already treat it as
    the log location, so the runtime must write to the same place or
    the override silently does nothing (``config['log_dir']`` was
    populated from it but never consumed).

    On non-root Linux, ``XDG_STATE_HOME`` is honoured — the XDG state
    directory is the spec-designated location for log files (default
    ``~/.local/state``). The canonical systemd unit sets
    ``XDG_STATE_HOME=/var/log`` so the service writes to
    ``/var/log/vnc-remote-secure``, matching the FHS layout.
    """
    override = os.environ.get('LOG_DIR', '').strip()
    if override:
        return override
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'logs')
    if _is_root():
        return os.path.join('/var/log', _APP_DIR_NAME)
    return _xdg_path('XDG_STATE_HOME', '.local/state')


def get_run_dir():
    """Return the runtime state directory for the current platform.

    On Windows there is no ``/run`` equivalent, so a ``run`` subdirectory
    of the data directory is used instead. On non-root Linux,
    ``XDG_RUNTIME_DIR`` is used when available.
    """
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'run')
    if _is_root():
        return os.path.join('/run', _APP_DIR_NAME)
    xdg_runtime = os.environ.get('XDG_RUNTIME_DIR')
    if xdg_runtime:
        return os.path.join(xdg_runtime, _APP_DIR_NAME)
    # justification: runtime dir, perms hardened by callers
    return os.path.join('/tmp', _APP_DIR_NAME)  # nosec B108


def get_ssl_dir():
    """Return the SSL certificate directory for the current platform."""
    if is_windows():
        return os.path.join(_win_base(), _APP_DIR_NAME_WIN, 'ssl')
    return os.path.join(get_data_dir(), 'ssl')


def _restrict_dir(path):
    """Restrict a directory to owner-only access (POSIX) or.

    owner+SYSTEM+Administrators (Windows).

    The run/ssl directories hold session stores, signing secrets and
    generated credentials — world-readable dirs would let any local
    user enumerate or (on filesystems ignoring file modes) read them.
    """
    if os.name == 'nt':
        import subprocess

        from vnc_remote_secure.core.processes import run_cmd
        user = os.environ.get('USERNAME', '')
        # (OI)(CI) so the grant propagates to files created inside.
        # NOTE: 'M' (Modify), not 'R,W' — plain R+W omits DELETE /
        # FILE_DELETE_CHILD, which breaks os.replace()-based atomic
        # writes (PID files, shared-state, credential rotation all
        # rename a tmp file into place).
        rights = '(OI)(CI)(M)'
        grants = [f'*S-1-5-18:{rights}', f'*S-1-5-32-544:{rights}']
        if user:
            grants.append(f'{user}:{rights}')
        try:
            run_cmd(
                ['icacls', path, '/reset'],
                capture_output=True, timeout=15, check=False)
            run_cmd(
                ['icacls', path, '/inheritance:r', '/grant:r', *grants],
                capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        # nosemgrep: python.lang.security.insecure-file-permissions.insecure-file-permissions (0o700 hardens)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)


def ensure_dirs():
    """Create all standard directories if they do not already exist."""
    for path in (get_config_dir(), get_data_dir(), get_log_dir(),
                 get_run_dir(), get_ssl_dir()):
        os.makedirs(path, exist_ok=True)
    # /tmp fallback (non-root Linux without XDG_RUNTIME_DIR) is shared —
    # an attacker could pre-create the dir with planted PID/state files
    # (ephemeral_sessions.json, auth_secret.key, shared_state.db are all
    # readable/forgable inside a foreign-owned dir). Refuse rather than
    # warn-and-continue: the previous behaviour ran the full stack on
    # attacker-controlled state. Only checked for the /tmp fallback: the
    # root and XDG paths may legitimately be owned by the service user
    # while the CLI runs as root.
    if (not is_windows() and os.name != 'nt'
            and not _is_root()
            and not os.environ.get('XDG_RUNTIME_DIR')):
        try:
            run_dir = get_run_dir()
            st = os.lstat(run_dir)
            if st.st_uid != os.geteuid():
                raise RuntimeError(
                    f"Runtime dir {run_dir} is owned by uid "
                    f"{st.st_uid}, not {os.geteuid()} — refusing to "
                    "start on possibly-squatted /tmp state. Set "
                    "XDG_RUNTIME_DIR (e.g. via systemd/logind) and "
                    "remove the foreign directory.")
            if not os.path.isdir(run_dir):
                raise RuntimeError(
                    f"Runtime dir {run_dir} exists but is not a "
                    "directory — refusing to use it.")
        except AttributeError:
            pass
    # run/ssl/config hold secrets (session stores, auth_secret.key,
    # generated_credentials.env, private keys) — keep them owner-only.
    for path in (get_config_dir(), get_run_dir(), get_ssl_dir()):
        _restrict_dir(path)
    if os.name == 'nt':
        _repair_state_file_acls()


def _repair_state_file_acls():
    """Re-apply restrictive ACLs to existing state files in run_dir.

    Files created before the Modify grant (R,W without DELETE) break
    os.replace()-based atomic writes — the ephemeral session store,
    shared-state DB, audit log and generated credentials all rewrite
    via tmp+rename and would silently lose state. Re-granting Modify
    on every startup repairs old files idempotently.
    """
    import subprocess

    from vnc_remote_secure.core.processes import run_cmd
    run_dir = get_run_dir()
    try:
        entries = os.listdir(run_dir)
    except OSError:
        return
    user = os.environ.get('USERNAME', '')
    for name in entries:
        p = os.path.join(run_dir, name)
        if not os.path.isfile(p):
            continue
        # Skip transient/lock artifacts — only durable state files.
        if name.endswith(('.tmp', '.lock')):
            continue
        grants = ['*S-1-5-18:(M)', '*S-1-5-32-544:(M)']
        if user:
            grants.append(f'{user}:(M)')
        try:
            run_cmd(
                ['icacls', p, '/reset'],
                capture_output=True, timeout=15, check=False)
            run_cmd(
                ['icacls', p, '/inheritance:r', '/grant:r', *grants],
                capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
