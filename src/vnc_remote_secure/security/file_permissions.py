"""Secret file permissions validation.

Validates that sensitive files (private keys, .env, certificates) are
not world-readable or group-readable. On Linux this checks file mode
bits; on Windows it checks ACLs via icacls.

Usage:
    from vnc_remote_secure.security.file_permissions import validate_secret_files
    findings = validate_secret_files()
"""
import logging
import os
import stat

logger = logging.getLogger(__name__)

# Files that should have restricted permissions.
SECRET_FILE_PATTERNS = (
    '.env',
    '*.pem',
    '*.key',
    '*.pfx',
    '*.p12',
)

# Directories that should have restricted permissions.
SECRET_DIRS = (
    'data/ssl',
    'ssl',
    'secrets',
)


def _is_windows() -> bool:
    return os.name == 'nt'


def _check_unix_permissions(path: str) -> list[dict]:
    """Check file permissions on Unix-like systems."""
    findings = []
    try:
        st = os.stat(path)
        mode = st.st_mode

        # Check if world-readable.
        if mode & stat.S_IROTH:
            findings.append({
                'severity': 'critical',
                'file': path,
                'message': f'{path} is world-readable (mode {oct(mode & 0o777)})',
            })

        # Check if group-readable (warning, not critical).
        if mode & stat.S_IRGRP:
            findings.append({
                'severity': 'warning',
                'file': path,
                'message': f'{path} is group-readable (mode {oct(mode & 0o777)})',
            })

        # Check if world-writable.
        if mode & stat.S_IWOTH:
            findings.append({
                'severity': 'critical',
                'file': path,
                'message': f'{path} is world-writable (mode {oct(mode & 0o777)})',
            })

    except OSError as e:
        # File may not exist; skip silently.
        logger.debug("Could not stat %s: %s", path, e)
    return findings


def _check_windows_permissions(path: str) -> list[dict]:
    """Check file permissions on Windows via icacls."""
    findings = []
    try:
        import re

        from vnc_remote_secure.core.processes import run_cmd
        result = run_cmd(
            ['icacls', path],
            capture_output=True, text=True, timeout=10,
        )
        # Match ACE entries only (e.g. "Everyone:(F)", "BUILTIN\Users:(RX)").
        # The icacls output header repeats the file path itself — which
        # contains the *directory* "C:\Users\..." — so a naive substring
        # check for "users" false-positives on every file stored under a
        # user profile. ACEs always appear as <principal>:<perms>.
        output = result.stdout
        aces = re.findall(r'([^\s:()]+):\(([^)]*)\)', output)
        principals = {p.lower() for p, _perms in aces}
        if any('everyone' in p or p.endswith('\\todos') or p == 'todos'
               for p in principals):
            findings.append({
                'severity': 'critical',
                'file': path,
                'message': f'{path} is accessible by Everyone',
            })
        if any(p.endswith('\\users') or p.endswith('\\usuarios')
               or p in ('users', 'usuarios') for p in principals):
            findings.append({
                'severity': 'warning',
                'file': path,
                'message': f'{path} is accessible by Users group',
            })
    except Exception as e:
        logger.debug("Could not check Windows permissions for %s: %s", path, e)
    return findings


def validate_secret_files(project_root: str | None = None) -> list[dict]:
    """Validate permissions of secret files.

    Args:
        project_root: Project root directory. Defaults to auto-detected.

    Returns:
        List of finding dicts with ``severity``, ``file``, and ``message``.
    """
    if project_root is None:
        from vnc_remote_secure.core.paths import find_project_root
        project_root = find_project_root()

    findings = []

    def _check(path):
        if _is_windows():
            findings.extend(_check_windows_permissions(path))
        else:
            findings.extend(_check_unix_permissions(path))

    # Check specific files.
    for pattern in SECRET_FILE_PATTERNS:
        if '*' in pattern:
            # Glob pattern — search in project root, data/ssl, the
            # canonical platform ssl dir and secrets/.
            import glob
            try:
                from vnc_remote_secure.core.paths import get_ssl_dir
                canonical_ssl = get_ssl_dir()
            except Exception:  # noqa: BLE001
                canonical_ssl = None
            search_paths = [
                os.path.join(project_root, pattern),
                os.path.join(project_root, 'data', 'ssl', pattern),
                os.path.join(project_root, 'ssl', pattern),
                os.path.join(project_root, 'secrets', pattern),
            ]
            if canonical_ssl:
                search_paths.append(os.path.join(canonical_ssl, pattern))
            for sp in search_paths:
                for f in glob.glob(sp):
                    if os.path.isfile(f):
                        _check(f)
        else:
            path = os.path.join(project_root, pattern)
            if os.path.isfile(path):
                _check(path)

    # The system config file the installer seeds (contains secrets
    # when the operator set real values) and the UltraVNC ini, which
    # carries the DES-obfuscated VNC password.
    extra_files = [
        os.path.join(
            os.environ.get('ProgramData', r'C:\ProgramData'),
            'VncRemoteSecure', 'config.env'),
        os.path.join('/etc', 'vnc-remote-secure', 'config.env'),
    ]
    # Runtime secret files under the canonical run/log dirs: session
    # tokens, the signing secret, the audit log and the shared-state
    # DB must be owner-only or any local user can hijack sessions /
    # forge tokens.
    try:
        from vnc_remote_secure.core.paths import get_log_dir, get_run_dir
        extra_files += [
            os.path.join(get_run_dir(), 'auth_secret.key'),
            os.path.join(get_run_dir(), 'generated_credentials.env'),
            os.path.join(get_run_dir(), 'ephemeral_sessions.json'),
            os.path.join(get_run_dir(), 'instance.id'),
            # Linux VNC password file written by the adapter
            # (vncpasswd-format DES obfuscation — still a credential).
            os.path.join(get_run_dir(), 'vnc_passwd.pwd'),
            os.path.join(get_run_dir(), 'shared_state.db'),
            os.path.join(get_run_dir(), 'shared_state.db-wal'),
            os.path.join(get_run_dir(), 'shared_state.db-shm'),
            os.path.join(get_log_dir(), 'audit.jsonl'),
        ]
    except Exception:  # noqa: BLE001
        pass
    if _is_windows():
        try:
            from vnc_remote_secure.platform.windows.installer import _find_ultravnc
            winvnc = _find_ultravnc()
            if winvnc:
                extra_files.append(
                    os.path.join(os.path.dirname(winvnc), 'ultravnc.ini'))
        except (ImportError, OSError):
            pass
    # Backup archives hold .env, SSL keys and the signing secret —
    # even the encrypted form must stay owner-only. (*.enc.tar.gz
    # matches the *.tar.gz glob.)
    import glob as _glob
    for bp in _glob.glob(os.path.join(project_root, 'backups', '*.tar.gz')):
        extra_files.append(bp)
    for path in extra_files:
        if os.path.isfile(path):
            _check(path)

    # Check secret directories.
    for d in SECRET_DIRS:
        path = os.path.join(project_root, d)
        if os.path.isdir(path):
            if _is_windows():
                findings.extend(_check_windows_permissions(path))
            else:
                findings.extend(_check_unix_permissions(path))

    return findings


def fix_secret_file_permissions(path: str) -> bool:
    """Fix permissions on a secret file.

    POSIX: ``chmod 0o600``. Windows: restrict the ACL to
    SYSTEM+Administrators+current user via universal SIDs — granting
    only ``USERNAME`` would lock out services running as SYSTEM.
    ``writable=True`` because the covered files (audit log, session
    store, shared-state db) are rewritten by the service itself.

    Returns:
        ``True`` if permissions were fixed, ``False`` on error.
    """
    if _is_windows():
        try:
            from vnc_remote_secure.security.certificates import _restrict_key_permissions
            _restrict_key_permissions(path, writable=True)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("ACL restriction failed for %s: %s", path, exc)
            return False

    try:
        os.chmod(path, 0o600)
        return True
    except OSError as e:
        logger.error("Could not fix permissions for %s: %s", path, e)
        return False
