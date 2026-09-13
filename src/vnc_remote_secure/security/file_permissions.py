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
from typing import List

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


def _check_unix_permissions(path: str) -> List[dict]:
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


def _check_windows_permissions(path: str) -> List[dict]:
    """Check file permissions on Windows via icacls."""
    findings = []
    try:
        import subprocess
        result = subprocess.run(
            ['icacls', path],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        # Check if Everyone or Users group has access.
        if 'everyone' in output:
            findings.append({
                'severity': 'critical',
                'file': path,
                'message': f'{path} is accessible by Everyone',
            })
        if r'\users' in output or 'builtin\\users' in output:
            findings.append({
                'severity': 'warning',
                'file': path,
                'message': f'{path} is accessible by Users group',
            })
    except Exception as e:
        logger.debug("Could not check Windows permissions for %s: %s", path, e)
    return findings


def validate_secret_files(project_root: str = None) -> List[dict]:
    """Validate permissions of secret files.

    Args:
        project_root: Project root directory. Defaults to auto-detected.

    Returns:
        List of finding dicts with ``severity``, ``file``, and ``message``.
    """
    if project_root is None:
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )

    findings = []

    # Check specific files.
    for pattern in SECRET_FILE_PATTERNS:
        if '*' in pattern:
            # Glob pattern — search in project root and data/ssl.
            import glob
            search_paths = [
                os.path.join(project_root, pattern),
                os.path.join(project_root, 'data', 'ssl', pattern),
                os.path.join(project_root, 'ssl', pattern),
                os.path.join(project_root, 'secrets', pattern),
            ]
            for sp in search_paths:
                for f in glob.glob(sp):
                    if os.path.isfile(f):
                        if _is_windows():
                            findings.extend(_check_windows_permissions(f))
                        else:
                            findings.extend(_check_unix_permissions(f))
        else:
            path = os.path.join(project_root, pattern)
            if os.path.isfile(path):
                if _is_windows():
                    findings.extend(_check_windows_permissions(path))
                else:
                    findings.extend(_check_unix_permissions(path))

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
    """Fix permissions on a secret file (Unix only).

    Sets the file to 600 (owner read/write only).

    Returns:
        ``True`` if permissions were fixed, ``False`` on error.
    """
    if _is_windows():
        # On Windows, restrict to current user only via icacls.
        try:
            import subprocess
            username = os.environ.get('USERNAME', 'Administrators')
            subprocess.run(
                ['icacls', path, '/inheritance:r', '/grant:r', f'{username}:F'],
                capture_output=True, timeout=10,
            )
            return True
        except Exception:
            return False

    try:
        os.chmod(path, 0o600)
        return True
    except OSError as e:
        logger.error("Could not fix permissions for %s: %s", path, e)
        return False
