"""Linux dependency checker.

Verifies that the system packages required by VNC Remote Secure are
installed and returns a list of any that are missing.
"""
import shutil
import subprocess

# Packages checked via their executable name (``which``/``command -v``).
_REQUIRED_BINARIES = [
    'tigervncserver',
    'Xvnc',
    'nginx',
    'openssl',
]

# Packages checked via ``dpkg`` package name.
_REQUIRED_PACKAGES = [
    'novnc',
    'websockify',
    'ttyd',
]


def _binary_exists(name):
    """Return True if ``name`` is on PATH."""
    return shutil.which(name) is not None


def _package_installed(name):
    """Return True if the dpkg package ``name`` is installed."""
    try:
        result = subprocess.run(
            ['dpkg', '-s', name],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_dependencies():
    """Check for missing Linux dependencies.

    Returns:
        A list of missing dependency names. An empty list means all
        required dependencies are present.
    """
    missing = []
    for binary in _REQUIRED_BINARIES:
        if not _binary_exists(binary):
            missing.append(binary)
    for pkg in _REQUIRED_PACKAGES:
        if not _package_installed(pkg):
            missing.append(pkg)
    return missing


def install_dependencies(packages=None):
    """Install missing packages via apt-get.

    Args:
        packages: Optional list of package names to install. When
            ``None`` the result of :func:`check_dependencies` is used.

    Returns:
        ``True`` if the installation command succeeded.

    Raises:
        PermissionError: if not running as root.
    """
    import os
    if os.geteuid() != 0:
        raise PermissionError("apt-get install requires root privileges")
    if packages is None:
        packages = check_dependencies()
    if not packages:
        return True
    result = subprocess.run(
        ['apt-get', 'install', '-y', *packages],
        capture_output=True, text=True,
    )
    return result.returncode == 0
