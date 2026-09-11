"""Windows dependency checker.

Verifies that UltraVNC, Python, Git Bash, and ffmpeg are available so
that the Windows deployment of VNC Remote Secure can function.
"""
import os
import shutil
import subprocess


def _binary_exists(name):
    """Return True if ``name`` is on PATH."""
    return shutil.which(name) is not None


def _check_registry_ultravnc():
    """Return True if UltraVNC appears in the registry."""
    try:
        result = subprocess.run(
            ['reg', 'query', r'HKLM\SOFTWARE\UVNC'],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_dependencies():
    """Check for missing Windows dependencies.

    Returns:
        A list of missing dependency names. An empty list means all
        required dependencies are present.
    """
    missing = []

    # UltraVNC - check common install paths and registry.
    ultravnc_paths = [
        os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'uvnc bvba', 'UltraVNC', 'winvnc.exe'),
        os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), 'uvnc bvba', 'UltraVNC', 'winvnc.exe'),
    ]
    ultravnc_found = any(os.path.exists(p) for p in ultravnc_paths) or _check_registry_ultravnc()
    if not ultravnc_found:
        missing.append('UltraVNC')

    # Python
    if not _binary_exists('python') and not _binary_exists('python3'):
        missing.append('Python')

    # Git Bash (ships with Git for Windows)
    if not _binary_exists('git'):
        missing.append('Git Bash')

    # ffmpeg (optional but recommended for audio streaming)
    if not _binary_exists('ffmpeg'):
        missing.append('ffmpeg')

    return missing
