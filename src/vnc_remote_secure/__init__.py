"""
VNC Remote Secure - Secure browser-based remote access.

Cross-platform package providing VNC desktop, web terminal, health monitoring,
and optional audio/gamepad forwarding behind an SSL reverse proxy.
"""
import os
from importlib.metadata import PackageNotFoundError, version

__all__ = ['__version__']


def _source_tree_version():
    """Read the version from pyproject.toml when running from a source
    checkout (the package is not pip-installed)."""
    import tomllib  # stdlib in Python 3.11+

    pyproject = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'pyproject.toml',
    )
    try:
        with open(pyproject, 'rb') as fh:
            return tomllib.load(fh)['project']['version']
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return None


try:
    __version__ = version("vnc-remote-secure")
except PackageNotFoundError:  # pragma: no cover - editable install missing
    __version__ = _source_tree_version() or "0.0.0"
