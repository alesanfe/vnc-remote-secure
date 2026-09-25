"""Test-isolation guard — a hard barrier between tests and the host.

Motivation: a smoke test once rotated the real ``VNC_PASSWORD`` in the
repo ``.env`` and spawned the real service stack. Unit tests monkeypatch
the seams they care about, but any code path that *forgets* to patch
reaches production state. ``VRS_TEST_MODE=1`` (set by the suite's
conftest) turns dangerous primitives into loud failures.

Rule: in test mode a write target under the *real* repository root is
only allowed when it lives inside one of the explicit override
directories (``VRS_DATA_DIR``/``VRS_RUN_DIR``/``VRS_CONFIG_DIR``/
``VRS_BACKUP_DIR``) or under the OS temp dir (``tmp_path`` lives
there). Detached process spawns and package upgrades are never
allowed unless ``VRS_TEST_ALLOW_SPAWN=1``.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


class TestIsolationError(RuntimeError):
    """Raised when a test-mode run would touch real host state."""


_REPO_ROOT = Path(__file__).resolve().parents[3]
_OVERRIDE_VARS = (
    'VRS_DATA_DIR', 'VRS_RUN_DIR', 'VRS_CONFIG_DIR', 'VRS_BACKUP_DIR')
_ALLOW_SPAWN = 'VRS_TEST_ALLOW_SPAWN'


def in_test_mode() -> bool:
    return os.environ.get('VRS_TEST_MODE') == '1'


def _allowed_roots() -> list[Path]:
    roots = [Path(tempfile.gettempdir()).resolve()]
    for var in _OVERRIDE_VARS:
        value = os.environ.get(var)
        if value:
            roots.append(Path(value).resolve())
    return roots


def guard_write(path: str | os.PathLike, what: str = 'write') -> None:
    """Abort (test mode only) when ``path`` lands inside the repo."""
    if not in_test_mode():
        return
    try:
        p = Path(path).resolve()
    except (OSError, TypeError):
        return
    if not p.is_relative_to(_REPO_ROOT):
        return  # outside the checkout entirely — nothing to guard
    if any(p.is_relative_to(root) for root in _allowed_roots()):
        return
    raise TestIsolationError(
        f'{what}: refusing to touch repo path in test mode: {p} '
        f'(set VRS_CONFIG_DIR/VRS_DATA_DIR/… to a tmp dir)')


def guard_spawn(what: str = 'spawn') -> None:
    """Abort detached spawns / package installs under test mode."""
    if not in_test_mode():
        return
    if os.environ.get(_ALLOW_SPAWN) == '1':
        return
    raise TestIsolationError(
        f'{what}: detached process spawn is disabled in test mode '
        f'(set {_ALLOW_SPAWN}=1 to opt in)')
