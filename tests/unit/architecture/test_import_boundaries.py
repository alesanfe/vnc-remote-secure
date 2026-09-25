"""Architecture boundary enforcement — via import-linter.

The layering rules live as contracts in ``pyproject.toml``
(``[tool.importlinter]``):

1. ``engine/*`` never imports transport (``services.*``, ``web.*``,
   ``cli.*``, ``backend.*``, HTTP frameworks) — a route handler
   reaching into a use case is fine; a use case reaching into HTTP is
   not.
2. ``engine/application`` and ``engine/domain`` never import
   ``security/*``/``monitoring/*``/``platform/*`` directly — all
   infrastructure access goes through ``engine.infrastructure.stores``.
3. Layer order: application → infrastructure → domain (domain depends
   on stdlib only).

This test just invokes ``lint-imports`` so CI fails on the same rule
set a developer can run locally.
"""
import subprocess
import sys


def test_import_linter_contracts_kept():
    proc = subprocess.run(
        [sys.executable, '-m', 'importlinter.cli'],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        f'lint-imports failed:\n{proc.stdout}\n{proc.stderr}')
