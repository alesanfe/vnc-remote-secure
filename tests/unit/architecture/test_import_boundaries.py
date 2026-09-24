"""Architecture boundary test — the Engine never sees transport.

engine/* must not import the Backend (services.*, web.*, cli.*) nor
HTTP/framework modules. This is the rule that keeps the layering real
during the progressive migration — a route handler reaching into
domain logic is fine; domain reaching into HTTP is not.
"""
import ast
import os

import pytest

_SRC = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')
_ENGINE = os.path.join(_SRC, 'vnc_remote_secure', 'engine')

_FORBIDDEN_PREFIXES = (
    'vnc_remote_secure.services',
    'vnc_remote_secure.web',
    'vnc_remote_secure.cli',
    'flask', 'django', 'tornado', 'aiohttp', 'fastapi', 'requests',
    'http.server',
)


def _engine_files():
    for root, _dirs, files in os.walk(_ENGINE):
        for f in files:
            if f.endswith('.py'):
                yield os.path.join(root, f)


def _imports(path):
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


@pytest.mark.parametrize('path', sorted(_engine_files()))
def test_engine_module_has_no_transport_imports(path):
    for mod in _imports(path):
        for bad in _FORBIDDEN_PREFIXES:
            assert not (mod == bad or mod.startswith(bad + '.')), (
                f'{os.path.relpath(path, _SRC)} imports {mod}')
