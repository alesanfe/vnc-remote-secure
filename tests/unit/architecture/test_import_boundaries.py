"""Architecture boundary tests — the layering stays real.

Rules enforced:

1. ``engine/*`` never imports transport (``services.*``, ``web.*``,
   ``cli.*``, HTTP/web frameworks). A route handler reaching into a
   use case is fine; a use case reaching into HTTP is not.
2. ``engine/application`` and ``engine/domain`` never import
   ``security/*`` directly — all infrastructure access goes through
   ``engine.infrastructure.stores`` so a future persistence swap
   touches one file.
3. ``engine/domain`` additionally must not import ``application`` or
   ``infrastructure`` — domain depends on nothing.
"""
import ast
import os

import pytest

_SRC = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src')
_PKG = os.path.join(_SRC, 'vnc_remote_secure')
_ENGINE = os.path.join(_PKG, 'engine')
_APP = os.path.join(_ENGINE, 'application')
_DOMAIN = os.path.join(_ENGINE, 'domain')

_TRANSPORT_PREFIXES = (
    'vnc_remote_secure.services',
    'vnc_remote_secure.web',
    'vnc_remote_secure.cli',
    'flask', 'django', 'tornado', 'aiohttp', 'fastapi', 'requests',
    'http.server',
)

_INFRA_PREFIXES = (
    'vnc_remote_secure.security',
    'vnc_remote_secure.monitoring',
    'vnc_remote_secure.platform',
)


def _py_files(root):
    for r, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith('.py'):
                yield os.path.join(r, f)


def _imports(path):
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def _hits(path, prefixes):
    return [
        mod for mod in _imports(path)
        if any(mod == p or mod.startswith(p + '.') for p in prefixes)
    ]


@pytest.mark.parametrize('path', sorted(_py_files(_ENGINE)))
def test_engine_module_has_no_transport_imports(path):
    bad = _hits(path, _TRANSPORT_PREFIXES)
    assert not bad, f'{os.path.relpath(path, _SRC)} imports {bad}'


@pytest.mark.parametrize('path', sorted(_py_files(_APP)))
def test_application_goes_through_infrastructure(path):
    bad = _hits(path, _INFRA_PREFIXES)
    assert not bad, (
        f'{os.path.relpath(path, _SRC)} imports {bad} directly — '
        'route it through engine.infrastructure.stores')


@pytest.mark.parametrize('path', sorted(_py_files(_DOMAIN)))
def test_domain_depends_on_nothing(path):
    bad = _hits(path, _TRANSPORT_PREFIXES + _INFRA_PREFIXES + (
        'vnc_remote_secure.engine.application',
        'vnc_remote_secure.engine.infrastructure',
    ))
    assert not bad, (
        f'{os.path.relpath(path, _SRC)} imports {bad} — domain must '
        'depend only on stdlib')
