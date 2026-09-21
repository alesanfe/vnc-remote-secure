#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for VNC Remote Secure.

Reads the dependency declarations from ``pyproject.toml`` (the single
source of truth) and emits a CycloneDX 1.5 JSON document listing every
runtime and dev dependency with its specifier. Resolved (installed)
versions are included when the package is importable via
``importlib.metadata`` — run inside the project venv for exact pins.

Usage:
    python tools/generate_sbom.py [--output sbom.json]
"""
import argparse
import json
import os
import re
import sys
import tomllib
from datetime import datetime, timezone


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, 'pyproject.toml')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def _installed_version(dist_name):
    """Return the installed version of ``dist_name`` or None."""
    try:
        from importlib.metadata import version
        return version(dist_name)
    except Exception:  # noqa: BLE001 - best-effort enrichment
        return None


def _component(name, spec, scope='required'):
    comp = {
        'type': 'library',
        'bom-ref': f'pkg:pypi/{name}',
        'name': name,
        'scope': scope,
        'purl': f'pkg:pypi/{name}',
        'properties': [
            {'name': 'cdx:specifier', 'value': spec},
        ],
    }
    version = _installed_version(name)
    if version:
        comp['version'] = version
        comp['purl'] = f'pkg:pypi/{name}@{version}'
        comp['bom-ref'] = comp['purl']
    return comp


def _split_spec(spec):
    """Split 'Flask>=3.0.3,<4.0' into ('Flask', '>=3.0.3,<4.0')."""
    match = re.match(r'^([A-Za-z0-9._-]+)\s*(.*)$', spec.strip())
    if not match:
        return spec, ''
    return match.group(1), match.group(2)


def generate(root):
    pyproject_path = os.path.join(root, 'pyproject.toml')
    with open(pyproject_path, 'rb') as f:
        pyproject = tomllib.load(f)

    project = pyproject['project']
    components = []

    for spec in project.get('dependencies', []):
        name, constraint = _split_spec(spec)
        components.append(_component(name, constraint))

    optional = project.get('optional-dependencies', {})
    for group, specs in optional.items():
        for spec in specs:
            name, constraint = _split_spec(spec)
            comp = _component(name, constraint, scope='optional')
            comp['properties'].append(
                {'name': 'cdx:extra', 'value': group})
            components.append(comp)

    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        # Deterministic UUID from the project URL — stable across
        # regenerations so diffs only reflect dependency changes.
        'serialNumber': 'urn:uuid:' + str(
            __import__('uuid').uuid5(
                __import__('uuid').NAMESPACE_URL,
                'https://github.com/alesanfe/vnc-remote-secure')),
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tools': {
                'components': [{
                    'type': 'application',
                    'name': 'vnc-remote-secure generate_sbom.py',
                    'version': project.get('version', '0.0.0'),
                }],
            },
            'component': {
                'type': 'application',
                'bom-ref': f"pkg:pypi/{project['name']}",
                'name': project['name'],
                'version': project.get('version', '0.0.0'),
                'description': project.get('description', ''),
                'licenses': [{'license': {'id': 'MIT'}}],
            },
        },
        'components': components,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', '-o', default='sbom.json',
                        help='Output path (default: sbom.json)')
    args = parser.parse_args()

    root = find_project_root()
    sbom = generate(root)
    out = os.path.abspath(args.output)
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2)
        f.write('\n')
    print(f"SBOM written: {out} "
          f"({len(sbom['components'])} components)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
