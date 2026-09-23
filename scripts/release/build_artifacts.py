#!/usr/bin/env python3
"""Release pipeline: build → checksums → SBOM → sign → verify.

Produces, under ``dist/``:

- ``*.whl`` + ``*.tar.gz`` via ``python -m build``
- ``SHA256SUMS.txt`` — sha256 of every artifact
- ``sbom.cdx.json`` — CycloneDX 1.5 SBOM of the runtime deps
  (stdlib-only generator; no cyclonedx-bom dependency)
- ``*.sig`` / ``*.asc`` — when cosign or gpg is on PATH, every
  artifact + the checksums file are signed; otherwise the build is
  unsigned and the script says so plainly.

Usage: ``python scripts/release/build_artifacts.py [--no-sign]``
"""
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time


def _root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(here, 'pyproject.toml')):
            return here
        here = os.path.dirname(here)
    return os.getcwd()


def _run(cmd: list, cwd: str) -> int:
    print(f"$ {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=cwd)


def build_packages(root: str) -> list:
    """Build wheel + sdist; returns artifact paths."""
    dist = os.path.join(root, 'dist')
    if os.path.isdir(dist):
        shutil.rmtree(dist)
    os.makedirs(dist)
    if _run([sys.executable, '-m', 'build'], root) != 0:
        sys.exit('build failed')
    return sorted(glob.glob(os.path.join(dist, '*')))


def write_checksums(artifacts: list, dist: str) -> str:
    """Write SHA256SUMS.txt covering every artifact."""
    path = os.path.join(dist, 'SHA256SUMS.txt')
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        for art in artifacts:
            digest = hashlib.sha256()
            with open(art, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    digest.update(chunk)
            f.write(f"{digest.hexdigest()}  {os.path.basename(art)}\n")
    print(f"[OK] {os.path.relpath(path, dist)}")
    return path


def write_sbom(dist: str) -> str:
    """Write a CycloneDX 1.5 JSON SBOM of the installed runtime deps.

    Uses importlib.metadata — an SBOM that requires a third-party
    generator would be unauditable inside this very build.
    """
    from importlib import metadata
    components = []
    for d in sorted(metadata.distributions(),
                    key=lambda x: (x.metadata['Name'] or '').lower()):
        name = d.metadata['Name']
        version = d.version
        if not name:
            continue
        components.append({
            'type': 'library',
            'bom-ref': f'pkg:pypi/{name.lower()}@{version}',
            'name': name,
            'version': version,
            'purl': f'pkg:pypi/{name.lower()}@{version}',
        })
    sbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'version': 1,
        'metadata': {
            'timestamp': time.strftime(
                '%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'component': {
                'type': 'application',
                'name': 'vnc-remote-secure',
                'bom-ref': 'pkg:pypi/vnc-remote-secure',
            },
        },
        'components': components,
    }
    path = os.path.join(dist, 'sbom.cdx.json')
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(sbom, f, indent=2)
    print(f"[OK] sbom.cdx.json ({len(components)} components)")
    return path


def sign_artifacts(paths: list, no_sign: bool) -> bool:
    """Sign each artifact with cosign (preferred) or gpg.

    Returns True when at least one signer ran; False when unsigned.
    """
    if no_sign:
        print("[WARN] signing disabled (--no-sign)")
        return False
    cosign = shutil.which('cosign')
    gpg = shutil.which('gpg') or shutil.which('gpg2')
    if cosign:
        ok = True
        for art in paths:
            rc = _run([cosign, 'sign-blob', '--yes',
                       '--output-signature', art + '.sig', art],
                      os.path.dirname(art))
            ok = ok and rc == 0
        return ok
    if gpg:
        ok = True
        for art in paths:
            rc = _run([gpg, '--batch', '--yes', '--detach-sign',
                       '--armor', '-o', art + '.asc', art],
                      os.path.dirname(art))
            ok = ok and rc == 0
        return ok
    print('[WARN] no cosign or gpg on PATH — release is UNSIGNED')
    return False


def main() -> int:
    """Run the full release pipeline; returns the verify exit code."""
    no_sign = '--no-sign' in sys.argv
    root = _root()
    dist = os.path.join(root, 'dist')

    artifacts = build_packages(root)
    if not artifacts:
        sys.exit('no artifacts produced')
    for a in artifacts:
        print(f"  artifact: {os.path.basename(a)}")

    sums = write_checksums(artifacts, dist)
    sbom = write_sbom(dist)
    sign_artifacts(artifacts + [sums, sbom], no_sign)

    verify = os.path.join(root, 'scripts', 'release',
                          'verify-release.py')
    return _run([sys.executable, verify], root)


if __name__ == '__main__':
    sys.exit(main())
