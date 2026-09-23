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
import os
import shutil
import subprocess
import sys


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
    """Write the CycloneDX SBOM via tools/generate_sbom.py.

    The canonical generator reads declared deps from pyproject.toml —
    listing every package in the build venv (importlib.metadata)
    would ship dev-tool noise as if it were a runtime dependency.
    """
    path = os.path.join(dist, 'sbom.cdx.json')
    root = os.path.dirname(dist)  # dist/ is directly under the root
    generator = os.path.join(root, 'tools', 'generate_sbom.py')
    rc = _run([sys.executable, generator, '--output', path], root)
    if rc != 0 or not os.path.isfile(path):
        sys.exit('SBOM generation failed')
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
