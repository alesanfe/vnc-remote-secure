#!/usr/bin/env python3
"""Collect the external-audit evidence package.

Runs the reproducible verification steps from
``docs/security/external-audit-scope.md`` and captures every output
into ``audit-evidence/<timestamp>/`` — a bundle an auditor can
diff against their own run.

Nothing here performs the audit; it packages the artifacts the
audit starts from: test results, posture checks, chain integrity,
build checksums and the threat model docs.

Usage: ``python scripts/security/collect-audit-evidence.py [--quick]``
"""
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


def _run_capture(cmd: list, out_file: str, cwd: str) -> int:
    """Run a command, capture stdout+stderr to a file. Returns rc."""
    print(f"$ {' '.join(cmd)} -> {os.path.basename(out_file)}")
    with open(out_file, 'w', encoding='utf-8', errors='replace') as f:
        f.write('$ ' + ' '.join(cmd) + '\n\n')
        f.flush()
        rc = subprocess.call(
            cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
    return rc


def main() -> int:
    """Collect the evidence bundle; returns 0 when everything ran."""
    quick = '--quick' in sys.argv
    root = _root()
    stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    out_dir = os.path.join(root, 'audit-evidence', stamp)
    os.makedirs(out_dir, exist_ok=True)

    manifest = {'collected_at': stamp, 'steps': []}

    def step(name, cmd):
        out = os.path.join(out_dir, name + '.txt')
        rc = _run_capture(cmd, out, root)
        manifest['steps'].append(
            {'name': name, 'cmd': cmd, 'exit_code': rc})

    # 1. Test evidence (full unit+security suite unless --quick)
    if not quick:
        step('pytest-unit-security',
             [sys.executable, '-m', 'pytest',
              'tests/unit', 'tests/security', '-q'])

    # 2. Posture + readiness (CLI — works on an installed system)
    step('security-check',
         [sys.executable, '-m', 'vnc_remote_secure.cli',
          'security', 'check'])
    step('doctor-json',
         [sys.executable, '-m', 'vnc_remote_secure.cli',
          'doctor', '--json'])

    # 3. Audit chain integrity
    step('verify-audit',
         [sys.executable, '-m', 'vnc_remote_secure.cli',
          'verify', 'audit'])

    # 4. Build + checksums when dist/ exists
    sums = os.path.join(root, 'dist', 'SHA256SUMS.txt')
    if os.path.isfile(sums):
        shutil.copy2(sums, os.path.join(out_dir, 'SHA256SUMS.txt'))
        manifest['steps'].append({
            'name': 'checksums', 'cmd': ['copied', sums],
            'exit_code': 0})

    # 5. Threat-model + scope docs referenced by the package
    for doc in ('docs/security/external-audit-scope.md',
                'docs/THREAT_MODEL.md',
                'docs/architecture/compatibility-matrix.md'):
        src = os.path.join(root, doc)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(
                out_dir, os.path.basename(doc)))

    # 6. Environment fingerprint (versions, never secrets)
    step('pip-freeze', [sys.executable, '-m', 'pip', 'freeze'])
    step('git-status', ['git', 'status', '--short'])
    step('git-log', ['git', 'log', '--oneline', '-20'])

    with open(os.path.join(out_dir, 'manifest.json'), 'w',
              encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    failures = [s for s in manifest['steps'] if s['exit_code'] != 0]
    print(f"\nEvidence collected in {out_dir}")
    print(f"{len(manifest['steps'])} steps, "
          f"{len(failures)} with nonzero exit (see manifest.json)")
    # Nonzero exits are INFORMATION for the auditor (e.g. doctor
    # warnings on a dev box) — the collection itself succeeded.
    return 0


if __name__ == '__main__':
    sys.exit(main())
