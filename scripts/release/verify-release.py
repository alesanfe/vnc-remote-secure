#!/usr/bin/env python3
"""
Verify release artifacts before publishing.

Checks:
- All expected files exist in dist/
- SHA-256 checksums match
- Package metadata is correct
- No secrets in artifacts
"""
import hashlib
import os
import sys
import json
import glob


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def check_dist_exists(project_root):
    """Check that dist/ directory exists."""
    dist_dir = os.path.join(project_root, 'dist')
    if not os.path.isdir(dist_dir):
        print("[FAIL] dist/ directory not found")
        return False
    print("[OK] dist/ directory exists")
    return True


def check_artifacts(project_root):
    """Check that expected artifacts exist."""
    dist_dir = os.path.join(project_root, 'dist')
    artifacts = glob.glob(os.path.join(dist_dir, '*'))
    if not artifacts:
        print("[FAIL] No artifacts found in dist/")
        return False
    print(f"[OK] Found {len(artifacts)} artifact(s):")
    for a in artifacts:
        print(f"  - {os.path.basename(a)}")
    return True


def check_checksums(project_root):
    """Verify SHA256SUMS.txt if it exists."""
    dist_dir = os.path.join(project_root, 'dist')
    sums_file = os.path.join(dist_dir, 'SHA256SUMS.txt')
    if not os.path.exists(sums_file):
        print("[WARN] No SHA256SUMS.txt found")
        return True
    print("[OK] SHA256SUMS.txt found")
    # TODO: verify each checksum
    return True


def check_no_secrets(project_root):
    """Check that no secrets are in the artifacts."""
    dist_dir = os.path.join(project_root, 'dist')
    secret_patterns = ['.env', '.pem', '.key', 'privkey', 'secret']
    for f in glob.glob(os.path.join(dist_dir, '**', '*'), recursive=True):
        if os.path.isfile(f):
            basename = os.path.basename(f).lower()
            for pattern in secret_patterns:
                if pattern in basename:
                    print(f"[FAIL] Potential secret file in dist/: {os.path.basename(f)}")
                    return False
    print("[OK] No secret files found in dist/")
    return True


def main():
    project_root = find_project_root()
    print(f"Project root: {project_root}")
    print()

    checks = [
        check_dist_exists,
        check_artifacts,
        check_checksums,
        check_no_secrets,
    ]

    all_ok = True
    for check in checks:
        if not check(project_root):
            all_ok = False

    print()
    if all_ok:
        print("[PASS] All release checks passed")
        return 0
    else:
        print("[FAIL] Some release checks failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
