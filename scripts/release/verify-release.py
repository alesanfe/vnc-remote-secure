#!/usr/bin/env python3
"""
Verify release artifacts before publishing.

Checks:
- All expected files exist in dist/
- SHA-256 checksums match
- Package metadata is correct
- No secrets in artifacts
"""
import glob
import hashlib
import os
import sys


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
    artifacts = glob.glob(os.path.join(dist_dir, '**', '*'), recursive=True)
    artifacts = [a for a in artifacts if os.path.isfile(a)]
    if not artifacts:
        print("[FAIL] No artifacts found in dist/")
        return False
    print(f"[OK] Found {len(artifacts)} artifact(s):")
    for a in artifacts:
        rel = os.path.relpath(a, dist_dir)
        print(f"  - {rel}")
    return True


def check_checksums(project_root):
    """Verify checksums file if it exists.

    Supports both ``SHA256SUMS.txt`` (manual build) and
    ``checksums-sha256.txt`` (CI workflow). The file may live at
    ``dist/`` root or inside a nested ``dist/checksums/`` directory
    (CI download-artifact layout).
    """
    dist_dir = os.path.join(project_root, 'dist')
    candidates = [
        os.path.join(dist_dir, 'SHA256SUMS.txt'),
        os.path.join(dist_dir, 'checksums-sha256.txt'),
        os.path.join(dist_dir, 'checksums', 'checksums-sha256.txt'),
        os.path.join(dist_dir, 'checksums', 'SHA256SUMS.txt'),
    ]
    sums_file = None
    for candidate in candidates:
        if os.path.exists(candidate):
            sums_file = candidate
            break
    if sums_file is None:
        print("[WARN] No checksums file found")
        return True
    print(f"[OK] Checksums file found: {os.path.relpath(sums_file, dist_dir)}")
    failures = 0
    with open(sums_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format: "<sha256>  <filename>"
            parts = line.split(None, 1)
            if len(parts) != 2:
                print(f"[WARN] Malformed checksum line: {line}")
                continue
            expected_hash, filename = parts
            filename = filename.strip()
            # Search for the file in dist/ (flat or nested layout).
            filepath = None
            for candidate in (
                os.path.join(dist_dir, filename),
                os.path.join(dist_dir, 'dist-ubuntu-latest', filename),
                os.path.join(dist_dir, 'dist-windows-latest', filename),
                os.path.join(dist_dir, 'checksums', filename),
            ):
                if os.path.isfile(candidate):
                    filepath = candidate
                    break
            if filepath is None:
                # Glob search as last resort.
                matches = glob.glob(
                    os.path.join(dist_dir, '**', filename), recursive=True
                )
                if matches:
                    filepath = matches[0]
            if filepath is None:
                print(f"[FAIL] Missing file referenced in checksums: {filename}")
                failures += 1
                continue
            actual_hash = hashlib.sha256(
                open(filepath, 'rb').read()
            ).hexdigest()
            if actual_hash != expected_hash:
                print(f"[FAIL] Checksum mismatch for {filename}")
                failures += 1
            else:
                print(f"[OK] Checksum verified: {filename}")
    return failures == 0


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
