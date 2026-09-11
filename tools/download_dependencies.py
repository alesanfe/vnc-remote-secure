#!/usr/bin/env python3
"""
Download third-party dependencies and verify their SHA-256 checksums.

Reads manifests from third_party/manifests/*.json and downloads
the specified binaries into the appropriate runtime directories.
"""
import hashlib
import json
import os
import sys
import urllib.request


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def load_manifests(project_root):
    """Load all manifests from third_party/manifests/."""
    manifests_dir = os.path.join(project_root, 'third_party', 'manifests')
    manifests = []
    if not os.path.isdir(manifests_dir):
        return manifests
    for f in sorted(os.listdir(manifests_dir)):
        if f.endswith('.json'):
            with open(os.path.join(manifests_dir, f)) as fh:
                manifests.append(json.load(fh))
    return manifests


def download_and_verify(manifest, project_root):
    """Download a dependency and verify its checksum."""
    name = manifest.get('name', 'unknown')
    url = manifest.get('download_url')
    filename = manifest.get('filename')
    expected_sha = manifest.get('sha256', 'TBD')

    if not url or not filename:
        print(f"[SKIP] {name}: no download URL or filename")
        return False

    if expected_sha == 'TBD':
        print(f"[WARN] {name}: SHA-256 not set in manifest, skipping verification")

    # Determine target directory
    platform = manifest.get('platform', 'cross-platform')
    if platform == 'windows':
        target_dir = os.path.join(project_root, 'bin')
    else:
        target_dir = os.path.join(project_root, 'vendor')

    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)

    if os.path.exists(target_path):
        print(f"[EXISTS] {name}: {target_path}")
        return True

    print(f"[DOWNLOAD] {name}: {url}")
    try:
        urllib.request.urlretrieve(url, target_path)
    except Exception as e:
        print(f"[ERROR] {name}: download failed: {e}", file=sys.stderr)
        return False

    # Verify checksum if available
    if expected_sha and expected_sha != 'TBD':
        actual_sha = hashlib.sha256(open(target_path, 'rb').read()).hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            print(f"[FAIL] {name}: SHA-256 mismatch!")
            print(f"  Expected: {expected_sha}")
            print(f"  Actual:   {actual_sha}")
            os.remove(target_path)
            return False
        print(f"[OK] {name}: SHA-256 verified")

    print(f"[DONE] {name}: {target_path}")
    return True


def main():
    project_root = find_project_root()
    manifests = load_manifests(project_root)

    if not manifests:
        print("No manifests found in third_party/manifests/")
        return 1

    print(f"Found {len(manifests)} manifest(s)")
    success = 0
    for manifest in manifests:
        if download_and_verify(manifest, project_root):
            success += 1

    print(f"\n{success}/{len(manifests)} dependencies ready")
    return 0 if success == len(manifests) else 1


if __name__ == '__main__':
    sys.exit(main())
