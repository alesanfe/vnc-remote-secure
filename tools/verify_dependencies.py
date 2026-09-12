#!/usr/bin/env python3
"""
Verify that downloaded third-party dependencies match their manifests.
Checks file existence and SHA-256 checksums.
"""
import hashlib
import json
import os
import sys


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def main():
    project_root = find_project_root()
    manifests_dir = os.path.join(project_root, 'third_party', 'manifests')

    if not os.path.isdir(manifests_dir):
        print("No manifests directory found")
        return 1

    all_ok = True
    for f in sorted(os.listdir(manifests_dir)):
        if not f.endswith('.json'):
            continue
        with open(os.path.join(manifests_dir, f)) as fh:
            manifest = json.load(fh)

        name = manifest.get('name', 'unknown')
        filename = manifest.get('filename')
        expected_sha = manifest.get('sha256', 'TBD')
        platform = manifest.get('platform', 'cross-platform')
        managed_by = manifest.get('managed_by', 'download')
        target_path_rel = manifest.get('target_path')
        clone_target = manifest.get('clone_target')

        if platform == 'windows':
            target_dir = os.path.join(project_root, 'bin')
        else:
            target_dir = os.path.join(project_root, 'vendor')

        # Prefer explicit target_path (used by manual/managed binaries),
        # then clone_target (git-clone), then filename as fallback.
        if target_path_rel:
            target_path = os.path.join(project_root, target_path_rel)
        elif clone_target:
            target_path = os.path.join(project_root, clone_target)
        elif filename:
            target_path = os.path.join(target_dir, filename)
        else:
            target_path = None

        if not target_path or not os.path.exists(target_path):
            print(f"[MISSING] {name}: {target_path or 'no filename'}")
            all_ok = False
            continue

        if expected_sha and expected_sha != 'TBD':
            actual_sha = hashlib.sha256(open(target_path, 'rb').read()).hexdigest()
            if actual_sha.lower() != expected_sha.lower():
                print(f"[MISMATCH] {name}: SHA-256 mismatch")
                all_ok = False
            else:
                print(f"[OK] {name}: verified")
        else:
            print(f"[PRESENT] {name}: {target_path} (no checksum to verify)")

    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
