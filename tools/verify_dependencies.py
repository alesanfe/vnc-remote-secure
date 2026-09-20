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


def find_manifests_dir(project_root):
    """Locate third_party/manifests/.

    Looks first at the package-relative location
    ``src/vnc_remote_secure/third_party/manifests`` (post-consolidation
    layout, also used by pip-installed wheels), then at the legacy
    ``<project_root>/third_party/manifests`` (pre-consolidation layout).
    """
    candidates = [
        os.path.join(project_root, 'src', 'vnc_remote_secure', 'third_party', 'manifests'),
        os.path.join(project_root, 'third_party', 'manifests'),
    ]
    return next((d for d in candidates if os.path.isdir(d)), None)


def main():
    project_root = find_project_root()
    manifests_dir = find_manifests_dir(project_root)

    if not manifests_dir:
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
        managed_by = manifest.get('managed_by', '')
        target_path_rel = manifest.get('target_path')
        clone_target = manifest.get('clone_target')

        # Skip manifests for other platforms (e.g. ttyd is Linux-only
        # and will never be present on a Windows dev machine).
        is_windows = sys.platform == 'win32'
        if platform == 'linux' and is_windows:
            print(f"[SKIP] {name}: Linux-only dependency")
            continue
        if platform == 'windows' and not is_windows:
            print(f"[SKIP] {name}: Windows-only dependency")
            continue
        # 'manual' dependencies cannot be fetched or verified by this
        # tool (e.g. MSI installers, alternatives to the primary choice)
        # — report their presence but never fail on their absence.
        manual = managed_by == 'manual'

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
            if manual:
                print(f"[SKIP] {name}: manual dependency not present "
                      f"({target_path or 'no filename'})")
            else:
                print(f"[MISSING] {name}: {target_path or 'no filename'}")
                all_ok = False
            continue

        # git-clone manifests pin a commit SHA instead of a file hash —
        # verify the checked-out HEAD so a re-pointed tag (or a hand-
        # edited vendor tree) is detected.
        pinned_sha = manifest.get('pinned_commit_sha')
        if pinned_sha and os.path.isdir(target_path):
            import subprocess
            try:
                head = subprocess.run(
                    ['git', '-C', target_path, 'rev-parse', 'HEAD'],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
            except (subprocess.CalledProcessError, FileNotFoundError):
                head = ''
            if head != pinned_sha:
                print(f"[MISMATCH] {name}: HEAD {head or '<unknown>'} "
                      f"!= pinned_commit_sha {pinned_sha}")
                all_ok = False
            else:
                print(f"[OK] {name}: HEAD matches pinned SHA")
            continue

        if os.path.isdir(target_path):
            print(f"[PRESENT] {name}: {target_path} (directory, no checksum)")
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
