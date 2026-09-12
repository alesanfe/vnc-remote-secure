#!/usr/bin/env python3
"""
Download third-party dependencies and verify their SHA-256 checksums.

Reads manifests from third_party/manifests/*.json and downloads
the specified binaries into the appropriate runtime directories.

Supports three manifest types via the "managed_by" field:
  - "download":  Direct file download (with optional zip extraction)
  - "git-clone": Clone a git repository to a target directory
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


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


def _verify_sha256(filepath, expected_sha, name):
    """Verify SHA-256 checksum of a file. Returns True if valid or no checksum."""
    if not expected_sha or expected_sha == 'TBD':
        print(f"[WARN] {name}: SHA-256 not set in manifest, skipping verification")
        return True
    actual_sha = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
    if actual_sha.lower() != expected_sha.lower():
        print(f"[FAIL] {name}: SHA-256 mismatch!")
        print(f"  Expected: {expected_sha}")
        print(f"  Actual:   {actual_sha}")
        return False
    print(f"[OK] {name}: SHA-256 verified")
    return True


def _download_file(url, target_path, name):
    """Download a file from URL to target path."""
    print(f"[DOWNLOAD] {name}: {url}")
    try:
        urllib.request.urlretrieve(url, target_path)
    except Exception as e:
        print(f"[ERROR] {name}: download failed: {e}", file=sys.stderr)
        return False
    return True


def _extract_zip(zip_path, extract_dir, name):
    """Extract a zip file to a directory."""
    print(f"[EXTRACT] {name}: {zip_path} -> {extract_dir}")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
        return True
    except Exception as e:
        print(f"[ERROR] {name}: extraction failed: {e}", file=sys.stderr)
        return False


def _git_clone(clone_url, target_dir, name, pinned_commit=None):
    """Clone a git repository to target directory."""
    if os.path.isdir(target_dir) and os.listdir(target_dir):
        print(f"[EXISTS] {name}: {target_dir}")
        return True

    print(f"[CLONE] {name}: {clone_url} -> {target_dir}")
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    try:
        subprocess.run(
            ['git', 'clone', '--depth', '1', clone_url, target_dir],
            check=True,
            capture_output=True,
        )
        if pinned_commit:
            subprocess.run(
                ['git', '-C', target_dir, 'checkout', pinned_commit],
                check=True,
                capture_output=True,
            )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {name}: git clone failed: {e.stderr.decode()}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(f"[ERROR] {name}: git not found", file=sys.stderr)
        return False
    return True


def download_and_verify(manifest, project_root):
    """Download a dependency and verify its checksum."""
    name = manifest.get('name', 'unknown')
    managed_by = manifest.get('managed_by', 'download')
    expected_sha = manifest.get('sha256', 'TBD')

    # Determine target directory
    platform = manifest.get('platform', 'cross-platform')
    if platform == 'windows':
        target_dir = os.path.join(project_root, 'bin')
    else:
        target_dir = os.path.join(project_root, 'vendor')

    # --- git-clone ---
    if managed_by == 'git-clone':
        clone_url = manifest.get('clone_url')
        clone_target = manifest.get('clone_target', name.lower() + '/')
        if not clone_url:
            print(f"[SKIP] {name}: no clone_url")
            return False
        target_path = os.path.join(project_root, clone_target)
        return _git_clone(clone_url, target_path, name, manifest.get('pinned_commit'))

    # --- manual (verify existing binary) ---
    if managed_by == 'manual':
        target_path_rel = manifest.get('target_path')
        filename = manifest.get('filename')
        if target_path_rel:
            target_path = os.path.join(project_root, target_path_rel)
        elif filename:
            target_path = os.path.join(target_dir, filename)
        else:
            print(f"[SKIP] {name}: no target_path or filename")
            return False
        if not os.path.exists(target_path):
            print(f"[MISSING] {name}: {target_path} not found. See notes in manifest for manual download.")
            return False
        print(f"[EXISTS] {name}: {target_path}")
        if expected_sha and expected_sha != 'TBD':
            if not _verify_sha256(target_path, expected_sha, name):
                return False
        return True

    # --- download ---
    url = manifest.get('download_url')
    filename = manifest.get('filename')
    if not url or not filename:
        print(f"[SKIP] {name}: no download URL or filename")
        return False

    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)

    if os.path.exists(target_path):
        print(f"[EXISTS] {name}: {target_path}")
        if expected_sha and expected_sha != 'TBD':
            if not _verify_sha256(target_path, expected_sha, name):
                return False
        return True

    # Download to temp file first
    with tempfile.NamedTemporaryFile(delete=False, suffix='_' + filename) as tmp:
        tmp_path = tmp.name

    try:
        if not _download_file(url, tmp_path, name):
            return False

        if not _verify_sha256(tmp_path, expected_sha, name):
            os.remove(tmp_path)
            return False

        # Move to final location
        shutil.move(tmp_path, target_path)

        # Extract if it's a zip archive
        archive_type = manifest.get('archive_type')
        if archive_type == 'zip' or filename.endswith('.zip'):
            extract_dir = os.path.join(target_dir, filename.rsplit('.', 1)[0])
            if not _extract_zip(target_path, extract_dir, name):
                return False
            print(f"[EXTRACTED] {name}: -> {extract_dir}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

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
