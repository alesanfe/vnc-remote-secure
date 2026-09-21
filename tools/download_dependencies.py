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
    """Load all manifests from third_party/manifests/.

    Looks first at the package-relative location
    ``src/vnc_remote_secure/third_party/manifests`` (post-consolidation
    layout, also used by pip-installed wheels), then at the legacy
    ``<project_root>/third_party/manifests`` (pre-consolidation layout).
    """
    candidates = [
        os.path.join(project_root, 'src', 'vnc_remote_secure', 'third_party', 'manifests'),
        os.path.join(project_root, 'third_party', 'manifests'),
    ]
    manifests_dir = next((d for d in candidates if d and os.path.isdir(d)), None)
    manifests = []
    if not manifests_dir:
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
        # urlopen with an explicit timeout — urlretrieve() relies on the
        # global socket timeout (unset here), so a stalled connection
        # would hang CI/developer runs indefinitely.
        with urllib.request.urlopen(url, timeout=120) as resp, \
                open(target_path, 'wb') as out:
            shutil.copyfileobj(resp, out)
    except Exception as e:
        print(f"[ERROR] {name}: download failed: {e}", file=sys.stderr)
        return False
    return True


def _extract_zip(zip_path, extract_dir, name):
    """Extract a zip file to a directory."""
    print(f"[EXTRACT] {name}: {zip_path} -> {extract_dir}")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Reject member paths that escape the target dir
            # (zip-slip) — same guard as the runtime UltraVNC
            # provisioning path in platform/windows/installer.py.
            dest = os.path.realpath(extract_dir)
            for member in zf.namelist():
                target = os.path.realpath(os.path.join(dest, member))
                if not target.startswith(dest + os.sep):
                    raise RuntimeError(
                        f"Unsafe path in {name} archive: {member}")
            try:
                zf.extractall(dest, filter='data')
            except TypeError:
                zf.extractall(dest)
        return True
    except Exception as e:
        print(f"[ERROR] {name}: extraction failed: {e}", file=sys.stderr)
        return False


def _git_clone(clone_url, target_dir, name, pinned_commit=None,
               pinned_sha=None):
    """Clone a git repository to target directory.

    When ``pinned_sha`` is given, the checked-out HEAD must equal it —
    tags are mutable (a force-moved tag must fail loudly, not silently
    vendored a different tree).
    """
    if os.path.isdir(target_dir) and os.listdir(target_dir):
        print(f"[EXISTS] {name}: {target_dir}")
        return True

    print(f"[CLONE] {name}: {clone_url} -> {target_dir}")
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    try:
        # A shallow clone only fetches the default-branch HEAD, so a
        # pinned tag/branch must be passed to ``--branch`` at clone
        # time — a later ``checkout`` cannot see refs the shallow
        # clone never fetched.
        clone_cmd = ['git', 'clone', '--depth', '1']
        if pinned_commit:
            clone_cmd += ['--branch', pinned_commit]
        clone_cmd += [clone_url, target_dir]
        subprocess.run(clone_cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {name}: git clone failed: {e.stderr.decode()}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(f"[ERROR] {name}: git not found", file=sys.stderr)
        return False
    if pinned_sha:
        try:
            head = subprocess.run(
                ['git', '-C', target_dir, 'rev-parse', 'HEAD'],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            head = ''
        if head != pinned_sha:
            print(
                f"[ERROR] {name}: checked-out HEAD {head or '<unknown>'} "
                f"does not match pinned_commit_sha {pinned_sha} — the "
                f"tag may have been re-pointed. Refusing to use it.",
                file=sys.stderr)
            shutil.rmtree(target_dir, ignore_errors=True)
            return False
        print(f"[VERIFIED] {name}: HEAD {head} matches pinned SHA")
    return True


def download_and_verify(manifest, project_root):
    """Download a dependency and verify its checksum."""
    name = manifest.get('name', 'unknown')
    managed_by = manifest.get('managed_by', 'download')
    expected_sha = manifest.get('sha256', 'TBD')

    # Determine target directory
    platform = manifest.get('platform', 'cross-platform')
    # Skip manifests for other platforms — the same gate
    # verify_dependencies.py applies, so running this tool on Windows
    # does not fetch Linux-only binaries (and vice versa).
    import sys as _sys
    is_windows = _sys.platform == 'win32'
    if platform == 'linux' and is_windows:
        print(f"[SKIP] {name}: Linux-only dependency")
        return False
    if platform == 'windows' and not is_windows:
        print(f"[SKIP] {name}: Windows-only dependency")
        return False
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
        return _git_clone(
            clone_url, target_path, name,
            manifest.get('pinned_commit'),
            manifest.get('pinned_commit_sha'))

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
        print("No manifests found (checked src/vnc_remote_secure/third_party/manifests/ and third_party/manifests/)")
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
