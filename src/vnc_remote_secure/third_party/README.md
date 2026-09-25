# Third-Party Dependencies

This directory contains manifests, licenses, and checksums for external
dependencies used by VNC Remote Secure. **No binaries are committed to the
repository** — they are downloaded and verified at install time.

## Structure

```
third_party/
├── README.md           # This file
├── manifests/          # JSON manifests describing each dependency
│   ├── novnc.json
│   ├── ttyd.json
│   ├── tightvnc.json
│   └── ultravnc.json
├── licenses/           # License texts for each dependency
│   ├── novnc.txt
│   ├── ttyd.txt
│   ├── tightvnc.txt
│   ├── ultravnc.txt
│   └── xterm.txt       # xterm.js is bundled by the frontend (npm), not
│                       # downloaded — the license text stays for compliance
└── checksums/          # SHA-256 checksums for verified downloads
    └── SHA256SUMS
```

## Why manifests instead of binaries?

1. **Repository size**: Binaries bloat the repo and make cloning slow.
2. **Security**: Downloaded binaries are verified against SHA-256 hashes.
3. **Updates**: Updating a dependency means changing a manifest, not
   committing a new binary.
4. **Licensing**: License texts are kept separately for compliance.
5. **No duplicates**: Git history doesn't accumulate backup copies
   (`_bak.exe`, old versions, etc.).

## Download and verification

```bash
# Download all dependencies (verifies SHA-256)
python tools/download_dependencies.py

# Verify existing dependencies
python tools/verify_dependencies.py
```

## noVNC

noVNC is a web-based VNC client written in JavaScript. It is cloned at
runtime by `tools/download_dependencies.py` (or `make setup-novnc`) into
the `novnc/` directory (which is gitignored).

If you need to vendor noVNC, use a git submodule pointing to a specific
commit:

```bash
git submodule add https://github.com/novnc/noVNC.git src/vnc_remote_secure/third_party/novnc
cd src/vnc_remote_secure/third_party/novnc
git checkout v1.4.0  # pin to a specific version
```
