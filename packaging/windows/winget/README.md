# WinGet manifests

WinGet manifest files (schema 1.9) for publishing VNC Remote Secure to
the [Windows Package Manager](https://github.com/microsoft/winget-cli)
community repository (`winget-pkgs`).

## Contents

| File                                  | Purpose                                              |
|---------------------------------------|------------------------------------------------------|
| `VncRemoteSecure.yaml`                | Version manifest (identifier, version).              |
| `VncRemoteSecure.installer.yaml`      | Installer definition (MSI type, arch, switches, hash).|
| `VncRemoteSecure.locale.en-US.yaml`   | Locale metadata (description, tags, license).        |

## Per-release steps

1. Build + sign the MSI: `packaging\windows\build-installer.ps1` then
   `signtool sign` (or CI's signing job).
2. Publish the MSI to the GitHub release.
3. In `VncRemoteSecure.installer.yaml` fill:
   - `InstallerUrl` — the release download URL
   - `InstallerSha256` — from `dist\SHA256SUMS.txt`
   - `ReleaseDate`
4. Bump `PackageVersion` in all three manifests (keep it in sync with
   `pyproject.toml`).

## Validation

```powershell
winget validate --manifest .\packaging\windows\winget\
winget install --manifest .\packaging\windows\winget\
```

## Status

Manifests exist and parse. They are NOT submittable until the
placeholder URL/hash are replaced by a signed release artifact.
