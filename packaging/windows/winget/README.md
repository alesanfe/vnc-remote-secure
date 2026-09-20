# WinGet manifests

This directory will contain the WinGet manifest files (YAML) required to
publish VNC Remote Secure to the
[Windows Package Manager](https://github.com/microsoft/winget-cli) community
repository (`winget-pkgs`).

## Planned contents

| File                                  | Purpose                                              |
|---------------------------------------|------------------------------------------------------|
| `vnc-remote-secure.yaml`              | Package version 1 manifest (identifier, version).   |
| `vnc-remote-secure.installer.yaml`    | Installer definitions (MSI URL, arch, SHA256).       |
| `vnc-remote-secure.locale.en-US.yaml` | Default locale metadata (description, tags, license).|
| `vnc-remote-secure.installer.1.0.0.yaml` | Per-version installer manifest.                   |

## Validation (future)

```powershell
winget validate .\packaging\windows\winget\
winget install --manifest .\packaging\windows\winget\
```

## Status

No manifests are published yet. The MSI produced by
[`packaging/windows/build-installer.ps1`](../build-installer.ps1) must be
signed and hosted before submission to the winget-pkgs repository.
