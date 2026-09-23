# WiX source files

Production WiX source (`.wxs`) for the Windows MSI installer.

## Contents

| File / dir                    | Purpose                                                  |
|-------------------------------|----------------------------------------------------------|
| `vnc-remote-secure.wxs`       | Product definition: ProgramData layout (parity with the Python installer), PATH entry, upgrade rules, Python-presence check. |
| `support/service-run.py`      | Service launcher installed to `%ProgramData%\VncRemoteSecure\` (adds `src/` to `sys.path`). |
| `support/vnc-remote.cmd`      | CLI shim installed to `ProgramFiles\VncRemoteSecure\bin\` + PATH. |

## Build

```powershell
# From the repository root — requires WiX v3 (candle/light/heat):
packaging\windows\build-installer.ps1
```

The script:

1. Builds the Python package (`python -m build`).
2. **Harvests** `src\vnc_remote_secure` with `heat` → `dist\app-files.wxs`
   (the component list is generated, never hand-maintained).
3. Compiles `vnc-remote-secure.wxs` + `app-files.wxs` with the package
   version from `pyproject.toml` (`-dPackageVersion`).
4. Links `dist\vnc-remote-secure-<version>.msi`.

## What the MSI does NOT do

Service registration, firewall rules, certificates and ACLs are
runtime OS-integration steps owned by `vnc-remote install` — run it
(elevated) after the MSI lands. This is the same flow as the manual
install path; the MSI's job is files + PATH only.
