# WiX source files

This directory will contain the WiX source (`.wxs`) files used to build the
Windows MSI installer for VNC Remote Secure.

## Planned contents

| File                          | Purpose                                                |
|-------------------------------|--------------------------------------------------------|
| `vnc-remote-secure.wxs`       | Main product definition (Product, Package, Features).  |
| `fragments/app.wxs`           | Fragment listing the Python package files to install.  |
| `fragments/cli.wxs`           | Fragment for the `vnc-remote` CLI wrapper / PATH entry.|
| `fragments/config.wxs`        | Fragment for default config under `%ProgramData%`.     |
| `ui/custom-ui.wxs`            | Optional custom UI dialog set.                         |
| `localization/en-us.wxl`      | English localization strings.                          |

## Build (future)

```powershell
# From the repository root:
candle packaging\windows\wix\vnc-remote-secure.wxs -o dist\vnc-remote-secure.wixobj
light  dist\vnc-remote-secure.wixobj -o dist\vnc-remote-secure.msi
```

The orchestrating script
[`packaging/windows/build-installer.ps1`](../build-installer.ps1) currently
emits a skeleton `.wxs` into `dist\`; the files here will replace that
skeleton with the production definitions.

## Status

**Placeholder.** No production `.wxs` files exist yet.
