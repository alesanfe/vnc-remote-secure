# Native Windows Components

This directory contains Windows-native PowerShell scripts and service definitions.

## Structure

```
src/vnc_remote_secure/native/windows/
├── VncRemote.psm1       # PowerShell module
├── VncRemote.psd1       # Module manifest
├── Firewall.ps1         # Windows Firewall management script
├── commands/            # Individual command scripts
└── service/             # Windows Service configuration
```

## Usage

### Direct script execution (root-level wrapper)
```powershell
.\VncRemote.ps1 Install
.\VncRemote.ps1 Start
.\VncRemote.ps1 Get-Status
.\VncRemote.ps1 Test-Configuration
.\VncRemote.ps1 Uninstall
```

### As a module
```powershell
Import-Module .\src\vnc_remote_secure\native\windows\VncRemote.psd1
Install-VncRemote
Get-VncRemoteStatus
Test-VncRemoteConfiguration
```

### Firewall management
```powershell
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Create
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action List
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Verify
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Remove
```

## What Windows Support Includes

- UltraVNC for VNC server (not TigerVNC)
- Python/Tornado web terminal (not ttyd)
- websockify for noVNC proxy
- Self-signed SSL certificates (no Let's Encrypt)
- Windows Firewall rules (only the landing portal port — default 8000 — public)
- Health dashboard with Windows-native metrics
- Restricted runtime user account (process-level isolation is partial —
  see `docs/adr/0007-cross-platform-windows-support.md`)

## What Windows Support Does NOT Include

- systemd (uses script-based process management)
- fail2ban (uses Windows Defender / Windows Firewall)
- Let's Encrypt / certbot (self-signed only)
- Full process impersonation (VNC/terminal processes may run as the
  invoking user — see ADR-0007)
- POSIX permissions (uses ACLs, but not fully implemented yet)
