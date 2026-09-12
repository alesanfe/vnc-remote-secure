# Native Windows Components

This directory contains Windows-native PowerShell scripts and service definitions.

## Structure

```
native/windows/
├── VncRemote.psm1       # PowerShell module (canonical source)
├── VncRemote.psd1       # Module manifest
├── Firewall.ps1         # Windows Firewall management script
├── commands/            # Individual command scripts (future)
└── service/             # Windows Service configuration (future)
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

### As a module (future)
```powershell
Import-Module .\native\windows\VncRemote.psd1
Install-VncRemote
Get-VncRemoteStatus
Test-VncRemoteConfiguration
```

### Firewall management
```powershell
.\native\windows\Firewall.ps1 -Action Create
.\native\windows\Firewall.ps1 -Action List
.\native\windows\Firewall.ps1 -Action Verify
.\native\windows\Firewall.ps1 -Action Remove
```

## What Windows Support Includes

- UltraVNC for VNC server (not TigerVNC)
- Python/Tornado web terminal (not ttyd)
- websockify for noVNC proxy
- Self-signed SSL certificates (no Let's Encrypt)
- Windows Firewall rules (only port 443 public)
- Health dashboard with Windows-native metrics

## What Windows Support Does NOT Include

- systemd (uses script-based process management)
- fail2ban (uses Windows Defender / Windows Firewall)
- Let's Encrypt / certbot (self-signed only)
- User isolation (uses current user, no temp user creation)
- POSIX permissions (uses ACLs, but not fully implemented yet)
