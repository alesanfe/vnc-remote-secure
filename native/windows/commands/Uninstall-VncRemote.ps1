# Uninstall-VncRemote.ps1 - Uninstall VNC Remote Secure from Windows
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallPath = "$env:ProgramData\VncRemoteSecure",
    [switch]$RemoveConfig,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Uninstallation ===" -ForegroundColor Cyan

# Stop services first
if ($PSCmdlet.ShouldProcess("Services", "Stop")) {
    & "$PSScriptRoot\Stop-VncRemote.ps1" -Force
}

# Remove firewall rules
if ($PSCmdlet.ShouldProcess("Firewall", "Remove rules")) {
    & "$PSScriptRoot\..\Firewall.ps1" -Action Remove
}

# Remove configuration
if ($RemoveConfig -and (Test-Path "$InstallPath\config")) {
    if ($PSCmdlet.ShouldProcess("$InstallPath\config", "Remove")) {
        Remove-Item "$InstallPath\config" -Recurse -Force
        Write-Host "  Removed: $InstallPath\config" -ForegroundColor Yellow
    }
}

# Remove data
if ($RemoveData -and (Test-Path "$InstallPath\data")) {
    if ($PSCmdlet.ShouldProcess("$InstallPath\data", "Remove")) {
        Remove-Item "$InstallPath\data" -Recurse -Force
        Write-Host "  Removed: $InstallPath\data" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Uninstallation complete." -ForegroundColor Green
