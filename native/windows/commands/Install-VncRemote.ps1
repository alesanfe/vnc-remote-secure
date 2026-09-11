# Install-VncRemote.ps1 - Install VNC Remote Secure on Windows
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallPath = "$env:ProgramData\VncRemoteSecure",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Installation ===" -ForegroundColor Cyan

# Check prerequisites
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python is required. Install Python 3.8+ from python.org"
    exit 1
}

# Create directories
$dirs = @(
    "$InstallPath",
    "$InstallPath\config",
    "$InstallPath\data",
    "$InstallPath\logs",
    "$InstallPath\secrets"
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        if ($PSCmdlet.ShouldProcess($dir, "Create directory")) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "  Created: $dir" -ForegroundColor Green
        }
    }
}

# Configure firewall
if ($PSCmdlet.ShouldProcess("Firewall", "Configure")) {
    & "$PSScriptRoot\..\Firewall.ps1" -Action Create
}

# Generate self-signed certificate if not exists
$certPath = "$InstallPath\data\ssl"
if (-not (Test-Path "$certPath\fullchain.pem") -or $Force) {
    if ($PSCmdlet.ShouldProcess("SSL Certificate", "Generate self-signed")) {
        Write-Host "  Generating self-signed certificate..." -ForegroundColor Yellow
        $env:PYTHONPATH = "$PSScriptRoot\..\..\..\src;$env:PYTHONPATH"
        python "$PSScriptRoot\..\..\..\scripts\utilities\generate_certificate.py" --output "$certPath" 2>$null
    }
}

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "Start with: vnc-remote start" -ForegroundColor White
