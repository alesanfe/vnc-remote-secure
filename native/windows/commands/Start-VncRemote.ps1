# Start-VncRemote.ps1 - Start VNC Remote Secure services on Windows
[CmdletBinding()]
param(
    [string]$Profile = "default",
    [switch]$NoSSL
)

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Starting ===" -ForegroundColor Cyan

$env:PYTHONPATH = "$PSScriptRoot\..\..\..\src;$env:PYTHONPATH"

if ($NoSSL) {
    $env:TLS_ENABLED = 'false'
}

if ($Profile -ne 'default') {
    $env:VNC_REMOTE_PROFILE = $Profile
}

# Start via Python CLI
& python -m vnc_remote_secure start $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Services started." -ForegroundColor Green
} else {
    Write-Error "Failed to start services (exit code: $LASTEXITCODE)"
    exit $LASTEXITCODE
}
