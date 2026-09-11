# Stop-VncRemote.ps1 - Stop VNC Remote Secure services on Windows
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Stopping ===" -ForegroundColor Cyan

$env:PYTHONPATH = "$PSScriptRoot\..\..\..\src;$env:PYTHONPATH"

if ($Force) {
    & python -m vnc_remote_secure stop --force
} else {
    & python -m vnc_remote_secure stop
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Services stopped." -ForegroundColor Green
} else {
    Write-Warning "Stop returned exit code: $LASTEXITCODE"
}
