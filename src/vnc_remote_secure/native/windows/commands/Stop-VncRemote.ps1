# Stop-VncRemote.ps1 - Stop VNC Remote Secure services on Windows
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Stopping ===" -ForegroundColor Cyan

# commands/ is four levels below src/; PYTHONPATH must contain <repo>/src
$env:PYTHONPATH = "$PSScriptRoot\..\..\..\..;$env:PYTHONPATH"

# Resolve Python interpreter (python → python3), same as Install/Uninstall.
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) { $pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyExe) {
    Write-Error "Python is required. Install Python 3.11+ from python.org"
    exit 1
}

& $pyExe.Source -m vnc_remote_secure.cli stop

if ($LASTEXITCODE -eq 0) {
    Write-Host "Services stopped." -ForegroundColor Green
} else {
    Write-Warning "Stop returned exit code: $LASTEXITCODE"
}
