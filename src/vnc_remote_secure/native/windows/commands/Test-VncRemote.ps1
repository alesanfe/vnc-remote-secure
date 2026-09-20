# Test-VncRemote.ps1 - Diagnose VNC Remote Secure readiness on Windows
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# commands/ is four levels below src/; PYTHONPATH must contain <repo>/src
$env:PYTHONPATH = "$PSScriptRoot\..\..\..\..;$env:PYTHONPATH"

# Resolve Python interpreter (python → python3), same as Install/Uninstall.
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) { $pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyExe) {
    Write-Error "Python is required. Install Python 3.11+ from python.org"
    exit 1
}

& $pyExe.Source -m vnc_remote_secure.cli doctor

# Also verify firewall rules
Write-Host ""
Write-Host "Firewall rules:" -ForegroundColor Cyan
& "$PSScriptRoot\..\Firewall.ps1" -Action Verify

exit $LASTEXITCODE
