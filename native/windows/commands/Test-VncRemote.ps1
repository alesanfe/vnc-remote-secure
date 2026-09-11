# Test-VncRemote.ps1 - Check VNC Remote Secure status on Windows
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$env:PYTHONPATH = "$PSScriptRoot\..\..\..\src;$env:PYTHONPATH"

& python -m vnc_remote_secure status

# Also verify firewall rules
Write-Host ""
Write-Host "Firewall rules:" -ForegroundColor Cyan
& "$PSScriptRoot\..\Firewall.ps1" -Action Verify

exit $LASTEXITCODE
