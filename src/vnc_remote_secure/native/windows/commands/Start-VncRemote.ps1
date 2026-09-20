# Start-VncRemote.ps1 - Start VNC Remote Secure services on Windows
[CmdletBinding()]
param(
    [string]$Profile = "default",
    [switch]$NoSSL
)

$ErrorActionPreference = 'Stop'

Write-Host "=== VNC Remote Secure - Starting ===" -ForegroundColor Cyan

# commands/ is four levels below src/; PYTHONPATH must contain <repo>/src
$env:PYTHONPATH = "$PSScriptRoot\..\..\..\..;$env:PYTHONPATH"

# Resolve Python interpreter (python → python3), same as Install/Uninstall.
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) { $pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyExe) {
    Write-Error "Python is required. Install Python 3.11+ from python.org"
    exit 1
}

if ($NoSSL) {
    # Match the CLI `--no-ssl` flag which sets BOTH variables —
    # TLS_ENABLED alone would be overridden by a lingering
    # DISABLE_SSL=false and vice versa.
    $env:TLS_ENABLED = 'false'
    $env:DISABLE_SSL = 'true'
}

if ($Profile -ne 'default') {
    # SECURITY_PROFILE is the canonical variable consumed by the Python
    # package (security/profiles.py). VNC_REMOTE_PROFILE is a deprecated
    # alias kept for backward compatibility only.
    $env:SECURITY_PROFILE = $Profile
    $env:VNC_REMOTE_PROFILE = $Profile
}

# Start via Python CLI
& $pyExe.Source -m vnc_remote_secure.cli start $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Services started." -ForegroundColor Green
} else {
    Write-Error "Failed to start services (exit code: $LASTEXITCODE)"
    exit $LASTEXITCODE
}
