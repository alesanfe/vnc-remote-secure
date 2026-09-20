# Install-VncRemote.ps1 - Install VNC Remote Secure on Windows
# Thin delegator to the canonical Python CLI.
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = 'Stop'

# Resolve Python interpreter.
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) { $pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyExe) {
    Write-Error "Python is required. Install Python 3.11+ from python.org"
    exit 1
}

# Set PYTHONPATH so the package is found from the source tree.
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..\..')).Path
$env:PYTHONPATH = "$repoRoot\src;$env:PYTHONPATH"

# Delegate to the canonical Python CLI.
$args = @('install')
if ($WhatIfPreference) { $args += '--dry-run' }

Write-Host "=== VNC Remote Secure - Installation ===" -ForegroundColor Cyan
& $pyExe.Source -m vnc_remote_secure.cli @args
