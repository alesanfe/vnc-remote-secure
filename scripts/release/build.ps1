# Build release artifacts (Windows) — manual convenience wrapper.
# CI uses `python -m build` directly; this script adds checksum generation.
# Usage: powershell -File scripts/release/build.ps1 [-Version X.Y.Z]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = ""
)

# Resolve the interpreter the same way the runtime scripts do:
# python first, then python3.
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyExe) { $pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyExe) { Write-Error 'Python not found on PATH. Install Python 3.11+.'; exit 1 }

if (-not $Version) {
    try {
        # scripts/release/ is two levels below the repo root; the package
        # lives in <root>/src.
        $repoSrc = Join-Path $PSScriptRoot '..\..\src'
        $env:PYTHONPATH = "$repoSrc;$env:PYTHONPATH"
        $Version = & $pyExe.Source -c "from vnc_remote_secure import __version__; print(__version__)" 2>$null
    } catch {}
    if (-not $Version -or ($Version -notmatch '^\d+\.\d+\.\d+')) {
        Write-Error "Cannot determine version from Python package. Pass -Version explicitly or install the package."
        exit 1
    }
}

Write-Host "=== Building VNC Remote Secure v$Version ===" -ForegroundColor Cyan

# Stamp the resolved version into the PowerShell module manifest —
# pyproject.toml is the single source of truth, but a .psd1 requires a
# literal ModuleVersion field, so it is synced here at build time.
$psd1 = Join-Path $PSScriptRoot '..\..\src\vnc_remote_secure\native\windows\VncRemote.psd1'
if (Test-Path $psd1) {
    (Get-Content $psd1 -Raw) -replace "ModuleVersion\s*=\s*'[^']*'",
        "ModuleVersion      = '$Version'" | Set-Content $psd1 -NoNewline
    Write-Host "Synced ModuleVersion=$Version in VncRemote.psd1" -ForegroundColor Green
}

# Clean previous builds
if ($PSCmdlet.ShouldProcess("dist/ and build/", "Clean previous builds")) {
    if (Test-Path dist) { Remove-Item dist -Recurse -Force }
    if (Test-Path build) { Remove-Item build -Recurse -Force }
    Get-ChildItem -Filter "*.egg-info" -Recurse -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

# Build Python package
if ($PSCmdlet.ShouldProcess("Python package", "Build")) {
    & $pyExe.Source -m build
}

# Generate checksums
if (Test-Path dist) {
    if ($PSCmdlet.ShouldProcess("dist/SHA256SUMS.txt", "Generate checksums")) {
        Push-Location dist
        $hashes = Get-FileHash * -Algorithm SHA256
        $hashes | ForEach-Object { "$($_.Hash)  $($_.Path)" } | Out-File -FilePath SHA256SUMS.txt -Encoding utf8
        Pop-Location
        Write-Host "Checksums generated: dist/SHA256SUMS.txt" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Build complete. Artifacts in dist/" -ForegroundColor Green
if (Test-Path dist) {
    Get-ChildItem dist | Format-Table Name, Length
}
