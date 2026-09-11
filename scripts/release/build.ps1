# Build release artifacts (Windows)
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = ""
)

if (-not $Version) {
    $Version = "0.0.0"
    try {
        $env:PYTHONPATH = "src;$env:PYTHONPATH"
        $Version = python -c "from vnc_remote_secure import __version__; print(__version__)" 2>$null
    } catch {}
}

Write-Host "=== Building VNC Remote Secure v$Version ===" -ForegroundColor Cyan

# Clean previous builds
if ($PSCmdlet.ShouldProcess("dist/ and build/", "Clean previous builds")) {
    if (Test-Path dist) { Remove-Item dist -Recurse -Force }
    if (Test-Path build) { Remove-Item build -Recurse -Force }
    Get-ChildItem -Filter "*.egg-info" -Recurse -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

# Build Python package
if ($PSCmdlet.ShouldProcess("Python package", "Build")) {
    python -m build
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
