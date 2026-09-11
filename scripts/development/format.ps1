# Format code (Windows)
[CmdletBinding()]
param()

Write-Host "=== Formatting code ===" -ForegroundColor Cyan

# Python formatting
$black = Get-Command black -ErrorAction SilentlyContinue
if ($black) {
    Write-Host "Running black..."
    black src/vnc_remote_secure/ tests/ tools/ scripts/utilities/ 2>$null
}

$ruff = Get-Command ruff -ErrorAction SilentlyContinue
if ($ruff) {
    Write-Host "Running ruff --fix..."
    ruff check --fix src/vnc_remote_secure/ tests/ tools/ 2>$null
}

Write-Host "Formatting complete." -ForegroundColor Green
