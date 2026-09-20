# Bootstrap development environment for VNC Remote Secure (Windows)
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Write-Host "=== VNC Remote Secure - Development Bootstrap ===" -ForegroundColor Cyan

# Check Python — same resolution as the runtime scripts (python, then
# python3); invoke the resolved executable rather than a bare name.
$pythonExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonExe) { $pythonExe = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pythonExe) {
    Write-Error "Python not found. Please install Python 3.11+."
    exit 1
}

# Create virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    if ($PSCmdlet.ShouldProcess(".venv", "Create virtual environment")) {
        & $pythonExe.Source -m venv .venv
    }
}

# Activate and install
if ($PSCmdlet.ShouldProcess("Dependencies", "Install development dependencies")) {
    & .venv\Scripts\Activate.ps1
    pip install --upgrade pip
    pip install -e ".[dev]"

    # Install pre-commit hooks
    $preCommit = Get-Command pre-commit -ErrorAction SilentlyContinue
    if ($preCommit) {
        pre-commit install
        Write-Host "Pre-commit hooks installed." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Development environment ready." -ForegroundColor Green
Write-Host "Activate with: .venv\Scripts\Activate.ps1"
