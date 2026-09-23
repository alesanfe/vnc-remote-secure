<#
.SYNOPSIS
    Build a Windows MSI installer for VNC Remote Secure.

.DESCRIPTION
    Builds the Python package with `python -m build`, then generates a WiX
    installer skeleton under dist\. Supports -WhatIf for dry-run inspection.

.PARAMETER Configuration
    Build configuration: Release (default) or Debug.

.PARAMETER WixToolPath
    Optional explicit path to the WiX toolset bin directory. If omitted the
    script looks for candle.exe / light.exe on PATH and in common locations.

.PARAMETER OutputDir
    Output directory for build artifacts. Defaults to .\dist.

.EXAMPLE
    .\build-installer.ps1
    Build the installer with defaults.

.EXAMPLE
    .\build-installer.ps1 -WhatIf
    Show what the script would do without executing any commands.

.NOTES
    Requires: Python 3.11+, the `build` package, and the WiX Toolset v3+.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [string]$WixToolPath,

    [string]$OutputDir = (Join-Path $PSScriptRoot '..\..\dist')
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Write-Step([string]$msg) { Write-Host "[build-installer] $msg" -ForegroundColor Cyan }
function Write-Fail([string]$msg) { Write-Host "[build-installer][ERROR] $msg" -ForegroundColor Red; exit 1 }

# --- 1. Check required tools -------------------------------------------------
Write-Step 'Checking required tools...'

# Resolve the interpreter the same way the runtime scripts do:
# python first, then python3, then a clear error.
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) { Write-Fail 'Python not found on PATH. Install Python 3.11+.' }
Write-Step "  Python: $($python.Source)"

$candle = $null
$light  = $null
$heat   = $null
if ($WixToolPath) {
    $candidateCandle = Join-Path $WixToolPath 'candle.exe'
    $candidateLight  = Join-Path $WixToolPath 'light.exe'
    $candidateHeat   = Join-Path $WixToolPath 'heat.exe'
    if (Test-Path $candidateCandle) { $candle = Get-Command $candidateCandle }
    if (Test-Path $candidateLight)  { $light  = Get-Command $candidateLight  }
    if (Test-Path $candidateHeat)   { $heat   = Get-Command $candidateHeat   }
} else {
    $candle = Get-Command candle -ErrorAction SilentlyContinue
    $light  = Get-Command light  -ErrorAction SilentlyContinue
    $heat   = Get-Command heat   -ErrorAction SilentlyContinue
    if (-not $candle -or -not $light -or -not $heat) {
        $wixCommon = @(
            "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
            "${env:ProgramFiles}\WiX Toolset v3.11\bin"
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if ($wixCommon) {
            $candle = Get-Command (Join-Path $wixCommon 'candle.exe') -ErrorAction SilentlyContinue
            $light  = Get-Command (Join-Path $wixCommon 'light.exe')  -ErrorAction SilentlyContinue
            $heat   = Get-Command (Join-Path $wixCommon 'heat.exe')   -ErrorAction SilentlyContinue
        }
    }
}

if (-not $candle -or -not $light -or -not $heat) {
    Write-Fail 'WiX Toolset not found (candle/light/heat). Install WiX v3+ or pass -WixToolPath.'
}
Write-Step "  WiX candle: $($candle.Source)"
Write-Step "  WiX light:  $($light.Source)"
Write-Step "  WiX heat:   $($heat.Source)"

# --- 2. Build the Python package ---------------------------------------------
Write-Step "Building Python package (python -m build) in $repoRoot"
if ($PSCmdlet.ShouldProcess($repoRoot, 'python -m build')) {
    Push-Location $repoRoot
    try {
        & $python.Source -m build
        if ($LASTEXITCODE -ne 0) { Write-Fail "python -m build failed (exit $LASTEXITCODE)." }
    }
    finally { Pop-Location }
}

# --- 3. Prepare output directory ---------------------------------------------
$OutputDir = (Resolve-Path (New-Item -ItemType Directory -Force -Path $OutputDir)).Path
Write-Step "Output directory: $OutputDir"

# --- 4. Resolve version and WiX sources --------------------------------------
# Read the version from the Python package (single source of truth: pyproject.toml).
$env:PYTHONPATH = "$repoRoot\src;$env:PYTHONPATH"
$pkgVersion = & $python.Source -c "from vnc_remote_secure import __version__; print(__version__)" 2>$null
if (-not $pkgVersion -or ($pkgVersion -notmatch '^\d+\.\d+\.\d+')) {
    Write-Fail "Cannot determine package version from Python. Is the package installed?"
}
$pkgVersion = $pkgVersion.Trim()
Write-Step "Package version: $pkgVersion"

$wixDir    = Join-Path $repoRoot 'packaging\windows\wix'
$mainWxs   = Join-Path $wixDir 'vnc-remote-secure.wxs'
$supportDir = Join-Path $wixDir 'support'
if (-not (Test-Path $mainWxs)) {
    Write-Fail "Production WiX source missing: $mainWxs"
}

# --- 5. Harvest the package tree (heat) --------------------------------------
# The component list is generated, not hand-maintained — every .py in
# src\vnc_remote_secure ships inside the MSI under PKG_SRC_DIR.
$appFilesWxs = Join-Path $OutputDir 'app-files.wxs'
$pkgSrc = Join-Path $repoRoot 'src\vnc_remote_secure'
Write-Step "Harvesting package files (heat): $pkgSrc"
if ($PSCmdlet.ShouldProcess($pkgSrc, "heat dir -> $appFilesWxs")) {
    & $heat.Source dir "$pkgSrc" -cg AppFilesGroup -gg -sfrag -srd `
        -dr PKG_SRC_DIR -var var.AppSrcDir -out "$appFilesWxs"
    if ($LASTEXITCODE -ne 0) { Write-Fail "heat failed (exit $LASTEXITCODE)." }
}

# --- 6. Compile and link the MSI --------------------------------------------
$mainObj  = Join-Path $OutputDir 'vnc-remote-secure.wixobj'
$filesObj = Join-Path $OutputDir 'app-files.wixobj'
$msiPath  = Join-Path $OutputDir "vnc-remote-secure-$pkgVersion.msi"

$candleArgs = @(
    "-dPackageVersion=$pkgVersion",
    "-dSupportDir=$supportDir",
    "-dAppSrcDir=$pkgSrc"
)
Write-Step "Compiling WiX sources (candle)"
if ($PSCmdlet.ShouldProcess($mainWxs, "candle -> $mainObj")) {
    & $candle.Source @candleArgs -out "$mainObj" "$mainWxs"
    if ($LASTEXITCODE -ne 0) { Write-Fail "candle failed (exit $LASTEXITCODE)." }
    & $candle.Source @candleArgs -out "$filesObj" "$appFilesWxs"
    if ($LASTEXITCODE -ne 0) { Write-Fail "candle failed (exit $LASTEXITCODE)." }
}

Write-Step "Linking MSI (light)"
if ($PSCmdlet.ShouldProcess($mainObj, "light -> $msiPath")) {
    & $light.Source -out "$msiPath" "$mainObj" "$filesObj"
    if ($LASTEXITCODE -ne 0) { Write-Fail "light failed (exit $LASTEXITCODE)." }
}

# --- 7. Done -----------------------------------------------------------------
Write-Step ''
Write-Step '============================================================'
Write-Step ' Build complete.'
Write-Step '============================================================'
Write-Step "  Artifacts : $OutputDir"
Write-Step "  MSI       : $msiPath"
Write-Step ''
Write-Step 'Post-install: run `vnc-remote install` (elevated) to register'
Write-Step 'the service, open the firewall and seed config.env.'
Write-Step ''
