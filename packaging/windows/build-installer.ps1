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
    Requires: Python 3.8+, the `build` package, and the WiX Toolset v3+.
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

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { Write-Fail 'Python not found on PATH. Install Python 3.8+.' }
Write-Step "  Python: $($python.Source)"

$candle = $null
$light  = $null
if ($WixToolPath) {
    $candidateCandle = Join-Path $WixToolPath 'candle.exe'
    $candidateLight  = Join-Path $WixToolPath 'light.exe'
    if (Test-Path $candidateCandle) { $candle = Get-Command $candidateCandle }
    if (Test-Path $candidateLight)  { $light  = Get-Command $candidateLight  }
} else {
    $candle = Get-Command candle -ErrorAction SilentlyContinue
    $light  = Get-Command light  -ErrorAction SilentlyContinue
    if (-not $candle -or -not $light) {
        $wixCommon = @(
            "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles}\WiX Toolset v3.14\bin",
            "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
            "${env:ProgramFiles}\WiX Toolset v3.11\bin"
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if ($wixCommon) {
            $candle = Get-Command (Join-Path $wixCommon 'candle.exe') -ErrorAction SilentlyContinue
            $light  = Get-Command (Join-Path $wixCommon 'light.exe')  -ErrorAction SilentlyContinue
        }
    }
}

if (-not $candle -or -not $light) {
    Write-Fail 'WiX Toolset not found. Install WiX v3+ or pass -WixToolPath.'
}
Write-Step "  WiX candle: $($candle.Source)"
Write-Step "  WiX light:  $($light.Source)"

# --- 2. Build the Python package ---------------------------------------------
Write-Step "Building Python package (python -m build) in $repoRoot"
if ($PSCmdlet.ShouldProcess($repoRoot, 'python -m build')) {
    Push-Location $repoRoot
    try {
        & python -m build
        if ($LASTEXITCODE -ne 0) { Write-Fail "python -m build failed (exit $LASTEXITCODE)." }
    }
    finally { Pop-Location }
}

# --- 3. Prepare output directory ---------------------------------------------
$OutputDir = (Resolve-Path (New-Item -ItemType Directory -Force -Path $OutputDir)).Path
Write-Step "Output directory: $OutputDir"

# --- 4. Create WiX installer skeleton ---------------------------------------
$wxsSkeleton = @'
<?xml version='1.0' encoding='UTF-8'?>
<!--
  WiX source skeleton for VNC Remote Secure.
  This is a starting point; refine Product/@Id, Component paths and
  Directory layout before producing a signed MSI.
-->
<Wix xmlns='http://schemas.microsoft.com/wix/2006/wi'>
  <Product Id='*' Name='VNC Remote Secure' Language='1033'
           Version='0.2.0' Manufacturer='VNC Remote Secure Contributors'
           UpgradeCode='PUT-GUID-HERE'>
    <Package Description='VNC Remote Secure MSI installer'
             Manufacturer='VNC Remote Secure Contributors'
             InstallerVersion='300' Compressed='yes' />
    <Media Id='1' Cabinet='vncrs.cab' EmbedCab='yes' />

    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='ProgramFiles64Folder' Name='PFiles'>
        <Directory Id='INSTALLDIR' Name='vnc-remote-secure'>
          <Component Id='MainFiles' Guid='PUT-GUID-HERE'>
            <!-- TODO: list built artifacts from dist\ -->
            <CreateFolder />
          </Component>
        </Directory>
      </Directory>
    </Directory>

    <Feature Id='Complete' Title='VNC Remote Secure' Level='1'>
      <ComponentRef Id='MainFiles' />
    </Feature>
  </Product>
</Wix>
'@

$wxsPath = Join-Path $OutputDir 'vnc-remote-secure.wxs'
Write-Step "Writing WiX skeleton: $wxsPath"
if ($PSCmdlet.ShouldProcess($wxsPath, 'Write WiX skeleton')) {
    Set-Content -Path $wxsPath -Value $wxsSkeleton -Encoding UTF8
}

# --- 5. Compile and link the MSI --------------------------------------------
$wixobjPath = Join-Path $OutputDir 'vnc-remote-secure.wixobj'
$msiPath    = Join-Path $OutputDir 'vnc-remote-secure.msi'

Write-Step "Compiling WiX source (candle)"
if ($PSCmdlet.ShouldProcess($wxsPath, "candle -out `"$wixobjPath`"")) {
    & $candle.Source -out "$wixobjPath" "$wxsPath"
    if ($LASTEXITCODE -ne 0) { Write-Fail "candle failed (exit $LASTEXITCODE)." }
}

Write-Step "Linking MSI (light)"
if ($PSCmdlet.ShouldProcess($wixobjPath, "light -out `"$msiPath`"")) {
    & $light.Source -out "$msiPath" "$wixobjPath"
    if ($LASTEXITCODE -ne 0) { Write-Fail "light failed (exit $LASTEXITCODE)." }
}

# --- 6. Done -----------------------------------------------------------------
Write-Step ''
Write-Step '============================================================'
Write-Step ' Build complete.'
Write-Step '============================================================'
Write-Step "  Artifacts : $OutputDir"
Write-Step "  MSI       : $msiPath"
Write-Step ''
