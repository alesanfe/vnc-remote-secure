<#
.SYNOPSIS
    VNC Remote Secure - Native PowerShell module for Windows

.DESCRIPTION
    Provides a stable command interface for VNC Remote Secure on Windows.
    Equivalent to the Bash 'vnc-remote' CLI but using native PowerShell mechanisms:
    - Approved verbs
    - Typed parameters
    - SupportsShouldProcess (-WhatIf, -Confirm)
    - Object output (not just text)
    - No Invoke-Expression
    - No plaintext passwords

    This is a thin compatibility wrapper: every function delegates to the
    canonical Python CLI (vnc_remote_secure.cli). For a script-style entry
    point with command dispatch use .\VncRemote.ps1 at the project root.

.EXAMPLE
    Import-Module .\src\vnc_remote_secure\native\windows\VncRemote.psd1
    Install-VncRemote
    Install-VncRemote -WhatIf
    Start-VncRemote -Verbose
    Get-VncRemoteStatus -Json
    Test-VncRemoteConfiguration
    Uninstall-VncRemote

.NOTES
    Requires: PowerShell 5.1+ or PowerShell 7+
    Requires: Git Bash, Python 3.11+, UltraVNC binaries
#>

# Version — read from the Python package (single source of truth: pyproject.toml)
# Get project directory first (module is at src/vnc_remote_secure/native/windows/,
# project root is four levels up).
$script:ProjectDir = Split-Path $PSScriptRoot -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent
$script:Version = '0.0.0'
$_pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $_pyExe) { $_pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if ($_pyExe) {
    $_pyPath = Join-Path $script:ProjectDir 'src'
    $_verOut = & $_pyExe.Source -c "import sys; sys.path.insert(0, r'$_pyPath'); from vnc_remote_secure import __version__; print(__version__)" 2>$null
    if ($_verOut -and ($_verOut -match '^\d+\.\d+\.\d+')) { $script:Version = $_verOut.Trim() }
}
Remove-Variable -Name _pyExe,_pyPath,_verOut -ErrorAction SilentlyContinue

# Colors (only if interactive)
if ($Host.UI.RawUI) {
    $script:ColorError = 'Red'
    $script:ColorWarn = 'Yellow'
    $script:ColorInfo = 'Cyan'
    $script:ColorSuccess = 'Green'
} else {
    $script:ColorError = ''
    $script:ColorWarn = ''
    $script:ColorInfo = ''
    $script:ColorSuccess = ''
}

function Write-InfoMessage {
    param(
        [string]$Message,
        [string]$Type = 'Info',
        [switch]$Quiet
    )
    if ($Quiet) { return }
    $colors = @{
        Error   = $script:ColorError
        Warn    = $script:ColorWarn
        Info    = $script:ColorInfo
        Success = $script:ColorSuccess
    }
    $prefix = @{
        Error   = '[ERROR]'
        Warn    = '[WARN]'
        Info    = '[INFO]'
        Success = '[OK]'
    }
    $color = $colors[$Type]
    $tag = $prefix[$Type]
    if ($color) {
        Write-Host "[$tag] $Message" -ForegroundColor $color
    } else {
        Write-Host "[$tag] $Message"
    }
}

# ============================================================================
# Helper: delegate to the canonical Python CLI
# ============================================================================

function Invoke-PythonCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcommand,
        [string[]]$ExtraArgs,
        [switch]$Json,
        [switch]$DryRun
    )

    $pyExe = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyExe) {
        $pyExe = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $pyExe) {
        Write-InfoMessage "Python not found. Install Python 3.11+ to use this command." 'Error' -Quiet:$Json
        throw "Python not found"
    }

    # Make the source checkout importable when the package is not
    # pip-installed (idempotent — the pip install wins if both exist).
    $srcDir = Join-Path $script:ProjectDir 'src'
    if (Test-Path $srcDir) {
        $env:PYTHONPATH = "$srcDir;$env:PYTHONPATH"
    }

    $pythonArgs = @('-m', 'vnc_remote_secure.cli', $Subcommand)

    # Map PowerShell switches to Python CLI flags.
    if ($DryRun) { $pythonArgs += '--dry-run' }
    if ($Json) { $pythonArgs += '--json' }
    if ($VerbosePreference -eq 'Continue') { $pythonArgs += '--verbose' }

    if ($ExtraArgs) { $pythonArgs += $ExtraArgs }
    & $pyExe.Source @pythonArgs
}

# ============================================================================
# Command: Get-Version
# ============================================================================

function Get-VncRemoteVersion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$Json
    )

    $result = [pscustomobject]@{
        Version      = $script:Version
        Name         = 'VNC Remote Secure'
        Description  = 'Secure browser-based remote access'
        Platform     = 'Windows'
        Architecture = $env:PROCESSOR_ARCHITECTURE
        ProjectDir   = $script:ProjectDir
        PowerShell   = $PSVersionTable.PSVersion.ToString()
    }

    if ($Json) {
        return ($result | ConvertTo-Json)
    }
    Write-Host "vnc-remote $($script:Version)"
    Write-Host "VNC Remote Secure - Secure browser-based remote access"
    Write-Host ""
    Write-Host "Platform:     Windows $($env:PROCESSOR_ARCHITECTURE)"
    Write-Host "PowerShell:   $($PSVersionTable.PSVersion)"
    Write-Host "Project:      $($script:ProjectDir)"
    return $result
}

# ============================================================================
# Command: Help
# ============================================================================

function Show-VncRemoteHelp {
    [CmdletBinding()]
    param()

    Write-Host @"
vnc-remote - Secure browser-based remote access (Windows)

This module is a thin compatibility wrapper that delegates all commands to
the canonical Python CLI (vnc_remote_secure.cli). All functionality is
implemented in Python; this module only maps PowerShell verb conventions
to the Python subcommands. For a script-style entry point with command
dispatch use .\VncRemote.ps1 at the project root.

USAGE:
    Import-Module .\src\vnc_remote_secure\native\windows\VncRemote.psd1
    <Command> [options]

COMMANDS (all delegate to the Python CLI):
    Install-VncRemote              Install and configure the system
    Start-VncRemote                Start all services
    Stop-VncRemote                 Stop all services and cleanup
    Restart-VncRemote              Restart all services
    Get-VncRemoteStatus            Check system status (Python: status)
    Test-VncRemoteConfiguration    Diagnose system readiness (Python: doctor)
    Backup-VncRemote               Create a backup
    Restore-VncRemote <file>       Restore from a backup
    Uninstall-VncRemote            Remove all project changes
    Get-VncRemoteVersion           Show version information (Python: version)
    Show-VncRemoteHelp             Show this help message

OPTIONS:
    -NoSsl              Start services without SSL/TLS (HTTP only, not recommended)
    -Verbose            Verbose output (debug messages)
    -Json               JSON output (Get-VncRemoteStatus, Test-VncRemoteConfiguration, Get-VncRemoteVersion)
    -DryRun             Simulate without making changes
    -WhatIf             Same as -DryRun (PowerShell native)
    -Confirm            Confirm before destructive operations

EXAMPLES:
    Install-VncRemote                    # Full installation
    Install-VncRemote -WhatIf            # Simulate installation
    Start-VncRemote -Verbose             # Start with debug output
    Start-VncRemote -NoSsl               # Start without TLS (HTTP only)
    Get-VncRemoteStatus -Json            # Status as JSON
    Test-VncRemoteConfiguration          # Check system readiness
    Backup-VncRemote                     # Create backup
    Restore-VncRemote backup.tar.gz      # Restore from backup
    Uninstall-VncRemote                  # Remove everything

ENVIRONMENT:
    Configuration is read from .env (see .env.example for all options)

EXIT CODES:
    0   Success
    1   General error
    2   Invalid arguments
    3   Prerequisites not met
    4   Service error
"@
}

# ============================================================================
# Command: Install
# ============================================================================

function Install-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$DryRun
    )

    # Delegate to the canonical Python installer (which also creates the
    # Windows Firewall rules via platform/windows/firewall.py).
    Invoke-PythonCli -Subcommand 'install' -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Start
# ============================================================================

function Start-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$NoSsl,
        [switch]$DryRun
    )

    # Delegate to the canonical Python service manager.
    $extra = @()
    if ($NoSsl) { $extra += '--no-ssl' }
    Invoke-PythonCli -Subcommand 'start' -ExtraArgs $extra -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Stop
# ============================================================================

function Stop-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$DryRun
    )

    # Delegate to the canonical Python service manager.
    Invoke-PythonCli -Subcommand 'stop' -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Restart
# ============================================================================

function Restart-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$NoSsl,
        [switch]$DryRun
    )

    # Delegate to the canonical Python service manager, which performs
    # an atomic stop+start under the cross-process lock.
    $extra = @()
    if ($NoSsl) { $extra += '--no-ssl' }
    Invoke-PythonCli -Subcommand 'restart' -ExtraArgs $extra -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Get-Status
# ============================================================================

function Get-VncRemoteStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$Json
    )

    # Delegate to the canonical Python service manager so PowerShell stays
    # a thin compatibility wrapper. The Python CLI returns real PID-based
    # status (not port probes) and honours the configured ports.
    Invoke-PythonCli -Subcommand 'status' -Json:$Json
}

# ============================================================================
# Command: Test-Configuration (doctor)
# ============================================================================

function Test-VncRemoteConfiguration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$Json
    )

    # Delegate to the canonical Python doctor command so PowerShell stays
    # a thin compatibility wrapper. The Python CLI performs the same
    # checks (OS, Python, UltraVNC, ffmpeg, .env, TLS, ports, firewall)
    # and is the single source of truth for diagnostics.
    Invoke-PythonCli -Subcommand 'doctor' -Json:$Json
}

# ============================================================================
# Command: Backup
# ============================================================================

function Backup-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$List,
        [switch]$DryRun
    )

    # Delegate to the canonical Python backup command.
    $extra = @()
    if ($List) { $extra += '--list' }
    Invoke-PythonCli -Subcommand 'backup' -ExtraArgs $extra -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Restore
# ============================================================================

function Restore-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile,
        [switch]$DryRun
    )

    # Delegate to the canonical Python restore command.
    Invoke-PythonCli -Subcommand 'restore' -ExtraArgs @($BackupFile) -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Uninstall
# ============================================================================

function Uninstall-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$KeepData,
        [switch]$DryRun
    )

    # Delegate to the canonical Python uninstaller, which stops services,
    # removes the Windows Service registration, firewall rules, the
    # runtime user, and optionally SSL certificates and data.
    $extra = @()
    if ($KeepData) { $extra += '--keep-data' }
    Invoke-PythonCli -Subcommand 'uninstall' -ExtraArgs $extra -DryRun:($DryRun -or $WhatIfPreference)
}

# ============================================================================
# Command: Session (ephemeral share sessions)
# ============================================================================

function Invoke-VncRemoteSession {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    # Delegate to the canonical Python session manager.
    Invoke-PythonCli -Subcommand 'session' -ExtraArgs $Arguments
}

# ============================================================================
# Command: Secrets (status, rotate, redact, check)
# ============================================================================

function Invoke-VncRemoteSecrets {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    # Delegate to the canonical Python secrets manager.
    Invoke-PythonCli -Subcommand 'secrets' -ExtraArgs $Arguments
}

# ============================================================================
# Command: Config (show-effective, validate, diff, migrate)
# ============================================================================

function Invoke-VncRemoteConfig {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    # Delegate to the canonical Python config manager.
    Invoke-PythonCli -Subcommand 'config' -ExtraArgs $Arguments
}

# ============================================================================
# Command: Verify (audit chain / backup integrity)
# ============================================================================

function Invoke-VncRemoteVerify {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    # Delegate to the canonical Python verifier (audit|backup).
    Invoke-PythonCli -Subcommand 'verify' -ExtraArgs $Arguments
}

# ============================================================================
# Command: Service (foreground service mode)
# ============================================================================

function Invoke-VncRemoteService {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    # Delegate to the canonical Python service mode.
    Invoke-PythonCli -Subcommand 'service' -ExtraArgs $Arguments
}
