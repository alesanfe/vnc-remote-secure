<#
.SYNOPSIS
    VNC Remote Secure - Native PowerShell CLI for Windows

.DESCRIPTION
    Provides a stable command interface for VNC Remote Secure on Windows.
    Equivalent to the Bash 'vnc-remote' CLI but using native PowerShell mechanisms:
    - Approved verbs
    - Typed parameters
    - SupportsShouldProcess (-WhatIf, -Confirm)
    - Object output (not just text)
    - No Invoke-Expression
    - No plaintext passwords

.EXAMPLE
    .\VncRemote.ps1 Install
    .\VncRemote.ps1 Install -WhatIf
    .\VncRemote.ps1 Start -Verbose
    .\VncRemote.ps1 Get-Status -Json
    .\VncRemote.ps1 Test-Configuration
    .\VncRemote.ps1 Uninstall

.NOTES
    Requires: PowerShell 5.1+ or PowerShell 7+
    Requires: Git Bash, Python 3.11+, UltraVNC binaries
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        'Install', 'Start', 'Stop', 'Restart', 'Get-Status',
        'Test-Configuration', 'Doctor', 'Backup', 'Restore', 'Uninstall',
        'Session', 'Secrets', 'Config', 'Service', 'Get-Version', 'Verify', 'Help'
    )]
    [string]$Command = 'Help',

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments,

    [switch]$Json,
    [switch]$DryRun,
    [switch]$NoSsl
)

# Version — read from the Python package (single source of truth: pyproject.toml)
$script:Version = '0.0.0'
$_pyExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $_pyExe) { $_pyExe = Get-Command python3 -ErrorAction SilentlyContinue }
if ($_pyExe) {
    $_pyPath = Join-Path $PSScriptRoot 'src'
    $_verOut = & $_pyExe.Source -c "import sys; sys.path.insert(0, r'$_pyPath'); from vnc_remote_secure import __version__; print(__version__)" 2>$null
    if ($_verOut -and ($_verOut -match '^\d+\.\d+\.\d+')) { $script:Version = $_verOut.Trim() }
}
Remove-Variable -Name _pyExe,_pyPath,_verOut -ErrorAction SilentlyContinue

# Get project directory (script is at project root)
$script:ProjectDir = $PSScriptRoot

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
    param([string]$Message, [string]$Type = 'Info')
    if ($Json) { return }
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
# Command: Get-Version
# ============================================================================

function Get-VncRemoteVersion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

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
    Write-Host @"
vnc-remote - Secure browser-based remote access (Windows)

This is a thin compatibility wrapper that delegates all commands to the
canonical Python CLI (vnc_remote_secure.cli). All functionality is
implemented in Python; this script only maps PowerShell verb conventions
to the Python subcommands.

USAGE:
    .\VncRemote.ps1 <Command> [options]

COMMANDS (all delegate to the Python CLI):
    Install              Install and configure the system
    Start                Start all services
    Stop                 Stop all services and cleanup
    Restart              Restart all services
    Get-Status           Check system status (Python: status)
    Test-Configuration   Diagnose system readiness (Python: doctor)
    Doctor               Alias for Test-Configuration
    Backup               Create a backup (use --list to list backups)
    Restore              Restore from a backup
    Uninstall            Remove all project changes
    Session              Manage ephemeral sessions
    Secrets              Manage secrets (status, rotate, redact, check)
    Config               Manage configuration (show-effective, validate, diff, migrate)
    Service              Run the service manager (for Windows Services)
    Get-Version          Show version information (Python: version)
    Help                 Show this help message

OPTIONS:
    -NoSsl              Start services without SSL/TLS (HTTP only, not recommended)
    -Verbose            Verbose output (debug messages)
    -Json               JSON output (Get-Status, Test-Configuration, Get-Version)
    -DryRun             Simulate without making changes
    -WhatIf             Same as -DryRun (PowerShell native)
    -Confirm            Confirm before destructive operations

EXAMPLES:
    .\VncRemote.ps1 Install                    # Full installation
    .\VncRemote.ps1 Install -WhatIf            # Simulate installation
    .\VncRemote.ps1 Start -Verbose             # Start with debug output
    .\VncRemote.ps1 Start -NoSsl              # Start without TLS (HTTP only)
    .\VncRemote.ps1 Get-Status -Json          # Status as JSON
    .\VncRemote.ps1 Test-Configuration         # Check system readiness
    .\VncRemote.ps1 Backup                    # Create backup
    .\VncRemote.ps1 Backup --list             # List available backups
    .\VncRemote.ps1 Restore backup.tar.gz      # Restore from backup
    .\VncRemote.ps1 Uninstall                 # Remove everything

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
# Helper: delegate to the canonical Python CLI
# ============================================================================

function Invoke-PythonCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcommand,
        [string[]]$ExtraArgs
    )

    $pyExe = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyExe) {
        $pyExe = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $pyExe) {
        Write-InfoMessage "Python not found. Install Python 3.11+ to use this command." 'Error'
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
    if ($script:IsDryRun) { $pythonArgs += '--dry-run' }
    if ($Json) { $pythonArgs += '--json' }
    if ($VerbosePreference -eq 'Continue') { $pythonArgs += '--verbose' }

    if ($ExtraArgs) { $pythonArgs += $ExtraArgs }
    & $pyExe.Source @pythonArgs
}

# ============================================================================
# Dispatch
# ============================================================================

# Handle -DryRun as alias for -WhatIf
# Use a script-level flag that all functions can check
$script:IsDryRun = $false
if ($DryRun) { $script:IsDryRun = $true }
if ($WhatIfPreference) { $script:IsDryRun = $true }

# Invoke-PythonCli already appends --dry-run/--json/--verbose from the
# script-level switches; callers only forward command-specific extras.
switch ($Command) {
    'Install'             { Invoke-PythonCli -Subcommand 'install' }
    'Start'               {
        $_flags = @()
        if ($NoSsl) { $_flags += '--no-ssl' }
        Invoke-PythonCli -Subcommand 'start' -ExtraArgs $_flags
    }
    'Stop'                { Invoke-PythonCli -Subcommand 'stop' }
    'Restart'             {
        $_flags = @()
        if ($NoSsl) { $_flags += '--no-ssl' }
        Invoke-PythonCli -Subcommand 'restart' -ExtraArgs $_flags
    }
    'Get-Status'          { Invoke-PythonCli -Subcommand 'status' }
    'Test-Configuration'  { Invoke-PythonCli -Subcommand 'doctor' }
    'Doctor'              { Invoke-PythonCli -Subcommand 'doctor' }
    'Backup'              {
        $_flags = @()
        if ($Arguments -and $Arguments.Count -ge 1 -and $Arguments[0] -eq '--list') { $_flags += '--list' }
        Invoke-PythonCli -Subcommand 'backup' -ExtraArgs $_flags
    }
    'Restore'             {
        if ($Arguments -and $Arguments.Count -ge 1) {
            Invoke-PythonCli -Subcommand 'restore' -ExtraArgs @($Arguments[0])
        } else {
            Write-InfoMessage "Usage: .\VncRemote.ps1 Restore <BACKUP_FILE>" 'Error'
            exit 2
        }
    }
    'Uninstall'           {
        $_flags = @()
        if ($Arguments -and $Arguments.Contains('--keep-data')) { $_flags += '--keep-data' }
        Invoke-PythonCli -Subcommand 'uninstall' -ExtraArgs $_flags
    }
    'Session'             { Invoke-PythonCli -Subcommand 'session' -ExtraArgs $Arguments }
    'Verify'              { Invoke-PythonCli -Subcommand 'verify' -ExtraArgs $Arguments }
    'Secrets'             { Invoke-PythonCli -Subcommand 'secrets' -ExtraArgs $Arguments }
    'Config'              { Invoke-PythonCli -Subcommand 'config' -ExtraArgs $Arguments }
    'Service'             { Invoke-PythonCli -Subcommand 'service' -ExtraArgs $Arguments }
    'Get-Version'         { Get-VncRemoteVersion }
    'Help'                { Show-VncRemoteHelp }
    default               { Show-VncRemoteHelp }
}
Remove-Variable -Name _flags -ErrorAction SilentlyContinue
