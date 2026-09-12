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
    Requires: Git Bash, Python 3.8+, UltraVNC binaries
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        'Install', 'Start', 'Stop', 'Restart', 'Get-Status',
        'Test-Configuration', 'Backup', 'Restore', 'Uninstall',
        'Get-Version', 'Help'
    )]
    [string]$Command = 'Help',

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments,

    [switch]$Json,
    [switch]$DryRun,
    [switch]$NoSsl
)

# Version
$script:Version = '0.2.0'

# Get project directory (script is at project root)
$script:ProjectDir = $PSScriptRoot
$script:LaunchScript = Join-Path $script:ProjectDir 'launch.sh'
$script:UninstallScript = Join-Path $script:ProjectDir 'scripts\maintenance\uninstall.sh'
$script:BackupScript = Join-Path $script:ProjectDir 'scripts\maintenance\backup.sh'
$script:RestoreScript = Join-Path $script:ProjectDir 'scripts\maintenance\restore.sh'
$script:FirewallScript = Join-Path $script:ProjectDir 'native\windows\Firewall.ps1'

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
        $result | ConvertTo-Json
    } else {
        Write-Host "vnc-remote $($script:Version)"
        Write-Host "VNC Remote Secure - Secure browser-based remote access"
        Write-Host ""
        Write-Host "Platform:     Windows $($env:PROCESSOR_ARCHITECTURE)"
        Write-Host "PowerShell:   $($PSVersionTable.PSVersion)"
        Write-Host "Project:      $($script:ProjectDir)"
    }
    return $result
}

# ============================================================================
# Command: Help
# ============================================================================

function Show-VncRemoteHelp {
    Write-Host @"
vnc-remote - Secure browser-based remote access (Windows)

USAGE:
    .\VncRemote.ps1 <Command> [options]

COMMANDS:
    Install              Install and configure the system
    Start                Start all services
    Stop                 Stop all services and cleanup
    Restart              Restart all services
    Get-Status           Check system status
    Test-Configuration   Diagnose system readiness (doctor)
    Backup               Create a backup
    Restore              Restore from a backup
    Uninstall            Remove all project changes
    Get-Version          Show version information
    Help                 Show this help message

OPTIONS:
    -Verbose             Verbose output (debug messages)
    -Json                JSON output (Get-Status, Test-Configuration)
    -DryRun              Simulate without making changes
    -WhatIf              Same as -DryRun (PowerShell native)
    -Confirm             Confirm before destructive operations

EXAMPLES:
    .\VncRemote.ps1 Install                    # Full installation
    .\VncRemote.ps1 Install -WhatIf            # Simulate installation
    .\VncRemote.ps1 Start -Verbose             # Start with debug output
    .\VncRemote.ps1 Get-Status -Json           # Status as JSON
    .\VncRemote.ps1 Test-Configuration         # Check system readiness
    .\VncRemote.ps1 Backup                     # Create backup
    .\VncRemote.ps1 Restore backup.tar.gz      # Restore from backup
    .\VncRemote.ps1 Uninstall                  # Remove everything

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
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Simulating installation (no changes will be made)" 'Info'
        Write-Host ""
        Write-Host "Would perform:"
        Write-Host "  1. Check prerequisites (OS, Python, Git Bash, UltraVNC)"
        Write-Host "  2. Install Python dependencies (tornado, websockify, etc.)"
        Write-Host "  3. Configure VNC server (UltraVNC, port, password)"
        Write-Host "  4. Generate SSL certificates (self-signed)"
        Write-Host "  5. Configure Windows Firewall rules (port 443 only)"
        Write-Host "  6. Start all services"
        Write-Host ""
        Write-InfoMessage "Run without -WhatIf to perform actual installation" 'Info'
        return
    }

    if (-not (Test-Path $script:LaunchScript)) {
        Write-InfoMessage "launch.sh not found at $script:LaunchScript" 'Error'
        throw "launch.sh not found"
    }

    Write-InfoMessage "Starting installation..." 'Info'

    # Find Git Bash
    $gitBash = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitBash) {
        Write-InfoMessage "Git Bash not found. Please install Git for Windows." 'Error'
        throw "Git Bash not found"
    }

    $gitDir = Split-Path $gitBash.Source -Parent
    $bashExe = Join-Path $gitDir 'bash.exe'

    if (-not (Test-Path $bashExe)) {
        Write-InfoMessage "bash.exe not found at $bashExe" 'Error'
        throw "bash.exe not found"
    }

    # Run launch.sh via Git Bash
    & $bashExe -c "cd '$($script:ProjectDir -replace '\\','/')' && bash launch.sh"
}

# ============================================================================
# Command: Start
# ============================================================================

function Start-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would start all services" 'Info'
        return
    }

    Write-InfoMessage "Starting services..." 'Info'

    $gitBash = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitBash) {
        Write-InfoMessage "Git Bash not found" 'Error'
        throw "Git Bash not found"
    }

    $gitDir = Split-Path $gitBash.Source -Parent
    # Git for Windows places bash.exe in bin/, not cmd/ (where git.exe lives).
    $bashExe = Join-Path (Split-Path $gitDir -Parent) 'bin\bash.exe'
    if (-not (Test-Path $bashExe)) {
        $bashExe = Join-Path $gitDir 'bash.exe'
    }
    if (-not (Test-Path $bashExe)) {
        $bashCmd = Get-Command bash -ErrorAction SilentlyContinue
        if ($bashCmd) { $bashExe = $bashCmd.Source }
    }

    $sslFlag = ''
    if ($NoSsl) { $sslFlag = ' --no-ssl' }
    & $bashExe -c "cd '$($script:ProjectDir -replace '\\','/')' && bash vnc-remote start$sslFlag"
}

# ============================================================================
# Command: Stop
# ============================================================================

function Stop-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would stop all services" 'Info'
        return
    }

    Write-InfoMessage "Stopping services..." 'Info'

    # Use the unified CLI (vnc-remote) to stop services consistently across platforms.
    $vncRemote = Join-Path $script:ProjectDir 'vnc-remote'
    if (Test-Path $vncRemote) {
        $gitBash = Get-Command git -ErrorAction SilentlyContinue
        if ($gitBash) {
            $gitDir = Split-Path $gitBash.Source -Parent
            $bashExe = Join-Path $gitDir 'bash.exe'
            & $bashExe -c "cd '$($script:ProjectDir -replace '\\','/')' && bash vnc-remote stop"
        }
    } else {
        Write-InfoMessage "vnc-remote wrapper not found; cannot stop services" 'Warn'
    }
}

# ============================================================================
# Command: Restart
# ============================================================================

function Restart-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would restart all services" 'Info'
        return
    }

    Write-InfoMessage "Restarting services..." 'Info'
    Stop-VncRemote
    Start-Sleep -Seconds 2
    Start-VncRemote
}

# ============================================================================
# Command: Get-Status
# ============================================================================

function Get-VncRemoteStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Load .env if available
    $envFile = Join-Path $script:ProjectDir '.env'
    $config = @{}
    if (Test-Path $envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.+)$') {
                $config[$matches[1]] = $matches[2]
            }
        }
    }

    $vncPort = if ($config['VNC_PORT']) { [int]$config['VNC_PORT'] } else { 5900 }
    $novncPort = if ($config['NOVNC_PORT']) { [int]$config['NOVNC_PORT'] } else { 6080 }
    $ttydPort = if ($config['TTYD_PORT']) { [int]$config['TTYD_PORT'] } else { 5000 }
    $healthPort = if ($config['HEALTH_WEB_PORT']) { [int]$config['HEALTH_WEB_PORT'] } else { 8090 }

    # Check if ports are listening
    function Test-PortListening {
        param([int]$Port)
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
            $listener.Start()
            $listener.Stop()
            return $false  # Port was available (we could listen)
        } catch {
            return $true  # Port is in use
        }
    }

    $services = [ordered]@{
        vnc    = [pscustomobject]@{ Name = 'vnc'; Status = if (Test-PortListening $vncPort) { 'running' } else { 'stopped' }; Port = $vncPort }
        novnc  = [pscustomobject]@{ Name = 'novnc'; Status = if (Test-PortListening $novncPort) { 'running' } else { 'stopped' }; Port = $novncPort }
        ttyd   = [pscustomobject]@{ Name = 'ttyd'; Status = if (Test-PortListening $ttydPort) { 'running' } else { 'stopped' }; Port = $ttydPort }
        health = [pscustomobject]@{ Name = 'health'; Status = if (Test-PortListening $healthPort) { 'running' } else { 'stopped' }; Port = $healthPort }
    }

    $result = [pscustomobject]@{
        Version  = $script:Version
        Platform = 'Windows'
        Services = $services.Values
    }

    if ($Json) {
        $result | ConvertTo-Json -Depth 3
    } else {
        Write-InfoMessage "System status:" 'Info'
        foreach ($svc in $services.Values) {
            $icon = if ($svc.Status -eq 'running') { '[RUNNING]' } else { '[STOPPED]' }
            $color = if ($svc.Status -eq 'running') { $script:ColorSuccess } else { $script:ColorWarn }
            if ($color) {
                Write-Host "  $icon $($svc.Name) (port $($svc.Port))" -ForegroundColor $color
            } else {
                Write-Host "  $icon $($svc.Name) (port $($svc.Port))"
            }
        }
    }
    return $result
}

# ============================================================================
# Command: Test-Configuration (doctor)
# ============================================================================

function Test-VncRemoteConfiguration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    # Use script-scope variables so inner function can access them
    $script:checks = [System.Collections.ArrayList]::new()
    $script:passed = 0
    $script:failed = 0
    $script:warned = 0

    function Add-Check {
        param([string]$Name, [string]$Status, [string]$Detail)
        $script:checks.Add([pscustomobject]@{
            Name   = $Name
            Status = $Status
            Detail = $Detail
        }) | Out-Null
        switch ($Status) {
            'OK'   { $script:passed++ }
            'FAIL' { $script:failed++ }
            'WARN' { $script:warned++ }
        }
    }

    if (-not $Json) {
        Write-Host "vnc-remote doctor - System Diagnostics (Windows)" -ForegroundColor Cyan
        Write-Host ""
    }

    # 1. Operating system
    $osVersion = [System.Environment]::OSVersion.Version
    $osName = if ($osVersion.Major -ge 10) { "Windows 10/11 ($osVersion)" } else { "Windows ($osVersion)" }
    Add-Check 'Operating system' 'OK' $osName

    # 2. Architecture
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        'AMD64' { Add-Check 'Architecture' 'OK' 'x64' }
        'ARM64' { Add-Check 'Architecture' 'OK' 'ARM64' }
        default { Add-Check 'Architecture' 'WARN' "$arch (untested)" }
    }

    # 3. PowerShell version
    $psVersion = $PSVersionTable.PSVersion.ToString()
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Add-Check 'PowerShell' 'OK' $psVersion
    } else {
        Add-Check 'PowerShell' 'FAIL' "Version $psVersion (requires 5.1+)"
    }

    # 4. Git Bash
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Add-Check 'Git Bash' 'OK' $git.Source
    } else {
        Add-Check 'Git Bash' 'FAIL' 'Not found (install Git for Windows)'
    }

    # 5. Python
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if ($python) {
        $pyVersion = & $python.Source --version 2>&1
        Add-Check 'Python' 'OK' $pyVersion.ToString().Trim()
    } else {
        Add-Check 'Python' 'FAIL' 'Not found (install Python 3.8+)'
    }

    # 6. UltraVNC
    $ultraVncPaths = @(
        (Join-Path $script:ProjectDir 'bin\ultravnc\x64\winvnc.exe'),
        (Join-Path $script:ProjectDir 'bin\ultravnc\winvnc.exe'),
        'C:\Program Files\UltraVNC\winvnc.exe',
        'C:\Program Files (x86)\UltraVNC\winvnc.exe'
    )
    $ultraVncFound = $false
    foreach ($path in $ultraVncPaths) {
        if (Test-Path $path) {
            Add-Check 'UltraVNC' 'OK' $path
            $ultraVncFound = $true
            break
        }
    }
    if (-not $ultraVncFound) {
        Add-Check 'UltraVNC' 'WARN' 'Not found (required for VNC server)'
    }

    # 7. ffmpeg (for audio streaming)
    $ffmpeg = Get-Command ffmpeg -ErrorAction SilentlyContinue
    if ($ffmpeg) {
        Add-Check 'ffmpeg' 'OK' 'Installed (audio streaming available)'
    } else {
        Add-Check 'ffmpeg' 'WARN' 'Not found (audio streaming disabled)'
    }

    # 8. .env file
    $envFile = Join-Path $script:ProjectDir '.env'
    if (Test-Path $envFile) {
        Add-Check '.env file' 'OK' 'Present'
    } else {
        Add-Check '.env file' 'WARN' 'Not found (run install or copy .env.example)'
    }

    # 9. SSL certificates
    $sslDir = Join-Path $script:ProjectDir 'data\ssl'
    $certPath = Join-Path $sslDir 'fullchain.pem'
    $keyPath = Join-Path $sslDir 'privkey.pem'
    if ((Test-Path $certPath) -and (Test-Path $keyPath)) {
        Add-Check 'TLS certificate' 'OK' 'Self-signed certificates present'
    } else {
        Add-Check 'TLS certificate' 'WARN' 'Not found (SSL disabled)'
    }

    # 10. Port availability
    $config = @{}
    if (Test-Path $envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.+)$') {
                $config[$matches[1]] = $matches[2]
            }
        }
    }

    $ports = @{
        'VNC_PORT'         = if ($config['VNC_PORT']) { [int]$config['VNC_PORT'] } else { 5900 }
        'NOVNC_PORT'       = if ($config['NOVNC_PORT']) { [int]$config['NOVNC_PORT'] } else { 6080 }
        'TTYD_PORT'        = if ($config['TTYD_PORT']) { [int]$config['TTYD_PORT'] } else { 5000 }
        'HEALTH_WEB_PORT'  = if ($config['HEALTH_WEB_PORT']) { [int]$config['HEALTH_WEB_PORT'] } else { 8090 }
    }

    foreach ($portName in $ports.Keys) {
        $port = $ports[$portName]
        $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        if ($connection) {
            Add-Check "Port $port ($portName)" 'WARN' 'In use'
        } else {
            Add-Check "Port $port ($portName)" 'OK' 'Available'
        }
    }

    # 11. Windows Firewall rules
    $fwRule = Get-NetFirewallRule -DisplayName 'VncRemoteSecure*' -ErrorAction SilentlyContinue
    if ($fwRule) {
        Add-Check 'Windows Firewall' 'OK' "Rules found: $($fwRule.Count)"
    } else {
        Add-Check 'Windows Firewall' 'WARN' 'No VncRemoteSecure rules (run install)'
    }

    # Summary
    $total = $script:passed + $script:failed + $script:warned

    $result = [pscustomobject]@{
        Version = $script:Version
        Platform = 'Windows'
        Checks = [pscustomobject]@{
            Total   = $total
            Passed  = $script:passed
            Warned  = $script:warned
            Failed  = $script:failed
        }
        Results = $script:checks
    }

    if ($Json) {
        $result | ConvertTo-Json -Depth 3
    } else {
        foreach ($check in $script:checks) {
            $icon = switch ($check.Status) {
                'OK'   { '[OK]  ' }
                'FAIL' { '[FAIL]' }
                'WARN' { '[WARN]' }
            }
            $color = switch ($check.Status) {
                'OK'   { $script:ColorSuccess }
                'FAIL' { $script:ColorError }
                'WARN' { $script:ColorWarn }
            }
            $line = "  $icon $($check.Name.PadRight(30)) $($check.Detail)"
            if ($color) {
                Write-Host $line -ForegroundColor $color
            } else {
                Write-Host $line
            }
        }

        Write-Host ""
        Write-Host "  Total: $total | Passed: $($script:passed) | Warnings: $($script:warned) | Failed: $($script:failed)" -ForegroundColor Cyan
        Write-Host ""

        if ($script:failed -gt 0) {
            Write-InfoMessage "Some checks failed. Fix them before installing." 'Error'
        } elseif ($script:warned -gt 0) {
            Write-InfoMessage "Some warnings. Review them before proceeding." 'Warn'
        } else {
            Write-InfoMessage "All checks passed. System is ready." 'Success'
        }
    }

    if ($script:failed -gt 0) { exit 3 }
    return $result
}

# ============================================================================
# Command: Backup
# ============================================================================

function Backup-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would create backup" 'Info'
        return
    }

    if (-not (Test-Path $script:BackupScript)) {
        Write-InfoMessage "backup.sh not found" 'Error'
        return
    }

    $gitBash = Get-Command git -ErrorAction SilentlyContinue
    if ($gitBash) {
        $gitDir = Split-Path $gitBash.Source -Parent
        $bashExe = Join-Path $gitDir 'bash.exe'
        & $bashExe -c "cd '$($script:ProjectDir -replace '\\','/')' && bash scripts/backup.sh"
    }
}

# ============================================================================
# Command: Restore
# ============================================================================

function Restore-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFile
    )

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would restore from $BackupFile" 'Info'
        return
    }

    if (-not (Test-Path $script:RestoreScript)) {
        Write-InfoMessage "restore.sh not found" 'Error'
        return
    }

    $gitBash = Get-Command git -ErrorAction SilentlyContinue
    if ($gitBash) {
        $gitDir = Split-Path $gitBash.Source -Parent
        $bashExe = Join-Path $gitDir 'bash.exe'
        $backupPath = ($BackupFile -replace '\\','/')
        & $bashExe -c "cd '$($script:ProjectDir -replace '\\','/')' && bash scripts/restore.sh '$backupPath'"
    }
}

# ============================================================================
# Command: Uninstall
# ============================================================================

function Uninstall-VncRemote {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($script:IsDryRun) {
        Write-InfoMessage "DRY RUN: Would uninstall (stop services, remove firewall rules, configs)" 'Info'
        return
    }

    # Stop services first
    Stop-VncRemote

    # Remove firewall rules using dedicated script
    $fwScript = Join-Path $script:ProjectDir 'native\windows\Firewall.ps1'
    if (Test-Path $fwScript) {
        & $fwScript -Action Remove
    } else {
        # Fallback: remove rules directly
        $fwRules = Get-NetFirewallRule -DisplayName 'VncRemoteSecure*' -ErrorAction SilentlyContinue
        if ($fwRules) {
            $fwRules | Remove-NetFirewallRule -Confirm:$false
            Write-InfoMessage "Removed Windows Firewall rules" 'Success'
        }
    }

    Write-InfoMessage "Uninstallation complete. Project files not removed." 'Info'
}

# ============================================================================
# Dispatch
# ============================================================================

# Handle -DryRun as alias for -WhatIf
# Use a script-level flag that all functions can check
$script:IsDryRun = $false
if ($DryRun) { $script:IsDryRun = $true }
if ($WhatIfPreference) { $script:IsDryRun = $true }

switch ($Command) {
    'Install'             { Install-VncRemote }
    'Start'               { Start-VncRemote }
    'Stop'                { Stop-VncRemote }
    'Restart'             { Restart-VncRemote }
    'Get-Status'          { Get-VncRemoteStatus }
    'Test-Configuration'  { Test-VncRemoteConfiguration }
    'Backup'              { Backup-VncRemote }
    'Restore'             {
        if ($Arguments -and $Arguments.Count -ge 1) {
            Restore-VncRemote -BackupFile $Arguments[0]
        } else {
            Write-InfoMessage "Usage: .\VncRemote.ps1 Restore <BACKUP_FILE>" 'Error'
            exit 2
        }
    }
    'Uninstall'           { Uninstall-VncRemote }
    'Get-Version'         { Get-VncRemoteVersion }
    'Help'                { Show-VncRemoteHelp }
    default               { Show-VncRemoteHelp }
}
