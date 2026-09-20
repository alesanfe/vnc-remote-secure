<#
.SYNOPSIS
    Pester tests for VncRemote.ps1 CLI

.DESCRIPTION
    Tests that the PowerShell CLI:
    - Has all expected commands
    - Get-Version returns correct version
    - Help displays all commands
    - -WhatIf prevents execution
    - Get-Status returns structured objects
    - Test-Configuration runs all checks

.NOTES
    Run with: Invoke-Pester tests/windows/VncRemote.Tests.ps1
    Requires: Pester 5.0+
#>

BeforeAll {
    $script:ProjectDir = $PSScriptRoot | Split-Path -Parent | Split-Path -Parent
    $script:CliScript = Join-Path $script:ProjectDir 'VncRemote.ps1'
    $script:FirewallScript = Join-Path $script:ProjectDir 'src\vnc_remote_secure\native\windows\Firewall.ps1'

    # Helper: run CLI and capture output
    function Invoke-Cli {
        param([string[]]$CliArgs)
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $script:CliScript @CliArgs 2>&1
        return ($output | Out-String)
    }
}

Describe 'VncRemote CLI' {
    Context 'Script existence' {
        It 'VncRemote.ps1 exists' {
            $script:CliScript | Should -Exist
        }

        It 'Firewall.ps1 exists' {
            $script:FirewallScript | Should -Exist
        }
    }

    Context 'Get-Version' {
        It 'Returns version 0.2.0' {
            $output = Invoke-Cli -CliArgs 'Get-Version'
            $output | Should -Match '0\.2\.0'
        }

        It 'Shows platform as Windows' {
            $output = Invoke-Cli -CliArgs 'Get-Version'
            $output | Should -Match 'Windows'
        }
    }

    Context 'Help' {
        It 'Displays all commands' {
            $output = Invoke-Cli -CliArgs 'Help'
            $output | Should -Match 'Install'
            $output | Should -Match 'Start'
            $output | Should -Match 'Stop'
            $output | Should -Match 'Get-Status'
            $output | Should -Match 'Test-Configuration'
            $output | Should -Match 'Uninstall'
            $output | Should -Match 'Backup'
            $output | Should -Match 'Restore'
        }

        It 'Shows -WhatIf option' {
            $output = Invoke-Cli -CliArgs 'Help'
            $output | Should -Match 'WhatIf'
        }

        It 'Shows -Json option' {
            $output = Invoke-Cli -CliArgs 'Help'
            $output | Should -Match 'Json'
        }
    }

    Context 'DryRun / WhatIf' {
        It 'Install -WhatIf does not execute' {
            $output = Invoke-Cli -CliArgs 'Install', '-WhatIf'
            $output | Should -Match 'DRY RUN'
            $output | Should -Match 'Would perform'
        }

        It 'Install -DryRun does not execute' {
            $output = Invoke-Cli -CliArgs 'Install', '-DryRun'
            $output | Should -Match 'DRY RUN'
        }

        It 'Uninstall -WhatIf does not execute' {
            $output = Invoke-Cli -CliArgs 'Uninstall', '-WhatIf'
            $output | Should -Match 'DRY RUN'
        }
    }

    Context 'Get-Status' {
        It 'Returns JSON when -Json specified' {
            $output = Invoke-Cli -CliArgs 'Get-Status', '-Json'
            # Extract just the JSON part (before the object table output)
            $jsonText = ($output -split "`n" | Where-Object { $_ -match '^\s*[\{\[]' -or $_ -match '^\s*"' -or $_ -match '^\s*\}' -or $_ -match '^\s*\]' }) -join "`n"
            { $jsonText | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Contains services in JSON output' {
            $output = Invoke-Cli -CliArgs 'Get-Status', '-Json'
            $jsonText = ($output -split "`n" | Where-Object { $_ -match '^\s*[\{\[]' -or $_ -match '^\s*"' -or $_ -match '^\s*\}' -or $_ -match '^\s*\]' }) -join "`n"
            $json = $jsonText | ConvertFrom-Json
            $json.Services | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Test-Configuration (doctor)' {
        It 'Runs without throwing' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'Summary'
        }

        It 'Checks configuration' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'config\.'
        }

        It 'Checks secrets' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'secrets\.'
        }

        It 'Checks for Python' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'deps\.python'
        }

        It 'Checks TLS certificates' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'tls\.'
        }

        It 'Checks ports' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'ports\.'
        }

        It 'Checks Windows Firewall' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration'
            $output | Should -Match 'firewall'
        }

        It 'Returns JSON when -Json specified' {
            $output = Invoke-Cli -CliArgs 'Test-Configuration', '-Json'
            # Extract just the JSON part
            $jsonText = ($output -split "`n" | Where-Object { $_ -match '^\s*[\{\[]' -or $_ -match '^\s*"' -or $_ -match '^\s*\}' -or $_ -match '^\s*\]' }) -join "`n"
            { $jsonText | ConvertFrom-Json } | Should -Not -Throw
        }
    }
}

Describe 'Firewall.ps1' {
    Context 'Script existence' {
        It 'Firewall.ps1 exists' {
            $script:FirewallScript | Should -Exist
        }
    }

    Context 'List action' {
        It 'List runs without error (no admin needed)' {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $script:FirewallScript -Action List 2>&1
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context 'Verify action' {
        It 'Verify runs without error' {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $script:FirewallScript -Action Verify 2>&1
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context 'Create -WhatIf' {
        It 'Create -WhatIf does not require admin' {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $script:FirewallScript -Action Create -WhatIf 2>&1
            $outputStr = ($output | Out-String)
            $outputStr | Should -Match 'VncRemoteSecure'
            $LASTEXITCODE | Should -Be 0
        }
    }
}
