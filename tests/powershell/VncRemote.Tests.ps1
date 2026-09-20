<#
.SYNOPSIS
    Pester tests for the VncRemote PowerShell module

.DESCRIPTION
    Tests that the module (src/vnc_remote_secure/native/windows/):
    - Imports cleanly without executing the CLI dispatch
    - Exports the documented function set
    - Get-VncRemoteVersion returns correct version
    - Show-VncRemoteHelp displays all commands
    - Exported functions delegate to the Python CLI

.NOTES
    Run with: Invoke-Pester tests/powershell/VncRemote.Tests.ps1
    Requires: Pester 5.0+
#>

BeforeAll {
    $script:ProjectDir = $PSScriptRoot | Split-Path -Parent | Split-Path -Parent
    $script:ModuleManifest = Join-Path $script:ProjectDir 'src\vnc_remote_secure\native\windows\VncRemote.psd1'
    $script:ModuleFile = Join-Path $script:ProjectDir 'src\vnc_remote_secure\native\windows\VncRemote.psm1'

    # Import the module once for all tests. A clean import must NOT emit
    # CLI output (the dispatch only runs when the file is dot-sourced).
    $script:ImportOutput = Import-Module $script:ModuleManifest -Force -PassThru 6>&1 | Out-String
}

Describe 'VncRemote module' {
    Context 'Module files' {
        It 'VncRemote.psd1 exists' {
            $script:ModuleManifest | Should -Exist
        }

        It 'VncRemote.psm1 exists' {
            $script:ModuleFile | Should -Exist
        }
    }

    Context 'Import' {
        It 'Imports without running the CLI dispatch' {
            $script:ImportOutput | Should -Not -Match 'COMMANDS \(all delegate'
        }

        It 'Exports the documented functions' {
            $expected = @(
                'Install-VncRemote', 'Start-VncRemote', 'Stop-VncRemote',
                'Restart-VncRemote', 'Get-VncRemoteStatus',
                'Test-VncRemoteConfiguration', 'Backup-VncRemote',
                'Restore-VncRemote', 'Uninstall-VncRemote',
                'Get-VncRemoteVersion', 'Show-VncRemoteHelp',
                'Invoke-VncRemoteSession', 'Invoke-VncRemoteSecrets',
                'Invoke-VncRemoteConfig', 'Invoke-VncRemoteService'
            )
            $exported = (Get-Command -Module VncRemote).Name
            foreach ($fn in $expected) {
                $exported | Should -Contain $fn
            }
        }
    }

    Context 'Get-VncRemoteVersion' {
        It 'Returns version 0.2.0' {
            $result = Get-VncRemoteVersion
            $result.Version | Should -Be '0.2.0'
        }

        It 'Reports platform as Windows' {
            $result = Get-VncRemoteVersion
            $result.Platform | Should -Be 'Windows'
        }

        It '-Json produces valid JSON' {
            $jsonText = Get-VncRemoteVersion -Json | Out-String
            { $jsonText | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    Context 'Show-VncRemoteHelp' {
        # Write-Host output travels on the information stream — capture via 6>&1.
        It 'Displays all commands' {
            $output = Show-VncRemoteHelp 6>&1 | Out-String
            $output | Should -Match 'Install-VncRemote'
            $output | Should -Match 'Start-VncRemote'
            $output | Should -Match 'Stop-VncRemote'
            $output | Should -Match 'Get-VncRemoteStatus'
            $output | Should -Match 'Test-VncRemoteConfiguration'
            $output | Should -Match 'Uninstall-VncRemote'
            $output | Should -Match 'Backup-VncRemote'
            $output | Should -Match 'Restore-VncRemote'
        }

        It 'Shows -WhatIf option' {
            $output = Show-VncRemoteHelp 6>&1 | Out-String
            $output | Should -Match 'WhatIf'
        }

        It 'Shows -Json option' {
            $output = Show-VncRemoteHelp 6>&1 | Out-String
            $output | Should -Match 'Json'
        }
    }

    Context 'Delegation' {
        It 'Functions delegate to the Python CLI' {
            $content = Get-Content $script:ModuleFile -Raw
            # Every exported command function must call Invoke-PythonCli
            # (thin-wrapper guarantee: no native reimplementations).
            $content | Should -Match "Invoke-PythonCli -Subcommand 'install'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'start'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'stop'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'restart'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'status'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'doctor'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'backup'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'restore'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'uninstall'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'session'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'secrets'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'config'"
            $content | Should -Match "Invoke-PythonCli -Subcommand 'service'"
        }

        It 'Restore-VncRemote requires a backup file' {
            { Restore-VncRemote -ErrorAction Stop } | Should -Throw
        }
    }
}
