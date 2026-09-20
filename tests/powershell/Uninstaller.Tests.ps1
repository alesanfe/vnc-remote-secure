# Uninstaller.Tests.ps1 - Tests for Windows uninstaller
Describe "Uninstaller" -Tag "Windows" {
    Context "Script exists" {
        It "Should have an Uninstall-VncRemote.ps1 script" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Uninstall-VncRemote.ps1" | Should -Exist
        }
    }

    Context "WhatIf support" {
        It "Should support -WhatIf parameter" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "Cleanup options" {
        It "Should have RemoveData option" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'RemoveData'
        }

        It "Should not pass flags the Python CLI does not support" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            # --keep-data and --dry-run are the only flags the Python
            # `uninstall` subcommand accepts besides the common ones.
            $scriptContent | Should -Not -Match "'--force'"
        }
    }
}
