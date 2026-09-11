# Uninstaller.Tests.ps1 - Tests for Windows uninstaller
Describe "Uninstaller" -Tag "Windows" {
    Context "Script exists" {
        It "Should have an Uninstall-VncRemote.ps1 script" {
            "$PSScriptRoot\..\..\native\windows\commands\Uninstall-VncRemote.ps1" | Should -Exist
        }
    }

    Context "WhatIf support" {
        It "Should support -WhatIf parameter" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "Cleanup options" {
        It "Should have RemoveConfig option" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'RemoveConfig'
        }

        It "Should have RemoveData option" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\commands\Uninstall-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'RemoveData'
        }
    }
}
