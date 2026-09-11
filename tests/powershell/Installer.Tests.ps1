# Installer.Tests.ps1 - Tests for Windows installer
BeforeAll {
    . "$PSScriptRoot\..\..\native\windows\commands\Install-VncRemote.ps1" -ErrorAction SilentlyContinue
}

Describe "Installer" -Tag "Windows" {
    Context "Script exists" {
        It "Should have an Install-VncRemote.ps1 script" {
            "$PSScriptRoot\..\..\native\windows\commands\Install-VncRemote.ps1" | Should -Exist
        }
    }

    Context "WhatIf support" {
        It "Should support -WhatIf parameter" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\commands\Install-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "Install path" {
        It "Should default to ProgramData" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\commands\Install-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'ProgramData'
        }
    }
}
