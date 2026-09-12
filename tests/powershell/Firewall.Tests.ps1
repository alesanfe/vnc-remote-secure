# Firewall.Tests.ps1 - Tests for Windows Firewall management
BeforeAll {
    . "$PSScriptRoot\..\..\native\windows\Firewall.ps1" -ErrorAction SilentlyContinue
}

Describe "Firewall Management" -Tag "Windows" {
    Context "Script exists" {
        It "Should have a Firewall.ps1 script" {
            "$PSScriptRoot\..\..\native\windows\Firewall.ps1" | Should -Exist
        }
    }

    Context "Firewall rule naming" {
        It "Should use consistent rule naming pattern" {
            # The firewall script should use 'VncRemoteSecure' prefix
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\Firewall.ps1" -Raw
            $scriptContent | Should -Match 'VncRemoteSecure'
        }
    }

    Context "WhatIf support" {
        It "Should support -WhatIf parameter" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\native\windows\Firewall.ps1" -Raw
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }
    }
}
