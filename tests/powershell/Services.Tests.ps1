# Services.Tests.ps1 - Tests for Windows Service management
Describe "Services" -Tag "Windows" {
    Context "Service config" {
        It "Should have a service-config.xml" {
            "$PSScriptRoot\..\..\native\windows\service\service-config.xml" | Should -Exist
        }

        It "Should define service name" {
            $content = Get-Content "$PSScriptRoot\..\..\native\windows\service\service-config.xml" -Raw
            $content | Should -Match '<name>vnc-remote-secure</name>'
        }

        It "Should set automatic start type" {
            $content = Get-Content "$PSScriptRoot\..\..\native\windows\service\service-config.xml" -Raw
            $content | Should -Match 'Automatic'
        }
    }

    Context "Command scripts" {
        It "Should have Start-VncRemote.ps1" {
            "$PSScriptRoot\..\..\native\windows\commands\Start-VncRemote.ps1" | Should -Exist
        }

        It "Should have Stop-VncRemote.ps1" {
            "$PSScriptRoot\..\..\native\windows\commands\Stop-VncRemote.ps1" | Should -Exist
        }
    }
}
