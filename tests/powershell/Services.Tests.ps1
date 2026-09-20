# Services.Tests.ps1 - Tests for Windows Service management
Describe "Services" -Tag "Windows" {
    Context "Service config" {
        It "Should have a service-config.xml" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\service\service-config.xml" | Should -Exist
        }

        It "Should define service name" {
            $content = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\service\service-config.xml" -Raw
            # SERVICE_NAME in platform/windows/services.py — sc.exe
            # registers the service under this exact name.
            $content | Should -Match '<name>VncRemoteSecure</name>'
        }

        It "Should set automatic start type" {
            $content = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\service\service-config.xml" -Raw
            $content | Should -Match 'Automatic'
        }
    }

    Context "Command scripts" {
        It "Should have Start-VncRemote.ps1" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Start-VncRemote.ps1" | Should -Exist
        }

        It "Should have Stop-VncRemote.ps1" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Stop-VncRemote.ps1" | Should -Exist
        }
    }
}
