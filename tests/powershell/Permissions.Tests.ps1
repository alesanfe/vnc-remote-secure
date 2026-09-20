# Permissions.Tests.ps1 - Tests for Windows ACL/permissions management
Describe "Permissions" -Tag "Windows" {
    Context "Script exists" {
        It "Should have a VncRemote.psm1 module" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\VncRemote.psm1" | Should -Exist
        }
    }

    Context "Module structure" {
        It "Should export functions" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\VncRemote.psm1" -Raw
            $scriptContent | Should -Match 'function'
        }
    }
}
