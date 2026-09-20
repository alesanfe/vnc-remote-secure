# Installer.Tests.ps1 - Tests for Windows installer
# These tests verify static properties of the installer script (existence,
# WhatIf support, default path). They do NOT execute the installer, which
# would require administrator privileges and create system directories.

Describe "Installer" -Tag "Windows" {
    Context "Script exists" {
        It "Should have an Install-VncRemote.ps1 script" {
            "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Install-VncRemote.ps1" | Should -Exist
        }
    }

    Context "WhatIf support" {
        It "Should support -WhatIf parameter" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Install-VncRemote.ps1" -Raw
            $scriptContent | Should -Match 'SupportsShouldProcess'
        }
    }

    Context "CLI delegation" {
        It "Should only pass flags the Python CLI supports" {
            $scriptContent = Get-Content "$PSScriptRoot\..\..\src\vnc_remote_secure\native\windows\commands\Install-VncRemote.ps1" -Raw
            # `vnc-remote install` accepts --dry-run/--json/--verbose/
            # --quiet only — no --force or install-path flag.
            $scriptContent | Should -Not -Match "'--force'"
        }
    }
}
