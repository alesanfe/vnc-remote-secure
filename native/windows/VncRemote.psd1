#
# Module manifest for VncRemote module
#

@{
    RootModule        = 'VncRemote.psm1'
    ModuleVersion      = '0.2.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'VNC Remote Secure Contributors'
    Description       = 'Native PowerShell module for VNC Remote Secure on Windows'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Install-VncRemote',
        'Start-VncRemote',
        'Stop-VncRemote',
        'Restart-VncRemote',
        'Get-VncRemoteStatus',
        'Test-VncRemoteConfiguration',
        'Backup-VncRemote',
        'Restore-VncRemote',
        'Uninstall-VncRemote',
        'Get-VncRemoteVersion'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
