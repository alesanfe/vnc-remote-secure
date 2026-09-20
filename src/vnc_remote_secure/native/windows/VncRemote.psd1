#
# Module manifest for VncRemote module
#

@{
    RootModule        = 'VncRemote.psm1'
    ModuleVersion      = '0.2.0'
    GUID              = '8a59fbcf-a91f-4ab5-86c5-18e0bfa9acf0'
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
        'Get-VncRemoteVersion',
        'Show-VncRemoteHelp',
        'Invoke-VncRemoteSession',
        'Invoke-VncRemoteSecrets',
        'Invoke-VncRemoteConfig',
        'Invoke-VncRemoteVerify',
        'Invoke-VncRemoteService'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
