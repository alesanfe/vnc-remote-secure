<#
.SYNOPSIS
    Manages Windows Firewall rules for VNC Remote Secure

.DESCRIPTION
    Creates minimal, identifiable, and removable firewall rules.
    Only exposes the landing-portal port (8000) publicly — on Windows
    there is no nginx, so the portal itself is the public entry point.
    Internal services (VNC, noVNC, web terminal, health) stay on loopback.

    Rules are tagged with 'VncRemoteSecure' prefix for easy identification and removal.

.EXAMPLE
    .\Firewall.ps1 -Action Create
    .\Firewall.ps1 -Action Remove
    .\Firewall.ps1 -Action List
    .\Firewall.ps1 -Action Create -WhatIf

.NOTES
    Requires: Administrator privileges
    Requires: PowerShell 5.1+
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Create', 'Remove', 'List', 'Verify')]
    [string]$Action = 'List',

    [int]$HttpsPort = 8000,

    [ValidateSet('Private', 'Domain', 'Public', 'Any')]
    [string[]]$Profiles = @('Private', 'Domain')
)

# Rule name prefix for identification
$script:RulePrefix = 'VncRemoteSecure'

# Must be admin for Create/Remove (unless -WhatIf)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Action -in @('Create', 'Remove') -and -not $isAdmin -and -not $WhatIfPreference) {
    Write-Error 'Administrator privileges required for Create/Remove actions'
    exit 1
}

function Get-VncRemoteFirewallRules {
    return Get-NetFirewallRule -DisplayName "$script:RulePrefix*" -ErrorAction SilentlyContinue
}

function New-VncRemoteFirewallRule {
    param(
        [string]$DisplayName,
        [string]$Description,
        [int]$Port,
        [string]$Direction = 'Inbound',
        [string]$Protocol = 'TCP',
        [string[]]$Profiles = @('Private', 'Domain')
    )

    $fullRuleName = "$script:RulePrefix $DisplayName"

    # Check if rule already exists (idempotency)
    $existing = Get-NetFirewallRule -DisplayName $fullRuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "Rule '$fullRuleName' already exists, skipping"
        return $existing
    }

    if ($PSCmdlet.ShouldProcess($fullRuleName, 'Create firewall rule')) {
        $params = @{
            DisplayName  = $fullRuleName
            Description  = $Description
            Direction    = $Direction
            Protocol     = $Protocol
            LocalPort    = $Port
            Action       = 'Allow'
            Profile      = ($Profiles -join ', ')
            Enabled      = $true
        }

        $rule = New-NetFirewallRule @params
        Write-Verbose "Created rule: $fullRuleName (port $Port, profiles: $($Profiles -join ', '))"
        return $rule
    }
}

function Remove-VncRemoteFirewallRule {
    param([string]$DisplayName)

    $fullRuleName = "$script:RulePrefix $DisplayName"
    $rule = Get-NetFirewallRule -DisplayName $fullRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        if ($PSCmdlet.ShouldProcess($fullRuleName, 'Remove firewall rule')) {
            $rule | Remove-NetFirewallRule
            Write-Verbose "Removed rule: $fullRuleName"
        }
    } else {
        Write-Verbose "Rule '$fullRuleName' not found, skipping"
    }
}

switch ($Action) {
    'Create' {
        Write-Host 'Creating VNC Remote Secure firewall rules...' -ForegroundColor Cyan

        # Only expose the portal port publicly
        # Internal services (VNC 5900/5901, noVNC 6080, web terminal 5000, health 8080/8090)
        # stay on loopback and do NOT need firewall rules
        New-VncRemoteFirewallRule `
            -DisplayName 'Portal' `
            -Description 'VNC Remote Secure - landing portal. Only public port.' `
            -Port $HttpsPort `
            -Profiles $Profiles

        Write-Host ''
        Write-Host 'Firewall rules created:' -ForegroundColor Green
        Write-Host "  - $script:RulePrefix Portal (port $HttpsPort, profiles: $($Profiles -join ', '))"
        Write-Host ''
        Write-Host 'Internal services remain on loopback (no public exposure):' -ForegroundColor Yellow
        Write-Host '  - VNC (5900/5901) - loopback only'
        Write-Host '  - noVNC (6080) - loopback only'
        Write-Host '  - Web terminal (5000) - loopback only'
        Write-Host '  - Health (8080/8090) - loopback only'
    }

    'Remove' {
        Write-Host 'Removing VNC Remote Secure firewall rules...' -ForegroundColor Cyan

        $rules = Get-VncRemoteFirewallRules
        if ($rules) {
            foreach ($rule in $rules) {
                if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove firewall rule')) {
                    # Use the public Remove helper for each named rule so
                    # the same code path serves the bulk action and any
                    # external caller that removes a single rule.
                    Remove-VncRemoteFirewallRule -DisplayName ($rule.DisplayName -replace "^$script:RulePrefix\s*", '')
                    Write-Verbose "Removed: $($rule.DisplayName)"
                }
            }
            Write-Host "Removed $($rules.Count) rule(s)" -ForegroundColor Green
        } else {
            Write-Host 'No VncRemoteSecure firewall rules found' -ForegroundColor Yellow
        }
    }

    'List' {
        $rules = Get-VncRemoteFirewallRules
        if ($rules) {
            Write-Host 'VNC Remote Secure firewall rules:' -ForegroundColor Cyan
            Write-Host ''
            $rules | Format-Table DisplayName, Enabled, Direction, Action, Profile -AutoSize

            # Show port bindings
            Write-Host 'Port bindings:' -ForegroundColor Cyan
            foreach ($rule in $rules) {
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                if ($portFilter) {
                    Write-Host "  $($rule.DisplayName): $($portFilter.Protocol) port $($portFilter.LocalPort)"
                }
            }
        } else {
            Write-Host 'No VncRemoteSecure firewall rules found' -ForegroundColor Yellow
        }
    }

    'Verify' {
        $rules = Get-VncRemoteFirewallRules
        # The public entry rule is created by either this script
        # ('VncRemoteSecure Portal') or the Python installer
        # ('VncRemoteSecure-<port>-tcp'). Verify a rule exists on the
        # portal port rather than matching a specific display name.
        $portalRule = $rules | Where-Object {
            $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $pf -and $pf.LocalPort -eq $HttpsPort
        }

        $result = [pscustomobject]@{
            RulesFound      = if ($rules) { $rules.Count } else { 0 }
            PortalRuleExists = $portalRule -ne $null
            RuleNames       = if ($rules) { $rules.DisplayName } else { @() }
        }

        if ($result.RulesFound -gt 0 -and $result.PortalRuleExists) {
            Write-Host 'Firewall configuration: OK' -ForegroundColor Green
            Write-Host "  Rules: $($result.RulesFound)" -ForegroundColor Green
            Write-Host "  Portal rule (port $HttpsPort): present" -ForegroundColor Green
        } elseif ($result.RulesFound -eq 0) {
            Write-Host 'Firewall configuration: NO RULES (run Create)' -ForegroundColor Yellow
        } else {
            Write-Host 'Firewall configuration: PARTIAL' -ForegroundColor Yellow
            if (-not $result.PortalRuleExists) {
                Write-Host "  - Portal rule on port $HttpsPort not found" -ForegroundColor Yellow
            }
        }

        return $result
    }
}
