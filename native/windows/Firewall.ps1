<#
.SYNOPSIS
    Manages Windows Firewall rules for VNC Remote Secure

.DESCRIPTION
    Creates minimal, identifiable, and removable firewall rules.
    Only exposes the gateway port (443) publicly.
    Internal services (VNC, noVNC, ttyd, health) stay on loopback.

    Rules are tagged with 'VncRemoteSecure' prefix for easy identification and removal.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action Create
    .\Manage-Firewall.ps1 -Action Remove
    .\Manage-Firewall.ps1 -Action List
    .\Manage-Firewall.ps1 -Action Create -WhatIf

.NOTES
    Requires: Administrator privileges
    Requires: PowerShell 5.1+
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Create', 'Remove', 'List', 'Verify')]
    [string]$Action,

    [int]$HttpsPort = 443,

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

        # Only expose HTTPS gateway port publicly
        # Internal services (VNC 5900/5901, noVNC 6080, ttyd 5000, health 8080/8090)
        # stay on loopback and do NOT need firewall rules
        New-VncRemoteFirewallRule `
            -DisplayName 'HTTPS Gateway' `
            -Description 'VNC Remote Secure - HTTPS gateway (nginx/websockify). Only public port.' `
            -Port $HttpsPort `
            -Profiles $Profiles

        Write-Host ''
        Write-Host 'Firewall rules created:' -ForegroundColor Green
        Write-Host "  - $script:RulePrefix HTTPS Gateway (port $HttpsPort, profiles: $($Profiles -join ', '))"
        Write-Host ''
        Write-Host 'Internal services remain on loopback (no public exposure):' -ForegroundColor Yellow
        Write-Host '  - VNC (5900/5901) - loopback only'
        Write-Host '  - noVNC (6080) - loopback only'
        Write-Host '  - ttyd (5000) - loopback only'
        Write-Host '  - Health (8080/8090) - loopback only'
    }

    'Remove' {
        Write-Host 'Removing VNC Remote Secure firewall rules...' -ForegroundColor Cyan

        $rules = Get-VncRemoteFirewallRules
        if ($rules) {
            foreach ($rule in $rules) {
                if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove firewall rule')) {
                    $rule | Remove-NetFirewallRule
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
        $httpsRule = $rules | Where-Object { $_.DisplayName -match 'HTTPS Gateway' }

        $result = [pscustomobject]@{
            RulesFound = if ($rules) { $rules.Count } else { 0 }
            HttpsRuleExists = $httpsRule -ne $null
            RuleNames = if ($rules) { $rules.DisplayName } else { @() }
        }

        if ($result.RulesFound -gt 0 -and $result.HttpsRuleExists) {
            Write-Host 'Firewall configuration: OK' -ForegroundColor Green
            Write-Host "  Rules: $($result.RulesFound)" -ForegroundColor Green
            Write-Host "  HTTPS Gateway: present" -ForegroundColor Green
        } elseif ($result.RulesFound -eq 0) {
            Write-Host 'Firewall configuration: NO RULES (run Create)' -ForegroundColor Yellow
        } else {
            Write-Host 'Firewall configuration: PARTIAL' -ForegroundColor Yellow
            if (-not $result.HttpsRuleExists) {
                Write-Host '  - HTTPS gateway rule not found' -ForegroundColor Yellow
            }
        }

        return $result
    }
}
