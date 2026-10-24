# ==========================================================================
#  LogBok.Policy.psm1 - policy engine & compliance monitoring
#  Test-LogBokCompliance : checks the current system state against policies.psd1.
#  Repair-LogBokCompliance: fixes remediable items (when AutoRemediate is on).
#  Each policy violation logs event 9005, forwarded to the Collector and emailed.
#  Depends on LogBok.Firewall.psm1 and LogBok.AntiRansomware.psm1 for remediation.
# ==========================================================================

function Get-LogBokPolicy {
    param([string]$Path)
    if (-not $Path) {
        $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $Path = Join-Path $root 'policies.psd1'
    }
    if (-not (Test-Path $Path)) { return $null }
    return Import-PowerShellDataFile -Path $Path
}

# returns a list of @{Item;Expected;Actual;Compliant;Remediable}
function Test-LogBokCompliance {
    param($Policy,[string]$InstallDir='C:\Scripts\LogBok')
    if (-not $Policy) { $Policy = Get-LogBokPolicy }
    $r = @()
    function Item($name,$expected,$actual,$remediable){ [pscustomobject]@{ Item=$name; Expected=$expected; Actual=$actual; Compliant=($expected -eq $actual); Remediable=$remediable } }

    if ($Policy.FirewallEnabled -ne $null) {
        $on = $true
        try { $on = -not ((& netsh advfirewall show allprofiles state) -match 'OFF|خاموش') } catch {}
        $r += Item 'FirewallEnabled' $Policy.FirewallEnabled $on $true
    }
    if ($Policy.DefenderRealtime -ne $null) {
        $on = $true
        try { $on = -not (Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring } catch {}
        $r += Item 'DefenderRealtime' $Policy.DefenderRealtime $on $true
    }
    if ($Policy.ControlledFolderAccess -ne $null) {
        $on = $false
        try { $on = ((Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess -ne 0) } catch {}
        $r += Item 'ControlledFolderAccess' $Policy.ControlledFolderAccess $on $true
    }
    if ($Policy.AgentPresent) {
        $t = Get-ScheduledTask -TaskName 'LogBok-Watchdog' -TaskPath '\LogBok\' -ErrorAction SilentlyContinue
        $r += Item 'AgentPresent' $true ([bool]($t -and $t.State -ne 'Disabled')) $true
    }
    if ($Policy.AuditEnabled) {
        $ok = $false
        try { $ok = ((& auditpol /get /subcategory:'{0CCE921D-69AE-11D9-BED3-505054503030}' /r) -match 'Success|Failure|موفق') } catch {}
        $r += Item 'AuditEnabled' $true $ok $true
    }
    foreach ($svc in @($Policy.RequiredServices)) {
        if (-not $svc) { continue }
        $running = $false
        try { $running = ((Get-Service -Name $svc -ErrorAction Stop).Status -eq 'Running') } catch {}
        $r += Item "Service:$svc" $true $running $true
    }
    foreach ($app in @($Policy.BlockedApps)) {
        if (-not $app) { continue }
        $blocked = $false
        try { $n = [IO.Path]::GetFileNameWithoutExtension($app)
              $blocked = [bool](Get-NetFirewallRule -DisplayName "LogBok-Block-$n*" -ErrorAction SilentlyContinue) } catch {}
        $r += Item "BlockApp:$app" $true $blocked $true
    }
    return $r
}

# remediate non-compliant, remediable items
function Repair-LogBokCompliance {
    param($Policy,$Compliance,[string]$InstallDir='C:\Scripts\LogBok')
    if (-not $Policy) { $Policy = Get-LogBokPolicy }
    if (-not $Policy.AutoRemediate) { return @() }
    Import-Module (Join-Path $InstallDir 'LogBok.Firewall.psm1') -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $InstallDir 'LogBok.AntiRansomware.psm1') -Force -ErrorAction SilentlyContinue
    $fixed = @()
    foreach ($c in ($Compliance | Where-Object { -not $_.Compliant -and $_.Remediable })) {
        try {
            switch -Regex ($c.Item) {
                '^FirewallEnabled$'        { Set-LogBokFirewall -Enabled $true; $fixed+=$c.Item }
                '^DefenderRealtime$'       { Set-LogBokDefenderRealtime -Enabled $true; $fixed+=$c.Item }
                '^ControlledFolderAccess$' { Enable-LogBokCFA | Out-Null; $fixed+=$c.Item }
                '^Service:(.+)$'           { Start-Service -Name $Matches[1] -ErrorAction SilentlyContinue; $fixed+=$c.Item }
                '^BlockApp:(.+)$'          { Block-LogBokApp -Path $Matches[1] | Out-Null; $fixed+=$c.Item }
                default { }
            }
        } catch {}
    }
    return $fixed
}

Export-ModuleMember -Function *
