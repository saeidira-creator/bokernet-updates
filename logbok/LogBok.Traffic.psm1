# ==========================================================================
#  LogBok.Traffic.psm1 - traffic policy (firewall management, native LogBok feature)
#  Allow "specific computer/network + user + port/protocol" and block the rest
#  (default-deny inbound). With full safety:
#    - a snapshot is taken before applying (compatible with Restore-LogBokChange).
#    - a management-allow rule for the server/console always stays open so you are not locked out.
#    - a single command reverts it to the previous state on all systems.
#  Rules are created with the "LogBok-Traffic-" prefix (no conflict with other products).
#  Per-host/user/port allow + default-deny, with snapshot & rollback.
# ==========================================================================

$script:Prefix = 'LogBok-Traffic-'

function Resolve-LBSid { param([string]$User)
    try { return (New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}

# traffic policy from config (compatible with the old FireBokPolicy name)
function Get-LBTrafficPolicy {
    param($Config)
    # an empty TrafficPolicy must not shadow a populated legacy FireBokPolicy
    if ($Config.TrafficPolicy -and (@($Config.TrafficPolicy.Allow).Count -gt 0 -or -not $Config.FireBokPolicy)) { return $Config.TrafficPolicy }
    if ($Config.FireBokPolicy) { return $Config.FireBokPolicy }
    return @{ DefaultInboundBlock = $false; Allow = @() }
}

function Get-LBTrafficRules { Get-NetFirewallRule -DisplayName "$($script:Prefix)*" -ErrorAction SilentlyContinue | Select-Object DisplayName,Direction,Action,Enabled }

# apply traffic policy with a snapshot
#  $Policy = @{ DefaultInboundBlock=$true; Allow=@( @{Name;Direction;Protocol;LocalPort;RemoteAddress;LocalUser;Program} ) }
function Invoke-LBTrafficApply {
    param(
        [string]$InstallDir='C:\Scripts\LogBok',
        [Parameter(Mandatory)]$Policy,
        [string]$ManageIp,                 # management server IP that must always stay open
        [string]$ChangeId=('TP'+(Get-Date).ToString('yyMMddHHmm',[Globalization.CultureInfo]::InvariantCulture))
    )
    Import-Module (Join-Path $InstallDir 'LogBok.Threat.psm1') -Force -ErrorAction SilentlyContinue
    $rp = New-LogBokRestore -ChangeId $ChangeId
    $acts = New-Object System.Collections.ArrayList

    # 0) record the current default-inbound state for rollback
    $curInbound = 'allowinbound'
    try { $p=(& netsh advfirewall show allprofiles firewallpolicy) -join ' '; if ($p -match 'BlockInbound') { $curInbound='blockinbound' } } catch {}
    [void]$acts.Add(@{ type='setinbound'; value=$curInbound })

    # 1) always keep management open (WinRM 5985/5986 + ICMP) so we are not locked out
    if ($ManageIp) {
        New-NetFirewallRule -DisplayName "$($script:Prefix)MGMT" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985,5986 -RemoteAddress $ManageIp -Enabled True -ErrorAction SilentlyContinue | Out-Null
        [void]$acts.Add(@{ type='delrule'; name="$($script:Prefix)MGMT" })
        New-NetFirewallRule -DisplayName "$($script:Prefix)MGMT-PING" -Direction Inbound -Action Allow -Protocol ICMPv4 -RemoteAddress $ManageIp -Enabled True -ErrorAction SilentlyContinue | Out-Null
        [void]$acts.Add(@{ type='delrule'; name="$($script:Prefix)MGMT-PING" })
    }

    # 2) allow rules
    foreach ($r in @($Policy.Allow)) {
        if (-not $r.Name) { continue }
        $rn = "$($script:Prefix)$($r.Name)"
        $p = @{ DisplayName=$rn; Direction=($r.Direction); Action='Allow'; Enabled='True' }
        if (-not $r.Direction) { $p.Direction='Inbound' }
        if ($r.Protocol)      { $p.Protocol   = $r.Protocol }
        if ($r.LocalPort)     { $p.LocalPort  = @(([string]$r.LocalPort -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        if ($r.RemoteAddress) { $p.RemoteAddress = @(([string]$r.RemoteAddress -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        if ($r.Program)       { $p.Program    = $r.Program }
        if ($r.LocalUser)     { $sid = Resolve-LBSid $r.LocalUser; if ($sid) { $p.LocalUser = "D:(A;;CC;;;$sid)" } }
        try { New-NetFirewallRule @p -ErrorAction Stop | Out-Null; [void]$acts.Add(@{ type='delrule'; name=$rn }) }
        catch {
            # simple fallback with netsh (no LocalUser)
            $dir = if ($p.Direction -eq 'Outbound') {'out'} else {'in'}
            $na = @('advfirewall','firewall','add','rule',"name=$rn","dir=$dir",'action=allow','enable=yes')
            if ($r.Protocol)      { $na += "protocol=$($r.Protocol)" }
            if ($r.LocalPort)     { $na += ('localport=' + (@($p.LocalPort) -join ',')) }
            if ($r.RemoteAddress) { $na += ('remoteip=' + (@($p.RemoteAddress) -join ',')) }
            if ($r.Program)       { $na += "program=$($r.Program)" }
            & netsh @na | Out-Null
            if ($LASTEXITCODE -eq 0) { [void]$acts.Add(@{ type='delrule'; name=$rn }) }
        }
    }

    # 3) block the rest (default-deny inbound)
    if ($Policy.DefaultInboundBlock) {
        & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    }

    $rp.Actions = $acts.ToArray()
    Save-LogBokRestore -RP $rp -InstallDir $InstallDir
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9011 -EntryType Warning -Message ("TRAFFIC POLICY apply on {0}: change={1} rules={2} defaultBlock={3}" -f $env:COMPUTERNAME,$ChangeId,@($Policy.Allow).Count,[bool]$Policy.DefaultInboundBlock) } catch {}
    return [pscustomobject]@{ ChangeId=$ChangeId; Rules=@($Policy.Allow).Count }
}

# remove all traffic-policy rules
#  Rules from older LogBok versions (FireBok-MGMT and FireBok-<config rule name>) are
#  removed only by exact name; the FireBok product's own rules are left untouched.
function Remove-LBTraffic {
    param([string]$InstallDir='C:\Scripts\LogBok', $Policy)
    Get-NetFirewallRule -DisplayName "$($script:Prefix)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $legacy = @('FireBok-MGMT','FireBok-MGMT-PING')
    foreach ($r in @($Policy.Allow)) { if ($r.Name) { $legacy += "FireBok-$($r.Name)" } }
    foreach ($n in $legacy) { Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    # back to the safe Windows default (inbound closed, outbound open) - not opening all ports
    & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9012 -EntryType Warning -Message ("TRAFFIC POLICY cleared on {0}" -f $env:COMPUTERNAME) } catch {}
}

Export-ModuleMember -Function Get-LBTrafficPolicy, Get-LBTrafficRules, Invoke-LBTrafficApply, Remove-LBTraffic
