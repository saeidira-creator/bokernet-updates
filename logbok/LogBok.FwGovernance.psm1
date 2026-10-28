# ==========================================================================
#  LogBok.FwGovernance.psm1 - firewall rule governance
#  Policy: users may not add/change firewall rules manually; only via
#  LogBok (LogBok- prefixed rules) or GPO; "FireBok-" rules, created by the separate
#  BokerNet product on the same system, are also allowed (coexistence only).
#
#  Behavior (as agreed): any "unknown" rule (not made by LogBok, not from GPO) only
#  raises an alert + email and is NOT removed - on both system types (domain and
#  standalone) alike. On domain systems, local merge can additionally be
#  turned off so the rule has no effect (but we still only report).
#
#  Depends on LogBok.Core (for logging). Emits event: 9013.
# ==========================================================================

# prefixes the product itself creates
$script:AllowedPrefixes = @('LogBok-','FireBok-')

# rule groups that Windows/Microsoft components create by themselves (never a person)
$script:MicrosoftRuleGroups = @('DiagTrack','Microsoft Edge','Microsoft Edge WebView2 Runtime','Windows Feature Experience Pack','Microsoft Edge Update')

function Write-LBFwEvent {
    param([string]$Message,[string]$Level='Warning',[int]$Id=9013)
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId $Id -EntryType $Level -Message $Message } catch {}
}

# domain-joined?
function Test-LBDomainJoined {
    try { return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { return $false }
}

# local rules that are neither LogBok nor GPO
#  - a GPO source is identified by PolicyStoreSourceType = GroupPolicy.
#  - rules with an allowed prefix are ignored.
#  - the supplementary safe list (AllowRuleNames from config) is also excluded.
function Get-LBUnknownFwRules {
    param([string[]]$ExtraAllow=@())
    $unknown = @()
    try {
        $rules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                 Where-Object { $_.Enabled -eq 'True' }
    } catch {
        # older Windows without NetSecurity -> use netsh (rule names)
        return Get-LBUnknownFwRulesNetsh -ExtraAllow $ExtraAllow
    }
    foreach ($r in $rules) {
        $name = $r.DisplayName
        if (-not $name) { continue }
        # created by the product itself?
        $isOurs = $false
        foreach ($p in $script:AllowedPrefixes) { if ($name.StartsWith($p)) { $isOurs = $true; break } }
        if ($isOurs) { continue }
        if ($ExtraAllow -contains $name) { continue }
        # came from GPO?
        $fromGpo = $false
        try { if ($r.PolicyStoreSourceType -eq 'GroupPolicy') { $fromGpo = $true } } catch {}
        # do not count built-in Windows rules (populated Group + system source) as "user-unknown":
        # focus on rules a user/app created manually (no Group, Local source).
        $isBuiltIn = $false
        # only built-in Windows groups (@... resource string) are allowed; anyone can
        # create a rule with an arbitrary -Group and must not hide from governance
        try { if ([string]$r.Group -like '@*') { $isBuiltIn = $true } } catch {}
        # rules Windows / Microsoft components create themselves on every server (not a person):
        #  - owned by an installed Windows app package (AppX, e.g. Windows Feature Experience Pack)
        #  - the telemetry service (DiagTrack) and Microsoft Edge / WebView2 (mDNS, etc.)
        try { if ([string]$r.Owner) { $isBuiltIn = $true } } catch {}
        try { if ($script:MicrosoftRuleGroups -contains [string]$r.Group) { $isBuiltIn = $true } } catch {}
        if ($fromGpo -or $isBuiltIn) { continue }
        # details of what the rule actually opens: protocol / port / program
        $proto = ''; $lport = ''; $prog = ''
        try { $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; if ($pf) { $proto = [string]$pf.Protocol; $lport = ([string[]]$pf.LocalPort) -join ',' } } catch { }
        try { $af = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; if ($af) { $prog = [string]$af.Program } } catch { }
        $unknown += [pscustomobject]@{
            Name = $name; Direction = [string]$r.Direction; Action = [string]$r.Action
            Protocol = $proto; LocalPort = $lport; Program = $prog; Profile = [string]$r.Profile
            Store = [string]$r.PolicyStoreSourceType; Group = [string]$r.Group
        }
    }
    return $unknown
}

# fallback for Windows without the NetSecurity module (name-based)
function Get-LBUnknownFwRulesNetsh {
    param([string[]]$ExtraAllow=@())
    $unknown=@()
    try {
        $out = & netsh advfirewall firewall show rule name=all 2>$null
        $cur=$null
        foreach($ln in $out){
            if($ln -match '^(Rule Name|نام قاعده):\s*(.+)$'){ $cur=$Matches[2].Trim() ;
                $isOurs=$false; foreach($p in $script:AllowedPrefixes){ if($cur.StartsWith($p)){$isOurs=$true} }
                if(-not $isOurs -and ($ExtraAllow -notcontains $cur)){ $unknown += [pscustomobject]@{Name=$cur;Direction='';Action='';Store='Local';Group=''} }
            }
        }
    } catch {}
    # this path returns all rules (including built-in); so in practice on an old system
    # it is better to fill ExtraAllow. This is only a minimal fallback.
    return $unknown
}

# detect & alert only (email/report only, no removal)
function Invoke-LBFwGovernanceCheck {
    param([string[]]$ExtraAllow=@())
    $unknown = Get-LBUnknownFwRules -ExtraAllow $ExtraAllow
    if ($unknown.Count -gt 0) {
        $domain = Test-LBDomainJoined
        $scope = if ($domain) { 'domain (GPO merge-off توصیه می‌شود؛ اثر نمی‌کند ولی خبر می‌دهیم)' } else { 'standalone' }
        $list = ($unknown | ForEach-Object {
            $det = "$($_.Name) [$($_.Direction)/$($_.Action)]"
            $pp = @(); if ($_.Protocol -and $_.Protocol -ne 'Any') { $pp += [string]$_.Protocol }; if ($_.LocalPort -and $_.LocalPort -ne 'Any') { $pp += 'port ' + $_.LocalPort }
            if ($pp.Count) { $det += ' ' + ($pp -join '/') }
            if ($_.Program -and $_.Program -ne 'Any') { $det += ' prog=' + $_.Program }
            $det
        }) -join ' ; '
        Write-LBFwEvent -Message ("UNAUTHORIZED FIREWALL RULE on {0} ({1}): {2}" -f $env:COMPUTERNAME,$scope,$list)
    }
    return $unknown
}

# --- on domain systems: turn off local rule merge ---------------------
#  AllowLocalPolicyMerge = 0  -> only GPO rules take effect (a manual local rule
#  does not apply at all). This is usually set from the GPO itself; this function is for
#  when you want to apply it locally and immediately.
function Set-LBLocalMerge {
    param([ValidateSet('Domain','Private','Public','All')][string]$Profile='All',[bool]$AllowMerge=$false)
    $profiles = if ($Profile -eq 'All') { 'Domain','Private','Public' } else { ,$Profile }
    $val = if ($AllowMerge) { 1 } else { 0 }
    foreach ($p in $profiles) {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${p}Profile"
        try {
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            New-ItemProperty -Path $key -Name 'AllowLocalPolicyMerge' -Value $val -PropertyType DWord -Force | Out-Null
        } catch {}
    }
    Write-LBFwEvent -Message ("Local firewall merge set to {0} on {1} (profiles={2})" -f $AllowMerge,$env:COMPUTERNAME,($profiles -join ',')) -Level Information -Id 9008
}

Export-ModuleMember -Function *
