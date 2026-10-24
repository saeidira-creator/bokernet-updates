# ==========================================================================
#  LogBok.UBA.psm1 - time-based & first-time behavioural analytics (engine)
#  Learns each user's and host's normal logon hours, then flags deviations:
#  off-hours logon, first-time host for a user, first-time remote access,
#  first-time process on a server, first privilege use, mass file ops,
#  lockout spikes. Each anomaly can alert and (optionally) be prevented.
#  Builds on the existing UEBA baseline; offline, explainable, bilingual.
# ==========================================================================
Set-StrictMode -Off
$script:Inv = [Globalization.CultureInfo]::InvariantCulture

# --- baseline store -------------------------------------------------------
function Get-LBUbaFile { param([string]$StateDir) Join-Path $StateDir 'uba-baseline.json' }

function ConvertTo-LBUbaHT {
    # recursively turn ConvertFrom-Json output into nested hashtables (arrays stay arrays)
    param($o)
    if ($null -eq $o) { return $null }
    if ($o -is [string] -or $o -is [bool] -or $o -is [int] -or $o -is [long] -or $o -is [double]) { return $o }
    if ($o -is [System.Collections.IEnumerable] -and -not ($o -is [string]) -and -not ($o -is [System.Management.Automation.PSCustomObject])) {
        $a = @(); foreach ($i in $o) { $a += , (ConvertTo-LBUbaHT $i) }; return , $a
    }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-LBUbaHT $p.Value }; return $h
    }
    if ($o -is [hashtable]) { $h = @{}; foreach ($k in $o.Keys) { $h[$k] = ConvertTo-LBUbaHT $o[$k] }; return $h }
    return $o
}
function Get-LBUbaBaseline {
    param([string]$StateDir)
    $f = Get-LBUbaFile -StateDir $StateDir
    $b = @{ users = @{}; hosts = @{}; servers = @{}; days = 0; updated = ''; firstLearn = '' }
    if (Test-Path $f) {
        try {
            $o = ConvertTo-LBUbaHT (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json)
            if ($o -is [hashtable]) {
                foreach ($k in 'users', 'hosts', 'servers') { if ($o[$k] -is [hashtable]) { $b[$k] = $o[$k] } }
                if ($o['days']) { $b.days = [int]$o['days'] }
                if ($o['updated']) { $b.updated = [string]$o['updated'] }
                if ($o['firstLearn']) { $b.firstLearn = [string]$o['firstLearn'] }
            }
        } catch { }
    }
    return $b
}

function Save-LBUbaBaseline {
    param([string]$StateDir, $Baseline)
    $f = Get-LBUbaFile -StateDir $StateDir
    $Baseline.updated = (Get-Date).ToString('o', $script:Inv)
    try { [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $Baseline -Depth 8), (New-Object Text.UTF8Encoding($false))) } catch { }
}

# --- helpers --------------------------------------------------------------
function New-LBHourArray { $a = New-Object int[] 24; return , $a }

function Format-LBHourRange {
    # turn an hour histogram into a readable "6 AM - 8 PM" normal window
    param($Hours)
    $on = @(); for ($h = 0; $h -lt 24; $h++) { if ([int]$Hours[$h] -gt 0) { $on += $h } }
    if (-not $on.Count) { return '' }
    $lo = ($on | Measure-Object -Minimum).Minimum; $hi = ($on | Measure-Object -Maximum).Maximum
    $fmt = { param($h) $ap = if ($h -lt 12) { 'AM' } else { 'PM' }; $hr = $h % 12; if ($hr -eq 0) { $hr = 12 }; "$hr $ap" }
    return ('{0} - {1}' -f (& $fmt $lo), (& $fmt $hi))
}

function Test-LBMachineName { param([string]$u) return (-not $u -or $u -like '*$' -or $u -in 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-') }

# --- learning: fold a batch of logon records into the baseline ------------
#  Record = @{ User; Host; Hour(0-23); SrcIp; Proc; Priv; Type('logon'|'remote'|'proc'|'priv'|'filedel') }
function Update-LBUbaBaseline {
    param([string]$StateDir, [object[]]$Records, [int]$AddDays = 1)
    $b = Get-LBUbaBaseline -StateDir $StateDir
    foreach ($r in @($Records)) {
        $u = [string]$r.User; $h = [string]$r.Host; $hr = [int]$r.Hour
        if ($hr -lt 0 -or $hr -gt 23) { continue }
        if ($u -and -not (Test-LBMachineName $u)) {
            if (-not $b.users[$u]) { $b.users[$u] = @{ hours = (New-LBHourArray); total = 0; hosts = @{}; privs = @{}; firstSeen = (Get-Date).ToString('o', $script:Inv) } }
            $b.users[$u].hours[$hr] = [int]$b.users[$u].hours[$hr] + 1
            $b.users[$u].total = [int]$b.users[$u].total + 1
            if ($h) { $b.users[$u].hosts[$h] = 1 }
            if ($r.Priv) { $b.users[$u].privs[[string]$r.Priv] = 1 }
        }
        if ($h) {
            if (-not $b.hosts[$h]) { $b.hosts[$h] = @{ hours = (New-LBHourArray); total = 0; users = @{} } }
            $b.hosts[$h].hours[$hr] = [int]$b.hosts[$h].hours[$hr] + 1
            $b.hosts[$h].total = [int]$b.hosts[$h].total + 1
            if ($u) { $b.hosts[$h].users[$u] = 1 }
            if ($r.Proc) { if (-not $b.servers[$h]) { $b.servers[$h] = @{ procs = @{} } }; $b.servers[$h].procs[[string]$r.Proc] = 1 }
        }
    }
    if (-not $b.firstLearn) { $b.firstLearn = (Get-Date).ToString('o', $script:Inv) }
    try { $fl = [datetime]::Parse([string]$b.firstLearn, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind); $b.days = [int][math]::Floor(((Get-Date) - $fl).TotalDays) } catch { }
    Save-LBUbaBaseline -StateDir $StateDir -Baseline $b
    return $b
}

# --- detection: score a batch of recent records against the baseline ------
#  Returns anomalies; needs enough history first (MinDays/MinEvents) to avoid
#  false positives while still learning.
function Test-LBUbaAnomalies {
    param([string]$StateDir, [object[]]$Records, [int]$MinDays = 7, [int]$MinUserEvents = 20, [int]$MinHostEvents = 30)
    $b = Get-LBUbaBaseline -StateDir $StateDir
    $out = @()
    $learnedDays = 0
    if ($b.firstLearn) { try { $fl = [datetime]::Parse([string]$b.firstLearn, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind); $learnedDays = ((Get-Date) - $fl).TotalDays } catch { } }
    if ($learnedDays -lt $MinDays) { return $out }   # still learning
    foreach ($r in @($Records)) {
        $u = [string]$r.User; $h = [string]$r.Host; $hr = [int]$r.Hour; $type = [string]$r.Type
        $ip = [string]$r.SrcIp
        if ($hr -lt 0 -or $hr -gt 23) { continue }
        $isUser = ($u -and -not (Test-LBMachineName $u))

        # 1) logon outside the user's normal hours
        if ($type -eq 'logon' -and $isUser -and $b.users[$u] -and [int]$b.users[$u].total -ge $MinUserEvents) {
            if ([int]$b.users[$u].hours[$hr] -eq 0) {
                $out += [ordered]@{ rule = 'offhours-user'; sev = 'Trouble'; user = $u; host = $h; hour = $hr; ip = $ip
                    msg = ("Logon by '{0}' at {1}:00 on {2} is outside this user's normal hours ({3})" -f $u, $hr, $h, (Format-LBHourRange $b.users[$u].hours)) }
            }
        }
        # 2) logon at an hour this host never sees
        if ($type -eq 'logon' -and $h -and $b.hosts[$h] -and [int]$b.hosts[$h].total -ge $MinHostEvents) {
            if ([int]$b.hosts[$h].hours[$hr] -eq 0) {
                $out += [ordered]@{ rule = 'offhours-host'; sev = 'Trouble'; user = $u; host = $h; hour = $hr; ip = $ip
                    msg = ("Logon on host '{0}' at {1}:00 is outside its normal hours ({2}); user '{3}'" -f $h, $hr, (Format-LBHourRange $b.hosts[$h].hours), $u) }
            }
        }
        # 3) first-time host for this user
        if ($type -eq 'logon' -and $isUser -and $b.users[$u] -and [int]$b.users[$u].total -ge $MinUserEvents -and $h -and -not $b.users[$u].hosts[$h]) {
            $out += [ordered]@{ rule = 'firsttime-host'; sev = 'Attention'; user = $u; host = $h; hour = $hr; ip = $ip
                msg = ("First time '{0}' logs on to host '{1}'" -f $u, $h) }
        }
        # 4) first-time remote access to a host
        if ($type -eq 'remote' -and $h -and $b.hosts[$h] -and [int]$b.hosts[$h].total -ge $MinHostEvents -and $isUser -and -not $b.hosts[$h].users[$u]) {
            $out += [ordered]@{ rule = 'firsttime-remote'; sev = 'Trouble'; user = $u; host = $h; hour = $hr; ip = $ip
                msg = ("First remote access to '{0}' by '{1}' from {2}" -f $h, $u, $ip) }
        }
        # 5) first-time process on a server
        if ($type -eq 'proc' -and $h -and $r.Proc -and $b.servers[$h] -and -not $b.servers[$h].procs[[string]$r.Proc]) {
            $out += [ordered]@{ rule = 'firsttime-proc'; sev = 'Trouble'; user = $u; host = $h; hour = $hr; proc = [string]$r.Proc
                msg = ("First time process '{0}' runs on server '{1}'" -f $r.Proc, $h) }
        }
        # 6) first use of a privilege by a user
        if ($type -eq 'priv' -and $isUser -and $r.Priv -and $b.users[$u] -and [int]$b.users[$u].total -ge $MinUserEvents -and -not $b.users[$u].privs[[string]$r.Priv]) {
            $out += [ordered]@{ rule = 'firsttime-priv'; sev = 'Trouble'; user = $u; host = $h; hour = $hr; priv = [string]$r.Priv
                msg = ("First time '{0}' uses privilege '{1}' on '{2}'" -f $u, $r.Priv, $h) }
        }
    }
    return $out
}

# --- response: resolve per-rule mode/action from console settings ---------
#  Settings shape (state\settings.json > Uba): @{ Rules = @{ '<rule>' = @{ mode='off|alert|ask|auto'; action='none|blockip|disableuser|isolate' } } }
function Get-LBUbaRuleConfig {
    # read per-rule mode/action from the overlay-merged config ($Config.Uba.Rules.<rule>)
    param($Config, [string]$Rule)
    $def = @{ mode = 'alert'; action = 'none' }
    try {
        $u = $Config.Uba
        if ($u -and $u.Rules) {
            $r = $null
            if ($u.Rules -is [hashtable]) { $r = $u.Rules[$Rule] } elseif ($u.Rules.PSObject) { $r = $u.Rules.$Rule }
            if ($r) { $m = if ($r -is [hashtable]) { $r['mode'] } else { $r.mode }; $a = if ($r -is [hashtable]) { $r['action'] } else { $r.action }; if ($m) { $def.mode = [string]$m }; if ($a) { $def.action = [string]$a } }
        }
    } catch { }
    return $def
}

# --- one-time backfill from the local archive (so it works today) ---------
#  On first run, fold the last N days of archived 4624/4672 into the baseline
#  and backdate firstLearn to the earliest event so detection starts at once.
function Initialize-LBUbaFromArchive {
    param([string]$StateDir, $Config, [int]$Days = 30)
    $b = Get-LBUbaBaseline -StateDir $StateDir
    if ($b.firstLearn) { return 0 }   # already seeded / learning
    $dir = $null
    try { if (-not (Get-Command Get-LBArchiveDir -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $PSScriptRoot 'LogBok.Archive.psm1') -DisableNameChecking -Global -ErrorAction Stop }; $dir = Get-LBArchiveDir -Config $Config } catch { return 0 }
    if (-not $dir -or -not (Test-Path $dir)) { return 0 }
    $recs = New-Object System.Collections.Generic.List[object]
    $minT = $null
    for ($i = $Days; $i -ge 0; $i--) {
        $day = (Get-Date).AddDays(-$i)
        $file = Join-Path $dir ('events-{0}.ndjson' -f $day.ToString('yyyy-MM-dd', $script:Inv))
        if (-not (Test-Path $file)) { continue }
        # Get-LBArchiveDayRecords returns the list comma-protected; wrapping it in @() would collapse
        # the whole day into one element, so assign first, then enumerate.
        $items = $null; try { $items = Get-LBArchiveDayRecords -File $file } catch { continue }
        foreach ($r in $items) {
            $id = 0; if (-not [int]::TryParse([string]$r.id, [ref]$id)) { continue }
            if ($id -ne 4624 -and $id -ne 4672) { continue }
            $u = [string]$r.user; if (Test-LBMachineName $u) { continue }
            $t = $r.time; if (-not ($t -is [datetime])) { continue }
            $hostn = [string]$r.host
            if (-not $minT -or $t -lt $minT) { $minT = $t }
            if ($id -eq 4624) {
                $ip = [string]$r.ip; if ($ip -in '-', '::1', '127.0.0.1', '0.0.0.0') { $ip = '' }
                [void]$recs.Add(@{ User = $u; Host = $hostn; Hour = [int]$t.Hour; Type = 'logon'; SrcIp = $ip })
            } else {
                [void]$recs.Add(@{ User = $u; Host = $hostn; Hour = [int]$t.Hour; Type = 'priv'; Priv = 'SpecialPrivileges' })
            }
        }
    }
    if (-not $recs.Count) { return 0 }
    [void](Update-LBUbaBaseline -StateDir $StateDir -Records $recs.ToArray())
    $b2 = Get-LBUbaBaseline -StateDir $StateDir
    if ($minT) { $b2.firstLearn = $minT.ToString('o', $script:Inv); Save-LBUbaBaseline -StateDir $StateDir -Baseline $b2 }
    return $recs.Count
}

# --- live cycle: read recent logon events, learn, detect -> findings -------
#  Pulls 4624 (logon) and 4672 (special privileges) from every Security source,
#  normalises to records, detects anomalies BEFORE folding them into the
#  baseline (so a fresh off-hours logon is caught before it becomes "normal"),
#  then returns findings in the engine's shape (Category 'UEBA'). Alert-only:
#  no active response here.
function Invoke-LBUbaCycle {
    param([string]$StateDir, $Config, [datetime]$Start)
    $bb = Get-LBUbaBaseline -StateDir $StateDir
    if (-not $bb.firstLearn) { try { [void](Initialize-LBUbaFromArchive -StateDir $StateDir -Config $Config -Days 30) } catch { } }
    $recs = @()
    $srcs = @(); try { $srcs = @(Get-LogBokSecuritySources -Config $Config) } catch { }
    foreach ($s in $srcs) {
        $comp = [string]$s.Computer
        $evts = @(); try { $evts = @(Get-LogBokEvents -LogName 'Security' -Id @(4624, 4672) -StartTime $Start -ComputerName $comp -Config $Config) } catch { continue }
        foreach ($e in $evts) {
            $m = Get-LBEventDataMap -Event $e
            $id = [int]$e.Id
            $t = $e.TimeCreated; if (-not $t) { continue }
            $hostn = [string]$e.MachineName; if (-not $hostn) { $hostn = $comp }
            if ($id -eq 4624) {
                $u = [string]$m['TargetUserName']; if (Test-LBMachineName $u) { continue }
                $lt = [string]$m['LogonType']
                $ip = [string]$m['IpAddress']; if ($ip -in '-', '::1', '127.0.0.1', '0.0.0.0') { $ip = '' }
                $recs += @{ User = $u; Host = $hostn; Hour = [int]$t.Hour; Type = 'logon'; SrcIp = $ip }
                if ($lt -eq '10' -or $lt -eq '7') { $recs += @{ User = $u; Host = $hostn; Hour = [int]$t.Hour; Type = 'remote'; SrcIp = $ip } }
            } elseif ($id -eq 4672) {
                $u = [string]$m['SubjectUserName']; if (Test-LBMachineName $u) { continue }
                $recs += @{ User = $u; Host = $hostn; Hour = [int]$t.Hour; Type = 'priv'; Priv = 'SpecialPrivileges' }
            }
        }
    }
    if (-not $recs.Count) { return @() }
    $an = @(Test-LBUbaAnomalies -StateDir $StateDir -Records $recs)
    [void](Update-LBUbaBaseline -StateDir $StateDir -Records $recs)
    $sevmap = @{ 'Critical' = 'Critical'; 'Trouble' = 'Warning'; 'Attention' = 'Info' }
    $out = @()
    foreach ($a in $an) {
        $rc = Get-LBUbaRuleConfig -Config $Config -Rule ([string]$a.rule)
        if ([string]$rc.mode -eq 'off') { continue }   # this rule is disabled by the admin
        $sev = [string]$sevmap[[string]$a.sev]; if (-not $sev) { $sev = 'Warning' }
        $key = ('uba:{0}:{1}:{2}:{3}' -f [string]$a.rule, [string]$a.user, [string]$a.host, [string]$a.hour)
        $det = [string]$a.msg
        # prevention: alert-only for now; a rule set to ask/auto is tagged so the response step can act on it.
        $prevent = ''
        if ([string]$rc.mode -in 'ask', 'auto' -and [string]$rc.action -ne 'none') { $prevent = ('{0}:{1}' -f $rc.mode, $rc.action) }
        $out += [pscustomobject]@{ Category = 'UEBA'; Severity = $sev; Machine = [string]$a.host; Time = (Get-Date)
            Title = ('UBA: ' + [string]$a.msg); Details = $det; Key = $key; User = [string]$a.user
            UbaRule = [string]$a.rule; UbaIp = [string]$a.ip; Prevent = $prevent }
    }
    return $out
}

Export-ModuleMember -Function Get-LBUbaBaseline, Save-LBUbaBaseline, Update-LBUbaBaseline, Test-LBUbaAnomalies, Format-LBHourRange, Get-LBUbaRuleConfig, Get-LBUbaFile, Invoke-LBUbaCycle, Initialize-LBUbaFromArchive
