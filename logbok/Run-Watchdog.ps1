# ==========================================================================
#  Run-Watchdog.ps1 - self-healing watchdog (every 2 minutes, runs as SYSTEM)
#  - reconciles jobs with config: a deleted active job -> recreate + tamper
#    alert (9001); a job disabled in config -> remove.
#  - telemetry, ransomware canaries, compliance, service health, vulnerability scan,
#    tracking, self-update, threat feed, firewall governance and FIM.
#  Repeated events (e.g. the same vulnerability or firewall rule) are re-logged
#  only when they change or 24 hours have passed (anti-flood).
# ==========================================================================
$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Agent.psm1') -Force -DisableNameChecking
$cfg = $null
try { Import-Module (Join-Path $root 'LogBok.Core.psm1') -Force -DisableNameChecking; $cfg = Get-LogBokConfig } catch {}
$collector = if ($cfg) { $cfg.CollectorFqdn } else { '' }
$fullEngine = Test-Path (Join-Path $root 'engine.flag')
# the agent must never slow the user down: Idle priority (runs only on spare CPU)
# the agent must never slow the user down: idle priority (runs only on spare CPU)
$wdSw = [Diagnostics.Stopwatch]::StartNew()
if (-not $fullEngine) { try { [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::Idle } catch {} }
$stateDir = Join-Path $root 'state'
if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
Register-LogBokEventSource

# an old-path agent (C:\Scripts\LogBok) moves itself to ProgramData\Agent (retries every 30 minutes until it succeeds)
# an agent in the old folder (C:\Scripts\LogBok) moves itself to ProgramData\Agent (retried every 30 min until done)
if (-not $fullEngine -and $env:ProgramData -and $root.TrimEnd('\') -ne (Join-Path $env:ProgramData 'Agent') -and (Test-Path (Join-Path $stateDir 'agent.json')) -and (Get-Command Start-LogBokAgentMove -ErrorAction SilentlyContinue)) {
    $mvf = Join-Path $stateDir 'move-started.txt'
    if (-not (Test-Path $mvf) -or (Get-Item $mvf).LastWriteTime -lt (Get-Date).AddMinutes(-30)) {
        try { if (Start-LogBokAgentMove -InstallDir $root) { Set-Content -Path $mvf -Value (Get-Date).ToString('o') -Encoding ASCII } } catch { }
    }
}

# --- write an event only if new/changed or older than N hours
$script:dedupFile = Join-Path $stateDir 'event-dedupe.json'
$script:dedup = @{}
if (Test-Path $script:dedupFile) { try { (Get-Content $script:dedupFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $script:dedup[$_.Name] = [string]$_.Value } } catch {} }
function Write-LBEventOnce {
    param([int]$Id, [string]$Type = 'Warning', [string]$Key, [string]$Message, [int]$RepeatHours = 24)
    $sha = [Security.Cryptography.SHA1]::Create()
    $h = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))).Replace('-','').Substring(0,16)
    $k = "$Id|$Key"
    $prev = $script:dedup[$k]
    if ($prev) {
        $p = $prev -split '\|'
        $when = [datetime]::MinValue
        [void][datetime]::TryParse($p[1], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$when)
        if ($p[0] -eq $h -and $when -gt (Get-Date).AddHours(-$RepeatHours)) { return }
    }
    $msg = if ($Message.Length -gt 30000) { $Message.Substring(0,30000) + ' …(truncated)' } else { $Message }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId $Id -EntryType $Type -Message $msg } catch {}
    $script:dedup[$k] = "$h|" + (Get-Date).ToString('o',[Globalization.CultureInfo]::InvariantCulture)
}
function Save-LBDedupe {
    $o = @{}; foreach ($k in $script:dedup.Keys) {
        $p = $script:dedup[$k] -split '\|'; $when = [datetime]::MinValue
        if ([datetime]::TryParse($p[1], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$when) -and $when -gt (Get-Date).AddDays(-7)) { $o[$k] = $script:dedup[$k] }
    }
    try { $o | ConvertTo-Json | Set-Content -Path $script:dedupFile -Encoding UTF8 } catch {}
}
function Test-Due {   # have N hours passed since the last run?
    param([string]$Name, [double]$Hours)
    $f = Join-Path $stateDir "last-$Name.txt"
    if (Test-Path $f) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse((Get-Content $f -Raw).Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) {
            if ((Get-Date) -lt $d.AddHours($Hours)) { return $false }
        }
    }
    return $true
}
function Set-Done { param([string]$Name) Set-Content -Path (Join-Path $stateDir "last-$Name.txt") -Value (Get-Date).ToString('o',[Globalization.CultureInfo]::InvariantCulture) -Encoding ASCII }

$repaired = @()

# 1) reconcile jobs with config
try {
    Import-Module (Join-Path $root 'LogBok.Jobs.psm1') -Force -DisableNameChecking
    $role = if ($fullEngine) { 'Engine' } else { 'Agent' }
    $knownFile = Join-Path $stateDir 'jobs-known.json'
    $known = @(); if (Test-Path $knownFile) { try { $known = @(Get-Content $knownFile -Raw | ConvertFrom-Json | ForEach-Object { $_ }) } catch {} }
    $changes = @(Sync-LBJobs -Config $(if ($cfg) { $cfg } else { @{} }) -InstallDir $root -Role $role -StartNew)
    foreach ($c in $changes) {
        if (-not $c.Ok) { Write-LBEventOnce -Id 9001 -Key "jobfail:$($c.Job)" -Message ("LogBok job '{0}' could not be created on {1}: {2}" -f $c.Job,$env:COMPUTERNAME,$c.Message); continue }
        switch -Wildcard ($c.Action) {
            'Created'    { if ($known -contains $c.Job) { $repaired += "job $($c.Job) recreated (was deleted)" } }
            'Re-enabled' { $repaired += "job $($c.Job) re-enabled (was disabled)" }
            'Started'    { }   # Syslog restarted after an outage
            'Removed*'   { try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9008 -EntryType Information -Message ("LogBok job '{0}' removed on {1} (disabled in config.psd1)" -f $c.Job,$env:COMPUTERNAME) } catch {} }
        }
    }
    $now = @(Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction SilentlyContinue | ForEach-Object { $_.TaskName -replace '^LogBok-','' })
    $now | ConvertTo-Json | Set-Content -Path $knownFile -Encoding UTF8
} catch {}

# 2) is telemetry (audit + forwarding) still in place?
if (-not (Test-LogBokClientTelemetry -Collector $collector)) {
    Set-LogBokClientTelemetry -Collector $collector
    $repaired += 'telemetry (audit policy was turned off)'
}

# 3) protect the install path (hourly; icacls on every run is heavy)
if (Test-Due 'protect' 1) { Protect-LogBokPath $root; Set-Done 'protect' }

# 4) if anything was repaired -> tamper event (goes to the Collector and is emailed)
if ($repaired.Count -gt 0) {
    Write-LogBokTamper -Message ("Tamper/repair on {0}: {1}" -f $env:COMPUTERNAME, ($repaired -join ' | '))
}

# 5) anti-ransomware canary check
try {
    if (-not $cfg -or $cfg.Enabled.Ransomware -ne $false) {
        Import-Module (Join-Path $root 'LogBok.AntiRansomware.psm1') -Force
        $tripped = @(Test-LogBokCanary -StateDir $stateDir)
        if ($tripped.Count -gt 0) {
            $det = ($tripped | ForEach-Object { "$($_.Path) [$($_.Reason)]" }) -join ' ; '
            Write-LBEventOnce -Id 9003 -Type Error -Key 'canary' -RepeatHours 1 -Message ("RANSOMWARE SUSPECTED on {0}: canary files {1}" -f $env:COMPUTERNAME,$det)
            # optional response: automatic isolation
            if ($cfg -and $cfg.AutoIsolateOnRansomware) {
                try {
                    Import-Module (Join-Path $root 'LogBok.Firewall.psm1') -Force
                    $ip = $null
                    if ($collector) { try { $ip = ([Net.Dns]::GetHostAddresses($collector) | Select-Object -First 1).IPAddressToString } catch {} }
                    Invoke-LogBokIsolate -AllowIp $ip -InstallDir $root
                } catch {}
            }
        }
    }
} catch {}

# 5.3) agent: follow the LogBok server's address (IP/name change)
if (-not $fullEngine) { try { [void](Update-LogBokCollectorAccess -InstallDir $root) } catch {} }
# tamper self-heal: remove any firewall rule that blocks the agent's push to the server, and alert (9001)
if (-not $fullEngine) { try { $unb = @(Assert-LogBokAgentUnblocked -InstallDir $root); if ($unb.Count) { Write-LogBokTamper -Message ("Tamper on {0}: firewall block on LogBok traffic removed - {1}" -f $env:COMPUTERNAME, ($unb -join ' ; ')) } } catch {} }
# 5.35) agent: push new events to the server (push, no remote access needed)
if (-not $fullEngine) { try { [void](Invoke-LogBokForward -InstallDir $root) } catch {} }
# 5.36) server: endpoint policies that explicitly target the server itself
if ($fullEngine) {
    try {
        Import-Module (Join-Path $root 'LogBok.Endpoint.psm1') -Force -DisableNameChecking
        $sdir = Join-Path $root 'state'
        $ep = Get-LBEffectivePolicy -StateDir $sdir -HostName $env:COMPUTERNAME -IsServer
        $cur = $null; $pjf = Join-Path $sdir 'policy.json'
        if (Test-Path $pjf) { try { $cur = Get-Content $pjf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
        $had = ($cur -and ((@($cur.policy.appBlocks).Count) -or $cur.policy.guard))
        $has = (@($ep.appBlocks).Count -or $ep.guard)
        if (($has -or $had) -and (-not $cur -or [string]$cur.status.rev -ne [string]$ep.rev)) { [void](Invoke-LogBokPolicy -InstallDir $root -Policy $ep) }
        elseif ($has -and @($ep.appBlocks).Count) { [void](Set-LogBokAppBlocks -InstallDir $root -Blocks @($ep.appBlocks)) }
    } catch {}
}

# 5.4) restart always-on jobs after a code update
#      long-running jobs (Web/Syslog/Guard) keep old code in memory: restart them when their code is newer
try {
    $codeMap = @{
        'Web'    = @('Run-Web.ps1','LogBok.Web.psm1','LogBok.Core.psm1','LogBok.Targets.psm1','LogBok.AgentPkg.psm1','LogBok.AgentDeploy.psm1','LogBok.Alerts.psm1','LogBok.Findings.psm1','LogBok.Connect.psm1','LogBok.Archive.psm1','LogBok.Guard.psm1','LogBok.Jobs.psm1','LogBok.Endpoint.psm1','LogBok.Reports.psm1','LogBok.Archive.psm1','LogBok.WebAuth.psm1','LogBok.Publish.psm1','LogBok.Update.psm1','LogBok.MailSecurity.psm1','LogBok.Remote.psm1')
        'Syslog' = @('Run-Syslog.ps1','LogBok.Syslog.psm1','LogBok.Core.psm1')
        'AgentIn' = @('Run-AgentIn.ps1','LogBok.AgentIn.psm1','LogBok.Core.psm1','LogBok.Targets.psm1','LogBok.AgentPkg.psm1','LogBok.Endpoint.psm1')
        'Guard'  = @('Run-Guard.ps1','LogBok.Guard.psm1','LogBok.Core.psm1')
    }
    foreach ($jn in $codeMap.Keys) {
        $tk = Get-ScheduledTask -TaskName "LogBok-$jn" -TaskPath '\LogBok\' -ErrorAction SilentlyContinue
        if (-not $tk -or $tk.State -ne 'Running') { continue }
        $ti = Get-ScheduledTaskInfo -TaskName "LogBok-$jn" -TaskPath '\LogBok\' -ErrorAction SilentlyContinue
        if (-not $ti -or -not $ti.LastRunTime -or $ti.LastRunTime.Year -lt 2000) { continue }
        $newest = @($codeMap[$jn] | ForEach-Object { $p = Join-Path $root $_; if (Test-Path $p) { (Get-Item $p).LastWriteTime } }) | Sort-Object -Descending | Select-Object -First 1
        if ($newest -and $newest -gt $ti.LastRunTime) {
            Stop-ScheduledTask -TaskName "LogBok-$jn" -TaskPath '\LogBok\' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-ScheduledTask -TaskName "LogBok-$jn" -TaskPath '\LogBok\' -ErrorAction SilentlyContinue
            try { Write-LogBokLog -Message ("جابِ {0} با کدِ تازه دوباره راه‌اندازی شد | job {0} restarted with updated code" -f $jn) -Config $cfg } catch { }
        }
    }
} catch {}

# 5.5) keep LogBok's own management path open
try {
    # server only; clients open no inbound port
    if ($fullEngine -and (-not $cfg -or $cfg.Management -eq $null -or $cfg.Management.ProtectSelf -ne $false)) {
        Import-Module (Join-Path $root 'LogBok.Connect.psm1') -Force -DisableNameChecking
        [void](Assert-LBMgmtAllow -Config $cfg -InstallDir $root)
    }
} catch {}

# 6) policy compliance + remediation
try {
    if (-not $cfg -or $cfg.Enabled.Policy -ne $false) {
        Import-Module (Join-Path $root 'LogBok.Policy.psm1') -Force
        $pol = Get-LogBokPolicy -Path (Join-Path $root 'policies.psd1')
        if ($pol) {
            $comp = Test-LogBokCompliance -Policy $pol -InstallDir $root
            $bad = @($comp | Where-Object { -not $_.Compliant })
            if ($bad.Count -gt 0) {
                $fixed = @(Repair-LogBokCompliance -Policy $pol -Compliance $comp -InstallDir $root)
                # re-check after remediation so "fixed" is not a lie
                if ($fixed.Count) {
                    $after = @(Test-LogBokCompliance -Policy $pol -InstallDir $root | Where-Object { -not $_.Compliant } | ForEach-Object { $_.Item })
                    $fixed = @($fixed | Where-Object { $after -notcontains $_ })
                }
                $desc = ($bad | ForEach-Object { "$($_.Item)=$($_.Actual)" }) -join ' ; '
                $fx = if ($fixed.Count) { " | fixed: $($fixed -join ',')" } else { '' }
                Write-LBEventOnce -Id 9005 -Key 'policy' -Message ("POLICY DRIFT on {0}: {1}{2}" -f $env:COMPUTERNAME,$desc,$fx)
            }
        }
    }
} catch {}

# 7) critical-service health (every cycle, with auto-repair)
try {
    if (-not $cfg -or $cfg.Enabled.Scan -ne $false) {
        Import-Module (Join-Path $root 'LogBok.Scanner.psm1') -Force
        $extra = @()
        try { $p2 = Get-LogBokPolicy -Path (Join-Path $root 'policies.psd1'); if ($p2) { $extra = @($p2.RequiredServices) } } catch {}
        if ($fullEngine -and $cfg -and $cfg.CollectionMode -eq 'Collector') { $extra += 'Wecsvc' }
        $svcIssues = @(Test-LogBokServices -Extra $extra -Fix)
        foreach ($si in $svcIssues) {
            Write-LBEventOnce -Id 9007 -Key "svc:$($si.Service)" -RepeatHours 1 -Message ("SERVICE HEALTH on {0}: {1} was {2}/{3} — restarted" -f $env:COMPUTERNAME,$si.Service,$si.Status,$si.StartMode)
        }
    }
} catch {}

# 8) hourly vulnerability scan + advice/remediation
try {
    if ((-not $cfg -or $cfg.Enabled.Scan -ne $false) -and (Test-Due 'scan' 1)) {
        Import-Module (Join-Path $root 'LogBok.Scanner.psm1') -Force
        $vulns = @(Invoke-LogBokScan)
        $fixed = @()
        if ($cfg -and $cfg.AutoFixVulnerabilities) { $fixed = @(Repair-LogBokScan -Findings $vulns) }
        foreach ($v in $vulns) {
            $didFix = if ($v.Id -in $fixed) { ' [AUTO-FIXED]' } else { '' }
            # once a day per weakness (not hourly)
            Write-LBEventOnce -Id 9006 -Key "vuln:$($v.Id)" -Message ("VULN on {0}: [{1}] {2}{3}`nProblem: {4}`nFix: {5}`nRemediable={6} Risky={7}" -f `
                $env:COMPUTERNAME,$v.Id,$v.Title,$didFix,$v.Problem,$v.Recommendation,$v.Remediable,$v.Risky)
        }
        Set-Done 'scan'
    }
} catch {}

# 9) track a specific app/service
try {
    if ($cfg -and $cfg.Watchlist -and $cfg.Enabled.Tracking -ne $false) {
        $tf = Join-Path $stateDir 'track.json'
        $prev = @{}; if (Test-Path $tf) { try { (Get-Content $tf -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $prev[$_.Name] = $_.Value } } catch {} }
        $cur = @{}
        foreach ($s in @($cfg.Watchlist.Services))  { if ($s) { $svc = Get-Service -Name $s -ErrorAction SilentlyContinue; $cur["svc:$s"]  = if ($svc) { [string]$svc.Status } else { 'absent' } } }
        foreach ($p in @($cfg.Watchlist.Processes)) { if ($p) { $pr = Get-Process -Name $p -ErrorAction SilentlyContinue; $cur["proc:$p"] = if ($pr) { 'running' } else { 'stopped' } } }
        foreach ($k in $cur.Keys) {
            $old = if ($prev.ContainsKey($k)) { $prev[$k] } else { '?' }
            if ($old -ne $cur[$k] -and $old -ne '?') {
                try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9009 -EntryType Information `
                      -Message ("TRACK on {0}: {1}  {2} -> {3}" -f $env:COMPUTERNAME,$k,$old,$cur[$k]) } catch {}
            }
        }
        ($cur | ConvertTo-Json) | Set-Content -Path $tf -Encoding UTF8
    }
} catch {}

# 10) updates
try {
    if ($cfg -and $cfg.Update -and $cfg.Update.Enabled -ne $false) {
        Import-Module (Join-Path $root 'LogBok.Update.psm1') -Force
        $isVendor = Test-Path (Join-Path $root 'Tools\privatekey.xml')
        $fast = $false; try { $fast = ($cfg.Update.DevFastPull -eq $true) } catch {}
        # client servers pull the vendor's SIGNED package from the internet feed
        # (update.bokernet.ir). DevFastPull = check EVERY watchdog tick (~2 min) so new
        # builds arrive within ~2 min while developing; if the version has not changed it
        # just compares and returns (no downloads). The vendor itself never pulls.
        if ($cfg.Update.ServerFeed -and -not $isVendor -and $fast) {
            try { Invoke-LBServerUpdate -InstallDir $root -Config $cfg | Out-Null } catch {}
        }
        # slower cadence: agent self-update (LAN) and, when not in fast mode, the feed pull
        $iv = if ($cfg.Update.IntervalHours) { [int]$cfg.Update.IntervalHours } else { 6 }
        if (Test-Due 'update' $iv) {
            Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 20)
            if ($cfg.Update.ServerFeed -and -not $isVendor -and -not $fast) {
                try { Invoke-LBServerUpdate -InstallDir $root -Config $cfg | Out-Null } catch {}
            }
            Invoke-LogBokSelfUpdate -InstallDir $root -Config $cfg | Out-Null
            Set-Done 'update'
        }
    }
} catch {}

# 10b) VENDOR only: auto-publish to the internet feed when a publish flag is dropped
#      (owner workflow writes dist\run-publish.flag after changing code/UI; this
#       runs owner\publish-github.ps1 within one watchdog tick - no manual step).
try {
    $pf = Join-Path $root 'owner\publish-github.ps1'
    $flag = Join-Path $root 'dist\run-publish.flag'
    $lock = Join-Path $root 'dist\publishing.lock'
    # The GitHub token is DPAPI-encrypted for the owner's Windows account, so publishing must run
    # as that user, never as SYSTEM. The per-user helper task (owner\auto-publish.ps1) picks up the
    # flag itself; the watchdog only makes sure that task exists and is running.
    $apTask = $null
    $aps = Join-Path $root 'owner\auto-publish.ps1'
    if ((Test-Path $flag) -and (Test-Path $aps) -and (Test-Path (Join-Path $root 'Tools\privatekey.xml'))) {
        try { $apTask = Get-ScheduledTask -TaskName 'LogBok AutoPublish' -ErrorAction Stop } catch { $apTask = $null }
        if (-not $apTask) {
            try {
                $u = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
                if ($u) {
                    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $aps)
                    $trg = New-ScheduledTaskTrigger -AtLogOn -User $u
                    $pri = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest
                    $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
                    $apTask = Register-ScheduledTask -TaskName 'LogBok AutoPublish' -Action $act -Trigger $trg -Principal $pri -Settings $set -Force -ErrorAction Stop
                }
            } catch { $apTask = $null }
        }
        if ($apTask) {
            try { if ([string](Get-ScheduledTask -TaskName 'LogBok AutoPublish').State -ne 'Running') { Start-ScheduledTask -TaskName 'LogBok AutoPublish' -ErrorAction Stop } } catch {}
        }
    }
    if ($apTask -or [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { }   # SYSTEM cannot decrypt the token - leave the flag for the helper
    elseif ((Test-Path (Join-Path $root 'Tools\privatekey.xml')) -and (Test-Path $pf) -and (Test-Path $flag)) {
        $busy = (Test-Path $lock) -and (((Get-Date) - (Get-Item $lock).LastWriteTime).TotalMinutes -lt 20)
        if (-not $busy) {
            $pnotes = ''; try { $pnotes = ((Get-Content $flag -Raw -ErrorAction SilentlyContinue) | Out-String).Trim() } catch {}
            Remove-Item $flag -Force -ErrorAction SilentlyContinue
            Set-Content -Path $lock -Value (Get-Date -Format s) -ErrorAction SilentlyContinue
            # pass the notes via a file (never via args - spaces would corrupt the version)
            try { Set-Content -Path (Join-Path $root 'dist\publish-notes.txt') -Value $pnotes -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
            $pa = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$pf)
            Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $pa -WindowStyle Hidden
        }
    }
} catch {}

# 11) recent-file suspicious scan
$scanFolders = @()
if ($cfg) { $scanFolders = @(if ($cfg.FileScanFolders -and @($cfg.FileScanFolders).Count) { $cfg.FileScanFolders } else { $cfg.WatchedFolders }) | Where-Object { $_ } }
try {
    if ((-not $cfg -or $cfg.Enabled.FileScan -ne $false) -and $scanFolders.Count -gt 0) {
        Import-Module (Join-Path $root 'LogBok.Behavior.psm1') -Force
        $hits = @(Invoke-LogBokFileScan -Folders $scanFolders -Config $cfg -RecentMinutes 10)
        foreach ($h in $hits) {
            Write-LBEventOnce -Id 9004 -Key "file:$($h.Path)" -RepeatHours 168 -Message ("SUSPICIOUS FILE on {0}: {1} (score={2}; {3})" -f $env:COMPUTERNAME,$h.Path,$h.Score,$h.Reasons)
        }
    }
} catch {}

# 12) threat feed - the automatic, harmless part (detection/report + defense update only)
#     block/quarantine enforcement only happens on console approval, not here.
try {
    Import-Module (Join-Path $root 'LogBok.Threat.psm1') -Force
    $feed = Get-LogBokThreatFeed -InstallDir $root
    if ($feed) {
        if (Test-Due 'defsig' 4) { Update-LogBokDefenses -Feed $feed; Set-Done 'defsig' }   # update Defender signatures
        foreach ($folder in $scanFolders) { if (Test-Path $folder) {
            Get-ChildItem $folder -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge (Get-Date).AddMinutes(-10) } | ForEach-Object {
                    $r = Test-LogBokFileAgainstFeed -Path $_.FullName -Feed $feed
                    if ($r) { Write-LBEventOnce -Id 9004 -Key "feed:$($_.FullName)" -RepeatHours 168 -Message ("THREAT-FEED MATCH on {0}: {1} ({2})" -f $env:COMPUTERNAME,$_.FullName,$r) }
                }
        } }
    }
} catch {}

# 13) firewall rule governance - an unknown manual rule only alerts/emails (no removal)
#     every 10 minutes; only when the list changes, or a once-a-day reminder
try {
    if ((-not $cfg -or $cfg.Enabled.FwGovernance -ne $false) -and (Test-Due 'fwgov' 0.16)) {
        Import-Module (Join-Path $root 'LogBok.FwGovernance.psm1') -Force
        $extraAllow = @(); if ($cfg -and $cfg.FwAllowRuleNames) { $extraAllow = @($cfg.FwAllowRuleNames) }
        $unk = @(Get-LBUnknownFwRules -ExtraAllow $extraAllow)
        if ($unk.Count -gt 0) {
            $domain = Test-LBDomainJoined
            $scope = if ($domain) { 'domain-joined (GPO AllowLocalPolicyMerge=0 recommended)' } else { 'standalone' }
            $list = ($unk | Sort-Object Name | ForEach-Object { "$($_.Name) [$($_.Direction)/$($_.Action)]" }) -join ' ; '
            Write-LBEventOnce -Id 9013 -Key 'fwgov' -Message ("UNAUTHORIZED FIREWALL RULE on {0} ({1}): {2}" -f $env:COMPUTERNAME,$scope,$list)
        }
        Set-Done 'fwgov'
    }
} catch {}

# 14) File Integrity Monitoring (FIM) - a change to critical files -> event 9014 (once per change)
try {
    if ($cfg -and $cfg.Enabled.FIM -ne $false -and $cfg.FimPaths -and @($cfg.FimPaths).Count -gt 0 -and (Test-Due 'fim' 0.16)) {
        Import-Module (Join-Path $root 'LogBok.FIM.psm1') -Force
        $inc = if ($cfg.FimInclude -and @($cfg.FimInclude).Count) { @($cfg.FimInclude) } else { $null }
        Invoke-LBFimCheck -StateDir $stateDir -Paths @($cfg.FimPaths) -Include $inc -UpdateBaseline | Out-Null
        Set-Done 'fim'
    }
} catch {}

Save-LBDedupe

# this cycle's resource cost, reported to the console
try {
    $me = [Diagnostics.Process]::GetCurrentProcess()
    $perf = [ordered]@{ At = (Get-Date).ToString('o'); Seconds = [math]::Round($wdSw.Elapsed.TotalSeconds, 1); CpuSeconds = [math]::Round($me.TotalProcessorTime.TotalSeconds, 2); MemMB = [int]($me.PeakWorkingSet64 / 1MB) }
    ($perf | ConvertTo-Json) | Set-Content -Path (Join-Path $stateDir 'perf.json') -Encoding UTF8
} catch {}
