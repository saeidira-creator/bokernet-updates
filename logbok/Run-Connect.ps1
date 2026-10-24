# ==========================================================================
#  Run-Connect.ps1 - connectivity test for systems/services + management-path protection
#  (every 15 minutes via Task Scheduler): writes status to state\connectivity.json
#  and ensures the always-open management rules so LogBok does not lose its own connectivity.
# ==========================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')    -Force
Import-Module (Join-Path $root 'LogBok.Connect.psm1') -Force -DisableNameChecking

$cfg = Get-LogBokConfig

# 1) keep the management path always open (even if the firewall was reset manually)
try {
    if (-not $cfg.Management -or $cfg.Management.ProtectSelf -ne $false) {
        $n = Assert-LBMgmtAllow -Config $cfg -InstallDir $root
        if ($n -gt 0) { Write-LogBokLog -Message "مسیرِ مدیریت بازسازی شد: $n رول | management allow-rules (re)created: $n" -Config $cfg }
    }
} catch { Write-LogBokLog -Message "خطا در محافظت از مسیرِ مدیریت: $($_.Exception.Message)" -Level WARN -Config $cfg }

# 1.5) detect roles of AD-imported sources (up to 20 each run)
try {
    Import-Module (Join-Path $root 'LogBok.Targets.psm1') -Force -DisableNameChecking
    $all = @(Get-LBTargets -InstallDir $root); $changed = $false; $n = 0
    foreach ($t in $all) {
        if ($n -ge 20) { break }
        if ($t.Kind -ne 'Windows' -or $t.RolesDetected -eq $true -or $t.Enabled -eq $false) { continue }
        $addr = if ($t.Address) { [string]$t.Address } else { [string]$t.Name }
        try { $r = @(Find-LBTargetRoles -Address $addr -TimeoutMs 500); $t.Roles = @(@($t.Roles) + $r | Where-Object { $_ } | Select-Object -Unique) } catch { }
        $t.RolesDetected = $true; $changed = $true; $n++
    }
    if ($changed) { Save-LBTargets -Targets $all -InstallDir $root; $cfg = Get-LogBokConfig }
} catch { Write-LogBokLog -Message "تشخیصِ نقشِ منابع: $($_.Exception.Message)" -Level WARN -Config $cfg }

# 1.7) agent packages with the current server address + auto deployment policies
try {
    Import-Module (Join-Path $root 'LogBok.AgentPkg.psm1') -Force -DisableNameChecking
    if (Update-LBAgentPackages -InstallDir $root -Config $cfg) { Write-LogBokLog -Message 'بسته‌های ایجنت با نشانیِ فعلیِ سرور بازسازی شد | agent packages rebuilt for the current server address' -Config $cfg }
    $sdA = Get-LBStateDir -Config $cfg
    if (Test-Path (Join-Path $sdA 'agent-policies.json')) {
        Import-Module (Join-Path $root 'LogBok.AgentDeploy.psm1') -Force -DisableNameChecking
        foreach ($m in @(Invoke-LBAgentPoliciesAuto -InstallDir $root -StateDir $sdA)) { Write-LogBokLog -Message ("سیاستِ استقرارِ ایجنت | agent policy: {0}" -f $m) -Config $cfg }
    }
} catch { Write-LogBokLog -Message "استقرارِ ایجنت: $($_.Exception.Message)" -Level WARN -Config $cfg }

# 1.7.5) daily automatic agent-identity backup (if configured in the console)
try {
    Import-Module (Join-Path $root 'LogBok.AgentIn.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $root 'LogBok.Backup.psm1') -Force -DisableNameChecking
    $mB = Invoke-LBAutoBackup -StateDir (Get-LBStateDir -Config $cfg) -InstallDir $root
    if ($mB) { Write-LogBokLog -Message ("پشتیبانِ ایجنت‌ها | {0}" -f $mB) -Level $(if ($mB -match 'failed') { 'WARN' } else { 'INFO' }) -Config $cfg }
} catch { Write-LogBokLog -Message "پشتیبانِ ایجنت‌ها: $($_.Exception.Message)" -Level WARN -Config $cfg }

# 1.8) default alert profiles (once)
try {
    Import-Module (Join-Path $root 'LogBok.Alerts.psm1') -Force -DisableNameChecking
    $na = Initialize-LBDefaultAlerts -StateDir (Get-LBStateDir -Config $cfg)
    if ($na) { Write-LogBokLog -Message ("{0} پروفایلِ هشدارِ پیش‌فرض ساخته شد | default alert profiles created: {0}" -f $na) -Config $cfg }
} catch { }

# 1.9) scheduled reports (email with CSV)
try {
    if (Test-Path (Join-Path (Get-LBStateDir -Config $cfg) 'report-schedules.json')) {
        Import-Module (Join-Path $root 'LogBok.Reports.psm1') -Force -DisableNameChecking
        foreach ($x in @(Invoke-LBScheduledReports -Config $cfg)) { Write-LogBokLog -Message ("گزارشِ زمان‌بندی‌شده فرستاده شد | scheduled report sent: {0} ({1} files, {2})" -f $x.name, $x.files, $x.result) -Config $cfg }
    }
} catch { Write-LogBokLog -Message "گزارشِ زمان‌بندی‌شده: $($_.Exception.Message)" -Level WARN -Config $cfg }

# 2) connectivity test
if (-not $cfg.Connectivity -or $cfg.Connectivity.Enabled -ne $false) {
    try {
        $res = @(Test-LBConnectivity -Config $cfg -InstallDir $root -Save)
        $fail = @($res | Where-Object { -not $_.Ok })
        Write-LogBokLog -Message ("آزمونِ ارتباط: {0} کانال، {1} ناموفق | connectivity: {2} channels, {3} failed" -f $res.Count, $fail.Count, $res.Count, $fail.Count) -Config $cfg
        # event 9020: when a previously healthy target goes down, alert once (no anti-flood inside Write-LBEventOnce; kept simple)
        # only a state change raises an event: new outage -> 9020, recovery -> 9021; an ongoing outage is reminded once per day
        # only state CHANGES raise events: newly failed -> 9020, recovered -> 9021; an ongoing outage is re-mentioned once a day
        $cfF = Join-Path (Get-LBStateDir -Config $cfg) 'connectivity-down.json'
        $prev = @{}; if (Test-Path $cfF) { try { (Get-Content $cfF -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $prev[$_.Name] = [string]$_.Value } } catch { } }
        $nowFail = @{}; foreach ($x in $fail) { $nowFail[("{0}|{1}" -f $x.Target, $x.Channel)] = $true }
        $newly = @(); $still = @(); $restored = @()
        foreach ($k in $nowFail.Keys) { if ($prev.ContainsKey($k)) { $still += $k } else { $newly += $k; $prev[$k] = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture) } }
        foreach ($k in @($prev.Keys)) { if (-not $nowFail.ContainsKey($k)) { $restored += $k; $prev.Remove($k) } }
        $remind = @(); foreach ($k in $still) { $since = $null; try { $since = [datetime]::Parse($prev[$k], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch { }; if ($since -and ((Get-Date) - $since).TotalHours -ge 24 -and (Get-Date).Hour -eq 8 -and (Get-Date).Minute -lt 20) { $remind += $k } }
        $fmt = { param($keys) ($keys | Group-Object { ($_ -split '\|')[0] } | ForEach-Object { "{0}: {1}" -f $_.Name, (@($_.Group | ForEach-Object { ($_ -split '\|')[1] }) -join ',') }) -join ' | ' }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' }
            if ($newly.Count) { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9020 -EntryType Warning -Message ("CONNECTIVITY problem on {0}: {1}" -f $env:COMPUTERNAME, (& $fmt $newly)) }
            if ($remind.Count) { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9020 -EntryType Warning -Message ("CONNECTIVITY still down on {0} (more than a day): {1}" -f $env:COMPUTERNAME, (& $fmt $remind)) }
            if ($restored.Count) { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9021 -EntryType Information -Message ("CONNECTIVITY restored on {0}: {1}" -f $env:COMPUTERNAME, (& $fmt $restored)) }
        } catch { }
        try { [IO.File]::WriteAllText($cfF, (ConvertTo-Json -InputObject $prev), (New-Object Text.UTF8Encoding($false))) } catch { }
    } catch { Write-LogBokLog -Message "خطا در آزمونِ ارتباط: $($_.Exception.Message)" -Level WARN -Config $cfg }
}
