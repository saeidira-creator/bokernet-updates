# ==========================================================================
#  LogBok.Jobs.psm1 - shared job catalog (scheduled tasks)
#
#  All jobs are created and enabled by default. A company that does not need a job
#  just sets it to $false in config.psd1 -> Jobs; the watchdog removes that task
#  within 2 minutes (and recreates it with $true).
#  Setup, Agent and Watchdog all use this single catalog.
#
#  All jobs are ON by default. Set Jobs.<Name> = $false in config.psd1 to turn
#  one off; the watchdog reconciles Task Scheduler within ~2 minutes.
# ==========================================================================

$script:TaskPath = '\LogBok\'

# weekday name from config (default Saturday - start of the work week)
function Get-LBWeekDay {
    param($Config)
    $d = if ($Config.Schedule -and $Config.Schedule.WeeklyDay) { [string]$Config.Schedule.WeeklyDay } else { 'Saturday' }
    if ($d -notin 'Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday') { $d = 'Saturday' }
    return $d
}
function Get-LBTime {
    param($Config, [string]$Key, [string]$Default)
    $t = if ($Config.Schedule -and $Config.Schedule.$Key) { [string]$Config.Schedule.$Key } else { $Default }
    if ($t -notmatch '^\d{1,2}:\d{2}$') { $t = $Default }
    return $t
}

# catalog
#  Role: Agent = all systems (client and server); Engine = engine server only
function Get-LBJobCatalog {
    param($Config)
    $wd = Get-LBWeekDay $Config
    return @(
        [pscustomobject]@{ Name='Watchdog';     Task='LogBok-Watchdog';     Script='Run-Watchdog.ps1';     Args='';           Role='Agent';  Kind='Repeat'; Minutes=2;  At=$null; Day=$null; NoLimit=$false
                           Fa='واچ‌داگ خوددرمان و ضدِدستکاری';            En='Self-healing watchdog & anti-tamper' }
        [pscustomobject]@{ Name='Realtime';     Task='LogBok-Realtime';     Script='Run-Realtime.ps1';     Args='';           Role='Engine'; Kind='Repeat'; Minutes=2;  At=$null; Day=$null; NoLimit=$false
                           Fa='پایش بلادرنگ و هشدارِ حملات';               En='Realtime detection & alerting' }
        [pscustomobject]@{ Name='Dashboard';    Task='LogBok-Dashboard';    Script='Run-Dashboard.ps1';    Args='';           Role='Engine'; Kind='Repeat'; Minutes=5;  At=$null; Day=$null; NoLimit=$false
                           Fa='بازسازیِ داشبوردِ زنده';                     En='Live dashboard rebuild' }
        [pscustomobject]@{ Name='DailyReport';  Task='LogBok-DailyReport';  Script='Run-Report.ps1';       Args='';           Role='Engine'; Kind='Daily';  Minutes=0;  At=(Get-LBTime $Config 'DailyReportTime' '07:00'); Day=$null; NoLimit=$false
                           Fa='گزارشِ روزانهٔ دسته‌بندی‌شده';               En='Daily categorized report' }
        [pscustomobject]@{ Name='LicenseWatch'; Task='LogBok-LicenseWatch'; Script='Run-LicenseWatch.ps1'; Args='';           Role='Engine'; Kind='Daily';  Minutes=0;  At=(Get-LBTime $Config 'LicenseWatchTime' '09:00'); Day=$null; NoLimit=$false
                           Fa='پایشِ انقضای لایسنس‌ها (هشدارِ هفتگی از ۳۰ روز قبل)'; En='License expiry watch (weekly mail from 30 days before)' }
        [pscustomobject]@{ Name='Compliance';   Task='LogBok-Compliance';   Script='Run-Compliance.ps1';   Args='-Scheduled'; Role='Engine'; Kind='Weekly'; Minutes=0;  At=(Get-LBTime $Config 'WeeklyTime' '08:00'); Day=$wd; NoLimit=$false
                           Fa='گزارشِ هفتگیِ انطباق';                       En='Weekly compliance report' }
        [pscustomobject]@{ Name='ADReport';     Task='LogBok-ADReport';     Script='Run-ADReport.ps1';     Args='';           Role='Engine'; Kind='Weekly'; Minutes=0;  At=(Get-LBTime $Config 'WeeklyTime' '08:00'); Day=$wd; NoLimit=$false
                           Fa='گزارشِ هفتگیِ وضعیتِ اکتیودایرکتوری';        En='Weekly Active Directory state report' }
        [pscustomobject]@{ Name='Syslog';       Task='LogBok-Syslog';       Script='Run-Syslog.ps1';       Args='';           Role='Engine'; Kind='Startup';Minutes=0;  At=$null; Day=$null; NoLimit=$true
                           Fa='سرورِ Syslog تجهیزاتِ شبکه (دائمی)';         En='Network-device syslog server (always on)' }
        [pscustomobject]@{ Name='Guard';        Task='LogBok-Guard';        Script='Run-Guard.ps1';        Args='';           Role='Agent';  Kind='Event';  Minutes=5;  At=$null; Day=$null; NoLimit=$false
                           Fa='سپرِ ورود: بلاکِ خودکارِ IPِ مهاجم (رویدادمحور)'; En='Login guard: auto-block attacking IPs (event-driven)' }
        [pscustomobject]@{ Name='Connect';      Task='LogBok-Connect';      Script='Run-Connect.ps1';      Args='';           Role='Engine'; Kind='Repeat'; Minutes=15; At=$null; Day=$null; NoLimit=$false
                           Fa='آزمونِ ارتباط با سیستم‌ها و سرویس‌ها + محافظت از مسیرِ مدیریت'; En='Connectivity test to machines/services + keep management path open' }
        [pscustomobject]@{ Name='AgentIn';      Task='LogBok-AgentIn';      Script='Run-AgentIn.ps1';      Args='';           Role='Engine'; Kind='Startup';Minutes=0;  At=$null; Day=$null; NoLimit=$true
                           Fa='دریافتِ رویداد از ایجنت‌ها (TCP 8687، همیشه روشن)'; En='Agent event intake (TCP 8687, always on)' }
        [pscustomobject]@{ Name='Web';          Task='LogBok-Web';          Script='Run-Web.ps1';          Args='';           Role='Engine'; Kind='Startup';Minutes=0;  At=$null; Day=$null; NoLimit=$true
                           Fa='کنسولِ وب (http://localhost:8686، همیشه روشن)'; En='Web console (http://localhost:8686, always on)' }
    )
}

# is the job enabled in config? (missing key = enabled)
function Test-LBJobEnabled {
    param($Config, [string]$Name)
    if ($Config.Jobs -and $Config.Jobs.ContainsKey($Name) -and $Config.Jobs[$Name] -eq $false) { return $false }
    # compatibility: a legacy Syslog.Enabled = $false also disables the job
    #  (only when config has no Jobs.Syslog section yet - an old config)
    $hasJobKey = $Config.Jobs -and $Config.Jobs.ContainsKey('Syslog')
    if ($Name -eq 'Syslog' -and -not $hasJobKey -and $Config.Syslog -and $Config.Syslog.ContainsKey('Enabled') -and $Config.Syslog.Enabled -eq $false) { return $false }
    return $true
}

# event subscriptions for event-driven jobs (Guard only)
function Get-LBJobSubscriptions {
    param($Job, $Config, [string]$InstallDir)
    if ($Job.Kind -ne 'Event' -or $Job.Name -ne 'Guard') { return @() }
    try {
        Import-Module (Join-Path $InstallDir 'LogBok.Guard.psm1') -DisableNameChecking -ErrorAction Stop
        return @(Get-LBGuardSubscriptions -Config $Config)
    } catch { return @() }
}
function Get-LBSubsSignature {
    param([string[]]$Subs)
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((@($Subs) -join '|'))) } finally { $sha.Dispose() }
    return ('sig:' + ([BitConverter]::ToString($h) -replace '-', '').Substring(0, 10))
}
# Task Scheduler event trigger (CIM)
function New-LBEventTrigger {
    param([string]$Subscription)
    $cls = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler' -ErrorAction Stop
    $t = New-CimInstance -CimClass $cls -ClientOnly
    $t.Subscription = $Subscription
    $t.Enabled = $true
    return $t
}

function New-LBJobTrigger {
    param($Job, [string[]]$Subs)
    switch ($Job.Kind) {
        'Repeat'  {
            $rep = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Job.Minutes) -RepetitionDuration (New-TimeSpan -Days 3650)
            # watchdog also runs at startup so the first contact (and update) happens right away
            if ($Job.Name -eq 'Watchdog') { return @($rep, (New-ScheduledTaskTrigger -AtStartup)) }
            return $rep
        }
        'Event'   {
            $list = @(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Job.Minutes) -RepetitionDuration (New-TimeSpan -Days 3650))
            foreach ($x in @($Subs)) { try { $list += New-LBEventTrigger -Subscription $x } catch { } }
            return $list
        }
        'Daily'   { return New-ScheduledTaskTrigger -Daily -At $Job.At }
        'Weekly'  { return New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Job.Day -At $Job.At }
        'Startup' { return New-ScheduledTaskTrigger -AtStartup }
    }
}

# An always-on job (Web/Syslog/AgentIn/Guard) whose task is not Running but whose script is
# still alive (left over after its task was rebuilt, or started outside the task) keeps the
# port and keeps serving OLD code; the task then fails every start with 'port in use'.
# Stop such leftover LogBok processes so the task can start cleanly with the current code.
function Stop-LBOrphanJob {
    param($Job)
    $n = 0
    try {
        $me = $PID
        foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop)) {
            if ($p.ProcessId -eq $me) { continue }
            $cl = [string]$p.CommandLine
            if ($cl -and $cl -like ('*' + $Job.Script + '*')) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $n++ } catch { } }
        }
    } catch { }
    if ($n) { Start-Sleep -Seconds 2 }
    return $n
}

function Register-LBJob {
    param($Job, [string]$InstallDir, [pscredential]$RunAs, [switch]$Start)
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\$($Job.Script)`""
    if ($Job.Args) { $arg += " $($Job.Args)" }
    $act = New-ScheduledTaskAction -Execute $ps -Argument $arg -WorkingDirectory $InstallDir
    $limit = if ($Job.NoLimit) { [TimeSpan]::Zero } else { New-TimeSpan -Hours 1 }
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -MultipleInstances IgnoreNew -ExecutionTimeLimit $limit -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $subs = @(Get-LBJobSubscriptions -Job $Job -Config $script:__cfg -InstallDir $InstallDir)
    $trg = New-LBJobTrigger -Job $Job -Subs $subs
    $desc = "$($Job.Fa) | $($Job.En) — LogBok"
    # a running instance (e.g. the Syslog listener) is stopped before rebuild so the port is freed
    try { Stop-ScheduledTask -TaskName $Job.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue } catch {}
    Unregister-ScheduledTask -TaskName $Job.Task -TaskPath $script:TaskPath -Confirm:$false -ErrorAction SilentlyContinue
    if ($Job.Kind -eq 'Event') { $desc += " [$(Get-LBSubsSignature -Subs $subs)]" }
    $reg = @{ TaskName=$Job.Task; TaskPath=$script:TaskPath; Action=$act; Trigger=$trg; Settings=$set; Description=$desc }
    if ($RunAs) {
        $reg.User = $RunAs.UserName
        $reg.Password = $RunAs.GetNetworkCredential().Password
        $reg.RunLevel = 'Highest'
    } else {
        $reg.Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    }
    try { Register-ScheduledTask @reg -ErrorAction Stop | Out-Null }
    catch {
        # missing event channel / event-trigger error -> time-based repetition only (works, just a bit later)
        if ($Job.Kind -ne 'Event') { throw }
        $reg.Trigger = @(New-LBJobTrigger -Job $Job -Subs @())
        $reg.Description = "$($Job.Fa) | $($Job.En) — LogBok [$(Get-LBSubsSignature -Subs $subs)] (time-only)"
        Register-ScheduledTask @reg -ErrorAction Stop | Out-Null
    }
    if ($Job.Name -eq 'Syslog') { Open-LBSyslogPort -Config $script:__cfg }
    # only recurring/always-on jobs run immediately (not the daily/weekly reports that send email)
    if ($Job.Kind -eq 'Startup') { [void](Stop-LBOrphanJob -Job $Job) }
    if (($Start -and $Job.Kind -in 'Repeat','Event') -or $Job.Kind -eq 'Startup') {
        try { Start-ScheduledTask -TaskName $Job.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue } catch {}
    }
    # protect the task XML file from deletion by an ordinary user
    try {
        $x = Join-Path $env:windir "System32\Tasks\LogBok\$($Job.Task)"
        if (Test-Path $x) { & icacls.exe $x /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null }
    } catch {}
}

function Open-LBSyslogPort {
    param($Config)
    $sp = 514
    if ($Config -and $Config.Syslog -and $Config.Syslog.Port) { $sp = [int]$Config.Syslog.Port }
    try {
        if (-not (Get-NetFirewallRule -DisplayName 'LogBok-Syslog-In' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'LogBok-Syslog-In' -Direction Inbound -Protocol UDP -LocalPort $sp -Action Allow -Enabled True -ErrorAction Stop | Out-Null
        }
    } catch {
        & netsh advfirewall firewall add rule name="LogBok-Syslog-In" dir=in action=allow protocol=UDP localport=$sp 2>$null | Out-Null
    }
}

# reconcile Task Scheduler with config
#  output: the list of changes (for log/alert)
function Sync-LBJobs {
    param(
        $Config,
        [string]$InstallDir = 'C:\Scripts\LogBok',
        [ValidateSet('Engine','Agent')][string]$Role = 'Engine',
        [pscredential]$RunAs,
        [switch]$StartNew,
        [switch]$Force      # rebuild all jobs (at install time)
    )
    if (-not $Config) { $Config = @{} }
    $script:__cfg = $Config
    $changes = New-Object System.Collections.ArrayList
    # an old-path agent, when a fresh install exists in ProgramData\Agent, does not touch the tasks (else it would point them back to the old path)
    # an agent running from an old folder never re-points tasks once the new home (ProgramData\Agent) exists
    if ($Role -eq 'Agent' -and $env:ProgramData) {
        $agHome = Join-Path $env:ProgramData 'Agent'
        if ($InstallDir.TrimEnd('\') -ne $agHome -and (Test-Path (Join-Path $agHome 'LogBok.Agent.psm1'))) { return $changes.ToArray() }
    }
    foreach ($j in (Get-LBJobCatalog $Config)) {
        $applies = ($j.Role -eq 'Agent') -or ($Role -eq 'Engine')
        $want = $applies -and (Test-LBJobEnabled $Config $j.Name) -and (Test-Path (Join-Path $InstallDir $j.Script))
        $t = Get-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
        if ($want) {
            $stale = $false
            if ($t -and $j.Kind -eq 'Event') {
                $sig = Get-LBSubsSignature -Subs @(Get-LBJobSubscriptions -Job $j -Config $Config -InstallDir $InstallDir)
                if ([string]$t.Description -notmatch [regex]::Escape($sig)) { $stale = $true }
            }
            # a task still running from another folder (e.g. the old C:\Scripts\LogBok path) is rebuilt
            # a task still running a script from another folder (e.g. the old C:\Scripts\LogBok) is rebuilt
            if ($t -and -not $stale -and $Role -eq 'Agent') { $a0 = @($t.Actions)[0]; if ($a0 -and ([string]$a0.Arguments) -notlike ('*"' + $InstallDir.TrimEnd('\') + '\*')) { $stale = $true } }
            if ($Force -or -not $t -or $stale) {
                try {
                    Register-LBJob -Job $j -InstallDir $InstallDir -RunAs $RunAs -Start:$StartNew
                    [void]$changes.Add([pscustomobject]@{ Job=$j.Name; Action=$(if($t){'Rebuilt'}else{'Created'}); Ok=$true; Message='' })
                } catch {
                    [void]$changes.Add([pscustomobject]@{ Job=$j.Name; Action='Create'; Ok=$false; Message=$_.Exception.Message })
                }
            } elseif ($t.State -eq 'Disabled') {
                try { Enable-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -ErrorAction Stop | Out-Null
                      [void]$changes.Add([pscustomobject]@{ Job=$j.Name; Action='Re-enabled'; Ok=$true; Message='' }) } catch {}
            } elseif ($j.Kind -eq 'Startup' -and $t.State -ne 'Running') {
                # an always-on job (Syslog) must always be running; clear a leftover instance first
                $killed = Stop-LBOrphanJob -Job $j
                try { Start-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
                      [void]$changes.Add([pscustomobject]@{ Job=$j.Name; Action='Started'; Ok=$true; Message=$(if ($killed) { "stopped $killed leftover process(es)" } else { '' }) }) } catch {}
            }
        } elseif ($t) {
            try {
                if ($j.Name -eq 'Syslog') { Stop-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue }
                Unregister-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -Confirm:$false -ErrorAction Stop
                [void]$changes.Add([pscustomobject]@{ Job=$j.Name; Action='Removed (disabled in config)'; Ok=$true; Message='' })
            } catch {}
        }
    }
    return $changes.ToArray()
}

# job status table for the console/dashboard
function Get-LBJobStatus {
    param($Config, [ValidateSet('Engine','Agent')][string]$Role = 'Engine')
    # fast: once from the Task Scheduler service (COM) - the ScheduledTasks cmdlets each take ~1 second
    # fast path: one COM call for the whole \LogBok\ folder (the CIM cmdlets cost ~1s per task)
    $byName = $null
    try {
        $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
        $fld = $svc.GetFolder($script:TaskPath.TrimEnd('\'))
        $byName = @{}
        foreach ($t in @($fld.GetTasks(1))) {
            $st = switch ([int]$t.State) { 1 { 'Disabled' } 2 { 'Queued' } 3 { 'Ready' } 4 { 'Running' } default { 'Unknown' } }
            $code = [long]$t.LastTaskResult; if ($code -lt 0) { $code += 4294967296 }
            $byName[[string]$t.Name] = @{ State = $st; LastRun = [datetime]$t.LastRunTime; Code = $code; Next = [datetime]$t.NextRunTime }
        }
    } catch { $byName = $null }
    foreach ($j in (Get-LBJobCatalog $Config)) {
        if ($j.Role -eq 'Engine' -and $Role -ne 'Engine') { continue }
        $state = 'Missing'; $last = $null; $code = $null; $next = $null
        if ($null -ne $byName) {
            $x = $byName[[string]$j.Task]
            if ($x) { $state = $x.State; if ($x.LastRun.Year -gt 2000) { $last = $x.LastRun }; $code = $x.Code; $next = $x.Next }
        } else {
            $t = Get-ScheduledTask -TaskName $j.Task -TaskPath $script:TaskPath -ErrorAction SilentlyContinue
            $info = if ($t) { $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue } else { $null }
            if ($t) { $state = [string]$t.State }
            if ($info) { if ($info.LastRunTime.Year -gt 2000) { $last = $info.LastRunTime }; $code = $info.LastTaskResult; $next = $info.NextRunTime }
        }
        [pscustomobject]@{
            Name     = $j.Name
            Task     = $j.Task
            Enabled  = (Test-LBJobEnabled $Config $j.Name)
            State    = $state
            LastRun  = $last
            LastCode = $code
            NextRun  = $next
            Fa = $j.Fa; En = $j.En
        }
    }
}

Export-ModuleMember -Function Get-LBJobCatalog, Test-LBJobEnabled, Sync-LBJobs, Get-LBJobStatus, Register-LBJob, Open-LBSyslogPort, Get-LBJobSubscriptions, Get-LBSubsSignature
