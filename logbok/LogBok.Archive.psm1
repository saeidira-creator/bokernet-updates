# ==========================================================================
#  LogBok.Archive.psm1 - انبار و جست‌وجوی لاگ (Log store & search)
#  رویدادهای مهم را به‌صورت نرمال‌شده در فایل‌های روزانهٔ NDJSON ذخیره می‌کند
#  و یک تابعِ جست‌وجوی سریع (بر اساس زمان/سیستم/کاربر/EventID/متن) می‌دهد.
#  سبک و بدون پایگاه‌دادهٔ بیرونی؛ روی خودِ سرورِ Collector اجرا می‌شود.
#  وابسته به LogBok.Core (Get-LogBokEvents, Get-LogBokEventField, …).
# ==========================================================================

function Get-LBArchiveDir {
    param($Config)
    $d = if ($Config.Paths.Archive) { $Config.Paths.Archive } else { Join-Path $Config.Paths.State '..\archive' }
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return (Resolve-Path $d).Path
}

$script:Inv = [Globalization.CultureInfo]::InvariantCulture
function Get-LBDayName { param([datetime]$Date) $Date.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }

# افزودنِ امنِ خطوط به فایل با اشتراکِ خواندن/نوشتن و تلاشِ مجدد
#  (لیسنرِ Syslog و موتور هم‌زمان می‌نویسند/می‌خوانند؛ Add-Content قفل می‌گرفت)
function Add-LBArchiveLines {
    param([string]$File, [string[]]$Lines)
    if (-not $Lines -or $Lines.Count -eq 0) { return }
    $text = ($Lines -join "`n") + "`n"
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    for ($try = 1; $try -le 5; $try++) {
        $fs = $null
        try {
            $fs = New-Object IO.FileStream($File, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            $fs.Write($bytes, 0, $bytes.Length)
            return
        } catch {
            if ($try -eq 5) { throw }
            Start-Sleep -Milliseconds (100 * $try)
        } finally { if ($fs) { $fs.Dispose() } }
    }
}

# خواندنِ خط‌به‌خط (بدونِ قفل‌کردنِ فایل برای نویسنده) | streaming read
function Read-LBArchiveLines {
    param([string]$File)
    if (-not (Test-Path -LiteralPath $File)) { return }
    $fs = $null; $sr = $null
    try {
        $fs = New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        while ($null -ne ($l = $sr.ReadLine())) { if ($l) { $l } }
    } catch { } finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
}

# --- کشِ رکوردهای هر روز (در حافظه، افزایشی) | per-day record cache (in memory, incremental) -------------
#  چرا: تجزیهٔ JSON خط‌به‌خط در PowerShell کند است (۳۰–۵۰ مگابایت در روز → ده‌ها ثانیه برای هر گزارش).
#  هر فایلِ روز یک‌بار (دسته‌ای، ۲۰۰۰ خط در هر ConvertFrom-Json) تجزیه می‌شود؛ فایلِ امروز فقط از جایی که
#  قبلاً خوانده شده ادامه می‌یابد. در کنسولِ وب، کش بینِ همهٔ کارگرها مشترک است ($global:LBWebShared).
#  why: line-by-line JSON parsing is slow in PowerShell. Each day file is parsed once (batched), today's
#  file is read incrementally from the last offset, and the web workers share one cache.
$script:DayCacheLocal = @{}
$script:DayCacheMax = 4   # روزهای نگه‌داشته‌شده در حافظه | days kept in memory
function Get-LBDayCacheStore { if ($global:LBWebShared) { if (-not $global:LBWebShared.ContainsKey('ArchiveDays')) { $global:LBWebShared['ArchiveDays'] = [hashtable]::Synchronized(@{}) }; return $global:LBWebShared['ArchiveDays'] }; return $script:DayCacheLocal }
function ConvertTo-LBCachedRecord {
    param($r)
    $t = $null
    if ($r.t -is [datetime]) { $t = $r.t } else { $tp = [datetime]::MinValue; if ([datetime]::TryParse([string]$r.t, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$tp)) { $t = $tp } }
    if (-not $t) { return $null }
    if ($t.Kind -eq [DateTimeKind]::Utc) { $t = $t.ToLocalTime() }
    $r | Add-Member -NotePropertyName time -NotePropertyValue $t -Force
    return $r
}
function Get-LBArchiveDayRecords {
    param([Parameter(Mandatory)][string]$File)
    if (-not (Test-Path -LiteralPath $File)) { return , (New-Object System.Collections.Generic.List[object]) }
    $store = Get-LBDayCacheStore
    $fi = Get-Item -LiteralPath $File
    $e = $store[$File]
    if ($e -and $e.Len -eq $fi.Length -and $e.Write -eq $fi.LastWriteTimeUtc) { $e.Used = Get-Date; return , $e.Items }
    if (-not $e -or $e.Len -gt $fi.Length) { $e = @{ Items = (New-Object System.Collections.Generic.List[object]); Off = 0L; Len = 0L; Write = [datetime]::MinValue; Used = Get-Date } }   # فایل کوچک شده → از نو | truncated -> restart
    $fs = $null
    try {
        $fs = New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        if ($e.Off -gt 0) { [void]$fs.Seek($e.Off, [IO.SeekOrigin]::Begin) }
        $buf = New-Object byte[] ($fs.Length - $e.Off); $n = 0; while ($n -lt $buf.Length) { $k = $fs.Read($buf, $n, $buf.Length - $n); if ($k -le 0) { break }; $n += $k }
        $end = $n; while ($end -gt 0 -and $buf[$end - 1] -ne 10) { $end-- }   # فقط خط‌های کامل | complete lines only (the writer may be mid-line)
        if ($end -gt 0) {
            $txt = [Text.Encoding]::UTF8.GetString($buf, 0, $end)
            $lines = $txt.Split([char]10)
            $batch = New-Object System.Collections.Generic.List[string]
            $flush = { if ($batch.Count) { $arr = $null; try { $arr = ('[' + ($batch.ToArray() -join ',') + ']') | ConvertFrom-Json } catch { $arr = @() }; foreach ($r in @($arr)) { if ($r) { $c = ConvertTo-LBCachedRecord $r; if ($c) { $e.Items.Add($c) } } }; $batch.Clear() } }
            foreach ($ln in $lines) { $l2 = $ln.TrimEnd([char]13); if (-not $l2 -or $l2[0] -ne '{') { continue }; $batch.Add($l2); if ($batch.Count -ge 2000) { . $flush } }
            . $flush
            $e.Off = $e.Off + $end
        }
        $e.Len = $fi.Length; $e.Write = $fi.LastWriteTimeUtc; $e.Used = Get-Date
    } catch { } finally { if ($fs) { $fs.Dispose() } }
    $store[$File] = $e
    # محدودیتِ حافظه: قدیمی‌ترین روزها (کم‌استفاده) حذف می‌شوند | evict least-recently-used days
    if ($store.Count -gt $script:DayCacheMax) { foreach ($k in @($store.Keys | Sort-Object { $store[$_].Used } | Select-Object -First ($store.Count - $script:DayCacheMax))) { $store.Remove($k) } }
    return , $e.Items
}
function Clear-LBArchiveDayCache { $store = Get-LBDayCacheStore; foreach ($k in @($store.Keys)) { $store.Remove($k) } }

# فایل‌های یک روز | files of one day: events-* (ویندوز) و syslog-* (تجهیزاتِ شبکه)
function Get-LBDayFiles {
    param([string]$Dir, [datetime]$Day, [ValidateSet('all','windows','syslog')][string]$Source = 'all')
    $d = Get-LBDayName $Day
    $out = @()
    if ($Source -ne 'syslog')  { $out += (Join-Path $Dir "events-$d.ndjson") }
    if ($Source -ne 'windows') { $out += (Join-Path $Dir "syslog-$d.ndjson") }
    return $out
}

# آخرین RecordIdِ برداشته‌شده از هر منبع (جلوگیری از رکوردِ تکراری)
function Get-LBIngestState {
    param([string]$Dir)
    $f = Join-Path $Dir 'ingest-state.json'; $h = @{}
    if (Test-Path $f) { try { (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $h[$_.Name] = [long]$_.Value } } catch {} }
    return $h
}
function Save-LBIngestState {
    param([string]$Dir, $State)
    try { $State | ConvertTo-Json | Set-Content -Path (Join-Path $Dir 'ingest-state.json') -Encoding UTF8 } catch {}
}

# نرمال‌سازیِ یک رویداد به رکوردِ یکدست | normalize one event
# فیلدهای گزارش‌پذیرِ هر رویداد (الگو: گزارش‌های ADAudit Plus / EventLog Analyzer) | report fields kept per event id
$script:LBReportFields = @{}
foreach ($pair in @(
    @(@(4624), 'TargetUserName,TargetDomainName,LogonType,IpAddress,WorkstationName,LogonProcessName,AuthenticationPackageName,ElevatedToken,TargetLogonId,ProcessName'),
    @(@(4625), 'TargetUserName,TargetDomainName,LogonType,IpAddress,WorkstationName,Status,SubStatus,FailureReason,ProcessName'),
    @(@(4634, 4647), 'TargetUserName,TargetDomainName,LogonType,TargetLogonId'),
    @(@(4648), 'SubjectUserName,TargetUserName,TargetServerName,ProcessName,IpAddress'),
    @(@(4740), 'TargetUserName,TargetDomainName,SubjectUserName'),
    @(@(4767), 'TargetUserName,SubjectUserName'),
    @(@(4771, 4768), 'TargetUserName,IpAddress,Status,ServiceName,TicketEncryptionType'),
    @(@(4769), 'TargetUserName,ServiceName,IpAddress,Status,TicketEncryptionType'),
    @(@(4776), 'TargetUserName,Workstation,Status'),
    @(@(4778, 4779), 'AccountName,AccountDomain,ClientName,ClientAddress,SessionName'),
    @(@(4800, 4801), 'TargetUserName'),
    @(@(4720, 4722, 4725, 4726, 4723, 4724, 4738, 4781, 4765, 4766, 4741, 4742, 4743), 'TargetUserName,TargetDomainName,SubjectUserName,OldTargetUserName,NewTargetUserName,SamAccountName,UserAccountControl'),
    @(@(4728, 4729, 4732, 4733, 4756, 4757, 4727, 4730, 4731, 4734, 4754, 4758), 'TargetUserName,MemberName,MemberSid,SubjectUserName,TargetDomainName'),
    @(@(4719), 'SubjectUserName,CategoryId,SubcategoryGuid,AuditPolicyChanges'),
    @(@(1102), 'SubjectUserName'),
    @(@(4794, 4713, 4739, 4616), 'SubjectUserName,PreviousTime,NewTime,ProcessName,DomainPolicyChanged'),
    @(@(5136, 5137, 5141), 'SubjectUserName,ObjectDN,ObjectClass,AttributeLDAPDisplayName,AttributeValue,OperationType'),
    @(@(4688), 'SubjectUserName,NewProcessName,CommandLine,ParentProcessName,TokenElevationType'),
    @(@(4697, 7045), 'SubjectUserName,ServiceName,ServiceFileName,ImagePath,ServiceType,StartType,ServiceStartType,AccountName,ServiceAccount'),
    @(@(7040), 'param1,param2,param3,param4'),
    @(@(4698, 4699, 4700, 4701, 4702), 'SubjectUserName,TaskName'),
    @(@(4946, 4947, 4948, 2004, 2005, 2006), 'SubjectUserName,RuleName,RuleId,ModifyingApplication,ModifyingUser'),
    @(@(4663, 4660, 4656), 'SubjectUserName,ObjectName,ObjectType,AccessList,AccessMask,ProcessName'),
    @(@(4670), 'SubjectUserName,ObjectName,ObjectType,OldSd,NewSd,ProcessName'),
    @(@(5142, 5143, 5144), 'SubjectUserName,ShareName,ShareLocalPath'),
    @(@(1074), 'param1,param2,param3,param5,param6,param7'),
    @(@(11707, 11724, 1033, 1034), 'param1,param2'),
    @(@(19, 20), 'updateTitle,errorCode')
)) { foreach ($id in $pair[0]) { $script:LBReportFields[[int]$id] = @($pair[1] -split ',') } }

function ConvertTo-LBRecord {
    param($Event,[string]$Computer)
    $map = Get-LBEventDataMap -Event $Event
    $user = [string]$map['TargetUserName']
    if (-not $user) { $user = [string]$map['SubjectUserName'] }
    if (-not $user) { $user = [string]$map['AccountName'] }
    $ip = [string]$map['IpAddress']
    if (-not $ip) { $ip = [string]$map['ClientAddress'] }
    $msg = ''
    try { if ($Event.Message) { $msg = (($Event.Message -split "`r?`n")[0]).Trim() } } catch {}
    $r = [ordered]@{
        t    = $Event.TimeCreated.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        host = [string]$Event.MachineName
        log  = [string]$Event.LogName
        id   = [int]$Event.Id
        lvl  = [string]$Event.LevelDisplayName
        prov = [string]$Event.ProviderName
        user = $user
        ip   = $ip
        rec  = [long]$Event.RecordId
        msg  = $msg
    }
    $flds = $script:LBReportFields[[int]$Event.Id]
    if ($flds) {
        $d = [ordered]@{}
        foreach ($f in $flds) {
            $v = [string]$map[$f]
            if ($v -and $v -ne '-') { $lim = $(if ($f -eq 'CommandLine' -or $f -eq 'AttributeValue') { 1000 } else { 300 }); if ($v.Length -gt $lim) { $v = $v.Substring(0, $lim) }; $d[$f] = $v }
        }
        if ($Event.Id -in 11707, 11724, 1033, 1034 -and -not $d.Count -and $msg) { $d['param1'] = $msg }
        if ($d.Count) { $r.d = $d }
    }
    return $r
}

# برداشت و افزودن رویدادهای تازه به انبار | ingest new events (append NDJSON)
function Invoke-LBArchiveIngest {
    param($Config,[datetime]$Start)
    $dir = Get-LBArchiveDir -Config $Config
    $written = 0
    # منابعِ لاگ: در حالت Collector از ForwardedEvents، وگرنه Security/System/Application
    $logs = if ($Config.CollectionMode -eq 'Collector') { @($Config.ForwardedLog) } else { @('Security','System','Application') }
    # لاگ‌های اضافیِ سفارشی از config (پارسرِ سفارشی) | custom extra logs
    $extra = @(); if ($Config.ArchiveExtraLogs) { $extra = @($Config.ArchiveExtraLogs) }
    $ist = Get-LBIngestState -Dir $dir
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        # ایجنت‌ها و سیستم‌های راه‌دور ForwardedEvents ندارند | push agents/remote hosts have their own logs
        $srcLogs = if ($s.Log -and $s.Log -ne $Config.ForwardedLog -and $s.Computer -ne 'localhost') { @('Security','System','Application') } else { $logs }
        foreach ($lg in (@($srcLogs) + $extra)) {
            if (-not $lg) { continue }
            $evts = Get-LogBokEvents -LogName $lg -StartTime $Start -ComputerName $s.Computer -MaxEvents 20000 -Config $Config
            if (-not $evts) { continue }
            $sk = "$($s.Computer)|$lg"
            $last = if ($ist.ContainsKey($sk)) { [long]$ist[$sk] } else { 0 }
            $max = $last
            # گروه‌بندی بر اساس روز برای نوشتن در فایلِ درست
            $byDay = @{}
            foreach ($e in $evts) {
                $rid = [long]$e.RecordId
                if ($rid -le $last -and $last -gt 0 -and ($last - $rid) -lt 50000000) { continue }   # قبلاً برداشته شده
                if ($rid -gt $max) { $max = $rid }
                $rec = ConvertTo-LBRecord -Event $e -Computer $s.Computer
                $day = Get-LBDayName $e.TimeCreated
                if (-not $byDay.ContainsKey($day)) { $byDay[$day] = [System.Collections.Generic.List[string]]::new() }
                $byDay[$day].Add(($rec | ConvertTo-Json -Compress -Depth 4))
            }
            foreach ($day in $byDay.Keys) {
                $file = Join-Path $dir "events-$day.ndjson"
                Add-LBArchiveLines -File $file -Lines $byDay[$day].ToArray()
                $written += $byDay[$day].Count
            }
            $ist[$sk] = $max
        }
    }
    # کانال‌های رویدادِ سفارشی (افزوده از کنسول/وب) روی سیستمِ خودشان | custom event channels
    foreach ($cs in @($Config.CustomSources | Where-Object { $_ -and [string]$_.Type -eq 'EventLog' -and $_.Log })) {
        $h = if ($cs.Host) { [string]$cs.Host } else { 'localhost' }
        if (@(Get-LBUnreachableHosts -Config $Config) -contains $h) { continue }
        $evts = Get-LogBokEvents -LogName ([string]$cs.Log) -StartTime $Start -ComputerName $h -MaxEvents 20000 -Config $Config
        if (-not $evts) { continue }
        $sk = "$h|$($cs.Log)"
        $last = if ($ist.ContainsKey($sk)) { [long]$ist[$sk] } else { 0 }
        $max = $last; $byDay = @{}
        foreach ($e in $evts) {
            $rid = [long]$e.RecordId
            if ($rid -le $last -and $last -gt 0 -and ($last - $rid) -lt 50000000) { continue }
            if ($rid -gt $max) { $max = $rid }
            $day = Get-LBDayName $e.TimeCreated
            if (-not $byDay.ContainsKey($day)) { $byDay[$day] = [System.Collections.Generic.List[string]]::new() }
            $byDay[$day].Add(((ConvertTo-LBRecord -Event $e -Computer $h) | ConvertTo-Json -Compress -Depth 4))
        }
        foreach ($day in $byDay.Keys) { Add-LBArchiveLines -File (Join-Path $dir "events-$day.ndjson") -Lines $byDay[$day].ToArray(); $written += $byDay[$day].Count }
        $ist[$sk] = $max
    }
    Save-LBIngestState -Dir $dir -State $ist
    # پاک‌سازیِ انبارِ قدیمی | retention
    $keep = if ($Config.ArchiveRetentionDays) { [int]$Config.ArchiveRetentionDays } else { 180 }
    Get-ChildItem -Path $dir -Filter '*.ndjson' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(events|syslog)-' -and $_.LastWriteTime -lt (Get-Date).AddDays(-$keep) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
    return $written
}

# جست‌وجو در انبار | search the store
function Search-LBArchive {
    param(
        $Config,
        [datetime]$From = (Get-Date).AddDays(-1),
        [datetime]$To   = (Get-Date),
        [string]$Computer, [string]$User, [string]$EventId, [string]$Text,
        [ValidateSet('all','windows','syslog')][string]$Source = 'all',
        [int]$Max = 500
    )
    $dir = Get-LBArchiveDir -Config $Config
    $results = [System.Collections.Generic.List[object]]::new()
    $day = $From.Date
    $txtLow = if ($Text) { $Text.ToLowerInvariant().Trim('*') } else { $null }
    while ($day -le $To.Date) {
        foreach ($file in (Get-LBDayFiles -Dir $dir -Day $day -Source $Source)) {
            if ($results.Count -ge $Max) { break }
            if (-not (Test-Path -LiteralPath $file)) { continue }
            foreach ($line in (Read-LBArchiveLines -File $file)) {
                if ($results.Count -ge $Max) { break }
                # پیش‌فیلترِ ارزان پیش از تجزیهٔ JSON | cheap pre-filter before JSON parse
                if ($txtLow -and $txtLow -notmatch '[*?]' -and $line.ToLowerInvariant().IndexOf($txtLow) -lt 0) { continue }
                $r = $null; try { $r = $line | ConvertFrom-Json } catch { continue }
                $t = if ($r.t -is [datetime]) { $r.t } else {
                    $tp = [datetime]::MinValue
                    if (-not [datetime]::TryParse([string]$r.t, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$tp)) { continue }
                    $tp }
                if ($t.Kind -eq [DateTimeKind]::Utc) { $t = $t.ToLocalTime() }
                if ($t -lt $From -or $t -gt $To) { continue }
                if ($Computer -and $r.host -notlike "*$Computer*") { continue }
                if ($User -and $r.user -notlike "*$User*") { continue }
                # شناسه رشته‌ای مقایسه می‌شود (شناسهٔ Syslog مثل SYS-CONFIG_I عددی نیست)
                if ($EventId -and "$($r.id)" -ne "$EventId") { continue }
                if ($Text -and ("$($r.msg) $($r.user) $($r.host) $($r.ip)" -notlike "*$Text*")) { continue }
                $results.Add($r)
            }
        }
        if ($results.Count -ge $Max) { break }
        $day = $day.AddDays(1)
    }
    return $results
}

# جست‌وجوی پیشرفته با Boolean/Wildcard | advanced boolean/wildcard search
#  پشتیبانی: AND OR NOT (یا && || !)، عبارتِ داخلِ "..."، و * به‌عنوان wildcard.
#  مثال:  'admin AND (fail* OR denied) NOT 10.0.0.5'
function Search-LBArchiveQuery {
    param($Config,[datetime]$From=(Get-Date).AddDays(-1),[datetime]$To=(Get-Date),[string]$Query,[int]$Max=500)
    # رکوردهای بازه را بگیر، سپس عبارت را روی متنِ هر رکورد ارزیابی کن
    $all = @(Search-LBArchive -Config $Config -From $From -To $To -Max 200000)
    if (-not $Query -or -not $Query.Trim()) { return ($all | Select-Object -First $Max) }
    $expr = ConvertTo-LBQueryExpr -Query $Query
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $all) {
        if ($out.Count -ge $Max) { break }
        $hay = ("$($r.t) $($r.host) $($r.id) $($r.lvl) $($r.user) $($r.ip) $($r.msg)").ToLower()
        if (Test-LBQuery -Haystack $hay -Expr $expr) { $out.Add($r) }
    }
    return $out
}

# تبدیلِ عبارتِ کاربر به آرایهٔ توکن | tokenize query into a token array
function ConvertTo-LBQueryExpr {
    param([string]$Query)
    $q = $Query -replace '&&',' AND ' -replace '\|\|',' OR '
    $toks = New-Object System.Collections.ArrayList
    # [^\s()]+ تا «denied)» به «denied» و «)» شکسته شود
    $found = [regex]::Matches($q, '"([^"]*)"|\(|\)|[^\s()]+')
    foreach ($mm in $found) {
        $tok = $mm.Value
        if ($tok -eq '(') { [void]$toks.Add(@{k='lp'}) }
        elseif ($tok -eq ')') { [void]$toks.Add(@{k='rp'}) }
        elseif ($tok -ceq 'AND' -or $tok -ceq 'OR' -or $tok -ceq 'NOT') { [void]$toks.Add(@{k=$tok.ToLower()}) }
        elseif ($tok -eq '!') { [void]$toks.Add(@{k='not'}) }
        elseif ($tok.Length -gt 1 -and $tok.StartsWith('!')) {
            # «!admin» (بدونِ فاصله) = NOT admin — قبلاً «!admin» یک کلمهٔ معمولی حساب می‌شد
            [void]$toks.Add(@{k='not'})
            $term = ($tok.Substring(1).Trim('"')).ToLower()
            $rx = [regex]::Escape($term) -replace '\\\*','.*' -replace '\\\?','.'
            [void]$toks.Add(@{k='term'; rx=$rx})
        }
        else {
            $term = ($tok.Trim('"')).ToLower()
            $rx = [regex]::Escape($term) -replace '\\\*','.*' -replace '\\\?','.'
            [void]$toks.Add(@{k='term'; rx=$rx})
        }
    }
    return ,($toks.ToArray())
}

# ارزیابیِ عبارت روی یک متن (پارسرِ بازگشتیِ نزولی) | evaluate boolean expr
function Test-LBQuery {
    param([string]$Haystack,$Expr)
    $script:__q = @($Expr); $script:__i = 0
    return [bool](Eval-LBOr $Haystack)
}
function Peek-LBTok { if ($script:__i -lt $script:__q.Count) { return $script:__q[$script:__i] } else { return $null } }
function Eval-LBOr {
    param([string]$Haystack)
    $v = Eval-LBAnd $Haystack
    while ($true) { $t=Peek-LBTok; if ($t -and $t.k -eq 'or') { $script:__i++; $r=Eval-LBAnd $Haystack; $v=($v -or $r) } else { break } }
    return $v
}
function Eval-LBAnd {
    param([string]$Haystack)
    $v = Eval-LBUnary $Haystack
    while ($true) {
        $t=Peek-LBTok
        if ($t -and ($t.k -eq 'and' -or $t.k -eq 'term' -or $t.k -eq 'not' -or $t.k -eq 'lp')) {
            if ($t.k -eq 'and') { $script:__i++ }
            $r=Eval-LBUnary $Haystack; $v=($v -and $r)
        } else { break }
    }
    return $v
}
function Eval-LBUnary {
    param([string]$Haystack)
    $t = Peek-LBTok
    if ($t -and $t.k -eq 'not') { $script:__i++; return (-not (Eval-LBUnary $Haystack)) }
    if ($t -and $t.k -eq 'lp')  { $script:__i++; $v=Eval-LBOr $Haystack; $n=Peek-LBTok; if ($n -and $n.k -eq 'rp') { $script:__i++ }; return $v }
    if ($t -and $t.k -eq 'term'){ $script:__i++; return [bool]([regex]::IsMatch($Haystack, $t.rx)) }
    $script:__i++; return $true
}

# آمارِ انبار | store stats
function Get-LBArchiveStats {
    param($Config)
    $dir = Get-LBArchiveDir -Config $Config
    $files = @(Get-ChildItem -Path $dir -Filter '*.ndjson' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(events|syslog)-' })
    # شمارشِ خط با کش: فایل‌های روزهای گذشته فقط یک‌بار شمرده می‌شوند
    $cacheF = Join-Path $dir 'stats-cache.json'; $cache = @{}
    if (Test-Path $cacheF) { try { (Get-Content $cacheF -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cache[$_.Name] = [string]$_.Value } } catch {} }
    $lines = 0; $newCache = @{}
    foreach ($f in $files) {
        $sig = "$($f.Length)"
        $c = $null
        if ($cache.ContainsKey($f.Name)) { $p = $cache[$f.Name] -split ':'; if ($p[0] -eq $sig) { $c = [long]$p[1] } }
        if ($null -eq $c) { $c = 0; foreach ($l in (Read-LBArchiveLines -File $f.FullName)) { $c++ } }
        $lines += $c; $newCache[$f.Name] = "${sig}:$c"
    }
    try { $newCache | ConvertTo-Json | Set-Content -Path $cacheF -Encoding UTF8 } catch {}
    $days = @($files | ForEach-Object { $_.BaseName -replace '^(events|syslog)-','' } | Select-Object -Unique).Count
    [pscustomobject]@{ Days=$days; Events=$lines; SizeMB=[math]::Round((($files|Measure-Object Length -Sum).Sum/1MB),1) }
}

Export-ModuleMember -Function Get-LBArchiveDayRecords,Clear-LBArchiveDayCache,Get-LBArchiveDir,ConvertTo-LBRecord,Invoke-LBArchiveIngest,Search-LBArchive,Search-LBArchiveQuery,ConvertTo-LBQueryExpr,Test-LBQuery,Get-LBArchiveStats,Add-LBArchiveLines,Read-LBArchiveLines,Get-LBDayName
