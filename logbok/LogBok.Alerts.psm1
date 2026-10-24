# ==========================================================================
#  LogBok.Alerts.psm1 — پروفایلِ هشدار و مسیریابیِ ایمیل (مثلِ ADAudit Plus)
#  Alert profiles: name, categories, minimum severity, hosts, keywords,
#  recipients, throttle, business hours. Each finding is emailed to the
#  recipients of every matching enabled profile. Profiles are stored in the
#  settings overlay (Alerts.Profiles) and edited from the web console/console.
#  اگر هیچ پروفایلی با یک یافتهٔ بحرانی جور نشد، طبقِ رفتارِ قبلی به Mail.To می‌رود.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
if (-not (Get-Module LogBok.Core)) { Import-Module (Join-Path (Split-Path -Parent $PSCommandPath) 'LogBok.Core.psm1') -DisableNameChecking -ErrorAction SilentlyContinue }
if (-not (Get-Module LogBok.Findings)) { Import-Module (Join-Path (Split-Path -Parent $PSCommandPath) 'LogBok.Findings.psm1') -DisableNameChecking -ErrorAction SilentlyContinue }
$script:SevRank = @{ Info=1; Warning=2; Critical=3 }

function Get-LBAlertSettings {
    param($Config)
    $a = if ($Config.Alerts) { $Config.Alerts } else { @{} }
    $bh = if ($a.BusinessHours) { $a.BusinessHours } else { @{} }
    [pscustomobject]@{
        Profiles        = @($a.Profiles | Where-Object { $_ })
        DefaultToMailTo = ($a.DefaultToMailTo -ne $false)
        BhDays          = @($(if ($bh.Days) { $bh.Days } else { @('Saturday','Sunday','Monday','Tuesday','Wednesday') }))
        BhStart         = [string]$(if ($bh.Start) { $bh.Start } else { '08:00' })
        BhEnd           = [string]$(if ($bh.End) { $bh.End } else { '17:00' })
    }
}

function Test-LBBusinessHours {
    param($S, [datetime]$Time)
    if (@($S.BhDays) -notcontains $Time.DayOfWeek.ToString()) { return $false }
    $m = $Time.Hour * 60 + $Time.Minute
    $a = [int]($S.BhStart.Split(':')[0]) * 60 + [int]($S.BhStart.Split(':')[1])
    $b = [int]($S.BhEnd.Split(':')[0]) * 60 + [int]($S.BhEnd.Split(':')[1])
    return ($m -ge $a -and $m -lt $b)
}

# آیا یافته با پروفایل جور است؟ | does a finding match a profile?
function Test-LBAlertMatch {
    param($Profile, $Finding, $S)
    if ($Profile.Enabled -eq $false) { return $false }
    $min = if ($Profile.MinSeverity -and $script:SevRank.ContainsKey([string]$Profile.MinSeverity)) { $script:SevRank[[string]$Profile.MinSeverity] } else { 3 }
    $rk = $script:SevRank[[string]$Finding.Severity]; if (-not $rk) { $rk = 1 }
    if ($rk -lt $min) { return $false }
    $cats = @($Profile.Categories | Where-Object { $_ })
    if ($cats.Count -and $cats -notcontains [string]$Finding.Category) { return $false }
    $hosts = @($Profile.Hosts | Where-Object { $_ })
    if ($hosts.Count) { $hit = $false; foreach ($h in $hosts) { if ([string]$Finding.Machine -like [string]$h) { $hit = $true; break } }; if (-not $hit) { return $false } }
    $kws = @($Profile.Keywords | Where-Object { $_ })
    if ($kws.Count) { $txt = ("{0} {1}" -f $Finding.Title, $Finding.Details); $hit = $false; foreach ($k in $kws) { if ($txt -like "*$k*") { $hit = $true; break } }; if (-not $hit) { return $false } }
    $bh = [string]$Profile.BusinessHours
    if ($bh -eq 'inside' -or $bh -eq 'outside') {
        $t = if ($Finding.Time -is [datetime]) { $Finding.Time } else { Get-Date }
        $in = Test-LBBusinessHours -S $S -Time $t
        if ($bh -eq 'inside' -and -not $in) { return $false }
        if ($bh -eq 'outside' -and $in) { return $false }
    }
    return $true
}

# برای هر یافته: گیرنده‌ها و پروفایل‌های جور | routes per finding
function Get-LBAlertRoutes {
    param($Config, [object[]]$Findings)
    $S = Get-LBAlertSettings -Config $Config
    $out = New-Object System.Collections.ArrayList
    foreach ($f in $Findings) {
        if (-not $f) { continue }
        $matched = @()
        foreach ($p in $S.Profiles) { if (Test-LBAlertMatch -Profile $p -Finding $f -S $S) { $matched += $p } }
        if ($matched.Count) {
            foreach ($p in $matched) {
                $rcpt = @($p.Recipients | Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' })
                if (-not $rcpt.Count) { $rcpt = @($Config.Mail.To) }
                $th = if ($p.ThrottleMinutes) { [int]$p.ThrottleMinutes } else { [int]$(if ($Config.AlertThrottleMinutes) { $Config.AlertThrottleMinutes } else { 15 }) }
                $dl = if ([string]$p.Delivery -eq 'digest') { 'digest' } else { 'instant' }
                $dm = if ($p.DigestMinutes) { [int]$p.DigestMinutes } else { 60 }
                [void]$out.Add([pscustomobject]@{ Finding=$f; ProfileId=[string]$p.Id; ProfileName=[string]$p.Name; Recipients=$rcpt; Throttle=$th; Delivery=$dl; DigestMinutes=$dm })
            }
        } elseif ($S.DefaultToMailTo -and [string]$f.Severity -eq 'Critical') {
            $th = [int]$(if ($Config.AlertThrottleMinutes) { $Config.AlertThrottleMinutes } else { 15 })
            [void]$out.Add([pscustomobject]@{ Finding=$f; ProfileId='default'; ProfileName='Default (Critical → Mail.To)'; Recipients=@($Config.Mail.To); Throttle=$th; Delivery='instant'; DigestMinutes=60 })
        }
    }
    return $out.ToArray()
}

# --- پروفایل‌های پیش‌فرض (الگو: ADAudit Plus، Log360، EventLog Analyzer، DataSecurity Plus) -----
#  default alert profiles modelled on ManageEngine's built-in alert profiles. Recipients empty
#  = the default recipients (Mail.To). Seeded once; «بازگردانیِ پیش‌فرض‌ها» re-adds missing ones.
function Get-LBDefaultAlertProfiles {
    $d = @(
        @{ Id='d-critical';  Name='همهٔ رویدادهای بحرانی | All critical security events';            Categories=@();                                                   MinSeverity='Critical'; ThrottleMinutes=15 }
        @{ Id='d-logon';     Name='ورودِ ناموفق، قفلِ حساب و حملهٔ رمز | Failed logons, lockouts & brute force'; Categories=@('BruteForce','Guard');                         MinSeverity='Warning';  ThrottleMinutes=30 }
        @{ Id='d-lockout';   Name='قفل‌شدنِ حسابِ کاربر | User account lockouts';                     Categories=@('ActiveDirectory'); Keywords=@('locked out','unlocked'); MinSeverity='Info';     ThrottleMinutes=10 }
        @{ Id='d-privgroup'; Name='تغییرِ گروه‌های مدیریتی | Privileged group membership changes';   Categories=@('ActiveDirectory'); Keywords=@('SENSITIVE','Admins','Administrators','Operators'); MinSeverity='Warning'; ThrottleMinutes=5 }
        @{ Id='d-usermgmt';  Name='مدیریتِ کاربر و گروه (ساخت/حذف/ریستِ رمز) | User & group management'; Categories=@('ActiveDirectory');                           MinSeverity='Warning';  ThrottleMinutes=15 }
        @{ Id='d-adattack';  Name='حملاتِ AD (DCSync، Kerberoasting، Golden Ticket…) | AD attacks';   Categories=@('ADAttack','Correlation');                          MinSeverity='Warning';  ThrottleMinutes=10 }
        @{ Id='d-tamper';    Name='پاک‌شدنِ لاگ و دستکاریِ حسابرسی/ایجنت | Log cleared & audit tampering'; Categories=@('Tamper');                                    MinSeverity='Warning';  ThrottleMinutes=10 }
        @{ Id='d-ransom';    Name='باج‌افزار و تغییرِ انبوهِ فایل | Ransomware & mass file changes';  Categories=@('Ransomware','MassFile');                          MinSeverity='Warning';  ThrottleMinutes=5 }
        @{ Id='d-files';     Name='فایل‌های حساس: یکپارچگی، مجوز، فایلِ مشکوک | File integrity, permissions & suspicious files'; Categories=@('FIM','FileSuspicion'); MinSeverity='Warning'; ThrottleMinutes=30 }
        @{ Id='d-acl';       Name='تغییرِ مجوزِ فایل/پوشه (خلاصه، ساعتی) | File/folder permission changes (hourly)'; Categories=@('FileACL');                   MinSeverity='Warning';  ThrottleMinutes=60 }
        @{ Id='d-malware';   Name='بدافزار (Defender) | Malware detected';                            Categories=@('Defender');                                        MinSeverity='Warning';  ThrottleMinutes=15 }
        @{ Id='d-policy';    Name='تغییرِ GPO و فایروال | GPO & firewall changes';                     Categories=@('GPO','Firewall','FwGovernance');                   MinSeverity='Warning';  ThrottleMinutes=30 }
        @{ Id='d-server';    Name='تغییرِ مشکوک روی سرور (سرویس/Task/PowerShell) | Suspicious server changes'; Categories=@('MemberServer','Behavior');             MinSeverity='Warning';  ThrottleMinutes=30 }
        @{ Id='d-apps';      Name='حمله به SQL، IIS و FTP | SQL, IIS & FTP attacks';                   Categories=@('SqlLogin','IISAttack','FtpAttack','FtpSuspicion','AppLog'); MinSeverity='Warning'; ThrottleMinutes=30 }
        @{ Id='d-network';   Name='تجهیزاتِ شبکه (syslog) | Network devices';                         Categories=@('Network');                                         MinSeverity='Warning';  ThrottleMinutes=30 }
        @{ Id='d-down';      Name='قطعیِ سرور، سرویس یا ارتباط | Server, service or connection down';  Categories=@('Connectivity','ServiceState');                     MinSeverity='Warning';  ThrottleMinutes=60 }
        @{ Id='d-afterhours';Name='فعالیتِ حساس بیرون از ساعتِ کاری | Sensitive activity after hours'; Categories=@('ActiveDirectory','BruteForce','MemberServer','GPO','Tamper'); MinSeverity='Warning'; BusinessHours='outside'; ThrottleMinutes=30 }
        @{ Id='d-vuln';      Name='آسیب‌پذیری و انطباق (روزانه) | Vulnerabilities & compliance (daily)'; Categories=@('Vulnerability','Policy');                     MinSeverity='Warning';  ThrottleMinutes=1440 }
        @{ Id='d-custom';    Name='قواعدِ لاگِ سفارشی | Custom log rules';                             Categories=@('Custom');                                          MinSeverity='Warning';  ThrottleMinutes=15 }
        @{ Id='d-endpoint';  Name='سلامت و امنیتِ سیستم‌ها (روزانه) | Endpoint health & security (daily)'; Categories=@('EndpointHealth');                             MinSeverity='Warning';  ThrottleMinutes=1440 }
        @{ Id='d-appcontrol';Name='اجرای برنامهٔ ممنوع | Blocked program execution';                      Categories=@('AppControl');                                      MinSeverity='Warning';  ThrottleMinutes=60 }
    )
    $instant = @('d-critical','d-lockout','d-privgroup','d-adattack','d-tamper','d-ransom','d-malware','d-down')
    foreach ($p in $d) {
        if (-not $p.ContainsKey('Keywords')) { $p.Keywords = @() }
        if (-not $p.ContainsKey('BusinessHours')) { $p.BusinessHours = 'any' }
        $p.Hosts = @(); $p.Recipients = @(); $p.Enabled = $true; $p.Builtin = $true; $p.Rev = $(if ($p.Id -in 'd-files', 'd-down', 'd-malware', 'd-acl') { 6 } elseif ($p.Id -in 'd-endpoint', 'd-appcontrol') { 5 } else { 3 })
        # فوری فقط برای موارد واقعاً حساس؛ بقیه خلاصهٔ ساعتی | instant only for truly urgent profiles, the rest hourly digest
        if ($instant -contains $p.Id) { $p.Delivery = 'instant' } else { $p.Delivery = 'digest'; $p.DigestMinutes = $(if ($p.Id -in 'd-vuln', 'd-endpoint') { 1440 } else { 60 }) }
    }
    return $d
}

# یک‌بار (یا با -Restore) پروفایل‌های پیش‌فرض را می‌نشاند | seed once / restore missing defaults
function Initialize-LBDefaultAlerts {
    param([Parameter(Mandatory)][string]$StateDir, [switch]$Restore)
    $ov = Get-LBSettingsOverlay -StateDir $StateDir
    $al = if ($ov -and $ov.Alerts) { $ov.Alerts } else { @{} }
    $cur = @($al.Profiles | Where-Object { $_ })
    if (-not $Restore -and $al.Seeded) {
        # ارتقای پروفایل‌های پیش‌فرضی که مدیر ویرایششان نکرده | upgrade untouched built-in profiles
        $defs = @{}; foreach ($d in (Get-LBDefaultAlertProfiles)) { $defs[[string]$d.Id] = $d }
        $changed = 0; $new = @()
        foreach ($p in $cur) {
            $d = $defs[[string]$p.Id]
            if ($d -and $p.Builtin -eq $true -and $p.Edited -ne $true -and [int]$p.Rev -lt [int]$d.Rev) { $new += $d; $changed++ } else { $new += $p }
        }
        $have = @{}; foreach ($p in $new) { $have[[string]$p.Id] = $true }
        foreach ($d in $defs.Values) { if (-not $have[[string]$d.Id] -and [int]$al.SeedRev -lt [int]$d.Rev) { $new += $d; $changed++ } }
        if ($changed) { [void](Set-LBSetting -Path 'Alerts.Profiles' -Value $new -StateDir $StateDir) }
        if ([int]$al.SeedRev -lt 6) { [void](Set-LBSetting -Path 'Alerts.SeedRev' -Value 6 -StateDir $StateDir) }
        return $changed
    }
    $have = @{}; foreach ($p in $cur) { $have[[string]$p.Id] = $true }
    $add = @(Get-LBDefaultAlertProfiles | Where-Object { -not $have[[string]$_.Id] })
    if ($add.Count) { [void](Set-LBSetting -Path 'Alerts.Profiles' -Value @($cur + $add) -StateDir $StateDir) }
    [void](Set-LBSetting -Path 'Alerts.Seeded' -Value $true -StateDir $StateDir)
    [void](Set-LBSetting -Path 'Alerts.SeedRev' -Value 6 -StateDir $StateDir)
    return $add.Count
}

# آیا ایمیل واقعاً تنظیم شده؟ | is SMTP actually configured (not the template)?
function Test-LBMailConfigured {
    param($Config)
    $m = $Config.Mail
    if (-not $m -or -not $m.SmtpServer -or [string]$m.SmtpServer -match 'yourcompany') { return $false }
    if (-not @($m.To | Where-Object { $_ -and $_ -notmatch 'yourcompany' }).Count) { return $false }
    return $true
}

# ثبتِ هشدارِ ارسال‌شده (تاریخچه در کنسولِ وب) | sent-alert history
function Add-LBAlertHistory {
    param($Config, $Route, [bool]$Ok, [string]$Error, [string]$FindingId)
    try {
        $sd = if ($Config.Paths.State -and (Test-Path $Config.Paths.State)) { $Config.Paths.State } else { Join-Path (Split-Path -Parent $PSCommandPath) 'state' }
        $f = Join-Path $sd 'alerts-sent.ndjson'
        $o = [ordered]@{ t=(Get-Date).ToString('o', $script:Inv); profile=$Route.ProfileName; to=(@($Route.Recipients) -join ', '); host=[string]$Route.Finding.Machine
                         sev=[string]$Route.Finding.Severity; title=[string]$Route.Finding.Title; id=$FindingId; ok=$Ok; err=$Error }
        [IO.File]::AppendAllLines($f, [string[]]@((ConvertTo-Json -InputObject $o -Compress)), (New-Object Text.UTF8Encoding($false)))
        $fi = Get-Item $f
        if ($fi.Length -gt 5MB) { $keep = @([IO.File]::ReadAllLines($f) | Select-Object -Last 2000); [IO.File]::WriteAllLines($f, [string[]]$keep, (New-Object Text.UTF8Encoding($false))) }
    } catch { }
}
function Get-LBAlertHistory {
    param($Config, [int]$Max = 100)
    $sd = if ($Config.Paths.State -and (Test-Path $Config.Paths.State)) { $Config.Paths.State } else { Join-Path (Split-Path -Parent $PSCommandPath) 'state' }
    $f = Join-Path $sd 'alerts-sent.ndjson'
    if (-not (Test-Path $f)) { return @() }
    $lines = @([IO.File]::ReadAllLines($f, [Text.Encoding]::UTF8) | Select-Object -Last $Max)
    [array]::Reverse($lines)
    return @($lines | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
}

# ارسالِ هشدارها طبقِ پروفایل‌ها (به‌جای حلقهٔ قدیمیِ «فقط بحرانی به Mail.To») | send routed alerts
# --- بی‌صداکردن | mutes (settings Alerts.Mutes: host, title, cat, until) ---------------------------
function Get-LBAlertMutes {
    param($Config)
    $sd = Get-LBStateDir -Config $Config
    $o = Get-LBSettingsOverlay -StateDir $sd
    $al = $o['Alerts']; if (-not ($al -is [hashtable])) { return @() }
    $now = Get-Date
    return @(@($al['Mutes']) | Where-Object { $_ } | Where-Object { $u = ConvertTo-LBDate ([string]$_.until); (-not $u) -or $u -gt $now })
}
function Test-LBAlertMuted {
    param([object[]]$Mutes, $Finding)
    $ttl = [regex]::Replace([string]$Finding.Title, '\d+', '#')
    foreach ($m in $Mutes) {
        if ($m.host -and [string]$m.host -ne '*' -and [string]$Finding.Machine -notlike [string]$m.host) { continue }
        if ($m.cat -and [string]$m.cat -ne [string]$Finding.Category) { continue }
        if ($m.title -and ([regex]::Replace([string]$m.title, '\d+', '#')) -ne $ttl) { continue }
        return $true
    }
    return $false
}
function Add-LBAlertMute {
    param($Config, [string]$HostName, [string]$Category, [string]$Title, [int]$Days = 7, [string]$By)
    $sd = Get-LBStateDir -Config $Config
    $o = Get-LBSettingsOverlay -StateDir $sd; $al = $o['Alerts']; $cur = @(); if ($al -is [hashtable]) { $cur = @(@($al['Mutes']) | Where-Object { $_ }) }
    $now = Get-Date
    $cur = @($cur | Where-Object { $u = ConvertTo-LBDate ([string]$_.until); (-not $u) -or $u -gt $now })
    $m = @{ host = $(if ($HostName) { $HostName } else { '*' }); cat = [string]$Category; title = [string]$Title; until = $(if ($Days -gt 0) { $now.AddDays($Days).ToString('o', $script:Inv) } else { '' }); by = $By; at = $now.ToString('o', $script:Inv) }
    [void](Set-LBSetting -Path 'Alerts.Mutes' -Value @($cur + $m) -StateDir $sd)
    return $m
}
function Remove-LBAlertMute {
    param($Config, [string]$HostName, [string]$Category, [string]$Title)
    $sd = Get-LBStateDir -Config $Config
    $o = Get-LBSettingsOverlay -StateDir $sd; $al = $o['Alerts']; $cur = @(); if ($al -is [hashtable]) { $cur = @(@($al['Mutes']) | Where-Object { $_ }) }
    $keep = @($cur | Where-Object { -not ([string]$_.host -eq $(if ($HostName) { $HostName } else { '*' }) -and [string]$_.cat -eq [string]$Category -and [string]$_.title -eq [string]$Title) })
    [void](Set-LBSetting -Path 'Alerts.Mutes' -Value $keep -StateDir $sd)
    return ($cur.Count - $keep.Count)
}
function Send-LBRoutedAlerts {
    param($Config, [object[]]$Findings, $State)
    $sent = 0
    $all = @(Get-LBAlertRoutes -Config $Config -Findings $Findings)
    # خلاصهٔ دوره‌ای برای پروفایل‌های «digest» | digest profiles are batched, not mailed one by one
    $mutes0 = @(Get-LBAlertMutes -Config $Config)
    if ($mutes0.Count) { $all = @($all | Where-Object { -not (Test-LBAlertMuted -Mutes $mutes0 -Finding $_.Finding) }) }
    $dg = @($all | Where-Object { $_.Delivery -eq 'digest' })
    if ($dg.Count) { Add-LBDigestItems -Config $Config -Routes $dg }
    $routes = @($all | Where-Object { $_.Delivery -ne 'digest' })
    # سقفِ ایمیلِ فوری در ساعت؛ بیشتر از آن به خلاصه می‌رود | hourly cap on instant mails, overflow → digest
    $cap = 10; if ($Config.Alerts -and $Config.Alerts.MaxPerHour) { $cap = [int]$Config.Alerts.MaxPerHour }
    $mutes = @(Get-LBAlertMutes -Config $Config)
    $hourKey = (Get-Date).ToString('yyyyMMddHH', $script:Inv)
    if ($State -and [string]$State['mail::hour'] -ne $hourKey) { $State['mail::hour'] = $hourKey; $State['mail::count'] = 0 }
    # یک ایمیل برای هر یافته به اجتماعِ گیرنده‌ها (هر پروفایل ضدِسیلِ خودش را دارد)
    $byF = @{}
    # سرورِ ایمیل در دسترس نبود؟ تا ۱۰ دقیقه تلاش نکن (وگرنه هر ارسال ~۲۰ ثانیه موتور را معطل می‌کند)
    # mail server unreachable recently? pause 10 min so the engine is not stalled by ~20s timeouts
    if ($State -and $State.ContainsKey('mail::pausedUntil')) {
        $pu = ConvertTo-LBDate ([string]$State['mail::pausedUntil'])
        if ($pu -and (Get-Date) -lt $pu) { return 0 }
    }
    foreach ($r in $routes) {
        if ($mutes.Count -and (Test-LBAlertMuted -Mutes $mutes -Finding $r.Finding)) { continue }
        # ضدِسیل بر اساسِ نوعِ رویداد روی هر سیستم (نه هر رکورد) | throttle per event type per host, not per record
        $grp = "{0}|{1}|{2}" -f $r.Finding.Category, $r.Finding.Machine, ([regex]::Replace([string]$r.Finding.Title, '\d+', '#'))
        $key = "alert::{0}::{1}" -f $r.ProfileId, $grp
        if (-not (Test-LogBokThrottle -Key $key -State $State -Config $Config -Minutes $r.Throttle)) { continue }
        # و مستقل از پروفایل: یک ایمیلِ فوری برای هر سیستم+عنوان حداکثر هر ۶۰ دقیقه (بحرانی: ۱۵) | regardless of profile: one instant mail per host+title per 60 min (Critical: 15)
        $gkey = "alertany::{0}|{1}" -f $r.Finding.Machine, ([regex]::Replace([string]$r.Finding.Title, '\d+', '#'))
        if (-not (Test-LogBokThrottle -Key $gkey -State $State -Config $Config -Minutes $(if ([string]$r.Finding.Severity -eq 'Critical') { 15 } else { 60 }))) { continue }
        $fk = $grp
        if (-not $byF.ContainsKey($fk)) { $byF[$fk] = @{ F=$r.Finding; To=@(); Keys=@(); Routes=@() } }
        $byF[$fk].To += @($r.Recipients); $byF[$fk].Keys += $key; $byF[$fk].Routes += $r
    }
    foreach ($fk in $byF.Keys) {
        $x = $byF[$fk]; $fd = $x.F
        $to = @($x.To | Where-Object { $_ } | Select-Object -Unique)
        if (-not $to.Count) { continue }
        $sevTag = switch ([string]$fd.Severity) { 'Critical' { 'CRITICAL' } 'Warning' { 'WARNING' } default { 'INFO' } }
        $subject = if ($Config.Language -eq 'en') { "$sevTag [$($fd.Machine)]: $($fd.Title)" } else { "$(switch ([string]$fd.Severity) { 'Critical' { '🔴 بحرانی' } 'Warning' { '🟠 هشدار' } default { '🔵 اطلاع' } }) [$($fd.Machine)]: $($fd.Title)" }
        if ($subject.Length -gt 180) { $subject = $subject.Substring(0, 180) + '…' }
        $body = New-LogBokAlertHtml -Finding $fd -Config $Config
        $fid = ''; try { $fid = Get-LBFindingId $fd } catch { }
        if ($fid -and $Config.Web -and $Config.Web.Enabled -ne $false) {
            $port = if ($Config.Web.Port) { [int]$Config.Web.Port } else { 8686 }
            $body += "<p style='font-family:Tahoma,sans-serif;font-size:12px'><a href='http://localhost:$port/#/event/$fid'>Open in LogBok web console / باز کردن در کنسولِ وب</a></p>"
        }
        if ($State -and [int]$State['mail::count'] -ge $cap) { Add-LBDigestItems -Config $Config -Routes @($x.Routes) -Overflow; continue }
        $ok = $false; $err = ''
        try { $ok = [bool](Send-LogBokMail -Subject $subject -Body $body -Html -To $to -Config $Config) } catch { $err = $_.Exception.Message }
        if ($ok -and $State) { $State['mail::count'] = [int]$State['mail::count'] + 1 }
        if (-not $ok -and $State) {
            $State['mail::pausedUntil'] = (Get-Date).AddMinutes(10).ToString('o', $script:Inv)
            foreach ($r in $x.Routes) { Add-LBAlertHistory -Config $Config -Route $r -Ok $false -Error $(if ($err) { $err } else { 'mail server unreachable — paused 10 min' }) -FindingId $fid }
            break
        }
        foreach ($k in $x.Keys) { if ($ok) { Set-LogBokThrottle -Key $k -State $State } }
        if ($ok) { Set-LogBokThrottle -Key ("alertany::{0}|{1}" -f $fd.Machine, ([regex]::Replace([string]$fd.Title, '\d+', '#'))) -State $State }
        foreach ($r in $x.Routes) { Add-LBAlertHistory -Config $Config -Route $r -Ok $ok -Error $err -FindingId $fid }
        if ($ok) { $sent++ }
    }
    try { $sent += Send-LBAlertDigests -Config $Config -State $State } catch { }
    return $sent
}

# --- خلاصهٔ هشدار (digest) | alert digests -------------------------------------------------------
function Get-LBDigestFile { param($Config) $sd = if ($Config.Paths.State -and (Test-Path $Config.Paths.State)) { $Config.Paths.State } else { Join-Path (Split-Path -Parent $PSCommandPath) 'state' }; Join-Path $sd 'alert-digest.ndjson' }
function Add-LBDigestItems {
    param($Config, [object[]]$Routes, [switch]$Overflow)
    $f = Get-LBDigestFile -Config $Config
    $lines = foreach ($r in $Routes) {
        $fd = $r.Finding; $fid = ''; try { $fid = Get-LBFindingId $fd } catch { }
        ConvertTo-Json -Compress -InputObject ([ordered]@{ p = $(if ($Overflow) { 'overflow' } else { [string]$r.ProfileId }); pn = $(if ($Overflow) { 'Overflow (hourly cap)' } else { [string]$r.ProfileName })
            m = [int]$(if ($Overflow) { 30 } else { $r.DigestMinutes }); to = @($r.Recipients); at = (Get-Date).ToString('o', $script:Inv)
            t = $(if ($fd.Time -is [datetime]) { $fd.Time.ToString('o', $script:Inv) } else { [string]$fd.Time }); sev = [string]$fd.Severity; host = [string]$fd.Machine; cat = [string]$fd.Category; title = [string]$fd.Title; id = $fid })
    }
    try { [IO.File]::AppendAllLines($f, [string[]]@($lines), (New-Object Text.UTF8Encoding($false))) } catch { }
}
function Send-LBAlertDigests {
    param($Config, $State)
    $f = Get-LBDigestFile -Config $Config
    if (-not (Test-Path $f)) { return 0 }
    if ($State -and $State.ContainsKey('mail::pausedUntil')) { $pu = ConvertTo-LBDate ([string]$State['mail::pausedUntil']); if ($pu -and (Get-Date) -lt $pu) { return 0 } }
    $items = @([IO.File]::ReadAllLines($f, [Text.Encoding]::UTF8) | Where-Object { $_ } | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
    if (-not $items.Count) { return 0 }
    $now = Get-Date; $keep = @(); $sent = 0; $sentP = @()
    foreach ($g in ($items | Group-Object p)) {
        $first = $null; foreach ($it in $g.Group) { $a = ConvertTo-LBDate ([string]$it.at); if ($a -and (-not $first -or $a -lt $first)) { $first = $a } }
        $mins = [int]($g.Group[0].m); if ($mins -lt 5) { $mins = 60 }
        if ($first -and $now -lt $first.AddMinutes($mins)) { $keep += $g.Group; continue }
        $to = @($g.Group | ForEach-Object { @($_.to) } | Where-Object { $_ } | Select-Object -Unique)
        if (-not $to.Count) { continue }
        $en = ($Config.Language -eq 'en')
        $rows = foreach ($t in ($g.Group | Group-Object { "{0}|{1}|{2}" -f $_.host, $_.cat, ([regex]::Replace([string]$_.title, '\d+', '#')) } | Sort-Object Count -Descending | Select-Object -First 200)) {
            $x = $t.Group[0]; $ttl = [string]$x.title; $pp = $ttl -split '\s\|\s', 2; if ($pp.Count -eq 2) { $ttl = $(if ($en) { $pp[1] } else { $pp[0] }) }
            $sevc = switch ([string]$x.sev) { 'Critical' { '#c0392b' } 'Warning' { '#b7791f' } default { '#2e6fa8' } }
            "<tr><td style='padding:4px 8px;color:$sevc'>$([System.Net.WebUtility]::HtmlEncode([string]$x.sev))</td><td style='padding:4px 8px'>$([System.Net.WebUtility]::HtmlEncode([string]$x.host))</td><td style='padding:4px 8px'>$([System.Net.WebUtility]::HtmlEncode($ttl))</td><td style='padding:4px 8px;text-align:center'>$($t.Count)</td></tr>"
        }
        $pn = [string]$g.Group[0].pn; $pp2 = $pn -split '\s\|\s', 2; if ($pp2.Count -eq 2) { $pn = $(if ($en) { $pp2[1] } else { $pp2[0] }) }
        $subj = if ($en) { "LogBok digest: $pn — $($g.Count) events" } else { "خلاصهٔ لاگ‌بوک: $pn — $($g.Count) رویداد" }
        $dir = if ($en) { 'ltr' } else { 'rtl' }
        $body = "<div dir='$dir' style='font-family:Tahoma,Segoe UI,sans-serif;font-size:13px'><h3 style='margin:0 0 8px'>$([System.Net.WebUtility]::HtmlEncode($subj))</h3><table style='border-collapse:collapse' border='1' cellspacing='0'><tr style='background:#eee'><th>Severity</th><th>Host</th><th>Event</th><th>Count</th></tr>$($rows -join '')</table></div>"
        $ok = $false; $err = ''
        try { $ok = [bool](Send-LogBokMail -Subject $subj -Body $body -Html -To $to -Config $Config) } catch { $err = $_.Exception.Message }
        if ($ok) { $sent++; $sentP += [string]$g.Name; if ($State) { $State['mail::count'] = [int]$State['mail::count'] + 1 } }
        else { $keep += $g.Group; if ($State) { $State['mail::pausedUntil'] = (Get-Date).AddMinutes(10).ToString('o', $script:Inv) }; break }
        try { $sd = Split-Path -Parent $f; [IO.File]::AppendAllLines((Join-Path $sd 'alerts-sent.ndjson'), [string[]]@((ConvertTo-Json -Compress -InputObject ([ordered]@{ t = (Get-Date).ToString('o', $script:Inv); profile = "digest: $($g.Group[0].pn)"; to = ($to -join ', '); host = ''; sev = ''; title = "$($g.Count) events"; id = ''; ok = $ok; err = $err }))), (New-Object Text.UTF8Encoding($false))) } catch { }
    }
    # فقط گروه‌های ارسال‌شده حذف می‌شوند؛ بقیه (موعد نرسیده/ناموفق/نرسیده به‌خاطرِ break) می‌مانند
    $remain = @($items | Where-Object { $sentP -notcontains [string]$_.p })
    if ($remain.Count -gt 5000) { $remain = @($remain | Select-Object -Last 5000) }
    [IO.File]::WriteAllLines($f, [string[]]@($remain | ForEach-Object { ConvertTo-Json -Compress -InputObject $_ }), (New-Object Text.UTF8Encoding($false)))
    return $sent
}

Export-ModuleMember -Function Get-LBAlertMutes, Test-LBAlertMuted, Add-LBAlertMute, Remove-LBAlertMute, Add-LBDigestItems, Send-LBAlertDigests, Get-LBAlertSettings, Test-LBBusinessHours, Test-LBAlertMatch, Get-LBAlertRoutes, Add-LBAlertHistory, Get-LBAlertHistory, Send-LBRoutedAlerts, Get-LBDefaultAlertProfiles, Initialize-LBDefaultAlerts, Test-LBMailConfigured
