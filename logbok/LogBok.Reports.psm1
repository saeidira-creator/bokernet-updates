# ==========================================================================
#  LogBok.Reports.psm1 — مرکزِ گزارش‌ها (الگو: ADAudit Plus / EventLog Analyzer / Log360 / Endpoint Central)
#  Reports center: 60+ predefined reports over the event store (logon, account,
#  policy, process, file, system), security findings and endpoint data (inventory,
#  risky software, security posture, missing patches, health); grouped/aggregated
#  views; account-lockout root-cause analyzer; logon sessions with duration;
#  user 360 activity trail; CSV export (Excel-friendly) and scheduled e-mail delivery.
#  فقط‌خواندنی است و هیچ تغییری در سیستم‌ها نمی‌دهد. | read-only.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$here = Split-Path -Parent $PSCommandPath
foreach ($m in 'LogBok.Core', 'LogBok.Archive', 'LogBok.Findings') { if (-not (Get-Module $m)) { $p = Join-Path $here "$m.psm1"; if (Test-Path $p) { Import-Module $p -DisableNameChecking -ErrorAction SilentlyContinue } } }

# --- مقدارهای خوانا | readable values -------------------------------------------------------
$script:LogonTypes = @{ '0' = 'System'; '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch (task)'; '5' = 'Service'; '7' = 'Unlock'; '8' = 'Network cleartext'; '9' = 'New credentials (runas)'; '10' = 'RDP'; '11' = 'Cached'; '12' = 'Cached RDP'; '13' = 'Cached unlock' }
$script:LogonTypesFa = @{ '0' = 'سیستم'; '2' = 'محلی'; '3' = 'شبکه'; '4' = 'تسک'; '5' = 'سرویس'; '7' = 'بازکردنِ قفل'; '8' = 'شبکه (متنِ ساده)'; '9' = 'runas'; '10' = 'ریموت‌دسکتاپ'; '11' = 'کش‌شده'; '12' = 'ریموتِ کش‌شده'; '13' = 'قفلِ کش‌شده' }
$script:NtStatus = @{
    '0xc000006a' = @('رمزِ اشتباه', 'Wrong password'); '0xc0000064' = @('کاربرِ ناموجود', 'No such user'); '0xc0000234' = @('حسابِ قفل‌شده', 'Account locked')
    '0xc0000072' = @('حسابِ غیرفعال', 'Account disabled'); '0xc000006f' = @('بیرون از ساعتِ مجاز', 'Outside allowed hours'); '0xc0000070' = @('سیستمِ غیرمجاز', 'Workstation not allowed')
    '0xc0000071' = @('رمزِ منقضی', 'Password expired'); '0xc0000193' = @('حسابِ منقضی', 'Account expired'); '0xc0000224' = @('باید رمز را عوض کند', 'Must change password')
    '0xc000015b' = @('این نوعِ ورود مجاز نیست', 'Logon type not granted'); '0xc000006d' = @('نام یا رمزِ نادرست', 'Bad user name or password'); '0xc0000133' = @('اختلافِ ساعت', 'Clock skew')
    '0xc0000413' = @('سیاستِ احرازِ هویت', 'Authentication firewall'); '0xc000005e' = @('سرورِ ورود در دسترس نیست', 'No logon server')
}
$script:KrbStatus = @{ '0x6' = @('کاربرِ ناموجود', 'No such user'); '0x12' = @('حسابِ غیرفعال/قفل', 'Account disabled/locked'); '0x17' = @('رمزِ منقضی', 'Password expired'); '0x18' = @('رمزِ اشتباه', 'Wrong password'); '0x25' = @('اختلافِ ساعت', 'Clock skew'); '0xc' = @('محدودیتِ سیاست', 'Policy restriction'); '0x0' = @('موفق', 'Success') }
$script:PrivGroups = @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'Remote Desktop Users', 'DnsAdmins', 'Group Policy Creator Owners', 'Hyper-V Administrators', 'Remote Management Users', 'Key Admins', 'Enterprise Key Admins', 'Cert Publishers')

function Get-LBTx { param([string]$Lang, $Pair) if (-not $Pair) { return '' }; if ($Lang -eq 'en') { return [string]$Pair[1] } else { return [string]$Pair[0] } }
function Get-LBD { param($r, [string]$f) if ($r -and $r.d) { $v = $r.d.$f; if ($null -ne $v) { return [string]$v } }; return '' }
function Get-LBLogonTypeText { param([string]$t, [string]$Lang) if (-not $t) { return '' }; $m = $(if ($Lang -eq 'en') { $script:LogonTypes } else { $script:LogonTypesFa }); if ($m.ContainsKey($t)) { return ("{0} ({1})" -f $m[$t], $t) }; return $t }
function Get-LBStatusText {
    param([string]$Status, [string]$Sub, [string]$Lang)
    foreach ($c in @($Sub, $Status)) { if ($c) { $k = $c.ToLowerInvariant(); if ($script:NtStatus.ContainsKey($k)) { return (Get-LBTx $Lang $script:NtStatus[$k]) } } }
    return $(if ($Sub -and $Sub -ne '0x0') { $Sub } else { $Status })
}
function Get-LBKrbText { param([string]$Status, [string]$Lang) $k = ([string]$Status).ToLowerInvariant(); if ($script:KrbStatus.ContainsKey($k)) { return (Get-LBTx $Lang $script:KrbStatus[$k]) }; return $Status }
function Test-LBMachineAccount { param([string]$u) return (-not $u -or $u -like '*$' -or $u -in 'ANONYMOUS LOGON', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', '-' -or $u -like 'DWM-*' -or $u -like 'UMFD-*') }
function Get-LBShortName { param([string]$p) if (-not $p) { return '' }; return ($p -split '[\\/]')[-1] }

# --- نشست‌ها: تاریخچه از رویدادها | session history from logon/logoff/RDP events -------------------
function Test-LBPublicIp {
    param([string]$Ip)
    if (-not $Ip -or $Ip -in '-', '::1', '127.0.0.1', '0.0.0.0', '::') { return $false }
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    if ($Ip -match '^(10\.|127\.|169\.254\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)' -or $Ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $false }
    return $true
}
function Get-LBSessionHistory {
    param($Config, [datetime]$From, [datetime]$To, [string]$HostLike, [string]$UserLike, [int]$Max = 5000)
    # سقفِ منطقی برای اینکه روی سرورِ پرترافیک یک درخواست، کارگر را قفل نکند (پیش‌روی ۲۴ ساعت برای جفت‌کردنِ ورود/خروج)
    # a sane ceiling so one request can't tie up a worker on a busy server; property-name sorts (far faster than a script-block sort)
    $recs = Get-LBArchiveRecords -Config $Config -Ids @(4624, 4634, 4647, 4778, 4779, 4608) -From $From.AddHours(-24) -To $To -HostLike $HostLike -Max 120000
    $open = @{}; $byUserHost = @{}; $done = New-Object System.Collections.Generic.List[object]
    $close = { param($k, $t, $how) $x = $open[$k]; if ($x) { $open.Remove($k); $x.end = $t; $x.how = $how; $done.Add($x); $uh = '{0}|{1}' -f $x.host, $x.userKey; if ($byUserHost[$uh] -eq $x) { $byUserHost.Remove($uh) } } }
    foreach ($r in @($recs | Sort-Object time)) {
        $h = [string]$r.host
        switch ([int]$r.id) {
            4624 {
                $lt = Get-LBD $r 'LogonType'; if ($lt -notin '2', '10', '11') { continue }
                $u = Get-LBD $r 'TargetUserName'; if (-not $u) { $u = [string]$r.user }; if (Test-LBMachineAccount $u) { continue }
                $dom = Get-LBD $r 'TargetDomainName'; $lid = Get-LBD $r 'TargetLogonId'; if (-not $lid) { continue }
                $ip = Get-LBD $r 'IpAddress'; if ($ip -in '-', '::1', '127.0.0.1') { $ip = '' }
                $ws = Get-LBD $r 'WorkstationName'; if ($ws -eq '-') { $ws = '' }
                $k = '{0}|{1}' -f $h, $lid
                $o = @{ host = $h; user = $(if ($dom -and $dom -ne '-') { "$dom\$u" } else { $u }); userKey = $u.ToLowerInvariant(); type = $(switch ($lt) { '10' { 'rdp' } '11' { 'cached' } default { 'console' } })
                        ip = $ip; device = $ws; start = $r.time; end = $null; how = 'open'; disc = 0; elevated = ((Get-LBD $r 'ElevatedToken') -match '1842|Yes') }
                $open[$k] = $o; $byUserHost[('{0}|{1}' -f $h, $o.userKey)] = $o
            }
            { $_ -in 4634, 4647 } { & $close ('{0}|{1}' -f $h, (Get-LBD $r 'TargetLogonId')) $r.time 'logoff' }
            { $_ -in 4778, 4779 } {
                $u = (Get-LBD $r 'AccountName').ToLowerInvariant(); $x = $byUserHost[('{0}|{1}' -f $h, $u)]
                if ($x) {
                    $cn = Get-LBD $r 'ClientName'; $ca = Get-LBD $r 'ClientAddress'
                    if ($cn -and $cn -ne 'Unknown') { $x.device = $cn }; if ($ca -and $ca -notin 'Unknown', '-') { $x.ip = $ca }
                    $x.type = 'rdp'; if ($r.id -eq 4779) { $x.disc++; $x.lastDisc = $r.time } else { $x.lastDisc = $null }
                }
            }
            4608 { foreach ($k in @($open.Keys | Where-Object { $_ -like "$h|*" })) { & $close $k $r.time 'reboot' } }   # سیستم ری‌استارت شد | computer restarted
        }
    }
    $now = Get-Date
    foreach ($x in @($open.Values)) { if (($now - $x.start).TotalHours -gt 72) { $x.how = 'unknown' }; $done.Add($x) }
    $ul = if ($UserLike) { $UserLike.ToLowerInvariant() } else { $null }
    return @($done | Where-Object { ($_.start -ge $From -or ($_.end -and $_.end -ge $From) -or (-not $_.end)) -and $_.start -le $To -and (-not $ul -or $_.user.ToLowerInvariant().Contains($ul)) } | Sort-Object start -Descending | Select-Object -First $Max)
}

# --- تعریفِ گزارش‌ها | report catalog -------------------------------------------------------------
function New-LBRep {
    param([string]$Id, [string]$Cat, [string]$Fa, [string]$En, [string]$DescFa = '', [string]$DescEn = '', [string]$Src = 'events', [int[]]$Ids = @(), [scriptblock]$Where, [object[]]$Cols, [string[]]$Group, [string[]]$Categories, [string]$MinSev)
    return @{ Id = $Id; Cat = $Cat; Fa = $Fa; En = $En; DescFa = $DescFa; DescEn = $DescEn; Src = $Src; Ids = $Ids; Where = $Where; Cols = $Cols; Group = $Group; Categories = $Categories; MinSev = $MinSev }
}
# ستون: @(key, fa, en)  ؛ key: time/host/user/ip/id/msg ، d:Field (فیلدِ رویداد) ، c:name (محاسبه‌شده)
$cT = @('time', 'زمان', 'Time'); $cH = @('host', 'سیستم', 'Computer'); $cU = @('user', 'کاربر', 'User'); $cI = @('ip', 'IP', 'IP')
$cBy = @('d:SubjectUserName', 'توسطِ', 'By'); $cLT = @('c:ltype', 'نوعِ ورود', 'Logon type'); $cWs = @('d:WorkstationName', 'از سیستمِ', 'From workstation')
$script:Cats = [ordered]@{
    logon = @('ورود و نشست', 'Logon & sessions'); account = @('حساب‌ها و گروه‌ها', 'Accounts & groups'); policy = @('سیاست، AD و پیکربندی', 'Policy, AD & configuration')
    process = @('برنامه، سرویس و تسک', 'Processes, services & tasks'); file = @('فایل و اشتراک', 'Files & shares'); system = @('سیستم و به‌روزرسانی', 'System & updates')
    security = @('یافته‌های امنیتی', 'Security findings'); endpoint = @('سیستم‌ها (ایجنت)', 'Endpoints (agent)')
}
$script:Reports = @(
    # ---------------- ورود | logon ----------------
    (New-LBRep 'logon-success' 'logon' 'ورودهای موفق' 'Successful logons' 'ورودِ کاربران (بدونِ حساب‌های سیستمی و سرویس‌ها)' 'User logons (machine accounts and services excluded)' -Ids 4624 -Where { param($r) -not (Test-LBMachineAccount $r.user) -and (Get-LBD $r 'LogonType') -notin '0', '5' } -Cols @($cT, $cH, $cU, $cLT, $cI, $cWs, @('d:AuthenticationPackageName', 'روش', 'Package')))
    (New-LBRep 'logon-failed' 'logon' 'ورودهای ناموفق' 'Failed logons' 'هر تلاشِ ناموفق با دلیل و مبدأ' 'Every failed logon with reason and source' -Ids 4625 -Cols @($cT, $cH, $cU, $cLT, $cI, $cWs, @('c:reason', 'دلیل', 'Reason'), @('c:proc', 'برنامه', 'Process')))
    (New-LBRep 'logon-rdp' 'logon' 'ورود و اتصالِ ریموت‌دسکتاپ' 'Remote Desktop activity' 'ورودِ RDP، اتصالِ دوباره و قطعِ نشست' 'RDP logons, reconnects and disconnects' -Ids 4624, 4778, 4779 -Where { param($r) $r.id -ne 4624 -or ((Get-LBD $r 'LogonType') -eq '10' -and -not (Test-LBMachineAccount $r.user)) } -Cols @($cT, $cH, $cU, @('c:rdpact', 'رویداد', 'Action'), $cI, @('d:ClientName', 'نامِ سیستمِ کاربر', 'Client name')))
    (New-LBRep 'logon-admin' 'logon' 'ورودهای با دسترسیِ مدیر' 'Administrator logons' 'ورودهایی که توکنِ ارتقایافته (Admin) دارند' 'Logons with an elevated (admin) token' -Ids 4624 -Where { param($r) (Get-LBD $r 'ElevatedToken') -eq '%%1842' -and -not (Test-LBMachineAccount $r.user) -and (Get-LBD $r 'LogonType') -in '2', '3', '10', '11' } -Cols @($cT, $cH, $cU, $cLT, $cI, $cWs))
    (New-LBRep 'logon-afterhours' 'logon' 'ورود بیرون از ساعتِ کاری' 'Logons outside business hours' 'ورودِ محلی/RDP بیرون از ساعتِ کاریِ تعریف‌شده در هشدارها' 'Interactive/RDP logons outside the business hours set in Alerts' -Ids 4624 -Where { param($r) -not (Test-LBMachineAccount $r.user) -and (Get-LBD $r 'LogonType') -in '2', '10', '11' -and -not (Test-LBRepBusinessHours $r.time) } -Cols @($cT, $cH, $cU, $cLT, $cI))
    (New-LBRep 'logon-explicit' 'logon' 'ورود با اعتبارنامهٔ دیگر (runas)' 'Logons with explicit credentials' 'استفاده از نام/رمزِ کاربرِ دیگر (4648) — نشانهٔ حرکتِ جانبی' 'Use of another account''s credentials (4648) — lateral movement indicator' -Ids 4648 -Where { param($r) -not (Test-LBMachineAccount (Get-LBD $r 'TargetUserName')) } -Cols @($cT, $cH, @('d:SubjectUserName', 'کاربرِ اصلی', 'Account'), @('d:TargetUserName', 'با حسابِ', 'Used account'), @('d:TargetServerName', 'به سرورِ', 'Target server'), @('c:proc', 'برنامه', 'Process'), $cI))
    (New-LBRep 'logon-kerberos' 'logon' 'خطاهای Kerberos' 'Kerberos failures' 'پیش‌احرازِ ناموفق و درخواستِ تیکتِ رد‌شده' 'Failed pre-authentication and refused ticket requests' -Ids 4771, 4768 -Where { param($r) (Get-LBD $r 'Status') -notin '', '0x0' } -Cols @($cT, $cH, $cU, $cI, @('c:krb', 'دلیل', 'Reason')))
    (New-LBRep 'logon-ntlm' 'logon' 'خطاهای NTLM' 'NTLM failures' 'اعتبارسنجیِ ناموفقِ NTLM روی کنترل‌کنندهٔ دامنه یا سیستم' 'Failed NTLM validation' -Ids 4776 -Where { param($r) (Get-LBD $r 'Status') -notin '', '0x0' } -Cols @($cT, $cH, $cU, @('d:Workstation', 'از سیستمِ', 'From workstation'), @('c:ntlm', 'دلیل', 'Reason')))
    (New-LBRep 'logon-sessions' 'logon' 'نشست‌های کاربران و مدت' 'User sessions and duration' 'از ورود تا خروج برای ورودِ محلی و RDP' 'From logon to logoff for interactive and RDP logons' -Src 'sessions' -Cols @(@('start', 'شروع', 'Start'), @('end', 'پایان', 'End'), @('dur', 'مدت (دقیقه)', 'Minutes'), $cH, $cU, $cLT, $cI))
    (New-LBRep 'logon-lockouts' 'logon' 'قفل‌شدنِ حساب‌ها' 'Account lockouts' 'رویدادِ 4740 با سیستمِ مبدأ' 'Event 4740 with the caller computer' -Ids 4740 -Cols @($cT, @('host', 'کنترل‌کننده', 'Domain controller'), $cU, @('d:TargetDomainName', 'سیستمِ مبدأ', 'Caller computer')))
    (New-LBRep 'lockout-analyzer' 'logon' 'تحلیلِ علتِ قفل‌شدن' 'Account lockout analyzer' 'برای هر قفل: تلاش‌های ناموفقِ قبلش، مبدأها و علتِ محتمل (سرویس، تسک، درایوِ شبکه، RDP…)' 'For every lockout: preceding failures, their sources and the likely cause (service, task, mapped drive, RDP…)' -Src 'lockout' -Cols @($cT, $cU, @('host', 'کنترل‌کننده', 'Domain controller'), @('caller', 'سیستمِ مبدأ', 'Caller computer'), @('fails', 'تلاشِ ناموفق', 'Failures'), @('sources', 'مبدأها', 'Sources'), @('cause', 'علتِ محتمل', 'Likely cause')))
    (New-LBRep 'logon-unlocks' 'logon' 'بازشدنِ قفلِ حساب' 'Account unlocks' 'چه کسی قفلِ چه حسابی را باز کرد' 'Who unlocked which account' -Ids 4767 -Cols @($cT, $cH, $cU, $cBy))
    (New-LBRep 'logon-wslock' 'logon' 'قفل/بازکردنِ صفحه' 'Workstation lock/unlock' 'قفل و بازکردنِ صفحهٔ کاربر' 'Screen lock and unlock' -Ids 4800, 4801 -Cols @($cT, $cH, $cU, @('c:lockact', 'رویداد', 'Action')))
    (New-LBRep 'logon-logoffs' 'logon' 'خروج‌ها' 'Logoffs' 'خروجِ کاربر از نشست' 'User logoffs' -Ids 4634, 4647 -Where { param($r) -not (Test-LBMachineAccount $r.user) -and (Get-LBD $r 'LogonType') -notin '3', '5', '0' } -Cols @($cT, $cH, $cU, $cLT))
    (New-LBRep 'agg-failed-ip' 'logon' 'ناموفق‌ها به تفکیکِ IP' 'Failed logons by source IP' 'کدام IPها بیشترین تلاشِ ناموفق را داشته‌اند' 'Which IPs failed most' -Ids 4625 -Group 'ip' -Cols @(,$cI))
    (New-LBRep 'agg-failed-user' 'logon' 'ناموفق‌ها به تفکیکِ کاربر' 'Failed logons by user' 'کدام حساب‌ها بیشترین ورودِ ناموفق را داشته‌اند' 'Which accounts failed most' -Ids 4625 -Group 'user', 'host' -Cols @($cU, $cH))
    (New-LBRep 'agg-logon-user' 'logon' 'ورودها به تفکیکِ کاربر و سیستم' 'Logons by user and computer' 'هر کاربر روی کدام سیستم‌ها و چند بار وارد شده' 'Where and how often each user logged on' -Ids 4624 -Where { param($r) -not (Test-LBMachineAccount $r.user) -and (Get-LBD $r 'LogonType') -in '2', '10', '11' } -Group 'user', 'host' -Cols @($cU, $cH))
    # ---------------- حساب‌ها | accounts ----------------
    (New-LBRep 'user-created' 'account' 'کاربرانِ ساخته‌شده' 'Users created' '' '' -Ids 4720 -Cols @($cT, $cH, $cU, $cBy))
    (New-LBRep 'user-deleted' 'account' 'کاربرانِ حذف‌شده' 'Users deleted' '' '' -Ids 4726 -Cols @($cT, $cH, $cU, $cBy))
    (New-LBRep 'user-enabled-disabled' 'account' 'فعال/غیرفعال‌شدنِ کاربر' 'Users enabled/disabled' '' '' -Ids 4722, 4725 -Cols @($cT, $cH, $cU, @('c:acct', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'user-password' 'account' 'تغییر و ریستِ رمز' 'Password changes and resets' 'ریست توسطِ مدیر (4724) یا تغییر توسطِ خودِ کاربر (4723)' 'Reset by an admin (4724) or changed by the user (4723)' -Ids 4723, 4724 -Cols @($cT, $cH, $cU, @('c:acct', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'user-modified' 'account' 'تغییرِ مشخصاتِ حساب' 'Account changes' 'تغییرِ ویژگی‌ها و تغییرِ نامِ حساب' 'Attribute changes and renames' -Ids 4738, 4781 -Cols @($cT, $cH, $cU, @('c:acct', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'group-added' 'account' 'افزوده‌شده به گروه' 'Added to groups' '' '' -Ids 4728, 4732, 4756 -Cols @($cT, $cH, @('c:member', 'عضو', 'Member'), @('d:TargetUserName', 'گروه', 'Group'), $cBy))
    (New-LBRep 'group-removed' 'account' 'حذف‌شده از گروه' 'Removed from groups' '' '' -Ids 4729, 4733, 4757 -Cols @($cT, $cH, @('c:member', 'عضو', 'Member'), @('d:TargetUserName', 'گروه', 'Group'), $cBy))
    (New-LBRep 'group-privileged' 'account' 'تغییرِ عضویتِ گروه‌های مدیریتی' 'Privileged group changes' 'Administrators، Domain Admins، Enterprise Admins، Remote Desktop Users و …' 'Administrators, Domain Admins, Enterprise Admins, Remote Desktop Users, …' -Ids 4728, 4732, 4756, 4729, 4733, 4757 -Where { param($r) $script:PrivGroups -contains (Get-LBD $r 'TargetUserName') } -Cols @($cT, $cH, @('c:member', 'عضو', 'Member'), @('d:TargetUserName', 'گروه', 'Group'), @('c:grpact', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'group-lifecycle' 'account' 'ساخت/حذفِ گروه' 'Groups created/deleted' '' '' -Ids 4727, 4731, 4754, 4730, 4734, 4758 -Cols @($cT, $cH, @('d:TargetUserName', 'گروه', 'Group'), @('c:acct', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'computer-accounts' 'account' 'حساب‌های کامپیوتر' 'Computer accounts' 'ساخت، تغییر و حذفِ حسابِ کامپیوتر در دامنه' 'Computer accounts created, changed, deleted' -Ids 4741, 4742, 4743 -Cols @($cT, $cH, @('d:TargetUserName', 'کامپیوتر', 'Computer account'), @('c:acct', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'sid-history' 'account' 'افزودنِ SID History' 'SID history changes' 'روشِ رایجِ ارتقای دسترسیِ پنهان' 'A common stealthy privilege-escalation technique' -Ids 4765, 4766 -Cols @($cT, $cH, $cU, $cBy))
    # ---------------- سیاست و پیکربندی | policy & configuration ----------------
    (New-LBRep 'audit-policy' 'policy' 'تغییرِ سیاستِ ممیزی' 'Audit policy changes' 'خاموش‌کردنِ ممیزی معمولاً پیش از حمله است' 'Disabling auditing often precedes an attack' -Ids 4719 -Cols @($cT, $cH, $cBy, @('d:AuditPolicyChanges', 'تغییر', 'Change')))
    (New-LBRep 'log-cleared' 'policy' 'پاک‌شدنِ لاگ‌ها' 'Event logs cleared' '' '' -Ids 1102, 104 -Cols @($cT, $cH, $cU, @('log', 'لاگ', 'Log')))
    (New-LBRep 'domain-policy' 'policy' 'تغییرِ سیاستِ دامنه/Kerberos/DSRM' 'Domain, Kerberos and DSRM policy changes' '' '' -Ids 4739, 4713, 4794 -Cols @($cT, $cH, $cBy, @('id', 'رویداد', 'Event')))
    (New-LBRep 'ad-changes' 'policy' 'تغییرِ اشیای اکتیودایرکتوری' 'Active Directory object changes' 'ساخت، تغییر و حذفِ اشیا (5136/5137/5141)' 'Objects created, modified, deleted (5136/5137/5141)' -Ids 5136, 5137, 5141 -Cols @($cT, $cH, $cBy, @('d:ObjectDN', 'شیء', 'Object'), @('d:ObjectClass', 'نوع', 'Class'), @('d:AttributeLDAPDisplayName', 'ویژگی', 'Attribute'), @('d:AttributeValue', 'مقدار', 'Value'), @('c:adop', 'عمل', 'Operation')))
    (New-LBRep 'gpo-changes' 'policy' 'تغییرِ Group Policy' 'Group Policy changes' '' '' -Ids 5136, 5137, 5141 -Where { param($r) (Get-LBD $r 'ObjectClass') -eq 'groupPolicyContainer' -or (Get-LBD $r 'ObjectDN') -like '*CN=Policies,CN=System*' } -Cols @($cT, $cH, $cBy, @('d:ObjectDN', 'GPO', 'GPO'), @('d:AttributeLDAPDisplayName', 'ویژگی', 'Attribute'), @('c:adop', 'عمل', 'Operation')))
    (New-LBRep 'fw-rules' 'policy' 'تغییرِ رول‌های فایروال' 'Firewall rule changes' '' '' -Ids 4946, 4947, 4948, 2004, 2005, 2006 -Cols @($cT, $cH, @('d:RuleName', 'رول', 'Rule'), @('c:fwact', 'تغییر', 'Change'), @('c:fwapp', 'برنامه', 'Application')))
    (New-LBRep 'time-change' 'policy' 'تغییرِ ساعتِ سیستم' 'System time changes' 'تغییرِ دستیِ ساعت (همگام‌سازیِ خودکار حذف شده)' 'Manual clock changes (automatic sync excluded)' -Ids 4616 -Where { param($r) (Get-LBD $r 'ProcessName') -notlike '*svchost.exe' -and (Get-LBD $r 'ProcessName') -notlike '*vmtoolsd.exe' } -Cols @($cT, $cH, $cBy, @('d:PreviousTime', 'ساعتِ قبلی', 'Previous'), @('d:NewTime', 'ساعتِ جدید', 'New'), @('c:proc', 'برنامه', 'Process')))
    # ---------------- برنامه و سرویس | processes & services ----------------
    (New-LBRep 'process-start' 'process' 'برنامه‌های اجراشده' 'Processes started' 'نیازمندِ ممیزیِ Process Creation (4688)' 'Requires Process Creation auditing (4688)' -Ids 4688 -Cols @($cT, $cH, $cU, @('c:newproc', 'برنامه', 'Program'), @('d:CommandLine', 'خطِ فرمان', 'Command line'), @('c:parent', 'برنامهٔ والد', 'Parent')))
    (New-LBRep 'process-suspicious' 'process' 'اجرای مشکوک (LOLBins)' 'Suspicious executions (LOLBins)' 'PowerShell کدشده، certutil، mshta، rundll32، vssadmin، wmic، psexec، …' 'Encoded PowerShell, certutil, mshta, rundll32, vssadmin, wmic, psexec, …' -Ids 4688 -Where { param($r) [bool](Get-LBLolbinReason $r) } -Cols @($cT, $cH, $cU, @('c:newproc', 'برنامه', 'Program'), @('c:lolbin', 'چرا مشکوک', 'Why'), @('d:CommandLine', 'خطِ فرمان', 'Command line')))
    (New-LBRep 'service-installed' 'process' 'سرویس‌های نصب‌شده' 'Services installed' 'نصبِ سرویس — روشِ رایجِ ماندگاریِ بدافزار و PsExec' 'Service installs — a common persistence and PsExec technique' -Ids 7045, 4697 -Cols @($cT, $cH, @('d:ServiceName', 'سرویس', 'Service'), @('c:svcpath', 'مسیر', 'Path'), @('c:svcacct', 'حساب', 'Account'), $cBy))
    (New-LBRep 'service-starttype' 'process' 'تغییرِ نوعِ شروعِ سرویس' 'Service start type changes' 'مثلاً غیرفعال‌شدنِ Defender یا Windows Update' 'e.g. Defender or Windows Update disabled' -Ids 7040 -Cols @($cT, $cH, @('d:param1', 'سرویس', 'Service'), @('d:param2', 'از', 'From'), @('d:param3', 'به', 'To')))
    (New-LBRep 'task-changes' 'process' 'تسک‌های زمان‌بندی‌شده' 'Scheduled task changes' 'ساخت، تغییر، حذف و فعال/غیرفعال‌شدنِ تسک' 'Tasks created, changed, deleted, enabled/disabled' -Ids 4698, 4699, 4700, 4701, 4702 -Cols @($cT, $cH, @('d:TaskName', 'تسک', 'Task'), @('c:taskact', 'تغییر', 'Change'), $cBy))
    (New-LBRep 'software-installs' 'process' 'نصب و حذفِ نرم‌افزار' 'Software installed/removed' 'از MsiInstaller' 'From MsiInstaller' -Ids 11707, 11724, 1033, 1034 -Cols @($cT, $cH, $cU, @('c:msiact', 'عمل', 'Action'), @('c:msiname', 'نرم‌افزار', 'Software')))
    # ---------------- فایل | files ----------------
    (New-LBRep 'file-access' 'file' 'دسترسی و تغییرِ فایل‌ها' 'File access and changes' 'نیازمندِ SACL روی پوشه‌های پایش‌شده' 'Requires SACLs on monitored folders' -Ids 4663 -Cols @($cT, $cH, $cU, @('d:ObjectName', 'فایل', 'File'), @('c:access', 'دسترسی', 'Access'), @('c:proc', 'برنامه', 'Process')))
    (New-LBRep 'file-deleted' 'file' 'فایل‌های حذف‌شده' 'Files deleted' '' '' -Ids 4663, 4660 -Where { param($r) $r.id -eq 4660 -or (Get-LBD $r 'AccessList') -match '%%1537' -or (Get-LBD $r 'AccessMask') -eq '0x10000' } -Cols @($cT, $cH, $cU, @('d:ObjectName', 'فایل', 'File'), @('c:proc', 'برنامه', 'Process')))
    (New-LBRep 'file-permissions' 'file' 'تغییرِ مجوزهای فایل/پوشه' 'File/folder permission changes' '' '' -Ids 4670 -Where { param($r) (Get-LBD $r 'ObjectType') -in 'File', 'Key', '' } -Cols @($cT, $cH, $cBy, @('d:ObjectName', 'شیء', 'Object'), @('d:ObjectType', 'نوع', 'Type'), @('c:proc', 'برنامه', 'Process')))
    (New-LBRep 'share-changes' 'file' 'تغییرِ پوشه‌های اشتراکی' 'Share changes' '' '' -Ids 5142, 5143, 5144 -Cols @($cT, $cH, @('d:ShareName', 'اشتراک', 'Share'), @('d:ShareLocalPath', 'مسیر', 'Path'), @('c:shareact', 'تغییر', 'Change'), $cBy))
    # ---------------- سیستم | system ----------------
    (New-LBRep 'startup-shutdown' 'system' 'روشن/خاموش و ری‌استارت' 'Startup, shutdown and restarts' 'شاملِ خاموشیِ ناگهانی و ری‌استارت با دلیل' 'Includes unexpected shutdowns and restarts with reason' -Ids 6005, 6006, 6008, 1074, 41 -Cols @($cT, $cH, @('c:boot', 'رویداد', 'Event'), $cU, @('c:bootwhy', 'دلیل/برنامه', 'Reason/process')))
    (New-LBRep 'updates-installed' 'system' 'به‌روزرسانی‌های نصب‌شده' 'Windows updates installed' 'از WindowsUpdateClient (19 موفق، 20 ناموفق)' 'From WindowsUpdateClient (19 ok, 20 failed)' -Ids 19, 20 -Cols @($cT, $cH, @('d:updateTitle', 'به‌روزرسانی', 'Update'), @('c:upres', 'نتیجه', 'Result')))
    # ---------------- یافته‌ها | findings ----------------
    (New-LBRep 'sec-all' 'security' 'همهٔ یافته‌های امنیتی' 'All security findings' 'هشدار و بحرانی' 'Warning and critical' -Src 'findings' -MinSev 'Warning' -Cols @($cT, @('sev', 'سطح', 'Severity'), @('cat', 'دسته', 'Category'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-critical' 'security' 'یافته‌های بحرانی' 'Critical findings' '' '' -Src 'findings' -MinSev 'Critical' -Cols @($cT, @('cat', 'دسته', 'Category'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-malware' 'security' 'بدافزار و Defender' 'Malware and Defender' '' '' -Src 'findings' -Categories 'Defender' -Cols @($cT, @('sev', 'سطح', 'Severity'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-ransomware' 'security' 'باج‌افزار و تغییرِ انبوهِ فایل' 'Ransomware and mass file changes' '' '' -Src 'findings' -Categories 'Ransomware', 'MassFile', 'FileSuspicion' -Cols @($cT, @('sev', 'سطح', 'Severity'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-attacks' 'security' 'حمله به ورود و AD' 'Logon and AD attacks' 'Brute force، Kerberoasting، DCSync، همبستگیِ چندمرحله‌ای' 'Brute force, Kerberoasting, DCSync, multi-stage correlation' -Src 'findings' -Categories 'BruteForce', 'ADAttack', 'Correlation', 'Guard', 'SqlLogin' -Cols @($cT, @('sev', 'سطح', 'Severity'), @('cat', 'دسته', 'Category'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-tamper' 'security' 'دستکاری و تغییرِ تنظیماتِ امنیتی' 'Tampering and security setting changes' '' '' -Src 'findings' -Categories 'Tamper', 'Firewall', 'Policy', 'Enforcement', 'GPO' -Cols @($cT, @('sev', 'سطح', 'Severity'), @('cat', 'دسته', 'Category'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'sec-appcontrol' 'security' 'کنترلِ اجرای برنامه' 'Application control' 'برنامه‌های ممنوعِ مسدود یا مغایرِ سیاست' 'Blocked or policy-violating program executions' -Src 'findings' -Categories 'AppControl' -Cols @($cT, @('sev', 'سطح', 'Severity'), $cH, @('title', 'رویداد', 'Finding')))
    (New-LBRep 'agg-findings' 'security' 'یافته‌ها به تفکیکِ دسته و سیستم' 'Findings by category and computer' '' '' -Src 'findings' -Group 'cat', 'host' -Cols @(@('cat', 'دسته', 'Category'), $cH))
    # ---------------- سیستم‌ها | endpoints ----------------
    (New-LBRep 'ep-agents' 'endpoint' 'وضعیتِ ایجنت‌ها' 'Agent status' 'آخرین تماس، نسخه و هزینهٔ اجرا' 'Last contact, version and cost per cycle' -Src 'agents' -Cols @($cH, @('seen', 'آخرین تماس', 'Last contact'), @('ver', 'نسخه', 'Version'), @('ip', 'IP', 'IP'), @('perf', 'هزینه', 'Cost'), @('state', 'وضعیت', 'State')))
    (New-LBRep 'ep-hardware' 'endpoint' 'سخت‌افزار و سیستم‌عامل' 'Hardware and operating system' '' '' -Src 'hardware' -Cols @($cH, @('os', 'سیستم‌عامل', 'OS'), @('build', 'بیلد', 'Build'), @('model', 'مدل', 'Model'), @('serial', 'سریال', 'Serial'), @('cpu', 'CPU', 'CPU'), @('ram', 'RAM (GB)', 'RAM (GB)'), @('disk', 'دیسکِ C (آزاد/کل)', 'Disk C (free/total)'), @('user', 'کاربر', 'User')))
    (New-LBRep 'ep-os-eol' 'endpoint' 'سیستم‌عاملِ بدونِ پشتیبانی' 'Unsupported operating systems' 'ویندوزهایی که دیگر به‌روزرسانیِ امنیتی نمی‌گیرند' 'Windows versions that no longer receive security updates' -Src 'hardware' -Where { param($r) [bool]$r.eol } -Cols @($cH, @('os', 'سیستم‌عامل', 'OS'), @('build', 'بیلد', 'Build'), @('eol', 'وضعیت', 'Status')))
    (New-LBRep 'ep-software' 'endpoint' 'نرم‌افزارهای نصب‌شده' 'Installed software' '' '' -Src 'software' -Cols @($cH, @('name', 'نرم‌افزار', 'Software'), @('version', 'نسخه', 'Version'), @('publisher', 'ناشر', 'Publisher'), @('installed', 'تاریخِ نصب', 'Installed')))
    (New-LBRep 'ep-riskysoft' 'endpoint' 'نرم‌افزارهای پرخطر' 'High-risk software' 'دسترسیِ ریموتِ ناامن، تورنت، فیلترشکن، ابزارِ هک، ماینر، نسخه‌های آسیب‌پذیر و منسوخ' 'Remote-access tools, P2P, VPN/proxy, hacking tools, miners, vulnerable and end-of-life versions' -Src 'riskysoft' -Cols @($cH, @('name', 'نرم‌افزار', 'Software'), @('version', 'نسخه', 'Version'), @('risk', 'خطر', 'Risk'), @('why', 'چرا', 'Why')))
    (New-LBRep 'ep-admins' 'endpoint' 'مدیرانِ محلی' 'Local administrators' 'اعضای گروهِ Administrators روی هر سیستم' 'Members of the local Administrators group on each computer' -Src 'admins' -Cols @($cH, @('member', 'عضو', 'Member')))
    (New-LBRep 'ep-posture' 'endpoint' 'پیکربندیِ امنیتیِ نادرست' 'Security misconfigurations' 'بررسی‌های امنیتیِ ناموفق روی هر سیستم (الگو: CIS)' 'Failed security checks on each computer (CIS-style)' -Src 'posture' -Cols @($cH, @('score', 'امتیاز', 'Score'), @('check', 'بررسی', 'Check'), @('sev', 'اهمیت', 'Severity'), @('value', 'وضعیتِ فعلی', 'Current'), @('fix', 'راهِ حل', 'Fix')))
    (New-LBRep 'ep-patches' 'endpoint' 'به‌روزرسانی‌های نصب‌نشده' 'Missing updates' 'به‌روزرسانی‌های امنیتی و مهمی که هنوز نصب نشده‌اند' 'Security and important updates not yet installed' -Src 'patches' -Cols @($cH, @('kb', 'KB', 'KB'), @('title', 'به‌روزرسانی', 'Update'), @('sev', 'شدت', 'Severity'), @('date', 'انتشار', 'Released'), @('reboot', 'نیازِ ری‌استارت', 'Reboot')))
    (New-LBRep 'ep-health' 'endpoint' 'مشکلاتِ سلامتِ سیستم‌ها' 'Endpoint health problems' 'دیسکِ پر، آنتی‌ویروسِ خاموش، امضای قدیمی، فایروالِ خاموش، ری‌استارتِ معوق' 'Low disk, antivirus off, old signatures, firewall off, pending reboot' -Src 'health' -Cols @($cH, @('problem', 'مشکل', 'Problem'), @('value', 'مقدار', 'Value'), @('at', 'زمانِ گزارش', 'Reported')))
)

function Test-LBRepBusinessHours {
    param([datetime]$Time)
    $bh = $script:RepBh
    if (-not $bh) { return $true }
    if (@($bh.Days) -notcontains $Time.DayOfWeek.ToString()) { return $false }
    $m = $Time.Hour * 60 + $Time.Minute
    return ($m -ge $bh.A -and $m -lt $bh.B)
}
$script:Lolbins = @(
    @('powershell.*(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20})', @('پاورشلِ کدشده', 'Encoded PowerShell')),
    @('powershell.*(downloadstring|downloadfile|iwr |invoke-webrequest|net\.webclient|iex)', @('دانلود و اجرا با پاورشل', 'PowerShell download & execute')),
    @('certutil.*(-urlcache|-decode|-split)', @('certutil برای دانلود/رمزگشایی', 'certutil download/decode')),
    @('\\mshta\.exe', @('mshta', 'mshta')), @('regsvr32.*(/i:|scrobj)', @('regsvr32 (Squiblydoo)', 'regsvr32 (Squiblydoo)')),
    @('rundll32.*(javascript:|\.dll,#|comsvcs.*minidump)', @('rundll32 مشکوک / تخلیهٔ حافظه', 'suspicious rundll32 / memory dump')),
    @('vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete', @('حذفِ نسخه‌های پشتیبانِ ویندوز', 'shadow copy/backup deletion')),
    @('bcdedit.*(recoveryenabled|bootstatuspolicy)', @('خاموش‌کردنِ بازیابیِ ویندوز', 'recovery disabled')),
    @('\\(psexec|psexesvc|paexec)', @('PsExec (اجرای راه‌دور)', 'PsExec (remote execution)')),
    @('wmic.*(process call create|/node:)', @('اجرای راه‌دور با WMIC', 'WMIC remote execution')),
    @('bitsadmin.*/transfer', @('دانلود با bitsadmin', 'bitsadmin download')),
    @('net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add', @('ساختِ کاربر از خطِ فرمان', 'user created from command line')),
    @('net1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add', @('افزودن به Administrators', 'added to Administrators')),
    @('schtasks.*/create', @('ساختِ تسک از خطِ فرمان', 'scheduled task from command line')),
    @('reg(\.exe)?\s+add.*\\currentversion\\run', @('ماندگاری در کلیدِ Run', 'Run-key persistence')),
    @('\\(mimikatz|procdump|rubeus|sharphound|bloodhound|lazagne|nc|ncat)(64)?\.exe', @('ابزارِ هک', 'hacking tool')),
    @('wevtutil.*\s(cl|clear-log)\s', @('پاک‌کردنِ لاگ', 'log clearing')),
    @('netsh.*advfirewall.*(state off|set allprofiles state off)', @('خاموش‌کردنِ فایروال', 'firewall disabled')),
    @('set-mppreference.*(disablerealtimemonitoring|exclusionpath)', @('دستکاریِ Defender', 'Defender tampering'))
)
function Get-LBLolbinReason {
    param($r, [string]$Lang = 'en')
    $s = ((Get-LBD $r 'NewProcessName') + ' ' + (Get-LBD $r 'CommandLine')).ToLowerInvariant()
    if (-not $s.Trim()) { return '' }
    foreach ($l in $script:Lolbins) { if ($s -match $l[0]) { return (Get-LBTx $Lang $l[1]) } }
    return ''
}

# مقدارِ هر ستون | value of a column for one record
function Get-LBRepValue {
    param($r, [string]$k, [string]$Lang)
    if ($k.StartsWith('d:')) { return (Get-LBD $r $k.Substring(2)) }
    if (-not $k.StartsWith('c:')) {
        if ($k -eq 'time') { return $r.time.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv) }
        $v = $r.$k; if ($null -eq $v) { return '' }; return [string]$v
    }
    $id = [int]$r.id
    switch ($k.Substring(2)) {
        'ltype'   { return (Get-LBLogonTypeText (Get-LBD $r 'LogonType') $Lang) }
        'reason'  { return (Get-LBStatusText (Get-LBD $r 'Status') (Get-LBD $r 'SubStatus') $Lang) }
        'krb'     { return (Get-LBKrbText (Get-LBD $r 'Status') $Lang) }
        'ntlm'    { return (Get-LBStatusText (Get-LBD $r 'Status') '' $Lang) }
        'proc'    { return (Get-LBShortName (Get-LBD $r 'ProcessName')) }
        'newproc' { return (Get-LBShortName (Get-LBD $r 'NewProcessName')) }
        'parent'  { return (Get-LBShortName (Get-LBD $r 'ParentProcessName')) }
        'lolbin'  { return (Get-LBLolbinReason $r $Lang) }
        'member'  { $m = Get-LBD $r 'MemberName'; if ($m -match '^CN=([^,]+)') { return $Matches[1] }; if ($m) { return $m }; return (Get-LBD $r 'MemberSid') }
        'rdpact'  { $p = @{ 4624 = @('ورود', 'Logon'); 4778 = @('اتصالِ دوباره', 'Reconnect'); 4779 = @('قطعِ اتصال', 'Disconnect') }; return (Get-LBTx $Lang $p[$id]) }
        'lockact' { $p = @{ 4800 = @('قفل', 'Locked'); 4801 = @('بازکردن', 'Unlocked') }; return (Get-LBTx $Lang $p[$id]) }
        'grpact'  { if ($id -in 4728, 4732, 4756) { return (Get-LBTx $Lang @('افزوده شد', 'Added')) }; return (Get-LBTx $Lang @('حذف شد', 'Removed')) }
        'acct'    {
            $p = @{ 4722 = @('فعال شد', 'Enabled'); 4725 = @('غیرفعال شد', 'Disabled'); 4723 = @('تغییرِ رمز توسطِ کاربر', 'Changed by user'); 4724 = @('ریستِ رمز توسطِ مدیر', 'Reset by admin')
                    4738 = @('تغییرِ مشخصات', 'Changed'); 4781 = @('تغییرِ نام', 'Renamed'); 4727 = @('ساخته شد', 'Created'); 4731 = @('ساخته شد', 'Created'); 4754 = @('ساخته شد', 'Created')
                    4730 = @('حذف شد', 'Deleted'); 4734 = @('حذف شد', 'Deleted'); 4758 = @('حذف شد', 'Deleted'); 4741 = @('ساخته شد', 'Created'); 4742 = @('تغییر کرد', 'Changed'); 4743 = @('حذف شد', 'Deleted') }
            $t = Get-LBTx $Lang $p[$id]; if ($id -eq 4781) { $t += (' : {0} → {1}' -f (Get-LBD $r 'OldTargetUserName'), (Get-LBD $r 'NewTargetUserName')) }; return $t }
        'adop'    { $p = @{ 5137 = @('ساخت', 'Created'); 5141 = @('حذف', 'Deleted') }; if ($id -eq 5136) { if ((Get-LBD $r 'OperationType') -eq '%%14675') { return (Get-LBTx $Lang @('مقدارِ قبلی حذف', 'Value removed')) }; return (Get-LBTx $Lang @('مقدارِ جدید', 'Value added')) }; return (Get-LBTx $Lang $p[$id]) }
        'fwact'   { $p = @{ 4946 = @('افزوده', 'Added'); 2004 = @('افزوده', 'Added'); 4947 = @('تغییر', 'Modified'); 2005 = @('تغییر', 'Modified'); 4948 = @('حذف', 'Deleted'); 2006 = @('حذف', 'Deleted') }; return (Get-LBTx $Lang $p[$id]) }
        'fwapp'   { return (Get-LBShortName (Get-LBD $r 'ModifyingApplication')) }
        'svcpath' { $v = Get-LBD $r 'ImagePath'; if (-not $v) { $v = Get-LBD $r 'ServiceFileName' }; return $v }
        'svcacct' { $v = Get-LBD $r 'AccountName'; if (-not $v) { $v = Get-LBD $r 'ServiceAccount' }; return $v }
        'taskact' { $p = @{ 4698 = @('ساخته شد', 'Created'); 4699 = @('حذف شد', 'Deleted'); 4700 = @('فعال شد', 'Enabled'); 4701 = @('غیرفعال شد', 'Disabled'); 4702 = @('تغییر کرد', 'Updated') }; return (Get-LBTx $Lang $p[$id]) }
        'msiact'  { $p = @{ 11707 = @('نصب شد', 'Installed'); 1033 = @('نصب شد', 'Installed'); 11724 = @('حذف شد', 'Removed'); 1034 = @('حذف شد', 'Removed') }; return (Get-LBTx $Lang $p[$id]) }
        'msiname' { $v = Get-LBD $r 'param1'; if (-not $v -or $v -match '^\s*$') { $v = [string]$r.msg }; if ($v -match 'Product:\s*(.+?)\s*--') { return $Matches[1] }; return $v }
        'access'  { $a = Get-LBD $r 'AccessList'; $map = @{ '%%4416' = 'Read'; '%%4417' = 'Write'; '%%4418' = 'Append'; '%%1537' = 'Delete'; '%%4423' = 'Write attributes'; '%%1539' = 'Write permissions'; '%%4424' = 'Write EA' }; $o = @(); foreach ($x in ($a -split '\s+')) { if ($map[$x]) { $o += $map[$x] } }; if ($o.Count) { return ($o -join ', ') }; return $a }
        'shareact'{ $p = @{ 5142 = @('ساخته شد', 'Added'); 5143 = @('تغییر کرد', 'Modified'); 5144 = @('حذف شد', 'Deleted') }; return (Get-LBTx $Lang $p[$id]) }
        'boot'    { $p = @{ 6005 = @('روشن شد', 'Started'); 6006 = @('خاموش شد', 'Shut down'); 6008 = @('خاموشیِ ناگهانی', 'Unexpected shutdown'); 1074 = @('ری‌استارت/خاموش توسطِ کاربر یا برنامه', 'Restart/shutdown initiated'); 41 = @('قطعِ برق یا هنگ', 'Power loss / hang') }; return (Get-LBTx $Lang $p[$id]) }
        'bootwhy' { if ($id -eq 1074) { return ('{0} — {1}' -f (Get-LBShortName (Get-LBD $r 'param1')), (Get-LBD $r 'param3')) }; return '' }
        'upres'   { if ($id -eq 19) { return (Get-LBTx $Lang @('نصب شد', 'Installed')) }; return ((Get-LBTx $Lang @('ناموفق', 'Failed')) + ' ' + (Get-LBD $r 'errorCode')) }
    }
    return ''
}

function Get-LBReportCatalog {
    param([string]$Lang = 'fa')
    $cats = @(); foreach ($k in $script:Cats.Keys) { $cats += [ordered]@{ key = $k; title = (Get-LBTx $Lang $script:Cats[$k]) } }
    $items = @($script:Reports | ForEach-Object { [ordered]@{ id = $_.Id; cat = $_.Cat; title = $(if ($Lang -eq 'en') { $_.En } else { $_.Fa }); desc = $(if ($Lang -eq 'en') { $_.DescEn } else { $_.DescFa }); src = $_.Src; grouped = [bool]$_.Group } })
    return [ordered]@{ categories = $cats; reports = $items }
}
function Get-LBReportDef { param([string]$Id) return ($script:Reports | Where-Object { $_.Id -eq $Id } | Select-Object -First 1) }

# --- خواندنِ انبار با پیش‌فیلتر و تجزیهٔ دسته‌ای (سریع روی PS 5.1) | fast store reader -----------------
function Get-LBArchiveRecords {
    param($Config, [int[]]$Ids, [datetime]$From, [datetime]$To, [string]$HostLike, [string]$UserLike, [string]$Text, [scriptblock]$Where, [int]$Max = 200000, [switch]$Newest)
    $dir = Get-LBArchiveDir -Config $Config
    $idSet = $null; if ($Ids -and $Ids.Count) { $idSet = New-Object 'System.Collections.Generic.HashSet[int]'; foreach ($i in $Ids) { [void]$idSet.Add([int]$i) } }
    $txt = if ($Text) { $Text.ToLowerInvariant() } else { $null }
    $out = New-Object System.Collections.Generic.List[object]
    # -Newest: از جدیدترین روز و جدیدترین رکورد، تا سقف جدیدترین‌ها حفظ شوند | newest day and record first, so the cap keeps the newest
    $day = if ($Newest) { $To.Date } else { $From.Date }
    while ((($Newest -and $day -ge $From.Date) -or (-not $Newest -and $day -le $To.Date)) -and $out.Count -lt $Max) {
        $f = Join-Path $dir ('events-' + $day.ToString('yyyy-MM-dd', $script:Inv) + '.ndjson')
        # رکوردهای روز از کشِ مشترک (یک‌بار تجزیه می‌شوند) | day records from the shared cache (parsed once)
        $dayRecs = Get-LBArchiveDayRecords -File $f
        $seq = if ($Newest) { for ($q = $dayRecs.Count - 1; $q -ge 0; $q--) { $dayRecs[$q] } } else { $dayRecs }
        foreach ($r in $seq) {
            if ($idSet) { $iv = 0; if (-not [int]::TryParse([string]$r.id, [ref]$iv) -or -not $idSet.Contains($iv)) { continue } }
            $t = $r.time
            if ($t -lt $From -or $t -gt $To) { continue }
            if ($HostLike -and [string]$r.host -notlike "*$HostLike*") { continue }
            if ($UserLike -and [string]$r.user -notlike "*$UserLike*" -and (Get-LBD $r 'MemberName') -notlike "*$UserLike*" -and (Get-LBD $r 'SubjectUserName') -notlike "*$UserLike*") { continue }
            if ($txt) { $hay = "$($r.msg) $($r.user) $($r.host) $($r.ip) $($r.id)"; if ($r.d) { foreach ($dp in $r.d.PSObject.Properties) { $hay += ' ' + [string]$dp.Value } }; if ($hay.ToLowerInvariant().IndexOf($txt) -lt 0) { continue } }
            if ($Where -and -not (& $Where $r)) { continue }
            $out.Add($r)
            if ($out.Count -ge $Max) { break }
        }
        $day = if ($Newest) { $day.AddDays(-1) } else { $day.AddDays(1) }
    }
    return , $out
}

# --- دادهٔ ایجنت‌ها | agent-reported data -----------------------------------------------------------
function Get-LBAgentFiles {
    param($Config, [string]$Name, [string]$HostLike)
    $sd = Get-LBStateDir -Config $Config
    $root = Join-Path $sd 'push'
    if (-not (Test-Path $root)) { return @() }
    $out = @()
    foreach ($d in @(Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue)) {
        if ($HostLike -and $d.Name -notlike "*$HostLike*") { continue }
        $f = Join-Path $d.FullName $Name
        if (-not (Test-Path $f)) { continue }
        $j = $null; try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        $out += [pscustomobject]@{ Host = $d.Name; Json = $j }
    }
    return $out
}
$script:RiskRules = @(
    @{ P = 'AnyDesk|TeamViewer|RustDesk|UltraViewer|Radmin|RealVNC|TightVNC|UltraVNC|Splashtop|AeroAdmin|Ammyy|Supremo|DWService|ScreenConnect|LogMeIn|Chrome Remote Desktop|NoMachine|Zoho Assist'; R = 'high'; W = @('دسترسیِ ریموتِ خارج از کنترل؛ روشِ رایجِ نفوذ و باج‌افزار', 'Unmanaged remote access — a common intrusion and ransomware vector') }
    @{ P = 'uTorrent|BitTorrent|qBittorrent|Vuze|FrostWire|eMule|Deluge|Transmission|BitComet|Tixati'; R = 'medium'; W = @('اشتراکِ فایلِ P2P؛ نشتِ داده و بدافزار', 'P2P file sharing — data leaks and malware') }
    @{ P = 'Psiphon|Hotspot Shield|Tor Browser|Ultrasurf|Windscribe|ProtonVPN|Lantern|v2rayN|Clash|Hiddify|NekoRay|OpenVPN Connect|Outline|Shadowsocks|Freegate|Betternet|Turbo VPN|SoftEther'; R = 'medium'; W = @('فیلترشکن/پروکسی؛ دور زدنِ کنترل‌های شبکه', 'VPN/proxy — bypasses network controls') }
    @{ P = 'Nmap|Zenmap|Wireshark|Cain|Mimikatz|Metasploit|Hashcat|John the Ripper|Angry IP Scanner|Advanced IP Scanner|NetScan|Burp Suite|sqlmap|Hydra|Responder|Process Hacker|Cheat Engine'; R = 'medium'; W = @('ابزارِ هک/اسکن؛ فقط برای مدیرانِ مجاز', 'Hacking/scanning tool — authorised admins only') }
    @{ P = 'NiceHash|XMRig|Claymore|PhoenixMiner|Honeyminer|Cudo Miner|MinerGate'; R = 'high'; W = @('ماینرِ رمزارز؛ مصرفِ منابع و نشانهٔ نفوذ', 'Crypto miner — resource abuse, often a compromise sign') }
    @{ P = 'Adobe Flash|Java\(TM\) [67]|Java [67] Update|Silverlight|Python 2\.|QuickTime|Internet Explorer [6-9]'; R = 'high'; W = @('نرم‌افزارِ منسوخ بدونِ وصلهٔ امنیتی', 'End-of-life software, no security fixes') }
)
$script:VulnVersions = @(
    @{ P = '^WinRAR'; Min = '6.23'; W = @('WinRAR قدیمی‌تر از 6.23 (CVE-2023-38831 و CVE-2025-8088)', 'WinRAR older than 6.23 (CVE-2023-38831, CVE-2025-8088)') }
    @{ P = '^7-Zip'; Min = '24.9'; W = @('7-Zip قدیمی‌تر از 24.09 (CVE-2024-11477 و CVE-2025-0411)', '7-Zip older than 24.09 (CVE-2024-11477, CVE-2025-0411)') }
    @{ P = '^Notepad\+\+'; Min = '8.6'; W = @('Notepad++ قدیمی (آسیب‌پذیری‌های شناخته‌شده)', 'Old Notepad++ (known vulnerabilities)') }
    @{ P = '^VLC media player'; Min = '3.0.21'; W = @('VLC قدیمی‌تر از 3.0.21', 'VLC older than 3.0.21') }
)
function ConvertTo-LBVersion { param([string]$v) $m = [regex]::Match([string]$v, '\d+(\.\d+){0,3}'); if (-not $m.Success) { return $null }; $p = @($m.Value.Split('.') | ForEach-Object { [int]$_ }); while ($p.Count -lt 4) { $p += 0 }; return (New-Object Version($p[0], $p[1], $p[2], $p[3])) }
function Get-LBSoftwareRisk {
    param([string]$Name, [string]$Version, [string]$Lang = 'fa')
    foreach ($r in $script:RiskRules) { if ($Name -match $r.P) { return @{ risk = $r.R; why = (Get-LBTx $Lang $r.W) } } }
    foreach ($r in $script:VulnVersions) { if ($Name -match $r.P) { $v = ConvertTo-LBVersion $Version; if (-not $v) { $v = ConvertTo-LBVersion $Name }; $mn = ConvertTo-LBVersion $r.Min; if ($v -and $mn -and $v -lt $mn) { return @{ risk = 'high'; why = (Get-LBTx $Lang $r.W) } } } }
    return $null
}
function Get-LBOsEol {
    param([string]$Caption, [string]$Build, [string]$Lang = 'fa')
    $c = [string]$Caption; $b = 0; [void][int]::TryParse(([string]$Build), [ref]$b)
    if ($c -match 'Windows (XP|Vista|7|8)\b|Windows 8\.1|Server 200[038]|Server 2012') { return (Get-LBTx $Lang @('بدونِ پشتیبانی', 'End of support')) }
    if ($c -match 'Windows 10' -and $c -notmatch 'LTSC|LTSB|Enterprise 2019|IoT') { return (Get-LBTx $Lang @('پشتیبانی پایان یافته (اکتبر ۲۰۲۵)؛ فقط با ESU', 'Support ended Oct 2025 — ESU only')) }
    if ($c -match 'Windows 11' -and $b -gt 0 -and $b -lt 22631) { return (Get-LBTx $Lang @('نسخهٔ ویندوز ۱۱ قدیمی (بدونِ به‌روزرسانی)', 'Old Windows 11 release (no updates)')) }
    return ''
}

# --- اجرای گزارش | run a report -------------------------------------------------------------------
function Invoke-LBReport {
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$Id, [datetime]$From = (Get-Date).AddDays(-1), [datetime]$To = (Get-Date),
          [string]$HostLike, [string]$UserLike, [string]$Text, [int]$Max = 5000, [string]$Lang = 'fa')
    $def = Get-LBReportDef -Id $Id
    if (-not $def) { throw "unknown report: $Id" }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $bhc = if ($Config.Alerts -and $Config.Alerts.BusinessHours) { $Config.Alerts.BusinessHours } else { @{} }
    $s0 = if ($bhc.Start) { [string]$bhc.Start } else { '08:00' }; $e0 = if ($bhc.End) { [string]$bhc.End } else { '17:00' }
    $script:RepBh = @{ Days = @($(if ($bhc.Days) { $bhc.Days } else { @('Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday') })); A = [int]$s0.Split(':')[0] * 60 + [int]$s0.Split(':')[1]; B = [int]$e0.Split(':')[0] * 60 + [int]$e0.Split(':')[1] }
    $cols = @($def.Cols | ForEach-Object { [ordered]@{ k = [string]$_[0]; t = $(if ($Lang -eq 'en') { [string]$_[2] } else { [string]$_[1] }) } })
    $rows = New-Object System.Collections.Generic.List[object]
    $total = 0
    $txtL = if ($Text) { $Text.ToLowerInvariant() } else { $null }
    $addRow = { param([object[]]$vals) if ($txtL -and (($vals -join ' ').ToLowerInvariant().IndexOf($txtL) -lt 0)) { return }; $script:__t++; if ($rows.Count -lt $Max) { $rows.Add($vals) } }
    $script:__t = 0
    switch ($def.Src) {
        'events' {
            $recs = Get-LBArchiveRecords -Config $Config -Ids $def.Ids -From $From -To $To -HostLike $HostLike -UserLike $UserLike -Where $def.Where -Max $(if ($def.Group) { 500000 } else { [math]::Max($Max * 4, 20000) })
            if ($def.Group) {
                $g = @{}
                foreach ($r in $recs) {
                    $kv = @($def.Group | ForEach-Object { Get-LBRepValue $r $_ $Lang })
                    $key = $kv -join [string][char]1
                    if (-not $g.ContainsKey($key)) { $g[$key] = @{ v = $kv; n = 0; a = $r.time; b = $r.time } }
                    $e = $g[$key]; $e.n++; if ($r.time -lt $e.a) { $e.a = $r.time }; if ($r.time -gt $e.b) { $e.b = $r.time }
                }
                foreach ($e in @($g.Values | Sort-Object { $_.n } -Descending)) { & $addRow (@($e.v) + @([string]$e.n, $e.a.ToString('yyyy-MM-dd HH:mm', $script:Inv), $e.b.ToString('yyyy-MM-dd HH:mm', $script:Inv))) }
                $cols = @($cols | Where-Object { $def.Group -contains $_.k }) + @([ordered]@{ k = 'count'; t = $(if ($Lang -eq 'en') { 'Count' } else { 'تعداد' }) }, [ordered]@{ k = 'first'; t = $(if ($Lang -eq 'en') { 'First' } else { 'اولین' }) }, [ordered]@{ k = 'last'; t = $(if ($Lang -eq 'en') { 'Last' } else { 'آخرین' }) })
            } else {
                foreach ($r in @($recs | Sort-Object time -Descending)) { & $addRow @($cols | ForEach-Object { Get-LBRepValue $r $_.k $Lang }) }
            }
        }
        'sessions' {
            # همان منطقِ صفحهٔ «نشست‌ها» | same logic as the Sessions page
            foreach ($x in @(Get-LBSessionHistory -Config $Config -From $From -To $To -HostLike $HostLike -UserLike $UserLike -Max 100000)) {
                $end = $x.end; $dur = [math]::Round(($(if ($end) { $end } else { Get-Date }) - $x.start).TotalMinutes, 0)
                $endTxt = if ($end) { $end.ToString('yyyy-MM-dd HH:mm', $script:Inv) } elseif ($x.how -eq 'unknown') { (Get-LBTx $Lang @('نامعلوم', 'unknown')) } else { (Get-LBTx $Lang @('باز', 'open')) }
                $ltc = switch ($x.type) { 'rdp' { '10' } 'cached' { '11' } default { '2' } }
                $srcTxt = (@($x.device, $x.ip) | Where-Object { $_ }) -join ' / '
                & $addRow @($x.start.ToString('yyyy-MM-dd HH:mm', $script:Inv), $endTxt, [string]$dur, [string]$x.host, [string]$x.user, (Get-LBLogonTypeText $ltc $Lang), $srcTxt)
            }
        }
        'lockout' {
            foreach ($row in @(Get-LBLockoutAnalysis -Config $Config -From $From -To $To -UserLike $UserLike -HostLike $HostLike -Lang $Lang)) { & $addRow @($row.time, $row.user, $row.dc, $row.caller, [string]$row.fails, $row.sources, $row.cause) }
        }
        'findings' {
            $minS = if ($def.MinSev) { $def.MinSev } else { '' }
            $res = Get-LBFindings -Config $Config -From $From -To $To -Category $def.Categories -Severity $minS -HostName $HostLike -Max 100000
            $sevT = @{ Critical = @('بحرانی', 'Critical'); Warning = @('هشدار', 'Warning'); Info = @('اطلاع', 'Info') }
            if ($def.Group) {
                $g = @{}
                foreach ($f in @($res.Items)) { $k = '{0}|{1}' -f $f.cat, $f.host; if (-not $g.ContainsKey($k)) { $g[$k] = @{ c = [string]$f.cat; h = [string]$f.host; n = 0; a = [string]$f.t; b = [string]$f.t } }; $g[$k].n++; if ([string]$f.t -lt $g[$k].a) { $g[$k].a = [string]$f.t }; if ([string]$f.t -gt $g[$k].b) { $g[$k].b = [string]$f.t } }
                foreach ($e in @($g.Values | Sort-Object { $_.n } -Descending)) { & $addRow @($e.c, $e.h, [string]$e.n, (Format-LBRepTime $e.a), (Format-LBRepTime $e.b)) }
                $cols = @($cols) + @([ordered]@{ k = 'count'; t = $(if ($Lang -eq 'en') { 'Count' } else { 'تعداد' }) }, [ordered]@{ k = 'first'; t = $(if ($Lang -eq 'en') { 'First' } else { 'اولین' }) }, [ordered]@{ k = 'last'; t = $(if ($Lang -eq 'en') { 'Last' } else { 'آخرین' }) })
            } else {
                foreach ($f in @($res.Items)) {
                    $ti = [string]$f.title; $ix = $ti.IndexOf(' | '); if ($ix -ge 0) { $ti = $(if ($Lang -eq 'en') { $ti.Substring($ix + 3) } else { $ti.Substring(0, $ix) }) }
                    $vals = foreach ($c in $cols) { switch ($c.k) { 'time' { Format-LBRepTime ([string]$f.t) } 'sev' { Get-LBTx $Lang $sevT[[string]$f.sev] } 'cat' { [string]$f.cat } 'host' { [string]$f.host } 'title' { $ti } default { '' } } }
                    & $addRow @($vals)
                }
            }
        }
        'agents' {
            $keys = @{}; try { if (Get-Command Get-LBAgentKeys -ErrorAction SilentlyContinue) { $keys = Get-LBAgentKeys -StateDir (Get-LBStateDir -Config $Config) } } catch { }
            foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'last.json' -HostLike $HostLike)) {
                $j = $a.Json; $seen = [string]$j.At; $ago = ''
                $dt = $null; try { $dt = ConvertTo-LBDate $seen } catch { }
                $state = ''; if ($dt) { $min = ((Get-Date) - $dt).TotalMinutes; $state = $(if ($min -le 10) { Get-LBTx $Lang @('آنلاین', 'online') } elseif ($min -le 1440) { Get-LBTx $Lang @('تأخیر', 'late') } else { Get-LBTx $Lang @('خاموش/قطع', 'offline') }) }
                $k = $keys[$a.Host]; if ($k -and [string]$k.Status -eq 'revoked') { $state = Get-LBTx $Lang @('ابطال‌شده', 'revoked') }
                $pf = if ($j.Perf) { '{0}s CPU · {1}MB' -f $j.Perf.CpuSeconds, $j.Perf.MemMB } else { '' }
                & $addRow @($a.Host, (Format-LBRepTime $seen), [string]$j.Version, [string]$j.Ip, $pf, $state)
            }
        }
        { $_ -in 'hardware', 'admins', 'software', 'riskysoft' } {
            foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'inventory.json' -HostLike $HostLike)) {
                $d = $a.Json.Data
                if ($def.Src -eq 'hardware') {
                    $c = @($d.disks | Where-Object { $_.d -eq 'C:' }) | Select-Object -First 1
                    $eol = Get-LBOsEol ([string]$d.os.n) ([string]$d.os.b) $Lang
                    $r = [pscustomobject]@{ eol = $eol }
                    if ($def.Where -and -not (& $def.Where $r)) { continue }
                    if ($Id -eq 'ep-os-eol') { & $addRow @($a.Host, [string]$d.os.n, [string]$d.os.b, $eol); continue }
                    & $addRow @($a.Host, [string]$d.os.n, [string]$d.os.b, ('{0} {1}' -f $d.hw.mf, $d.hw.model).Trim(), [string]$d.hw.serial, ((@($d.cpu) | ForEach-Object { $_.n }) -join ' · '), [string]$d.hw.ramGB, $(if ($c) { '{0} / {1} GB' -f $c.freeGB, $c.sizeGB } else { '' }), [string]$d.hw.user)
                } elseif ($def.Src -eq 'admins') {
                    foreach ($m in @($d.admins)) { if ($m) { & $addRow @($a.Host, [string]$m) } }
                } else {
                    foreach ($s in @($d.software)) {
                        if (-not $s) { continue }
                        if ($def.Src -eq 'riskysoft') { $rk = Get-LBSoftwareRisk ([string]$s.n) ([string]$s.v) $Lang; if (-not $rk) { continue }; & $addRow @($a.Host, [string]$s.n, [string]$s.v, $(if ($rk.risk -eq 'high') { Get-LBTx $Lang @('بالا', 'High') } else { Get-LBTx $Lang @('متوسط', 'Medium') }), $rk.why) }
                        else { & $addRow @($a.Host, [string]$s.n, [string]$s.v, [string]$s.p, [string]$s.d) }
                    }
                }
            }
        }
        'posture' {
            foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'posture.json' -HostLike $HostLike)) {
                $d = $a.Json.Data
                foreach ($c in @($d.checks | Where-Object { $_ -and $_.ok -eq $false })) { & $addRow @($a.Host, [string]$d.score, $(if ($Lang -eq 'en') { [string]$c.en } else { [string]$c.fa }), $(if ($c.sev -eq 'high') { Get-LBTx $Lang @('بالا', 'High') } elseif ($c.sev -eq 'medium') { Get-LBTx $Lang @('متوسط', 'Medium') } else { Get-LBTx $Lang @('کم', 'Low') }), [string]$c.val, $(if ($Lang -eq 'en') { [string]$c.fixEn } else { [string]$c.fixFa })) }
            }
        }
        'patches' {
            foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'patches.json' -HostLike $HostLike)) {
                foreach ($u in @($a.Json.Data.missing)) { if ($u) { & $addRow @($a.Host, [string]$u.kb, [string]$u.title, [string]$u.sev, [string]$u.date, $(if ($u.reboot) { Get-LBTx $Lang @('بله', 'Yes') } else { '' })) } }
            }
        }
        'health' {
            foreach ($row in @(Get-LBHealthProblems -Config $Config -HostLike $HostLike -Lang $Lang)) { & $addRow @($row.host, $row.problem, $row.value, $row.at) }
        }
    }
    $sw.Stop()
    return [ordered]@{ id = $Id; title = $(if ($Lang -eq 'en') { $def.En } else { $def.Fa }); columns = $cols; rows = $rows.ToArray(); total = $script:__t; truncated = ($script:__t -gt $rows.Count); ms = [int]$sw.ElapsedMilliseconds
                       from = $From.ToString('yyyy-MM-dd HH:mm', $script:Inv); to = $To.ToString('yyyy-MM-dd HH:mm', $script:Inv) }
}
function Format-LBRepTime { param([string]$s) $d = $null; try { $d = ConvertTo-LBDate $s } catch { }; if ($d) { if ($d.Kind -eq [DateTimeKind]::Utc) { $d = $d.ToLocalTime() }; return $d.ToString('yyyy-MM-dd HH:mm', $script:Inv) }; return $s }

# --- تحلیلِ علتِ قفل‌شدن | account lockout analyzer --------------------------------------------------
function Get-LBLockoutAnalysis {
    param($Config, [datetime]$From, [datetime]$To, [string]$UserLike, [string]$HostLike, [string]$Lang = 'fa', [int]$LookbackMinutes = 60)
    $locks = Get-LBArchiveRecords -Config $Config -Ids @(4740) -From $From -To $To -UserLike $UserLike -HostLike $HostLike -Max 2000
    if (-not $locks.Count) { return @() }
    $fails = Get-LBArchiveRecords -Config $Config -Ids @(4625, 4771, 4776) -From $From.AddMinutes(-$LookbackMinutes) -To $To -Max 300000
    $byUser = @{}
    foreach ($f in $fails) { $u = ([string]$f.user).ToLowerInvariant(); if (-not $u) { continue }; if (-not $byUser.ContainsKey($u)) { $byUser[$u] = New-Object System.Collections.Generic.List[object] }; $byUser[$u].Add($f) }
    $out = @()
    foreach ($l in @($locks | Sort-Object time -Descending)) {
        $u = ([string]$l.user).ToLowerInvariant()
        $rel = @(); if ($byUser.ContainsKey($u)) { $rel = @($byUser[$u] | Where-Object { $_.time -le $l.time.AddSeconds(5) -and $_.time -ge $l.time.AddMinutes(-$LookbackMinutes) }) }
        $src = @{}; $types = @{}; $procs = @{}
        foreach ($f in $rel) {
            $s = [string]$f.ip; if (-not $s -or $s -in '-', '::1', '127.0.0.1') { $s = Get-LBD $f 'WorkstationName' }; if (-not $s) { $s = Get-LBD $f 'Workstation' }; if (-not $s) { $s = [string]$f.host }
            $src[$s] = 1 + [int]$src[$s]
            $lt = Get-LBD $f 'LogonType'; if ($f.id -eq 4771) { $lt = 'krb' } elseif ($f.id -eq 4776) { $lt = 'ntlm' }; if ($lt) { $types[$lt] = 1 + [int]$types[$lt] }
            $p = Get-LBShortName (Get-LBD $f 'ProcessName'); if ($p) { $procs[$p] = 1 + [int]$procs[$p] }
        }
        $top = @($src.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value }) -join ', '
        $caller = Get-LBD $l 'TargetDomainName'
        $tk = @($types.Keys)
        $cause = if ($tk -contains '5') { Get-LBTx $Lang @('سرویسی با رمزِ قدیمی روی سیستمِ مبدأ اجرا می‌شود (services.msc → Log On)', 'A service runs with the old password on the source computer (services.msc → Log On)') }
                 elseif ($tk -contains '4') { Get-LBTx $Lang @('تسکِ زمان‌بندی‌شده با رمزِ قدیمی (Task Scheduler)', 'A scheduled task uses the old password (Task Scheduler)') }
                 elseif ($tk -contains '10') { Get-LBTx $Lang @('نشستِ ریموت‌دسکتاپِ باز یا اتصالِ RDP ذخیره‌شده با رمزِ قدیمی', 'An open RDP session or a saved RDP connection with the old password') }
                 elseif ($tk -contains '3') { Get-LBTx $Lang @('درایوِ شبکه، برنامه یا گوشیِ متصل با رمزِ قدیمی (Credential Manager را پاک کنید)', 'A mapped drive, app or phone with the old password (clear Credential Manager)') }
                 elseif ($tk -contains '7' -or $tk -contains '2' -or $tk -contains '11') { Get-LBTx $Lang @('کاربر پشتِ سیستم رمز را اشتباه وارد کرده', 'The user typed a wrong password at the console') }
                 elseif ($tk -contains 'krb') { Get-LBTx $Lang @('درخواستِ Kerberos از سیستمِ مبدأ با رمزِ قدیمی (برنامه، سرویس یا دستگاه)', 'Kerberos requests from the source with the old password (app, service or device)') }
                 elseif ($tk -contains 'ntlm') { Get-LBTx $Lang @('اعتبارسنجیِ NTLM از سیستمِ مبدأ (برنامه یا درایوِ شبکه)', 'NTLM validation from the source (app or mapped drive)') }
                 elseif (-not $rel.Count) { Get-LBTx $Lang @('تلاشِ ناموفقِ ثبت‌شده‌ای پیدا نشد؛ ممیزیِ ورود روی سیستمِ مبدأ را بررسی کنید', 'No recorded failures; check logon auditing on the source computer') }
                 else { Get-LBTx $Lang @('نامشخص', 'Unknown') }
        if ($procs.Count) { $cause += ' — ' + ((@($procs.Keys) | Select-Object -First 3) -join ', ') }
        $out += [ordered]@{ time = $l.time.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv); user = [string]$l.user; dc = [string]$l.host; caller = $caller; fails = $rel.Count; sources = $top; cause = $cause }
    }
    return $out
}

# --- مشکلاتِ سلامت | endpoint health problems (also used for findings) ---------------------------
function Get-LBHealthProblems {
    param($Config, [string]$HostLike, [string]$Lang = 'fa')
    $h = if ($Config.EndpointHealth) { $Config.EndpointHealth } else { @{} }
    $minFree = if ($h.MinDiskFreePct) { [int]$h.MinDiskFreePct } else { 10 }
    $maxSig = if ($h.MaxSignatureAgeDays) { [int]$h.MaxSignatureAgeDays } else { 3 }
    $out = @()
    foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'health.json' -HostLike $HostLike)) {
        $d = $a.Json.Data; $at = Format-LBRepTime ([string]$a.Json.At)
        if ($null -ne $d.cFreePct -and [int]$d.cFreePct -lt $minFree) { $out += [ordered]@{ host = $a.Host; key = 'disk'; sev = $(if ([int]$d.cFreePct -lt 5) { 'Critical' } else { 'Warning' }); problem = (Get-LBTx $Lang @('فضای دیسکِ C کم است', 'Low disk space on C:')); value = ('{0}% ({1} GB)' -f $d.cFreePct, $d.cFreeGB); at = $at } }
        if ($d.av) {
            if ($d.av.rt -eq $false) { $out += [ordered]@{ host = $a.Host; key = 'av-off'; sev = 'Critical'; problem = (Get-LBTx $Lang @('محافظتِ آنیِ Defender خاموش است', 'Defender real-time protection is off')); value = 'off'; at = $at } }
            elseif ($null -ne $d.av.sigAge -and [int]$d.av.sigAge -gt $maxSig) { $out += [ordered]@{ host = $a.Host; key = 'av-sig'; sev = 'Warning'; problem = (Get-LBTx $Lang @('امضای آنتی‌ویروس قدیمی است', 'Antivirus signatures are out of date')); value = ('{0} d' -f $d.av.sigAge); at = $at } }
        }
        if ($d.fw) { $off = @($d.fw.PSObject.Properties | Where-Object { $_.Value -eq $false } | ForEach-Object { $_.Name }); if ($off.Count) { $out += [ordered]@{ host = $a.Host; key = 'fw-off'; sev = 'Critical'; problem = (Get-LBTx $Lang @('فایروالِ ویندوز خاموش است', 'Windows Firewall is off')); value = ($off -join ', '); at = $at } } }
        if ($d.rebootPending -eq $true) { $out += [ordered]@{ host = $a.Host; key = 'reboot'; sev = 'Info'; problem = (Get-LBTx $Lang @('برای تکمیلِ به‌روزرسانی ری‌استارت لازم است', 'A restart is pending to finish updates')); value = $(if ($d.uptimeH) { '{0} h uptime' -f $d.uptimeH } else { '' }); at = $at } }
        if ($null -ne $d.memFreePct -and [int]$d.memFreePct -lt 5) { $out += [ordered]@{ host = $a.Host; key = 'mem'; sev = 'Warning'; problem = (Get-LBTx $Lang @('حافظهٔ آزاد خیلی کم است', 'Very low free memory')); value = ('{0}%' -f $d.memFreePct); at = $at } }
        if ($d.isolated -eq $true) { $out += [ordered]@{ host = $a.Host; key = 'isolated'; sev = 'Warning'; problem = (Get-LBTx $Lang @('سیستم ایزوله است', 'Computer is isolated')); value = ''; at = $at } }
    }
    # فقط ایجنت‌های فعال (نه لغوشده/فراموش‌شده) | only agents with an active key, not revoked/forgotten ones
    $active = $null; try { if (-not (Get-Command Get-LBAgentKeys -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $PSScriptRoot 'LogBok.AgentIn.psm1') -DisableNameChecking -ErrorAction Stop }; $ak = Get-LBAgentKeys -StateDir (Get-LBStateDir -Config $Config); if ($ak.Count) { $active = @{}; foreach ($k in @($ak.Keys)) { if ([string]$ak[$k].Status -eq 'active') { $active[([string]$k).ToUpperInvariant()] = $true } } } } catch { $active = $null }
    foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'last.json' -HostLike $HostLike)) {
        if ($null -ne $active -and -not $active[([string]$a.Host).ToUpperInvariant()]) { continue }
        $dt = $null; try { $dt = ConvertTo-LBDate ([string]$a.Json.At) } catch { }
        if ($dt) { $hrs = ((Get-Date) - $dt).TotalHours; $off = if ($h.OfflineHours) { [double]$h.OfflineHours } else { 24 }; if ($hrs -gt $off -and $hrs -lt 24 * 60) { $out += [ordered]@{ host = $a.Host; key = 'offline'; sev = 'Warning'; problem = (Get-LBTx $Lang @('ایجنت تماس نگرفته', 'Agent has not reported')); value = ('{0} h' -f [math]::Round($hrs, 0)); at = (Format-LBRepTime ([string]$a.Json.At)) } } }
    }
    return $out
}


# --- یافته‌های سلامت و امنیتِ سیستم‌ها (روزی یک‌بار برای هر مشکل) | endpoint health findings ---------------
function Get-LBEndpointFindings {
    param([Parameter(Mandatory)]$Config)
    $sd = Get-LBStateDir -Config $Config
    $sf = Join-Path $sd 'endpoint-findings.json'
    $st = @{}; if (Test-Path $sf) { try { $st = ConvertTo-LBHashtable (Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json); if (-not ($st -is [hashtable])) { $st = @{} } } catch { $st = @{} } }
    $fa = @(Get-LBHealthProblems -Config $Config -Lang fa); $en = @(Get-LBHealthProblems -Config $Config -Lang en)
    $items = @()
    for ($i = 0; $i -lt $fa.Count; $i++) { if ($fa[$i].sev -eq 'Info') { continue }; $items += @{ host = $fa[$i].host; key = $fa[$i].key; sev = $fa[$i].sev; fa = $fa[$i].problem; en = $en[$i].problem; val = $fa[$i].value } }
    $h = if ($Config.EndpointHealth) { $Config.EndpointHealth } else { @{} }
    $minScore = if ($h.MinPostureScore) { [int]$h.MinPostureScore } else { 60 }
    foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'posture.json')) {
        $sc = [int]$a.Json.Data.score
        if ($sc -gt 0 -and $sc -lt $minScore) { $n = @($a.Json.Data.checks | Where-Object { $_.ok -eq $false }).Count; $items += @{ host = $a.Host; key = 'posture'; sev = 'Warning'; fa = "پیکربندیِ امنیتیِ ضعیف (امتیاز $sc از ۱۰۰)"; en = "Weak security configuration (score $sc/100)"; val = "$n failed checks" } }
    }
    $maxAge = if ($h.MaxPatchAgeDays) { [int]$h.MaxPatchAgeDays } else { 30 }
    foreach ($a in @(Get-LBAgentFiles -Config $Config -Name 'patches.json')) {
        $old = @($a.Json.Data.missing | Where-Object { $_ -and $_.security -and $_.date -and ((Get-Date) - [datetime]::ParseExact([string]$_.date, 'yyyy-MM-dd', $script:Inv)).TotalDays -gt $maxAge })
        if ($old.Count) { $items += @{ host = $a.Host; key = 'patch-old'; sev = 'Warning'; fa = ("{0} به‌روزرسانیِ امنیتیِ قدیمی نصب نشده" -f $old.Count); en = ("{0} old security update(s) not installed" -f $old.Count); val = ((@($old | Select-Object -First 5 | ForEach-Object { $_.kb })) -join ', ') } }
    }
    $out = @(); $now = Get-Date; $seen = @{}
    foreach ($it in $items) {
        $k = '{0}|{1}' -f $it.host, $it.key; $seen[$k] = $true
        $last = $null; if ($st[$k]) { try { $last = ConvertTo-LBDate ([string]$st[$k]) } catch { } }
        if ($last -and $last -gt $now.AddHours(-24)) { continue }
        $st[$k] = $now.ToString('o', $script:Inv)
        $out += [pscustomobject]@{ Category = 'EndpointHealth'; Severity = $it.sev; Machine = $it.host; Time = $now; Title = ('{0} | {1}' -f $it.fa, $it.en)
                                   Details = ("سیستم: {0}`nمقدار: {1}" -f $it.host, $it.val); Key = ('EP|{0}|{1}|{2}' -f $it.host, $it.key, $now.ToString('yyyyMMdd', $script:Inv)) }
    }
    foreach ($k in @($st.Keys)) { if (-not $seen[$k]) { $st.Remove($k) } }
    try { [IO.File]::WriteAllText($sf, (ConvertTo-Json -InputObject $st), (New-Object Text.UTF8Encoding($false))) } catch { }
    return $out
}

# --- ۳۶۰ درجهٔ کاربر | user 360 activity trail -------------------------------------------------------
# کاربرانِ اخیر (ورودهای موفق) برای انتخابِ سریع در «کاربر ۳۶۰» | recent users (successful logons) for quick pick in User 360
function Get-LBRecentUsers {
    param([Parameter(Mandatory)]$Config, [int]$Hours = 24, [int]$Top = 40)
    $skip = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-|)$'
    $recs = Get-LBArchiveRecords -Config $Config -Ids @(4624, 4625) -From (Get-Date).AddHours(-$Hours) -To (Get-Date) -Max 30000 -Newest
    $m = @{}
    foreach ($r in $recs) {
        $u = [string]$r.user; if ($u -match '\\') { $u = $u.Split('\')[-1] }
        if (-not $u -or $u -match $skip -or $u.EndsWith('$')) { continue }
        $lt = Get-LBD $r 'LogonType'; if ($lt -in '0', '5') { continue }
        $k = $u.ToLowerInvariant()
        if (-not $m.ContainsKey($k)) { $m[$k] = [ordered]@{ user = $u; logons = 0; failed = 0; hosts = @{}; last = $r.time } }
        $e = $m[$k]; if ([int]$r.id -eq 4625) { $e.failed++ } else { $e.logons++ }; $e.hosts[[string]$r.host] = 1; if ($r.time -gt $e.last) { $e.last = $r.time }
    }
    return @($m.Values | Sort-Object { $_.failed * 5 + $_.logons } -Descending | Select-Object -First $Top | ForEach-Object {
        [ordered]@{ user = $_.user; logons = $_.logons; failed = $_.failed; hosts = $_.hosts.Count; last = $_.last.ToString('yyyy-MM-dd HH:mm', $script:Inv) } })
}

function Get-LBUserActivity {
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string]$User, [datetime]$From = (Get-Date).AddDays(-7), [datetime]$To = (Get-Date), [string]$Lang = 'fa', [int]$Max = 500)
    $u = $User.Trim(); if ($u -match '\\') { $u = $u.Split('\')[-1] }
    if (-not $u -or $u.Length -lt 2) { throw 'user name required' }
    $ids = @(4624, 4625, 4634, 4647, 4648, 4740, 4767, 4771, 4776, 4778, 4779, 4800, 4801, 4720, 4722, 4725, 4726, 4723, 4724, 4738, 4781, 4728, 4729, 4732, 4733, 4756, 4757, 4688, 4698, 4702, 4697, 7045, 4663, 4660, 4670, 1102, 4719, 5136, 5137, 5141)
    $ul = $u.ToLowerInvariant()
    # بدونِ جست‌وجوی متنیِ سنگین؛ شرطِ دقیقِ کاربر کافی است | no heavy full-text pass; the exact user check is enough
    $recs = Get-LBArchiveRecords -Config $Config -Ids $ids -From $From -To $To -Max 20000 -Newest -Where { param($r) ([string]$r.user).ToLowerInvariant() -eq $ul -or (Get-LBD $r 'SubjectUserName').ToLowerInvariant() -eq $ul -or (Get-LBD $r 'MemberName').ToLowerInvariant() -like "*cn=$ul,*" -or (Get-LBD $r 'TargetUserName').ToLowerInvariant() -eq $ul }
    $sum = [ordered]@{ logons = 0; failed = 0; lockouts = 0; hosts = @{}; ips = @{}; admin = 0; afterHours = 0; changesBy = 0; changesOn = 0; processes = 0 }
    $bhc = if ($Config.Alerts -and $Config.Alerts.BusinessHours) { $Config.Alerts.BusinessHours } else { @{} }
    $s0 = if ($bhc.Start) { [string]$bhc.Start } else { '08:00' }; $e0 = if ($bhc.End) { [string]$bhc.End } else { '17:00' }
    $script:RepBh = @{ Days = @($(if ($bhc.Days) { $bhc.Days } else { @('Saturday', 'Sunday', 'Monday', 'Tuesday', 'Wednesday') })); A = [int]$s0.Split(':')[0] * 60 + [int]$s0.Split(':')[1]; B = [int]$e0.Split(':')[0] * 60 + [int]$e0.Split(':')[1] }
    $tl = New-Object System.Collections.Generic.List[object]
    $names = @{
        4624 = @('ورود', 'Logon'); 4625 = @('ورودِ ناموفق', 'Failed logon'); 4634 = @('خروج', 'Logoff'); 4647 = @('خروج', 'Logoff'); 4648 = @('ورود با اعتبارنامهٔ دیگر', 'Explicit credentials'); 4740 = @('حساب قفل شد', 'Account locked out')
        4767 = @('قفل باز شد', 'Account unlocked'); 4771 = @('Kerberos ناموفق', 'Kerberos failure'); 4776 = @('NTLM', 'NTLM validation'); 4778 = @('اتصالِ دوبارهٔ RDP', 'RDP reconnect'); 4779 = @('قطعِ RDP', 'RDP disconnect')
        4800 = @('قفلِ صفحه', 'Screen locked'); 4801 = @('بازکردنِ صفحه', 'Screen unlocked'); 4720 = @('حساب ساخته شد', 'Account created'); 4722 = @('حساب فعال شد', 'Account enabled'); 4725 = @('حساب غیرفعال شد', 'Account disabled')
        4726 = @('حساب حذف شد', 'Account deleted'); 4723 = @('رمز را عوض کرد', 'Changed password'); 4724 = @('رمز ریست شد', 'Password reset'); 4738 = @('حساب تغییر کرد', 'Account changed'); 4781 = @('تغییرِ نام', 'Renamed')
        4728 = @('عضوِ گروه شد', 'Added to group'); 4732 = @('عضوِ گروه شد', 'Added to group'); 4756 = @('عضوِ گروه شد', 'Added to group'); 4729 = @('از گروه حذف شد', 'Removed from group'); 4733 = @('از گروه حذف شد', 'Removed from group'); 4757 = @('از گروه حذف شد', 'Removed from group')
        4688 = @('اجرای برنامه', 'Process started'); 4698 = @('ساختِ تسک', 'Task created'); 4702 = @('تغییرِ تسک', 'Task updated'); 4697 = @('نصبِ سرویس', 'Service installed'); 7045 = @('نصبِ سرویس', 'Service installed')
        4663 = @('دسترسی به فایل', 'File access'); 4660 = @('حذفِ فایل', 'File deleted'); 4670 = @('تغییرِ مجوز', 'Permission change'); 1102 = @('پاک‌کردنِ لاگ', 'Log cleared'); 4719 = @('تغییرِ سیاستِ ممیزی', 'Audit policy change')
        5136 = @('تغییرِ شیءِ AD', 'AD object change'); 5137 = @('ساختِ شیءِ AD', 'AD object created'); 5141 = @('حذفِ شیءِ AD', 'AD object deleted')
    }
    foreach ($r in @($recs | Sort-Object time -Descending)) {
        $isSubject = ((Get-LBD $r 'SubjectUserName').ToLowerInvariant() -eq $ul -and ([string]$r.user).ToLowerInvariant() -ne $ul)
        $id = [int]$r.id; $lt = Get-LBD $r 'LogonType'
        if ($id -eq 4624) { if ($lt -in '0', '5') { continue }; $sum.logons++; $sum.hosts[[string]$r.host] = 1 + [int]$sum.hosts[[string]$r.host]; if ($r.ip -and $r.ip -notin '-', '::1', '127.0.0.1') { $sum.ips[[string]$r.ip] = 1 + [int]$sum.ips[[string]$r.ip] }; if ((Get-LBD $r 'ElevatedToken') -eq '%%1842') { $sum.admin++ }; if ($lt -in '2', '10', '11' -and -not (Test-LBRepBusinessHours $r.time)) { $sum.afterHours++ } }
        elseif ($id -in 4625, 4771) { $sum.failed++ } elseif ($id -eq 4740) { $sum.lockouts++ } elseif ($id -eq 4688) { $sum.processes++ }
        elseif ($id -in 4720, 4722, 4725, 4726, 4724, 4738, 4781, 4728, 4729, 4732, 4733, 4756, 4757) { if ($isSubject) { $sum.changesBy++ } else { $sum.changesOn++ } }
        if ($tl.Count -ge $Max) { continue }
        if ($id -in 4634, 4647 -and $lt -eq '3') { continue }
        $what = Get-LBTx $Lang $names[$id]
        if ($isSubject -and $id -in 4720, 4722, 4725, 4726, 4724, 4738, 4781, 4728, 4729, 4732, 4733, 4756, 4757) { $what = (Get-LBTx $Lang @('انجام داد: ', 'Did: ')) + $what }
        $det = switch ($id) {
            { $_ -in 4624, 4634, 4647 } { Get-LBLogonTypeText $lt $Lang }
            4625 { '{0} — {1}' -f (Get-LBLogonTypeText $lt $Lang), (Get-LBStatusText (Get-LBD $r 'Status') (Get-LBD $r 'SubStatus') $Lang) }
            { $_ -in 4728, 4729, 4732, 4733, 4756, 4757 } { $m = Get-LBRepValue $r 'c:member' $Lang; '{0} → {1}' -f $m, (Get-LBD $r 'TargetUserName') }
            4688 { Get-LBRepValue $r 'd:CommandLine' $Lang }
            { $_ -in 4663, 4660, 4670 } { Get-LBD $r 'ObjectName' }
            { $_ -in 4697, 7045 } { Get-LBD $r 'ServiceName' }
            { $_ -in 4698, 4702 } { Get-LBD $r 'TaskName' }
            4740 { Get-LBD $r 'TargetDomainName' }
            4648 { '{0} @ {1}' -f (Get-LBD $r 'TargetUserName'), (Get-LBD $r 'TargetServerName') }
            { $_ -in 5136, 5137, 5141 } { Get-LBD $r 'ObjectDN' }
            default { '' }
        }
        $tl.Add([ordered]@{ time = $r.time.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv); host = [string]$r.host; what = $what; detail = [string]$det; ip = [string]$r.ip; id = $id; bad = ($id -in 4625, 4740, 4771, 1102, 4719) })
    }
    $fnd = @()
    try { $fr = Get-LBFindings -Config $Config -From $From -To $To -Text $u -Max 100; $fnd = @($fr.Items | ForEach-Object { $ti = [string]$_.title; $ix = $ti.IndexOf(' | '); if ($ix -ge 0) { $ti = $(if ($Lang -eq 'en') { $ti.Substring($ix + 3) } else { $ti.Substring(0, $ix) }) }; [ordered]@{ id = [string]$_.id; time = (Format-LBRepTime ([string]$_.t)); sev = [string]$_.sev; cat = [string]$_.cat; host = [string]$_.host; title = $ti } }) } catch { }
    $risk = 0
    $risk += [math]::Min(30, $sum.failed * 2); $risk += 15 * [math]::Min(2, $sum.lockouts); $risk += [math]::Min(20, $sum.afterHours * 5); $risk += [math]::Min(20, $sum.changesBy * 4)
    $risk += [math]::Min(30, 10 * @($fnd | Where-Object { $_.sev -eq 'Critical' }).Count + 3 * @($fnd | Where-Object { $_.sev -eq 'Warning' }).Count)
    $risk = [math]::Min(100, $risk)
    return [ordered]@{ user = $u; from = $From.ToString('yyyy-MM-dd HH:mm', $script:Inv); to = $To.ToString('yyyy-MM-dd HH:mm', $script:Inv); risk = $risk
                       summary = [ordered]@{ logons = $sum.logons; failed = $sum.failed; lockouts = $sum.lockouts; admin = $sum.admin; afterHours = $sum.afterHours; changesBy = $sum.changesBy; changesOn = $sum.changesOn; processes = $sum.processes
                                             hosts = @($sum.hosts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object { [ordered]@{ name = $_.Key; n = $_.Value } })
                                             ips = @($sum.ips.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object { [ordered]@{ name = $_.Key; n = $_.Value } }) }
                       timeline = $tl.ToArray(); findings = $fnd; total = $recs.Count }
}

# --- CSV | Excel-friendly CSV (UTF-8 BOM) ------------------------------------------------------------
function ConvertTo-LBReportCsv {
    param($Report)
    $sb = New-Object Text.StringBuilder
    $q = { param($v) $s = [string]$v; if ($s -match '^[=+\-@]') { $s = "'" + $s }; '"' + ($s -replace '"', '""') + '"' }
    [void]$sb.AppendLine((@($Report.columns | ForEach-Object { & $q $_.t }) -join ','))
    foreach ($r in @($Report.rows)) { [void]$sb.AppendLine((@($r | ForEach-Object { & $q $_ }) -join ',')) }
    return $sb.ToString()
}

# --- گزارش‌های زمان‌بندی‌شده | scheduled reports --------------------------------------------------
function Get-LBReportSchedules {
    param([string]$StateDir)
    $f = Join-Path $StateDir 'report-schedules.json'
    if (-not (Test-Path $f)) { return @() }
    try { $h = ConvertTo-LBHashtable (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json); if ($h -is [hashtable]) { return @($h) }; return @($h | Where-Object { $_ -is [hashtable] }) } catch { return @() }
}
function Save-LBReportSchedules { param([string]$StateDir, [object[]]$Items) $f = Join-Path $StateDir 'report-schedules.json'; [IO.File]::WriteAllText("$f.tmp", (ConvertTo-Json -InputObject @($Items) -Depth 6), (New-Object Text.UTF8Encoding($false))); Move-Item "$f.tmp" $f -Force }
function Set-LBReportSchedule {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][hashtable]$Item, [string]$By)
    if (-not $Item.Id) { $Item.Id = 'rs' + [guid]::NewGuid().ToString('N').Substring(0, 8) }
    if ([string]$Item.Id -notmatch '^[A-Za-z0-9_\-]{1,40}$') { throw 'invalid id' }
    if (-not ([string]$Item.Name).Trim()) { throw 'نام لازم است | name required' }
    $reps = @(@($Item.Reports) | Where-Object { $_ -and (Get-LBReportDef -Id ([string]$_)) } | ForEach-Object { [string]$_ })
    if (-not $reps.Count) { throw 'حداقل یک گزارش انتخاب کنید | choose at least one report' }
    $to = @(@($Item.Recipients) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' })
    if (-not $to.Count) { throw 'حداقل یک ایمیلِ معتبر لازم است | at least one valid e-mail' }
    $freq = if ([string]$Item.Freq -in 'daily', 'weekly', 'monthly') { [string]$Item.Freq } else { 'weekly' }
    $range = if ([string]$Item.Range -in '24h', '7d', '30d') { [string]$Item.Range } else { $(if ($freq -eq 'daily') { '24h' } elseif ($freq -eq 'monthly') { '30d' } else { '7d' }) }
    $all = @(Get-LBReportSchedules -StateDir $StateDir)
    $old = $all | Where-Object { [string]$_.Id -eq [string]$Item.Id } | Select-Object -First 1
    $o = @{ Id = [string]$Item.Id; Name = ([string]$Item.Name).Trim(); Reports = $reps; Recipients = $to; Freq = $freq; Range = $range
            Day = [math]::Max(0, [math]::Min(28, [int]$Item.Day)); Hour = [math]::Max(0, [math]::Min(23, [int]$Item.Hour)); Enabled = ($Item.Enabled -ne $false)
            Lang = $(if ([string]$Item.Lang -eq 'en') { 'en' } else { 'fa' }); HostLike = ([string]$Item.HostLike).Trim(); By = $By; Updated = (Get-Date).ToString('o', $script:Inv)
            LastRun = $(if ($old) { [string]$old.LastRun } else { '' }); LastResult = $(if ($old) { [string]$old.LastResult } else { '' }) }
    Save-LBReportSchedules -StateDir $StateDir -Items @(@($all | Where-Object { [string]$_.Id -ne $o.Id }) + $o)
    return $o
}
function Remove-LBReportSchedule { param([string]$StateDir, [string]$Id) Save-LBReportSchedules -StateDir $StateDir -Items @(Get-LBReportSchedules -StateDir $StateDir | Where-Object { [string]$_.Id -ne $Id }) }
function Get-LBScheduleLastSlot {
    param($S, [datetime]$Now = (Get-Date))
    $h = [int]$S.Hour
    switch ([string]$S.Freq) {
        'daily'   { $t = $Now.Date.AddHours($h); if ($t -gt $Now) { $t = $t.AddDays(-1) }; return $t }
        'monthly' { $d = [math]::Max(1, [int]$S.Day); $t = (New-Object DateTime($Now.Year, $Now.Month, $d)).AddHours($h); if ($t -gt $Now) { $t = $t.AddMonths(-1) }; return $t }
        default   { $wd = [int]$S.Day % 7; $t = $Now.Date.AddHours($h); while ([int]$t.DayOfWeek -ne $wd -or $t -gt $Now) { $t = $t.AddDays(-1) }; return $t }
    }
}
function Invoke-LBScheduledReports {
    param([Parameter(Mandatory)]$Config, [string]$OnlyId, [switch]$Force)
    $sd = Get-LBStateDir -Config $Config
    $all = @(Get-LBReportSchedules -StateDir $sd)
    $sent = @(); $changed = $false
    foreach ($s in $all) {
        if ($OnlyId -and [string]$s.Id -ne $OnlyId) { continue }
        if (-not $Force) {
            if ($s.Enabled -eq $false) { continue }
            $slot = Get-LBScheduleLastSlot -S $s
            $last = $null; if ($s.LastRun) { try { $last = ConvertTo-LBDate ([string]$s.LastRun) } catch { } }
            if ($last -and $last -ge $slot) { continue }
            if (-not $last -and $slot -lt (Get-Date).AddHours(-2)) { $s.LastRun = (Get-Date).ToString('o', $script:Inv); $changed = $true; continue }   # تازه ساخته شده: از بازهٔ بعد | first slot after creation
        }
        $to = Get-Date; $from = switch ([string]$s.Range) { '24h' { $to.AddHours(-24) } '30d' { $to.AddDays(-30) } default { $to.AddDays(-7) } }
        $outDir = Join-Path $(if ($Config.Paths.Reports) { [string]$Config.Paths.Reports } else { Join-Path $sd '..\reports' }) 'scheduled'
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        $files = @(); $sum = New-Object Text.StringBuilder; $lang = [string]$s.Lang
        [void]$sum.Append('<div style="font-family:Tahoma,Segoe UI,sans-serif;direction:' + $(if ($lang -eq 'en') { 'ltr' } else { 'rtl' }) + '">')
        [void]$sum.Append('<h2 style="margin:0 0 6px">' + [Net.WebUtility]::HtmlEncode([string]$s.Name) + '</h2><p style="color:#666;margin:0 0 12px">' + $from.ToString('yyyy-MM-dd HH:mm', $script:Inv) + ' — ' + $to.ToString('yyyy-MM-dd HH:mm', $script:Inv) + '</p>')
        foreach ($rid in @($s.Reports)) {
            try {
                $r = Invoke-LBReport -Config $Config -Id $rid -From $from -To $to -HostLike ([string]$s.HostLike) -Max 50000 -Lang $lang
                $fn = Join-Path $outDir ('{0}-{1}-{2}.csv' -f (Get-Date).ToString('yyyyMMdd-HHmm', $script:Inv), $s.Id, $rid)
                [IO.File]::WriteAllText($fn, (ConvertTo-LBReportCsv $r), (New-Object Text.UTF8Encoding($true)))
                $files += $fn
                [void]$sum.Append('<h3 style="margin:16px 0 4px">' + [Net.WebUtility]::HtmlEncode([string]$r.title) + ' — ' + $r.total + '</h3>')
                if ($r.rows.Count) {
                    [void]$sum.Append('<table style="border-collapse:collapse;font-size:12px"><tr>')
                    foreach ($c in $r.columns) { [void]$sum.Append('<th style="border:1px solid #ccc;padding:3px 6px;background:#f3f3f3">' + [Net.WebUtility]::HtmlEncode([string]$c.t) + '</th>') }
                    [void]$sum.Append('</tr>')
                    foreach ($row in @($r.rows | Select-Object -First 15)) { [void]$sum.Append('<tr>'); foreach ($v in $row) { [void]$sum.Append('<td style="border:1px solid #ddd;padding:3px 6px">' + [Net.WebUtility]::HtmlEncode([string]$v) + '</td>') }; [void]$sum.Append('</tr>') }
                    [void]$sum.Append('</table>')
                    if ($r.total -gt 15) { [void]$sum.Append('<p style="color:#666">' + $(if ($lang -eq 'en') { 'Full list in the attached CSV.' } else { 'فهرستِ کامل در فایلِ CSVِ پیوست.' }) + '</p>') }
                }
            } catch { [void]$sum.Append('<p style="color:#b00">' + [Net.WebUtility]::HtmlEncode("$rid : $($_.Exception.Message)") + '</p>') }
        }
        [void]$sum.Append('</div>')
        $res = 'ok'
        try { Send-LogBokMail -Subject ([string]$s.Name) -Body $sum.ToString() -Html -Attachments $files -To @($s.Recipients) -Config $Config } catch { $res = 'mail: ' + $_.Exception.Message }
        $s.LastRun = (Get-Date).ToString('o', $script:Inv); $s.LastResult = $res; $changed = $true
        $sent += [ordered]@{ id = [string]$s.Id; name = [string]$s.Name; files = $files.Count; result = $res }
    }
    if ($changed) { Save-LBReportSchedules -StateDir $sd -Items $all }
    return $sent
}

Export-ModuleMember -Function Get-LBRecentUsers, Get-LBSessionHistory, Test-LBPublicIp, Get-LBEndpointFindings, Get-LBReportCatalog, Get-LBReportDef, Invoke-LBReport, Get-LBArchiveRecords, Get-LBLockoutAnalysis, Get-LBHealthProblems, Get-LBUserActivity, ConvertTo-LBReportCsv, `
    Get-LBReportSchedules, Set-LBReportSchedule, Remove-LBReportSchedule, Invoke-LBScheduledReports, Get-LBScheduleLastSlot, Get-LBSoftwareRisk, Get-LBOsEol, Get-LBAgentFiles, Get-LBLolbinReason, Get-LBLogonTypeText, Get-LBStatusText
