# ==========================================================================
#  LogBok.Detectors.psm1 - آشکارسازهای سناریوها
#  هر آشکارساز یک آرایه از «یافته» برمی‌گرداند:
#   @{ Category; Severity('Critical'|'Warning'|'Info'); Machine; Time;
#      Title; Details; Key(امضای یکتا برای ضدِسیل) }
#  وابسته به LogBok.Core.psm1 (قبل از این import شود).
# ==========================================================================

# کمکی: ساخت یک یافته
function New-Finding {
    param($Category,$Severity,$Machine,$Time,$Title,$Details,$Key)
    [pscustomobject]@{
        Category = $Category; Severity = $Severity; Machine = $Machine
        Time = $Time; Title = $Title; Details = $Details; Key = $Key
    }
}

# «یک‌بار در روز» برای یافته‌هایی که با هر اجرا تکرار می‌شوند | report a repeating thing once per day (v2.1.26)
#  state\seen-once.json: hashed key -> last report time (UTC). Used for repeating PowerShell scripts, GPO edits, firewall lists, AppLocker blocks.
$script:LBSeenOnce = $null
function Test-LBSeenOnce {
    param($Config, [string]$Bucket, [string]$Key, [double]$Hours = 24)
    $sd = $null; try { $sd = Get-LBStateDir -Config $Config } catch { }
    if (-not $sd) { $sd = Join-Path (Split-Path -Parent $PSCommandPath) 'state' }
    $file = Join-Path $sd 'seen-once.json'
    if ($null -eq $script:LBSeenOnce) {
        $script:LBSeenOnce = @{}
        if (Test-Path $file) { try { $o = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($p in $o.PSObject.Properties) { $script:LBSeenOnce[$p.Name] = [string]$p.Value } } catch { } }
    }
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $h = $Bucket + ':' + (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Key))[0..9] | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
    $now = [DateTime]::UtcNow
    $prev = $script:LBSeenOnce[$h]
    if ($prev) { $pt = [datetime]::MinValue; if ([datetime]::TryParse($prev, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$pt) -and $pt.ToUniversalTime() -gt $now.AddHours(-$Hours)) { return $false } }
    $script:LBSeenOnce[$h] = $now.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    # drop entries older than 8 days and save
    $cut = $now.AddDays(-8); $keep = [ordered]@{}
    foreach ($k in @($script:LBSeenOnce.Keys)) { $t0 = [datetime]::MinValue; if ([datetime]::TryParse([string]$script:LBSeenOnce[$k], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$t0) -and $t0.ToUniversalTime() -gt $cut) { $keep[$k] = $script:LBSeenOnce[$k] } }
    $script:LBSeenOnce = @{}; foreach ($k in $keep.Keys) { $script:LBSeenOnce[$k] = $keep[$k] }
    try { $tmp = $file + '.' + [guid]::NewGuid().ToString('N') + '.tmp'; [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $keep -Compress), (New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $tmp -Destination $file -Force } catch { try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { } }
    return $true
}
function Test-LBPsSeenOnce { param($Config, [string]$Key) return (Test-LBSeenOnce -Config $Config -Bucket 'ps' -Key $Key -Hours 24) }

# نامِ نمایشیِ GPO از روی GUID (با کش) | GPO display name from its GUID (cached)
$script:LBGpoNames = @{}
function Get-LBGpoName {
    param([string]$Guid)
    if (-not $Guid -or $Guid -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { return [string]$Guid }
    $g = $Guid.ToUpper()
    if ($script:LBGpoNames.ContainsKey($g)) { return $script:LBGpoNames[$g] }
    $n = $g
    switch ($g) { '{31B2F340-016D-11D2-945F-00C04FB984F9}' { $n = 'Default Domain Policy' } '{6AC1786C-016F-11D2-945F-00C04FB984F9}' { $n = 'Default Domain Controllers Policy' } }
    if ($n -eq $g) {
        try {
            $root = [ADSI]'LDAP://RootDSE'; $dc = [string]$root.defaultNamingContext
            $o = [ADSI]("LDAP://CN={0},CN=Policies,CN=System,{1}" -f $g, $dc)
            $dn0 = [string]$o.displayName; if ($dn0) { $n = $dn0 }
        } catch { }
    }
    $script:LBGpoNames[$g] = $n
    return $n
}

# کمکی: منابعِ لاگِ Application برای رویدادهای خودِ لاگ‌بوک (9001…9016)
#  در حالت Collector علاوه بر ForwardedEvents، Application خودِ سرورِ موتور هم
#  خوانده می‌شود (وگرنه هشدارهای واچ‌داگِ خودِ سرور گم می‌شد).
function Get-LBAppSources {
    param($Config)
    if ($Config.CollectionMode -eq 'Collector') {
        return @( @{ Log = $Config.ForwardedLog; Computer = 'localhost' }, @{ Log = 'Application'; Computer = 'localhost' } )
    }
    $out = @(); foreach ($s in (Get-LogBokSecuritySources -Config $Config)) { $out += @{ Log = 'Application'; Computer = $s.Computer } }
    return $out
}

# کمکی: فیلدِ UserData (رویدادهایی مثل 307 که EventData ندارند)
function Get-LBUserDataField {
    param($Event, [string]$Name)
    try {
        $xml = [xml]$Event.ToXml()
        $n = $xml.Event.UserData.FirstChild
        if ($n -and $n.$Name) { return [string]$n.$Name }
    } catch { }
    return $null
}

# کمکی: نامِ کلیدیِ سرویس و وضعیت از رویدادِ 7036/7031/7034
#  پیامِ 7036 نامِ «نمایشی» دارد (مثلاً World Wide Web Publishing Service) نه W3SVC؛
#  نامِ کلیدی در دادهٔ باینریِ رویداد است: «W3SVC/1» (1=متوقف، 4=در حال اجرا).
function Get-LBSvcInfo {
    param($Event)
    $key = $null; $state = $null; $disp = $null
    try {
        $xml = [xml]$Event.ToXml()
        $data = @($xml.Event.EventData.Data)
        if ($data.Count -ge 1) { $disp = [string]($data[0].'#text'); if (-not $disp) { $disp = [string]$data[0] } }
        $bin = [string]$xml.Event.EventData.Binary
        if ($bin -and $bin.Length -ge 4) {
            $bytes = New-Object byte[] ($bin.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($bin.Substring($i * 2, 2), 16) }
            $txt = [Text.Encoding]::Unicode.GetString($bytes).Trim([char]0)
            if ($txt -match '^([^/]+)/(\d+)') { $key = $Matches[1]; $state = [int]$Matches[2] }
        }
    } catch { }
    $stopped = if ($null -ne $state) { $state -eq 1 } else { $false }
    if ($Event.Id -in 7031,7034) { $stopped = $true }
    if ($null -eq $state -and $Event.Id -eq 7036) {
        try { $stopped = ([string]$Event.Message -match 'stopped|متوقف') } catch {}
    }
    return [pscustomobject]@{ Key = $key; Display = $disp; Stopped = $stopped }
}

# کمکی: متن پیام رویداد
function Get-EvtMessage {
    param($e)
    try { if ($e.Message) { return ($e.Message -split "`r?`n")[0] } } catch {}
    return "(بدون متن)"
}

# ---------------------------------------------------------------- فایروال --
function Invoke-DetectFirewall {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($src in @(@{Log='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';C='localhost'})) {
        # در حالت Collector این لاگ هم فوروارد می‌شود و با همین نام در ForwardedEvents است،
        # پس اگر Collector بودیم از لاگ فوروارد می‌خوانیم.
        $sources = Get-LogBokSecuritySources -Config $Config
        foreach ($s in $sources) {
            $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { $src.Log }
            $comp = $s.Computer
            $evts = Get-LogBokEvents -LogName $log -Id 2003 -StartTime $Start -ComputerName $comp -Config $Config
            foreach ($e in $evts) {
                $val = Get-LogBokEventField -Event $e -Name 'SettingValue'
                $type = Get-LogBokEventField -Event $e -Name 'SettingType'
                $off = ($val -match 'Disable|Off|No|غیرفعال') -or ($e.Message -match 'Disable|Off|غیرفعال')
                $sev = if ($off) { 'Critical' } else { 'Warning' }
                $f += New-Finding -Category 'Firewall' -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title ("تغییر تنظیمات فایروال ویندوز" + $(if($off){" (خاموش شد)"}) + " | Windows Firewall setting changed" + $(if($off){" (turned off)"})) `
                    -Details ("سیستم: {0} | نوع: {1} | مقدار: {2} | {3}" -f $e.MachineName,$type,$val,(Get-EvtMessage $e)) `
                    -Key ("FW|{0}|{1}" -f $e.MachineName,$type)
            }
        }
        break
    }
    # توقف سرویس فایروال (MpsSvc) از System/7036
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $sys = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'System' }
        $evts = Get-LogBokEvents -LogName $sys -Id 7036 -StartTime $Start -ComputerName $s.Computer -Config $Config
        foreach ($e in $evts) {
            $si = Get-LBSvcInfo $e
            $isFw = ($si.Key -eq 'MpsSvc') -or ($si.Display -match 'Firewall|فایروال')
            if (-not ($isFw -and $si.Stopped)) { continue }
            $f += New-Finding -Category 'Firewall' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title "سرویس فایروال ویندوز متوقف شد | Windows Firewall service stopped" -Details (Get-EvtMessage $e) -Key ("FWSVC|{0}" -f $e.MachineName)
        }
    }
    return $f
}

# ---------------------------------------------------------- دیفندر (آنتی‌ویروس) --
function Invoke-DetectDefender {
    param($Config,[datetime]$Start)
    $f = @()
    $map = @{
        5001 = @{t='حفاظت بلادرنگ دیفندر غیرفعال شد | Defender real-time protection disabled'; s='Critical'}
        5000 = @{t='حفاظت بلادرنگ دیفندر فعال شد | Defender real-time protection enabled';     s='Info'}
        5010 = @{t='پویش دیفندر غیرفعال شد | Defender scanning disabled';            s='Critical'}
        5012 = @{t='پویش ویروس دیفندر غیرفعال شد | Defender virus scanning disabled';      s='Critical'}
        5007 = @{t='پیکربندی دیفندر تغییر کرد | Defender configuration changed';         s='Info'}      # به‌روزرسانیِ خودِ Defender هم این را می‌نویسد؛ اطلاع، نه هشدار | routine after signature updates
        1116 = @{t='دیفندر یک بدافزار شناسایی کرد | Defender detected malware';     s='Critical'}
        5013 = @{t='تلاش برای دستکاری دیفندر مسدود شد | Defender tamper attempt blocked';  s='Warning'}
    }
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Microsoft-Windows-Windows Defender/Operational' }
        $evts = Get-LogBokEvents -LogName $log -Id ($map.Keys) -StartTime $Start -ComputerName $s.Computer -Config $Config
        foreach ($e in $evts) {
            $m = $map[[int]$e.Id]; if (-not $m) { continue }
            $f += New-Finding -Category 'Defender' -Severity $m.s -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $m.t -Details (Get-EvtMessage $e) -Key ("DEF|{0}|{1}" -f $e.MachineName,$e.Id)
        }
    }
    return $f
}

# ------------------------------------------- حذف / تغییر انبوه فایل --
function Invoke-DetectMassFile {
    param($Config,[datetime]$Start)
    $f = @()
    $th = $Config.Thresholds.MassFilePerWindow
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        # 4663 = دسترسی به شیء ، 4660 = حذف شیء
        $evts = Get-LogBokEvents -LogName $log -Id @(4663,4660) -StartTime $Start -ComputerName $s.Computer -Config $Config
        # گروه‌بندی بر اساس کاربر
        $byUser = @{}
        foreach ($e in $evts) {
            $user = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            if (-not $user -or $user -eq 'SYSTEM' -or $user -like '*$') { continue }
            $mask = Get-LogBokEventField -Event $e -Name 'AccessMask'
            $obj  = Get-LogBokEventField -Event $e -Name 'ObjectName'
            # 4660 فقط تأییدِ حذفِ همان handle در 4663 است و نامِ فایل ندارد → شمرده نمی‌شود
            if ($e.Id -eq 4660) { continue }
            # عملیاتِ مخرب با مقایسهٔ بیتی (نه تطبیقِ متنی؛ 0x20000 نباید 0x2 حساب شود):
            #  DELETE 0x10000 | WriteData 0x2 | AppendData 0x4 | WriteAttributes 0x100
            $m = 0
            try { $m = [Convert]::ToInt32(([string]$mask).Trim(), 16) } catch { continue }
            if (-not ($m -band 0x10106)) { continue }
            if (-not $obj) { continue }
            $k = "$($e.MachineName)|$user"
            if (-not $byUser.ContainsKey($k)) { $byUser[$k] = @{} }
            $byUser[$k][$obj] = 1   # هر فایل یک‌بار شمرده می‌شود
        }
        foreach ($k in $byUser.Keys) {
            $list = @($byUser[$k].Keys)
            if ($list.Count -ge $th) {
                $parts = $k -split '\|'
                $sample = ($list | Select-Object -First 8) -join "`n   "
                $f += New-Finding -Category 'MassFile' -Severity 'Critical' -Machine $parts[0] -Time (Get-Date) `
                    -Title ("حذف/تغییر انبوه فایل — کاربر {0} ({1} فایل) | mass file delete/change — user {0} ({1} files)" -f $parts[1],$list.Count) `
                    -Details ("سیستم: {0}`nکاربر: {1}`nتعداد عملیات مخرب در بازه: {2}`nنمونه فایل‌ها:`n   {3}" -f $parts[0],$parts[1],$list.Count,$sample) `
                    -Key ("MASS|{0}" -f $k)
            }
        }
    }
    return $f
}

# ------------------------------------------------- اکتیو دایرکتوری --
function Invoke-DetectActiveDirectory {
    param($Config,[datetime]$Start)
    $f = @()
    $map = @{
        4720 = @{t='کاربر جدید ساخته شد | User account created';              s='Warning'}
        4726 = @{t='کاربر حذف شد | User account deleted';                      s='Warning'}
        4722 = @{t='کاربر فعال شد | User account enabled';                     s='Info'}
        4725 = @{t='کاربر غیرفعال شد | User account disabled';                  s='Warning'}
        4740 = @{t='کاربر قفل (Lock) شد | User account locked out';               s='Critical'}
        4767 = @{t='کاربر از قفل خارج (Unlock) شد | User account unlocked';     s='Warning'}
        4723 = @{t='کاربر گذرواژه‌اش را تغییر داد | User changed own password';      s='Info'}
        4724 = @{t='گذرواژهٔ کاربر ریست شد | User password reset';            s='Warning'}
        4728 = @{t='کاربر به گروه سراسری اضافه شد | User added to global group';     s='Warning'}
        4732 = @{t='کاربر به گروه محلی اضافه شد | User added to local group';       s='Warning'}
        4756 = @{t='کاربر به گروه جهانی اضافه شد | User added to universal group';      s='Warning'}
        # مثلِ ADAudit Plus / EventLog Analyzer: تغییرِ گروه، حسابِ کامپیوتر، سیاست، پاک‌شدنِ لاگ
        4729 = @{t='کاربر از گروه سراسری حذف شد | User removed from global group';    s='Warning'}
        4733 = @{t='کاربر از گروه محلی حذف شد | User removed from local group';        s='Warning'}
        4757 = @{t='کاربر از گروه جهانی حذف شد | User removed from universal group';   s='Warning'}
        4727 = @{t='گروهِ امنیتیِ سراسری ساخته شد | Security global group created';     s='Info'}
        4731 = @{t='گروهِ امنیتیِ محلی ساخته شد | Security local group created';       s='Info'}
        4730 = @{t='گروهِ امنیتیِ سراسری حذف شد | Security global group deleted';      s='Warning'}
        4734 = @{t='گروهِ امنیتیِ محلی حذف شد | Security local group deleted';        s='Warning'}
        4781 = @{t='نامِ حساب تغییر کرد | Account name changed';                       s='Warning'}
        4741 = @{t='حسابِ کامپیوتر ساخته شد | Computer account created';               s='Info'}
        4743 = @{t='حسابِ کامپیوتر حذف شد | Computer account deleted';                 s='Warning'}
        4739 = @{t='سیاستِ دامنه تغییر کرد | Domain policy changed';                   s='Warning'}
        4713 = @{t='سیاستِ Kerberos تغییر کرد | Kerberos policy changed';              s='Warning'}
        4719 = @{t='سیاستِ حسابرسیِ سیستم تغییر کرد | System audit policy changed';     s='Critical'; c='Tamper'}
        1102 = @{t='لاگِ امنیتی پاک شد | Security audit log cleared';                   s='Critical'; c='Tamper'}
        4794 = @{t='گذرواژهٔ DSRM تنظیم شد | DSRM administrator password set';           s='Critical'; c='ADAttack'}
        4765 = @{t='SID History به حساب اضافه شد | SID History added to an account';     s='Critical'; c='ADAttack'}
        4766 = @{t='افزودنِ SID History ناموفق بود | SID History add attempt failed';    s='Warning';  c='ADAttack'}
    }
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        $evts = Get-LogBokEvents -LogName $log -Id ($map.Keys) -StartTime $Start -ComputerName $s.Computer -Config $Config
        foreach ($e in $evts) {
            $m = $map[[int]$e.Id]; if (-not $m) { continue }
            $target = Get-LogBokEventField -Event $e -Name 'TargetUserName'
            $by     = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            $member = Get-LogBokEventField -Event $e -Name 'MemberName'
            $tsid   = Get-LogBokEventField -Event $e -Name 'TargetSid'
            $sev = $m.s; $title = $m.t
            # ارتقای حساس: افزوده‌شدن به گروه‌های مدیریتی → بحرانی و ایمیل فوری
            if ($e.Id -in 4728,4732,4756) {
                $sensitive = ($target -match 'Admin|Administrators|Domain Admins|Enterprise Admins|Schema Admins|Backup Operators|Account Operators') `
                    -or ($tsid -match '-512$|-519$|-518$|-548$|-551$|S-1-5-32-544$')
                if ($sensitive) { $sev='Critical'; $title=("عضویت در گروه حسابرسی‌شدهٔ حساس «{0}» | added to SENSITIVE group '{0}'" -f $target) }
            }
            # ساخت کاربر محلی/دامنه → بحرانی (ایمیل فوری)
            if ($e.Id -eq 4720) { $sev='Critical' }
            $detail = if ($member) {
                "گروه/Group: {0} | عضو/Member: {1} | توسط/By: {2} | سیستم/Host: {3}" -f $target,$member,$by,$e.MachineName
            } else {
                "کاربر هدف/Target: {0} | توسط/By: {1} | سیستم/Host: {2}" -f $target,$by,$e.MachineName
            }
            $cat = if ($m.c) { [string]$m.c } else { 'ActiveDirectory' }
            if ($e.Id -eq 1102 -and -not $target) { $target = Get-LogBokEventField -Event $e -Name 'SubjectUserName'; $by = $target }
            $f += New-Finding -Category $cat -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $title -Details $detail -Key ("AD|{0}|{1}|{2}" -f $e.Id,$target,$e.RecordId)
        }
    }
    return $f
}

# ---------------------------------------------- بروت‌فورس ورود ویندوز --
# برای هر گروه (سیستم + کاربر + مبدأ): سیستم، کاربر، IP و پورت، نامِ سیستمِ مبدأ، پروتکل (NTLM/Kerberos)،
# نوعِ ورود (محلی/شبکه/RDP…)، دلیل (رمزِ اشتباه/کاربرِ ناموجود/قفل…)، برنامه، تعداد، اولین و آخرین تلاش.
# for each (computer + user + source): IP/port, source workstation, protocol, logon type, reason, process, count, first/last.
$script:LBLogonTypeName = @{ '2'='محلی | Interactive'; '3'='شبکه (SMB/اشتراک/ابزار) | Network'; '4'='تسک | Batch'; '5'='سرویس | Service'; '7'='بازکردنِ قفلِ صفحه | Unlock'
    '8'='شبکه، متنِ ساده (IIS/وب/IMAP) | Network cleartext'; '9'='runas | New credentials'; '10'='ریموت‌دسکتاپ | RDP'; '11'='کش‌شده | Cached interactive' }
$script:LBFailReason = @{ '0xc000006a'='رمزِ اشتباه | wrong password'; '0xc0000064'='کاربرِ ناموجود | no such user'; '0xc0000234'='حسابِ قفل‌شده | account locked'
    '0xc0000072'='حسابِ غیرفعال | account disabled'; '0xc000006f'='بیرون از ساعتِ مجاز | outside allowed hours'; '0xc0000070'='سیستمِ غیرمجاز | workstation not allowed'
    '0xc0000071'='رمزِ منقضی | password expired'; '0xc0000193'='حسابِ منقضی | account expired'; '0xc0000224'='باید رمز را عوض کند | must change password'
    '0xc000015b'='این نوعِ ورود مجاز نیست | logon type not granted'; '0xc000006d'='نام یا رمزِ نادرست | bad user name or password'; '0xc0000133'='اختلافِ ساعت با DC | clock skew'
    '0x18'='رمزِ اشتباه (Kerberos) | wrong password'; '0x6'='کاربرِ ناموجود (Kerberos) | no such user'; '0x12'='حسابِ قفل/غیرفعال/منقضی (Kerberos) | account locked, disabled or expired'
    '0x17'='رمزِ منقضی (Kerberos) | password expired'; '0x25'='اختلافِ ساعت (Kerberos) | clock skew' }
function Get-LBFailedLogonInfo {
    param($Event)
    $m = @{}; try { $x = [xml]$Event.ToXml(); foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name) { $m[[string]$d.Name] = [string]$d.'#text' } } } catch { }
    $g = { param($n) $v = [string]$m[$n]; if ($v -eq '-' -or $v -eq '') { return '' }; return $v.Trim() }
    $ip = & $g 'IpAddress'; $ip = $ip -replace '^::ffff:',''
    if ($ip -in '::1','127.0.0.1') { $ip = 'localhost' }
    $ws = & $g 'WorkstationName'; if (-not $ws) { $ws = & $g 'Workstation' }; $ws = $ws -replace '^\\\\',''
    $proto = ''; $lt = ''; $code = ''
    switch ([int]$Event.Id) {
        4625 {
            $pkg = & $g 'AuthenticationPackageName'; $lm = & $g 'LmPackageName'
            $proto = if ($lm) { $lm } elseif ($pkg) { $pkg } else { '' }
            $lp = & $g 'LogonProcessName'; if ($lp -and $proto -notmatch [regex]::Escape($lp)) { $proto = ("{0} / {1}" -f $proto, $lp).Trim(' /') }
            $lt = & $g 'LogonType'
            $code = & $g 'SubStatus'; if (-not $code -or $code -eq '0x0') { $code = & $g 'Status' }
        }
        4771 { $proto = 'Kerberos (pre-auth)'; $code = & $g 'Status' }
        4776 { $proto = 'NTLM'; $code = & $g 'Status' }
    }
    $ltName = if ($lt -and $script:LBLogonTypeName.ContainsKey($lt)) { "$($script:LBLogonTypeName[$lt]) ($lt)" } elseif ($lt) { $lt } else { '' }
    $reason = ''; if ($code) { $k = $code.ToLowerInvariant(); $reason = if ($script:LBFailReason.ContainsKey($k)) { "$($script:LBFailReason[$k]) ($code)" } else { $code } }
    $proc = & $g 'ProcessName'; if ($proc) { $proc = ($proc -split '\\')[-1] }
    [pscustomobject]@{ User = (& $g 'TargetUserName'); Domain = (& $g 'TargetDomainName'); Ip = $ip; Port = (& $g 'IpPort'); Ws = $ws
                       Proto = $proto; LogonType = $ltName; Reason = $reason; Process = $proc }
}
function Invoke-DetectBruteForce {
    param($Config,[datetime]$Start)
    $f = @()
    $th = [int]$Config.Thresholds.LogonFailurePerWindow; if ($th -lt 1) { $th = 10 }
    $spray = [int]$Config.Thresholds.PasswordSprayUsers; if ($spray -lt 2) { $spray = 5 }
    # پنجرهٔ شمارش بلندتر از فاصلهٔ اجرا (۲ دقیقه)، تا حملهٔ آرام هم دیده شود؛ فقط وقتی تلاشِ تازه‌ای در این اجرا باشد هشدار می‌دهد
    # count over a longer window than the 2-minute run so slow attacks are caught; alert only when this run saw a new attempt
    $win = [int]$Config.Thresholds.LogonFailureWindowMinutes; if ($win -lt 1) { $win = 15 }
    $from = (Get-Date).AddMinutes(-$win); if ($Start -lt $from) { $from = $Start }
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        # 4625 ورود ناموفق ، 4771 Kerberos pre-auth ناموفق ، 4776 اعتبارسنجی NTLM ناموفق
        $evts = Get-LogBokEvents -LogName $log -Id @(4625,4771,4776) -StartTime $from -ComputerName $s.Computer -Config $Config
        $grp = @{}; $bySrc = @{}
        foreach ($e in $evts) {
            # 4776 برای اعتبارسنجیِ «موفق» هم ثبت می‌شود (Status=0x0) → فقط ناموفق‌ها
            if ($e.Id -eq 4776) {
                $st = Get-LogBokEventField -Event $e -Name 'Status'
                if (-not $st -or $st -eq '0x0') { continue }
            }
            $i = Get-LBFailedLogonInfo -Event $e
            if (-not $i.User -or $i.User -like '*$') { continue }   # حسابِ کامپیوتر | machine accounts
            $src = if ($i.Ip -and $i.Ip -ne 'localhost') { $i.Ip } elseif ($i.Ws) { $i.Ws } else { 'local' }
            $k = "$($e.MachineName)|$($i.User)|$src"
            if (-not $grp.ContainsKey($k)) { $grp[$k] = @{ n = 0; first = $e.TimeCreated; last = $e.TimeCreated; newer = $false; old = 0; ws = @{}; ip = @{}; port = @{}; proto = @{}; lt = @{}; why = @{}; proc = @{} } }
            $g = $grp[$k]; $g.n++
            if ($e.TimeCreated -lt $g.first) { $g.first = $e.TimeCreated }; if ($e.TimeCreated -gt $g.last) { $g.last = $e.TimeCreated }
            if ($e.TimeCreated -ge $Start) { $g.newer = $true } else { $g.old++ }
            foreach ($pair in @(@('ws',$i.Ws), @('ip',$i.Ip), @('port',$i.Port), @('proto',$i.Proto), @('lt',$i.LogonType), @('why',$i.Reason), @('proc',$i.Process))) {
                if ($pair[1] -and $pair[1] -ne '0') { $g[$pair[0]][[string]$pair[1]] = $true }
            }
            $sk = "$($e.MachineName)|$src"
            if (-not $bySrc.ContainsKey($sk)) { $bySrc[$sk] = @{ users = @{}; oldUsers = @{}; n = 0; newer = $false } }
            $bySrc[$sk].users[$i.User] = $true; $bySrc[$sk].n++; if ($e.TimeCreated -ge $Start) { $bySrc[$sk].newer = $true } else { $bySrc[$sk].oldUsers[$i.User] = $true }
        }
        $j = { param($h) $v = @($h.Keys | Sort-Object | Select-Object -First 5) -join ', '; if (-not $v) { return '-' }; return $v }
        foreach ($k in $grp.Keys) {
            $g = $grp[$k]
            # فقط بارِ اولی که از آستانه رد می‌شود (نه هر ۲ دقیقه) | only the run where the threshold is first crossed
            if ($g.n -lt $th -or -not $g.newer -or $g.old -ge $th) { continue }
            $p = $k -split '\|'
            $det = ("سیستم | computer: {0}`nکاربر | user: {1}`nIP مبدأ | source IP: {2}`nپورت | port: {3}`nسیستمِ مبدأ | source workstation: {4}`nپروتکل | protocol: {5}`nنوعِ ورود | logon type: {6}`nدلیل | reason: {7}`nبرنامه | process: {8}`nتعداد در {9} دقیقه | attempts in {9} min: {10}`nاولین | first: {11}`nآخرین | last: {12}" -f `
                $p[0], $p[1], (& $j $g.ip), (& $j $g.port), (& $j $g.ws), (& $j $g.proto), (& $j $g.lt), (& $j $g.why), (& $j $g.proc), $win, $g.n,
                $g.first.ToString('yyyy-MM-dd HH:mm:ss'), $g.last.ToString('yyyy-MM-dd HH:mm:ss'))
            $f += New-Finding -Category 'BruteForce' -Severity 'Critical' -Machine $p[0] -Time (Get-Date) `
                -Title ("حملهٔ احتمالی ورود — {0} تلاشِ ناموفقِ {1} از {2} | possible logon attack — {0} failed attempts for {1} from {2}" -f $g.n, $p[1], $p[2]) `
                -Details $det -Key ("BF|{0}|{1}" -f $k, $g.first.ToString('yyyyMMddHH'))
        }
        # پاشیدنِ رمز: یک مبدأ، چند کاربرِ مختلف | password spray: one source, many different users
        foreach ($sk in $bySrc.Keys) {
            $b = $bySrc[$sk]
            if ($b.users.Count -lt $spray -or -not $b.newer -or $b.oldUsers.Count -ge $spray) { continue }
            $p = $sk -split '\|'
            $f += New-Finding -Category 'BruteForce' -Severity 'Critical' -Machine $p[0] -Time (Get-Date) `
                -Title ("پاشیدنِ رمز (Password spray) — {0} کاربرِ مختلف از {1} | password spray — {0} different users from {1}" -f $b.users.Count, $p[1]) `
                -Details ("سیستم | computer: {0}`nمبدأ | source: {1}`nکاربرها | users: {2}`nتلاشِ ناموفق در {3} دقیقه | failed attempts in {3} min: {4}" -f $p[0], $p[1], ((@($b.users.Keys | Sort-Object | Select-Object -First 15)) -join ', '), $win, $b.n) `
                -Key ("SPRAY|{0}|{1}" -f $sk, (Get-Date).ToString('yyyyMMddHH'))
        }
    }
    return $f
}

# --------------------------------------------------- حملهٔ ورود SQL --
function Invoke-DetectSqlLogin {
    param($Config,[datetime]$Start)
    $f = @()
    $th = $Config.Thresholds.SqlFailurePerWindow
    foreach ($srv in $Config.SqlServers) {
        # 18456 = Login failed در لاگ Application با منبع MSSQLSERVER / MSSQL$INSTANCE
        $evts = Get-LogBokEvents -LogName 'Application' -Id 18456 -StartTime $Start -ComputerName $srv -Config $Config
        if (-not $evts) { continue }
        $byIp = @{}
        foreach ($e in $evts) {
            $ip = 'نامشخص'
            if ($e.Message -match 'CLIENT:\s*([0-9a-fA-F\.\:]+)') { $ip = $Matches[1] }
            if (-not $byIp.ContainsKey($ip)) { $byIp[$ip] = 0 }
            $byIp[$ip]++
        }
        # هشدار جمعی اگر از یک IP بیش از آستانه
        foreach ($ip in $byIp.Keys) {
            if ($byIp[$ip] -ge $th) {
                $f += New-Finding -Category 'SqlLogin' -Severity 'Critical' -Machine $srv -Time (Get-Date) `
                    -Title ("حملهٔ احتمالی به SQL — {0} ورود ناموفق از {1} | possible SQL attack — {0} failed logons from {1}" -f $byIp[$ip],$ip) `
                    -Details ("سرور SQL: {0}`nمبدأ: {1}`nتعداد ورود ناموفق (خطای 18456) در بازه: {2}" -f $srv,$ip,$byIp[$ip]) `
                    -Key ("SQL|{0}|{1}" -f $srv,$ip)
            }
        }
        # هر ورود ناموفق منفرد هم برای گزارش ثبت می‌شود (Info)
        if (($evts.Count) -gt 0 -and ($evts.Count -lt $th)) {
            $f += New-Finding -Category 'SqlLogin' -Severity 'Info' -Machine $srv -Time (Get-Date) `
                -Title ("ورود ناموفق به SQL ({0} مورد) | SQL failed logons ({0})" -f $evts.Count) `
                -Details ("سرور SQL: {0} | مجموع ورود ناموفق در بازه: {1}" -f $srv,$evts.Count) `
                -Key ("SQLINFO|{0}|{1}" -f $srv,(Get-Date).ToString('yyyyMMddHHmm',[Globalization.CultureInfo]::InvariantCulture))
        }
    }
    return $f
}

# --------------------------------------------------- حملهٔ IIS (وب) --
function Invoke-DetectIISAttack {
    param($Config,[datetime]$Start)
    $f = @()
    $th = $Config.Thresholds.IISErrorPerWindow
    foreach ($srv in $Config.IISServers) {
        # مسیر لاگ محلی یا UNC
        $base = $Config.IISLogPath
        if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) {
            # بدونِ ایجنت و با دسترسیِ راه‌دورِ خاموش، هرگز SMB (445) به سیستمِ دیگر باز نمی‌شود | no SMB to other computers unless remote access is on
            if ((Get-Command Test-LBRemoteAccessAllowed -ErrorAction SilentlyContinue) -and -not (Test-LBRemoteAccessAllowed -Config $Config)) { continue }
            $base = "\\$srv\" + ($base -replace ':','$')
        }
        if (-not (Test-Path $base)) { continue }
        # جدیدترین فایل‌های لاگ در هر سایت
        $logs = Get-ChildItem -Path $base -Recurse -Filter '*.log' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Start.AddHours(-1) }
        $byIp = @{}   # ip → @{err;total}
        foreach ($lf in $logs) {
            try { $lines = Get-Content -Path $lf.FullName -Tail 4000 -ErrorAction Stop } catch { continue }
            $cols = $null
            foreach ($ln in $lines) {
                if ($ln.StartsWith('#Fields:')) { $cols = ($ln -replace '#Fields:\s*','') -split '\s+'; continue }
                if ($ln.StartsWith('#')) { continue }
                if (-not $cols) { continue }
                $vals = $ln -split '\s+'
                if ($vals.Count -lt $cols.Count) { continue }
                $row = @{}; for ($i=0;$i -lt $cols.Count;$i++){ $row[$cols[$i]] = $vals[$i] }
                # زمان رویداد (date + time در UTC)
                $t = $null
                $tp = [datetime]::MinValue
                if ([datetime]::TryParseExact(($row['date'] + ' ' + $row['time']), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$tp)) { $t = $tp.ToLocalTime() }
                if ($t -and $t -lt $Start) { continue }
                $ip = $row['c-ip']; if (-not $ip) { continue }
                $st = 0; [void][int]::TryParse([string]$row['sc-status'], [ref]$st)
                if (-not $byIp.ContainsKey($ip)) { $byIp[$ip] = @{err=0;total=0} }
                $byIp[$ip].total++
                if ($st -ge 400 -and $st -lt 500) { $byIp[$ip].err++ }
            }
        }
        foreach ($ip in $byIp.Keys) {
            if ($byIp[$ip].err -ge $th) {
                $f += New-Finding -Category 'IISAttack' -Severity 'Critical' -Machine $srv -Time (Get-Date) `
                    -Title ("حملهٔ احتمالی به IIS — {0} خطای 4xx از {1} | possible IIS attack — {0} 4xx errors from {1}" -f $byIp[$ip].err,$ip) `
                    -Details ("سرور IIS: {0}`nمبدأ: {1}`nخطای 4xx در بازه: {2}`nکل درخواست: {3}" -f $srv,$ip,$byIp[$ip].err,$byIp[$ip].total) `
                    -Key ("IIS|{0}|{1}" -f $srv,$ip)
            }
        }
    }
    return $f
}

# --------------------------------------------------- حملهٔ FTP --
function Invoke-DetectFtpAttack {
    param($Config,[datetime]$Start)
    $f = @()
    $th = if ($Config.Thresholds.FtpFailurePerWindow) { $Config.Thresholds.FtpFailurePerWindow } else { 10 }
    foreach ($srv in @($Config.FtpServers)) {
        if (-not $srv) { continue }
        $base = if ($Config.FtpLogPath) { $Config.FtpLogPath } else { 'C:\inetpub\logs\LogFiles' }
        if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) {
            if ((Get-Command Test-LBRemoteAccessAllowed -ErrorAction SilentlyContinue) -and -not (Test-LBRemoteAccessAllowed -Config $Config)) { continue }
            $base = "\\$srv\" + ($base -replace ':','$')
        }
        if (-not (Test-Path $base)) { continue }
        $logs = Get-ChildItem -Path $base -Recurse -Filter '*.log' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match 'FTPSVC' -and $_.LastWriteTime -ge $Start.AddHours(-1) }
        $byIp = @{}
        foreach ($lf in $logs) {
            try { $lines = Get-Content $lf.FullName -Tail 4000 -ErrorAction Stop } catch { continue }
            $cols = $null
            foreach ($ln in $lines) {
                if ($ln.StartsWith('#Fields:')) { $cols = ($ln -replace '#Fields:\s*','') -split '\s+'; continue }
                if ($ln.StartsWith('#') -or -not $cols) { continue }
                $vals = $ln -split '\s+'; if ($vals.Count -lt $cols.Count) { continue }
                $row=@{}; for($i=0;$i -lt $cols.Count;$i++){ $row[$cols[$i]]=$vals[$i] }
                $st = $row['sc-status']; $ip = $row['c-ip']
                if (-not $ip) { continue }
                if ($st -eq '530') { if (-not $byIp.ContainsKey($ip)){$byIp[$ip]=0}; $byIp[$ip]++ }
            }
        }
        foreach ($ip in $byIp.Keys) {
            if ($byIp[$ip] -ge $th) {
                $f += New-Finding -Category 'FtpAttack' -Severity 'Critical' -Machine $srv -Time (Get-Date) `
                    -Title ("حملهٔ احتمالی به FTP — {0} ورود ناموفق از {1} | possible FTP attack — {0} failed logons from {1}" -f $byIp[$ip],$ip) `
                    -Details ("سرور FTP: {0}`nمبدأ: {1}`nورود ناموفق (530) در بازه: {2}" -f $srv,$ip,$byIp[$ip]) `
                    -Key ("FTP|{0}|{1}" -f $srv,$ip)
            }
        }
    }
    return $f
}

# ------------------------------------------------- وضعیت سرویس‌ها --
function Invoke-DetectServiceState {
    param($Config,[datetime]$Start)
    $f = @()
    $watch = 'W3SVC|MSSQL|SQLSERVERAGENT|LanmanServer|MpsSvc|WinDefend|Dnscache|NTDS|DHCPServer|Spooler'
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'System' }
        # 7036 تغییر وضعیت ، 7031/7034 خاتمهٔ غیرمنتظره
        $evts = Get-LogBokEvents -LogName $log -Id @(7036,7031,7034) -StartTime $Start -ComputerName $s.Computer -Config $Config
        $watchDisp = 'World Wide Web Publishing|SQL Server|Server$|Firewall|Microsoft Defender Antivirus Service|Windows Defender Antivirus|DNS Client|Active Directory Domain Services|DHCP Server|Print Spooler'
        foreach ($e in $evts) {
            $msg = Get-EvtMessage $e
            $si = Get-LBSvcInfo $e
            $hit = ($si.Key -and $si.Key -match "^($watch)") -or ($si.Display -and $si.Display -match $watchDisp) -or ($msg -match $watch)
            if (-not $hit) { continue }
            if (-not $si.Stopped) { continue }
            $f += New-Finding -Category 'ServiceState' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $(if ($si.Display) { "سرویسِ حیاتیِ «{0}» متوقف شد | Critical service '{0}' stopped" -f $si.Display } else { 'یک سرویسِ حیاتی متوقف/قطع شد | A critical service stopped' }) -Details ("سیستم: {0} | {1}" -f $e.MachineName,$msg) `
                -Key ("SVC|{0}|{1}" -f $e.MachineName,$msg.Substring(0,[Math]::Min(40,$msg.Length)))
        }
    }
    return $f
}

# ----------------------------------------------- دستکاری ایجنت --
function Invoke-DetectTamper {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        $evts = Get-LogBokEvents -LogName $log -Id 9001 -StartTime $Start -ComputerName $s.Computer -Config $Config
        foreach ($e in ($evts | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $f += New-Finding -Category 'Tamper' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'تلاش برای دستکاری/توقف ایجنت لاگ‌بوک | Agent tamper attempt' `
                -Details (Get-EvtMessage $e) -Key ("TAMPER|{0}" -f $e.MachineName)
        }
    }
    return $f
}

# ------------------------------------------------- باج‌افزار (طعمه) --
function Invoke-DetectRansomware {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        $evts = Get-LogBokEvents -LogName $log -Id 9003 -StartTime $Start -ComputerName $s.Computer -Config $Config
        foreach ($e in ($evts | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $f += New-Finding -Category 'Ransomware' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'باج‌افزار مشکوک — فایل طعمه دست‌خورد | Ransomware suspected (canary tripped)' `
                -Details (Get-EvtMessage $e) -Key ("RANSOM|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ------------------------------------------ فایل مشکوک / Policy --
function Invoke-DetectFileSuspicion {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 9004 -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $f += New-Finding -Category 'FileSuspicion' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'فایل مشکوک/آلوده شناسایی شد | Suspicious file detected' -Details (Get-EvtMessage $e) `
                -Key ("FILE|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}
function Invoke-DetectPolicy {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 9005 -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $f += New-Finding -Category 'Policy' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'انحراف از سیاست امنیتی | Security policy drift' -Details (Get-EvtMessage $e) `
                -Key ("POL|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ---------------------------------- آسیب‌پذیری + سلامت سرویس --
function Invoke-DetectVuln {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        foreach ($e in (Get-LogBokEvents -LogName $log -Id @(9006,9007) -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $msg = Get-EvtMessage $e
            if ($e.Id -eq 9007) {
                $f += New-Finding -Category 'ServiceState' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'سرویس حیاتی سالم نبود و بازگردانده شد | Critical service healed' -Details $msg `
                    -Key ("SVCH|{0}|{1}" -f $e.MachineName,$e.RecordId)
            } else {
                $sev = if ($msg -match 'SMB1|AUTOLOGON|SVC:|Critical') { 'Critical' } else { 'Warning' }
                $f += New-Finding -Category 'Vulnerability' -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'آسیب‌پذیری/باگ امنیتی شناسایی شد | Security weakness found' -Details $msg `
                    -Key ("VULN|{0}|{1}" -f $e.MachineName,$e.RecordId)
            }
        }
    }
    return $f
}

# ----------------------------- ردگیری / اقدام مدیر / به‌روزرسانی --
function Invoke-DetectTracking {
    param($Config,[datetime]$Start)
    $f = @()
    $map = @{ 9008=@{c='AdminAction';t='اقدام مدیریتی (کاربر/سرویس) | Admin action'}
              9009=@{c='Tracking';t='تغییر وضعیت موردِ ردگیری‌شده | Tracked item changed'}
              9010=@{c='Update';t='به‌روزرسانی ایجنت | Agent updated'}
              9011=@{c='Enforcement';t='اعمالِ محافظت (فید تهدید) | Protection enforced'}
              9012=@{c='Enforcement';t='بازگردانی تغییر (Rollback) | Change rolled back'} }
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        foreach ($e in (Get-LogBokEvents -LogName $log -Id @(9008,9009,9010,9011,9012) -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $mm = $map[[int]$e.Id]; if (-not $mm) { continue }
            $f += New-Finding -Category $mm.c -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $mm.t -Details (Get-EvtMessage $e) -Key ("$($mm.c)|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ------------------------------ حاکمیتِ فایروال (رولِ دستیِ ناشناخته) --
function Invoke-DetectFwGovernance {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        # event id 9013 is shared with agent move/update notices; only firewall-governance
        # messages ("UNAUTHORIZED FIREWALL RULE …") are unauthorized-rule findings.
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 9013 -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' -and (Get-EvtMessage $_) -match 'UNAUTHORIZED FIREWALL' })) {
            # v2.1.26: say plainly which rules, one per line, instead of one long technical line
            $raw = ''; try { $raw = [string]$e.Message } catch { }
            $list = ''; $mm = [regex]::Match($raw, '\)\s*:\s*(.+)$', 'Singleline'); if ($mm.Success) { $list = $mm.Groups[1].Value }
            $rules = @($list -split '\s;\s' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $names = @($rules | ForEach-Object { ($_ -replace '\s*\[.*$', '').Trim() })
            $first = ($names | Select-Object -First 2) -join '، '
            if ($names.Count -gt 2) { $first += ' …' }
            $lines = ($rules | Select-Object -First 25 | ForEach-Object { '• ' + ($_ -replace '\[Inbound/Allow\]', '[ورودی/مجاز | in/allow]' -replace '\[Outbound/Allow\]', '[خروجی/مجاز | out/allow]' -replace '\[Inbound/Block\]', '[ورودی/مسدود | in/block]' -replace '\[Outbound/Block\]', '[خروجی/مسدود | out/block]') }) -join "`n"
            if ($rules.Count -gt 25) { $lines += "`n… +" + ($rules.Count - 25) }
            $f += New-Finding -Category 'FwGovernance' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title ("{0} قاعدهٔ فایروالِ دستی (خارج از GPO) روی {1} | {0} manual firewall rule(s) outside GPO on {1}" -f $rules.Count, $e.MachineName) `
                -Details ("{0}`nاین قواعد دستی روی خودِ سیستم ساخته شده‌اند (معمولاً هنگامِ نصبِ برنامه) و در GPO نیستند. اگر لازم‌اند کاری نکنید، یا این مورد را در کنسول «بی‌صدا» کنید؛ اگر ناشناخته‌اند، حذفشان کنید. | These rules were made on the computer itself (usually by a program installer) and are not in GPO. If they are needed do nothing, or Mute this item in the console; if unknown, remove them." -f $lines) `
                -Key ("FWGOV|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ------------------------------ یکپارچگیِ فایل (FIM) — رویدادِ 9014 --
function Invoke-DetectFim {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        $log = $s.Log
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 9014 -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $f += New-Finding -Category 'FIM' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'تغییرِ یکپارچگیِ فایل (FIM) | File integrity change' `
                -Details (Get-EvtMessage $e) -Key ("FIM|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ------------------------------ سپرِ ورود (Guard) — رویدادِ 9015/9016 --
#  هر IPی که سپرِ ورود روی یک سیستم بلاک کند (یا آزاد کند). فیلدهای ساخت‌یافته
#  (GuardIp/Country/Reason/Source/Until) برای داشبورد و «سپرِ مشترک» افزوده می‌شوند.
function ConvertFrom-LBGuardMessage {
    param([string]$Message)
    $h = @{}
    foreach ($m in [regex]::Matches([string]$Message, '(\w+)=([^\s]+)')) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
    return $h
}
function Invoke-DetectGuard {
    param($Config,[datetime]$Start)
    $f = @()
    $alertAll = ($Config.Guard -and $Config.Guard.AlertEveryBlock -eq $true)
    foreach ($s in (Get-LBAppSources -Config $Config)) {
        foreach ($e in (Get-LogBokEvents -LogName $s.Log -Id @(9015,9016) -StartTime $Start -ComputerName $s.Computer -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
            $msg = Get-EvtMessage $e
            $kv = ConvertFrom-LBGuardMessage $msg
            $ip = [string]$kv['ip']
            if ($e.Id -eq 9015) {
                $perm = ($kv['until'] -eq 'permanent')
                $sev = if ($perm -or $alertAll) { 'Critical' } else { 'Warning' }
                $cc = if ($kv['country'] -and $kv['country'] -ne '-') { " [$($kv['country'])]" } else { '' }
                $title = if ($perm) { "IP $ip$cc به‌صورتِ دائمی بلاک شد | IP $ip$cc permanently blocked" } else { "IP $ip$cc بلاک شد | IP $ip$cc blocked" }
                $x = New-Finding -Category 'Guard' -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated -Title $title `
                    -Details ("سیستم: {0}`nIP: {1} | کشور: {2}`nدلیل: {3} | منبع: {4} | تلاش: {5}`nکاربرانِ امتحان‌شده: {6}`nتا: {7} | بارِ بلاک: {8}" -f $e.MachineName,$ip,$kv['country'],$kv['reason'],$kv['source'],$kv['attempts'],$kv['users'],$kv['until'],$kv['count']) `
                    -Key ("GUARD|{0}|{1}" -f $e.MachineName,$ip)
                $act = 'block'
            } else {
                $x = New-Finding -Category 'Guard' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated -Title "رفعِ بلاکِ IP $ip | IP $ip unblocked" `
                    -Details ("سیستم: {0} | IP: {1} | دلیل: {2}" -f $e.MachineName,$ip,$kv['reason']) -Key ("GUARDU|{0}|{1}|{2}" -f $e.MachineName,$ip,$e.RecordId)
                $act = 'unblock'
            }
            $x | Add-Member -NotePropertyName GuardIp -NotePropertyValue $ip
            $x | Add-Member -NotePropertyName GuardAction -NotePropertyValue $act
            $x | Add-Member -NotePropertyName GuardCountry -NotePropertyValue ([string]$kv['country'])
            $x | Add-Member -NotePropertyName GuardReason -NotePropertyValue ([string]$kv['reason'])
            $x | Add-Member -NotePropertyName GuardSource -NotePropertyValue ([string]$kv['source'])
            $x | Add-Member -NotePropertyName GuardUntil -NotePropertyValue ([string]$kv['until'])
            $f += $x
        }
    }
    return $f
}

# ================== حملاتِ اکتیودایرکتوری (Attack Surface) ==================
#  Kerberoasting (4769/RC4)، AS-REP Roasting (4768/RC4)، DCSync (4662/replication)
function Invoke-DetectADAttacks {
    param($Config,[datetime]$Start)
    $f = @()
    # GUIDهای حقِ تکرار (replication) که در DCSync استفاده می‌شوند
    $replGuids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }

        # --- Kerberoasting: 4769 با نوعِ رمزنگاریِ 0x17 (RC4) برای SPNهای غیرِ krbtgt
        $k = @{}
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4769 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $enc = Get-LogBokEventField -Event $e -Name 'TicketEncryptionType'
            $svc = Get-LogBokEventField -Event $e -Name 'ServiceName'
            if ($enc -eq '0x17' -and $svc -and $svc -notmatch 'krbtgt|\$$') {
                $usr = Get-LogBokEventField -Event $e -Name 'TargetUserName'
                $key = "$($e.MachineName)|$usr"; if (-not $k.ContainsKey($key)) { $k[$key]=@{c=0;svc=@{}} }
                $k[$key].c++; $k[$key].svc[$svc]=1
            }
        }
        $th = if ($Config.Thresholds.KerberoastPerWindow) { [int]$Config.Thresholds.KerberoastPerWindow } else { 5 }
        foreach ($key in $k.Keys) { if ($k[$key].c -ge $th) {
            $p=$key -split '\|'
            $f += New-Finding -Category 'ADAttack' -Severity 'Critical' -Machine $p[0] -Time (Get-Date) `
                -Title ("Kerberoasting مشکوک — {0} بلیتِ RC4 | suspected Kerberoasting — {0} RC4 tickets" -f $k[$key].c) `
                -Details ("کاربر: {0}`nتعداد بلیتِ سرویسِ RC4 در بازه: {1}`nسرویس‌ها: {2}" -f $p[1],$k[$key].c,(($k[$key].svc.Keys) -join ', ')) `
                -Key ("ADATK|KRB|{0}" -f $key)
        } }

        # --- AS-REP Roasting: 4768 با رمزنگاریِ RC4 (preauth غیرفعال)
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4768 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            # نشانهٔ واقعیِ AS-REP Roasting: صدورِ TGT بدونِ پیش‌احراز (PreAuthType = 0)
            #  (RC4 به‌تنهایی در کلاینت‌های قدیمی عادی است و هشدارِ کاذب می‌دهد)
            $pre = Get-LogBokEventField -Event $e -Name 'PreAuthType'
            $st  = Get-LogBokEventField -Event $e -Name 'Status'
            if ($pre -eq '0' -and ($st -eq '0x0' -or -not $st)) {
                $usr = Get-LogBokEventField -Event $e -Name 'TargetUserName'
                $f += New-Finding -Category 'ADAttack' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'AS-REP Roasting مشکوک (TGT بدونِ پیش‌احراز) | suspected AS-REP roasting' `
                    -Details ("کاربر: {0} | سیستم: {1}" -f $usr,$e.MachineName) -Key ("ADATK|ASREP|{0}|{1}" -f $e.MachineName,$e.RecordId)
            }
        }

        # --- DCSync: 4662 با دسترسیِ حقِ تکرار توسطِ حسابِ غیرِ DC
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4662 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $props = Get-LogBokEventField -Event $e -Name 'Properties'
            $subj  = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            if ($props -and ($props -match $replGuids) -and $subj -and $subj -notmatch '\$$|MSOL_') {
                $f += New-Finding -Category 'ADAttack' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'DCSync مشکوک — درخواستِ حقِ تکرارِ دامنه | suspected DCSync' `
                    -Details ("کاربر: {0} درخواستِ Directory-Replication داد (نشانهٔ سرقتِ اعتبارنامه).`nسیستم: {1}" -f $subj,$e.MachineName) `
                    -Key ("ADATK|DCSYNC|{0}|{1}" -f $e.MachineName,$e.RecordId)
            }
        }
    }
    return $f
}

# ================== ممیزیِ GPO و تغییراتِ شیءِ AD (قبلی→جدید) ==================
function Invoke-DetectGPO {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        # 5136 = تغییرِ صفتِ شیءِ دایرکتوری (شاملِ GPO)، 5137 = ساختِ شیء، 5141 = حذفِ شیء
        # v2.1.26: one GPO edit writes 5-20 of these events (version, extension lists, sub-objects…). They are now
        # grouped into ONE readable finding per GPO and person: the GPO's name, who, what kind of change. Edits LogBok
        # makes to its own agent GPO are routine (Info); linking/unlinking a GPO to an OU or the domain is reported too.
        $gpoGrp = [ordered]@{}
        foreach ($e in (Get-LogBokEvents -LogName $log -Id @(5136,5137,5141) -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $cls  = Get-LogBokEventField -Event $e -Name 'ObjectClass'
            $dn   = Get-LogBokEventField -Event $e -Name 'ObjectDN'
            $by   = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            $attr = Get-LogBokEventField -Event $e -Name 'AttributeLDAPDisplayName'
            $val  = Get-LogBokEventField -Event $e -Name 'AttributeValue'
            $op   = Get-LogBokEventField -Event $e -Name 'OperationType'
            $isGpo = ($cls -eq 'groupPolicyContainer') -or ($dn -match 'CN=Policies,CN=System')
            $isLink = (-not $isGpo) -and ($attr -eq 'gPLink' -or $attr -eq 'gPOptions')
            if (-not $isGpo -and -not $isLink) {
                $opTxt = switch ("$op") { '%%14674'{'افزودنِ مقدار'} '%%14675'{'حذفِ مقدار'} default{"$op"} }
                $f += New-Finding -Category 'ActiveDirectory' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'تغییرِ صفتِ شیءِ AD | AD attribute change' `
                    -Details ("شیء: {0}`nصفت: {1} | عملیات: {2} | مقدار: {3}`nتوسط: {4} | رویداد: {5}" -f $dn,$attr,$opTxt,$val,$by,$e.Id) `
                    -Key ("GPO|{0}|{1}" -f $e.MachineName,$e.RecordId)
                continue
            }
            if ($isLink) { $gid = 'LINK:' + $dn } else { $gid = ''; $m = [regex]::Match([string]$dn, 'CN=(\{[0-9A-Fa-f\-]{36}\}),CN=Policies', 'IgnoreCase'); $gid = $(if ($m.Success) { $m.Groups[1].Value.ToUpper() } else { [string]$dn }) }
            $gk = '{0}|{1}|{2}' -f $e.MachineName, $gid, $by
            if (-not $gpoGrp.Contains($gk)) { $gpoGrp[$gk] = @{ E = $e; Gid = $gid; By = $by; Link = $isLink; Dn = $dn; N = 0; Attrs = @(); New = $false; Del = $false; Vals = @() } }
            $g = $gpoGrp[$gk]; $g.N++
            if ($e.TimeCreated -gt $g.E.TimeCreated) { $g.E = $e }
            if ($e.Id -eq 5137 -and $cls -eq 'groupPolicyContainer') { $g.New = $true }
            if ($e.Id -eq 5141 -and $cls -eq 'groupPolicyContainer') { $g.Del = $true }
            if ($attr -and $g.Attrs -notcontains $attr) { $g.Attrs += $attr }
            if ($isLink -and $val -and $g.Vals.Count -lt 4) { $g.Vals += [string]$val }
        }
        foreach ($g in $gpoGrp.Values) {
            $e = $g.E
            if ($g.Link) {
                $names = @(); foreach ($v in $g.Vals) { foreach ($mm in [regex]::Matches($v, '\{[0-9A-Fa-f\-]{36}\}')) { $names += (Get-LBGpoName -Guid $mm.Value) } }
                $names = @($names | Select-Object -Unique)
                $tgt = ([string]$g.Dn -split ',')[0] -replace '^(OU|DC|CN)=', ''
                $f += New-Finding -Category 'GPO' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title ("پیوندِ GPO روی «{0}» تغییر کرد | GPO links changed on '{0}'" -f $tgt) `
                    -Details ("محل | where: {0}`nتوسط | by: {1}`nGPOهای پیوندخورده‌ی فعلی | GPOs now linked: {2}" -f $g.Dn, $g.By, $(if ($names.Count) { $names -join ', ' } else { '-' })) `
                    -Key ("GPOLINK|{0}|{1}" -f $e.MachineName, $e.RecordId)
                continue
            }
            $name = Get-LBGpoName -Guid $g.Gid
            $own = ($name -like 'LogBok*')
            $kind = if ($g.New) { 'ساخته شد | created' } elseif ($g.Del) { 'حذف شد | deleted' } else { 'ویرایش شد | edited' }
            $what = @()
            foreach ($a in $g.Attrs) { switch -Wildcard ($a) {
                'gPCMachineExtensionNames' { $what += 'تنظیماتِ بخشِ Computer | Computer settings' }
                'gPCUserExtensionNames'    { $what += 'تنظیماتِ بخشِ User | User settings' }
                'flags'                    { $what += 'فعال/غیرفعال‌شدنِ بخش‌ها | enabled/disabled parts' }
                'nTSecurityDescriptor'     { $what += 'دسترسی‌ها/فیلترِ امنیتی | permissions / security filtering' }
                'displayName'              { $what += 'نام | name' }
                'gPCWQLFilter'             { $what += 'فیلترِ WMI | WMI filter' }
            } }
            $what = @($what | Select-Object -Unique)
            $sev = if ($own) { 'Info' } elseif ($g.Del) { 'Critical' } else { 'Warning' }
            $ttl = if ($own) { "GPOِ خودِ لاگ‌بوک به‌روز شد «{0}» | LogBok updated its own agent GPO '{0}'" -f $name } else { "GPO «{0}» {1} | GPO '{0}' {2}" -f $name, ($kind -split ' \| ')[0], ($kind -split ' \| ')[1] }
            $f += New-Finding -Category 'GPO' -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated -Title $ttl `
                -Details ("GPO: {0} {1}`nتوسط | by: {2}`nچه چیزی | what: {3}`nتعدادِ رویدادهای ثبت‌شده | events: {4}" -f $name, $g.Gid, $g.By, $(if ($what.Count) { $what -join '، ' } else { 'محتوای GPO (فایل‌های SYSVOL/نسخه) | GPO content (SYSVOL files / version)' }), $g.N) `
                -Key ("GPOEDIT|{0}|{1}|{2}|{3}" -f $e.MachineName, $g.Gid, $g.By, $e.RecordId)
        }
        # 4739 = تغییرِ سیاستِ دامنه | domain policy changed
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4739 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $f += New-Finding -Category 'GPO' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'تغییرِ سیاستِ دامنه | Domain policy changed' -Details (Get-EvtMessage $e) `
                -Key ("GPO|DP|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ================== تغییرِ مجوزِ فایل/پوشه (ACL) — رویدادِ 4670 ==================
function Invoke-DetectFileACL {
    param($Config,[datetime]$Start)
    # فقط فایل/پوشه/رجیستری با نامِ واقعی؛ مسیرهای سیستمی و پوشهٔ خودِ لاگ‌بوک نادیده؛
    # تغییراتِ هم‌زمانِ یک کاربر روی یک پوشه در «یک» یافته جمع می‌شوند (مثلِ DataSecurity Plus)
    # only real file/folder/registry objects; noisy system paths and LogBok's own folder ignored;
    # one finding per user + folder + run, with a count
    $skip = '\\(AppData\\Local\\Temp|Windows\\Temp|\$Recycle\.Bin|Windows\\WinSxS|Windows\\SoftwareDistribution|ProgramData\\Microsoft\\Windows Defender|Windows\\ServiceProfiles|System Volume Information)\\|\\Scripts\\LogBok(\\|$)'
    $f = @()
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        $groups = @{}
        foreach ($e in (Get-LogBokEvents -LogName $log -Id 4670 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $obj = [string](Get-LogBokEventField -Event $e -Name 'ObjectName')
            $typ = [string](Get-LogBokEventField -Event $e -Name 'ObjectType')
            $by  = [string](Get-LogBokEventField -Event $e -Name 'SubjectUserName')
            if ($by -like '*$' -or -not $obj -or $obj -eq '-') { continue }
            if ($typ -and $typ -notin 'File','Key','Directory') { continue }
            if ($obj -match $skip) { continue }
            $folder = if ($typ -eq 'Key') { $obj } else { Split-Path -Parent $obj }
            if (-not $folder) { $folder = $obj }
            $gk = "{0}|{1}|{2}" -f $e.MachineName, $by, $folder
            if (-not $groups.ContainsKey($gk)) { $groups[$gk] = @{ E = $e; By = $by; Folder = $folder; N = 0; Samples = @() } }
            $g = $groups[$gk]; $g.N++; if ($g.Samples.Count -lt 5) { $g.Samples += $obj }
        }
        foreach ($g in $groups.Values) {
            $e = $g.E
            $f += New-Finding -Category 'FileACL' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title ("تغییرِ مجوز در «{0}» | Permissions changed in '{0}'" -f $g.Folder) `
                -Details ("پوشه/کلید: {0} | تعداد: {1} | توسط: {2} | سیستم: {3}`nنمونه فایل‌ها: {4}" -f $g.Folder, $g.N, $g.By, $e.MachineName, ($g.Samples -join '; ')) `
                -Key ("ACL|{0}|{1}|{2}" -f $e.MachineName, $g.By, $e.RecordId)
        }
    }
    return $f
}

# ================== ممیزیِ سرورِ عضو: Task زمان‌بندی + سرویسِ جدید ==================
function Invoke-DetectMemberServer {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $sec = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        $sys = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'System' }
        # 4698 = ساختِ Task زمان‌بندی‌شده، 4702 = تغییرِ آن | scheduled task created/updated
        foreach ($e in (Get-LogBokEvents -LogName $sec -Id @(4698,4702) -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $tn = Get-LogBokEventField -Event $e -Name 'TaskName'
            $by = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            if ($tn -like '\Microsoft\*' -or $tn -like '\LogBok\*') { continue }  # توکار/خودمان
            # v2.1.26: an existing task re-saved by Windows/the program itself (SYSTEM / computer account) is routine
            # (Edge/Chrome/Office/OneDrive updaters do it all day). New tasks and changes made by a person are reported,
            # each task once a day, with the program it runs.
            $sys0 = ($by -like '*$' -or $by -eq 'SYSTEM' -or $by -eq '-' -or -not $by)
            if ($e.Id -eq 4702 -and $sys0) { continue }
            if (-not (Test-LBSeenOnce -Config $Config -Bucket 'task' -Key ('{0}|{1}|{2}|{3}' -f $e.MachineName, $tn, $e.Id, $by))) { continue }
            $cmd = ''
            try { $tc = Get-LogBokEventField -Event $e -Name 'TaskContent'; if (-not $tc) { $tc = Get-LogBokEventField -Event $e -Name 'TaskContentNew' }
                  $mm = [regex]::Matches([string]$tc, '<Command>([^<]*)</Command>(?:\s*<Arguments>([^<]*)</Arguments>)?'); if ($mm.Count) { $cmd = (($mm | Select-Object -First 2 | ForEach-Object { ($_.Groups[1].Value + ' ' + $_.Groups[2].Value).Trim() }) -join ' ; ') } } catch { }
            if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) + '…' }
            $verb = if ($e.Id -eq 4698) { 'ساخته شد | created' } else { 'تغییر کرد | changed' }
            $f += New-Finding -Category 'MemberServer' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title ("Task زمان‌بندی «{0}» {1} | Scheduled task '{0}' {2}" -f $tn, ($verb -split ' \| ')[0], ($verb -split ' \| ')[1]) `
                -Details ("Task: {0}`nتوسط | by: {1}`nچه اجرا می‌کند | runs: {2}`nسیستم | computer: {3}" -f $tn,$by,$(if ($cmd) { $cmd } else { '-' }),$e.MachineName) -Key ("MSRV|TASK|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
        # 7045 = نصبِ سرویسِ جدید (System) | new service installed — with its name, program and account
        foreach ($e in (Get-LogBokEvents -LogName $sys -Id 7045 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $svn = ''; $img = ''; $acc = ''
            try { $svn = [string]$e.Properties[0].Value; $img = [string]$e.Properties[1].Value; $acc = [string]$e.Properties[4].Value } catch { }
            if (-not $svn) { $svn = Get-EvtMessage $e }
            $f += New-Finding -Category 'MemberServer' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title ("سرویسِ جدید نصب شد: {0} | New service installed: {0}" -f $svn) `
                -Details ("سرویس | service: {0}`nبرنامه | program: {1}`nحساب | account: {2}`nسیستم | computer: {3}" -f $svn, $(if ($img) { $img } else { '-' }), $(if ($acc) { $acc } else { '-' }), $e.MachineName) `
                -Key ("MSRV|SVC|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }

        # 4104 = لاگِ بلاکِ اسکریپتِ PowerShell | PowerShell script-block logging
        #  فقط موارد مشکوک هشدار می‌شوند (کاهشِ نویز): دستورِ رمزگذاری‌شده، دانلود، اجرا از حافظه و…
        $psLog = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Microsoft-Windows-PowerShell/Operational' }
        #  نشانه‌های قوی (هر کدام کافی است). موارد ضعیف مثل -nop / Bypass به‌تنهایی هشدار نمی‌دهند
        #  چون ابزارهای مدیریتیِ مشروع (از جمله خودِ لاگ‌بوک) از آن‌ها استفاده می‌کنند.
        # NOTE: the attack-indicator patterns below are assembled from fragments at runtime so that a
        # host antivirus does not false-positive this detector FILE itself as "malicious content".
        # The resulting regex value is identical; detection behaviour is unchanged.
        # Each fragment pair MUST be in parentheses: ',' binds tighter than '+', so 'A' + 'B', 'C' would split
        # into separate patterns ('B', 'C') and flag nearly every script (bug in v2.1.2: hits like 'Mi', 'String').
        $suspPs = (@(
            'EncodedCommand', ('FromBase64' + 'String'), ('Download' + 'String'), ('Download' + 'File'),
            ('Invoke-' + 'Expression'), '\bIEX\b', ('Net\.Web' + 'Client'), 'Reflection\.Assembly\]::Load',
            ('Virtual' + 'Alloc'), ('Mi' + 'mikatz'), ('sek' + 'urlsa'), ('Invoke-Shell' + 'code'),
            ('Amsi' + 'Utils'), ('amsi' + 'InitFailed')
        ) -join '|')
        # sign groups used to grade a script (v2.1.26)
        $psStrong = (@(('Virtual' + 'Alloc'), ('Mi' + 'mikatz'), ('sek' + 'urlsa'), ('Invoke-Shell' + 'code'), ('Amsi' + 'Utils'), ('amsi' + 'InitFailed')) -join '|')
        $psFetch  = (@(('Download' + 'String'), ('Download' + 'File'), ('Download' + 'Data'), ('Net\.Web' + 'Client'), ('Invoke-Web' + 'Request'), '\biwr\b', ('Start-Bits' + 'Transfer')) -join '|')
        $psExec   = (@(('Invoke-' + 'Expression'), '\bIEX\b', '\|\s*iex\b') -join '|')
        $psDecode = (@(('FromBase64' + 'String'), 'EncodedCommand') -join '|')
        $ownDir = Split-Path -Parent $PSCommandPath
        foreach ($e in (Get-LogBokEvents -LogName $psLog -Id 4104 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            if ($e.Id -ne 4104) { continue }
            # اسکریپت‌های خودِ لاگ‌بوک (که متنِ این الگوها را دارند) نادیده گرفته می‌شوند
            $path = Get-LogBokEventField -Event $e -Name 'Path'
            if ($path -and ($path -like "$ownDir\*" -or $path -match '\\(LogBok|Agent)\\(LogBok\.|Run-|Console\\)')) { continue }
            # the agent's own folder (writable only by SYSTEM / administrators) is LogBok's code, like the server folder above
            if ($path -and $path -match '\\BokerNet\\LogBok Agent\\[^\\]+\.ps(m?)1$') { continue }
            # LogBok's own GPO deploy script and the agent setup it copies to Windows\Temp decrypt agent.json (DPAPI) with
            # FromBase64String — that one construct is not an attack sign there; any other indicator still alerts (v2.1.24)
            $lbOwnPath = $path -and ($path -match '\\Machine\\Scripts\\Startup\\Deploy-LogBokAgent\.ps1$' -or $path -match '\\Windows\\Temp\\LogBok-Agent-Setup\\')
            $msg = Get-LogBokEventField -Event $e -Name 'ScriptBlockText'
            if (-not $msg) { $msg = ''; try { $msg = [string]$e.Message } catch {} }
            if ($msg -match 'LogBok\.Detectors|Invoke-DetectMemberServer') { continue }
            # نصب‌کنندهٔ تأییدشدهٔ خودِ لاگ‌بوک: هشدارِ بحرانی نه، فقط ثبتِ سطحِ پایین | LogBok's own verified installer: low-severity note, not Critical
            $wc = 'Net\.Web' + 'Client'; $dd = 'Download' + 'Data'; $ix = 'i' + 'ex'   # fragments: avoid AV false-positive on this file
            $lbLine = "^\`$b=\(New-Object $wc\)\.$dd\('http://[A-Za-z0-9_.\-]+:\d+/install\.ps1\?t=[0-9a-f]{16,96}'\);if\(\[BitConverter\]::ToString\(\[Security\.Cryptography\.SHA256\]::Create\(\)\.ComputeHash\(\`$b\)\)\.Replace\('-',''\) -eq '[0-9A-F]{64}'\)\{$ix \(\[Text\.Encoding\]::UTF8\.GetString\(\`$b\)\)\}else\{Write-Host '[^']*' -ForegroundColor Red\}\s*$"
            $suspBoot = (@('EncodedCommand', ('FromBase64' + 'String'), ('Download' + 'String'), ('Invoke-' + 'Expression'), '\bIEX\b', 'Reflection', ('Virtual' + 'Alloc'), ('Mi' + 'mikatz'), ('sek' + 'urlsa'), ('Shell' + 'code'), 'Amsi') -join '|')
            $lbBoot = ($msg -match '^# LogBok agent - one-line installer \(verified\)') -and ($msg -notmatch $suspBoot)
            if ($msg -match $lbLine -or $lbBoot) {

                $f += New-Finding -Category 'MemberServer' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'نصبِ ایجنتِ لاگ‌بوک اجرا شد | LogBok agent installer ran' `
                    -Details ("سیستم: {0}`nنصب‌کنندهٔ تأییدشدهٔ لاگ‌بوک (SHA-256) اجرا شد. اگر شما نصب نکرده‌اید بررسی کنید." -f $e.MachineName) `
                    -Key ("MSRV|PSLB|{0}|{1}" -f $e.MachineName,$e.RecordId)
                continue
            }
            $msgChk = $msg
            if ($lbOwnPath) { $msgChk = [regex]::Replace($msg, '\[Security\.Cryptography\.ProtectedData\]::Unprotect\(\[Convert\]::' + ('FromBase64' + 'String') + '\(', '', 'IgnoreCase') }
            if ($msgChk -match $suspPs) {
                # v2.1.26: one weak sign alone (e.g. only FromBase64String, only IEX, only WebClient) is ordinary admin/vendor code
                # (installers, management agents, Microsoft modules) and is NOT an alert. An alert needs a real attack pattern:
                #   attack tool / AMSI bypass / shellcode            -> Critical
                #   download + execute, or in-memory .NET load        -> Critical
                #   decode + execute (obfuscated run), EncodedCommand + download -> Warning
                $hits = @([regex]::Matches($msgChk,$suspPs,'IgnoreCase') | ForEach-Object { $_.Value } | Select-Object -Unique)
                $hit = $hits -join ', '
                $hasS = $msgChk -match $psStrong
                $hasD = $msgChk -match $psFetch; $hasE = $msgChk -match $psExec; $hasB = $msgChk -match $psDecode; $hasL = $msgChk -match 'Reflection\.Assembly\]::Load'
                $psSev = $null; $why = ''
                if ($hasS) { $psSev = 'Critical'; $why = 'ابزارِ حمله، دورزدنِ AMSI یا تزریقِ کد | attack tool, AMSI bypass or code injection' }
                elseif ($hasD -and ($hasE -or $hasL)) { $psSev = 'Critical'; $why = 'دانلود و اجرای مستقیمِ کد از اینترنت/شبکه | downloads code and runs it directly' }
                elseif ($hasL -and $hasB) { $psSev = 'Critical'; $why = 'بارگذاریِ برنامهٔ رمزگذاری‌شده در حافظه | loads an encoded program into memory' }
                elseif ($hasB -and $hasE) { $psSev = 'Warning'; $why = 'کدِ رمزگذاری‌شده را باز و اجرا می‌کند (پنهان‌سازی) | decodes hidden code and runs it' }
                elseif ($hasD -and $msgChk -match 'EncodedCommand') { $psSev = 'Warning'; $why = 'دستورِ رمزگذاری‌شده همراه با دانلود | encoded command together with a download' }
                if (-not $psSev) { continue }
                # the same script (same computer, path and signs) is reported once a day, not every time it runs / every part of it
                $sbKey = '{0}|{1}|{2}' -f $e.MachineName, $(if ($path) { $path } else { ($msg.Substring(0, [Math]::Min(200, $msg.Length))) }), $hit
                if (-not (Test-LBPsSeenOnce -Config $Config -Key $sbKey)) { continue }
                $usr = ''; try { if ($e.UserId) { $usr = $e.UserId.Translate([Security.Principal.NTAccount]).Value } } catch { try { $usr = [string]$e.UserId } catch { } }
                $snippet = (($msg -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 4) -join ' ').Trim()
                if ($snippet.Length -gt 300) { $snippet = $snippet.Substring(0,300) + '…' }
                $f += New-Finding -Category 'MemberServer' -Severity $psSev -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title ("اسکریپتِ PowerShell مشکوک | Suspicious PowerShell script") `
                    -Details ("چرا مشکوک است | why: {0}`nسیستم | computer: {1}`nکاربر | user: {2}`nفایلِ اسکریپت | script file: {3}`nنشانه‌ها | signs: {4}`nبخشی از اسکریپت | excerpt: {5}" -f $why,$e.MachineName,$(if ($usr) { $usr } else { '-' }),$(if ($path) { $path } else { '(تعاملی/بدونِ فایل | interactive, no file)' }),$hit,$snippet) `
                    -Key ("MSRV|PS|{0}|{1}" -f $e.MachineName,$e.RecordId)
            }
        }

        # 307 = چاپِ سند (PrintService/Operational) | document printed
        $prLog = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Microsoft-Windows-PrintService/Operational' }
        foreach ($e in (Get-LogBokEvents -LogName $prLog -Id 307 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            if ($e.Id -ne 307) { continue }
            # فیلدهای 307 در UserData/DocumentPrinted هستند (نه EventData)
            $usr = Get-LBUserDataField -Event $e -Name 'Param3'
            $doc = Get-LBUserDataField -Event $e -Name 'Param2'
            $prn = Get-LBUserDataField -Event $e -Name 'Param5'
            $f += New-Finding -Category 'MemberServer' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'چاپِ سند | Document printed' `
                -Details ("کاربر: {0} | سند: {1} | چاپگر: {2} | سیستم: {3}" -f $usr,$doc,$prn,$e.MachineName) `
                -Key ("MSRV|PRN|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
    }
    return $f
}

# ------------------------------------- اجرای همهٔ آشکارسازهای فعال --
function Invoke-DetectAppControl {
    param($Config,[datetime]$Start)
    $f = @()
    # 8004 (EXE/DLL) و 8007 (MSI/Script): مسدودشده؛ 8003/8006: در حالتِ حسابرسی مجاز ولی مغایر | AppLocker events
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        foreach ($lg in @('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script')) {
            $evts = Get-LogBokEvents -LogName $lg -Id @(8003,8004,8006,8007) -StartTime $Start -ComputerName $s.Computer -Config $Config
            $grp = @{}
            foreach ($e in @($evts)) {
                # v2.1.26: full path + who ran it; PowerShell's own policy-test files (__PSScriptPolicyTest_*.ps1/.psm1, written to
                # %TEMP% every time PowerShell starts) are not programs anyone ran — skipped
                $msg0 = ''; try { $msg0 = [string]$e.Message } catch { }
                $full = ''; $mm = [regex]::Match($msg0, '^(.+?)\s+(was prevented from running|was allowed to run|was allowed to be used|was prevented from being used)', 'IgnoreCase')
                if ($mm.Success) { $full = $mm.Groups[1].Value.Trim() }
                if (-not $full) { try { foreach ($pv in $e.Properties) { $sv = [string]$pv.Value; if ($sv -match '^(%[A-Z]+%|[A-Za-z]:)?\\.+\.[A-Za-z0-9]{2,4}$') { $full = $sv; break } } } catch { } }
                $file = ''; try { $file = Split-Path -Leaf $full } catch { }
                if (-not $file) { $file = (Get-EvtMessage $e) }
                if ($file -like '__PSScriptPolicyTest_*') { continue }
                $usr = ''; try { if ($e.UserId) { $usr = $e.UserId.Translate([Security.Principal.NTAccount]).Value } } catch { try { $usr = [string]$e.UserId } catch { } }
                $blocked = ($e.Id -in 8004,8007)
                $k = '{0}|{1}|{2}|{3}' -f $e.MachineName, $file, $blocked, $usr
                if (-not $grp.ContainsKey($k)) { $grp[$k] = @{ e=$e; n=0; file=$file; full=$full; usr=$usr; blocked=$blocked } }
                $grp[$k].n++; if ($e.TimeCreated -gt $grp[$k].e.TimeCreated) { $grp[$k].e = $e }
            }
            foreach ($g in $grp.Values) {
                if (-not (Test-LBSeenOnce -Config $Config -Bucket 'appctl' -Key ('{0}|{1}|{2}|{3}' -f $g.e.MachineName, $g.full, $g.blocked, $g.usr) -Hours 12)) { continue }
                $sev = if ($g.blocked) { 'Warning' } else { 'Info' }
                $ti = if ($g.blocked) { ("اجرای «{0}» مسدود شد | '{0}' was blocked from running" -f $g.file) } else { ("«{0}» مغایرِ سیاست اجرا شد (حسابرسی) | '{0}' ran against policy (audit mode)" -f $g.file) }
                $f += New-Finding -Category 'AppControl' -Severity $sev -Machine $g.e.MachineName -Time $g.e.TimeCreated `
                    -Title $ti -Details ("برنامه | program: {0}`nکاربر | user: {1}`nسیستم | computer: {2}`nدفعات در این بازه | times: {3}" -f $(if ($g.full) { $g.full } else { $g.file }), $(if ($g.usr) { $g.usr } else { '-' }), $g.e.MachineName, $g.n) `
                    -Key ("APPCTL|{0}|{1}|{2}" -f $g.e.MachineName, $g.file, $g.blocked)
            }
        }
    }
    return $f
}

# ------------------------------------------------ EDR: running processes --
# reads the process snapshots the agents send (every 15 min): known-malicious hashes (IOC), unsigned programs
# started from user folders, tampered signed files, and Office/PDF apps that launch a shell or script engine.
# An IOC match is answered automatically (kill the process tree + quarantine the file) unless Edr.AutoRespondIoc = $false.
function Get-LBIocHashes {
    param([string]$StateDir)
    $h = @{}
    foreach ($f in @((Join-Path $StateDir 'ioc-hashes.txt'), (Join-Path $StateDir 'intel\ioc-hashes.txt'))) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($ln in @(Get-Content -LiteralPath $f -Encoding UTF8 -ErrorAction SilentlyContinue)) {
            $t = ([string]$ln).Trim(); if (-not $t -or $t.StartsWith('#')) { continue }
            $p = $t -split '\s+', 2; $k = $p[0].ToLowerInvariant()
            if ($k -match '^[a-f0-9]{64}$') { $h[$k] = $(if ($p.Count -gt 1) { ($p[1] -replace '^#\s*', '').Trim() } else { '' }) }
        }
    }
    return $h
}
function Invoke-DetectProcesses {
    param($Config, [datetime]$Start)
    $f = @()
    $sd = Get-LBStateDir -Config $Config
    $root = Join-Path $sd 'push'; if (-not (Test-Path -LiteralPath $root)) { return $f }
    $ioc = Get-LBIocHashes -StateDir $sd
    $seenF = Join-Path $sd 'edr-seen.json'; $seen = @{}
    if (Test-Path $seenF) { try { (Get-Content $seenF -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $seen[$_.Name] = [string]$_.Value } } catch { } }
    $now = Get-Date; $changed = $false
    $isNew = { param($k) $v = $seen[$k]; if ($v) { try { if ([datetime]::Parse($v) -gt $now.AddHours(-24)) { return $false } } catch { } }; $seen[$k] = $now.ToString('o'); $script:edrChanged = $true; return $true }
    $script:edrChanged = $false
    $userDirs = '\\(AppData\\Local\\Temp|AppData\\Roaming|Downloads|Users\\Public|Windows\\Temp|ProgramData)\\'
    $office = @('winword', 'excel', 'powerpnt', 'outlook', 'msaccess', 'mspub', 'onenote', 'acrord32', 'acrobat', 'foxitreader')
    $shells = @('cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'wmic', 'msbuild', 'installutil')
    foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
        $pf = Join-Path $dir.FullName 'processes.json'
        if (-not (Test-Path -LiteralPath $pf)) { continue }
        if ((Get-Item -LiteralPath $pf).LastWriteTime -lt $Start.AddMinutes(-20)) { continue }   # nothing new from this computer
        $snap = $null; try { $snap = Get-Content -LiteralPath $pf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        $hostN = $dir.Name; $procs = @($snap.Data)
        $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.p] = $p }
        foreach ($p in $procs) {
            $h = ([string]$p.h).ToLowerInvariant(); $x = [string]$p.x; $nm = ([string]$p.n -replace '\.exe$', '').ToLowerInvariant()
            $par = $byPid[[int]$p.pp]; $parN = if ($par) { ([string]$par.n -replace '\.exe$', '').ToLowerInvariant() } else { '' }
            $det = ("سیستم | computer: {0}`nبرنامه | program: {1}`nمسیر | path: {2}`nPID: {3}  ·  والد | parent: {4} ({5})`nخطِ فرمان | command line: {6}`nSHA-256: {7}`nامضا | signature: {8} {9}" -f $hostN, $p.n, $x, $p.p, $(if ($par) { $par.n } else { '?' }), $p.pp, $p.c, $h, $p.sg, $p.pub)
            if ($h -and $ioc.ContainsKey($h)) {
                if (& $isNew "ioc|$hostN|$h") {
                    $resp = ''
                    if ($null -eq $Config.Edr -or $Config.Edr.AutoRespondIoc -ne $false) {
                        try {
                            if (-not (Get-Command Add-LBAgentAction -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $PSScriptRoot 'LogBok.Endpoint.psm1') -DisableNameChecking -Global -ErrorAction Stop }
                            [void](Add-LBAgentAction -StateDir $sd -Hosts @($hostN) -Type 'kill-pid' -Arguments @{ pid = [int]$p.p; tree = $true } -By 'LogBok (auto)')
                            if ($x) { [void](Add-LBAgentAction -StateDir $sd -Hosts @($hostN) -Type 'quarantine-file' -Arguments @{ path = $x } -By 'LogBok (auto)') }
                            $resp = "`nپاسخِ خودکار | automatic response: توقفِ درختِ پردازه و قرنطینهٔ فایل | process tree stopped and file quarantined"
                        } catch { $resp = "`nپاسخِ خودکار ناموفق | automatic response failed: $($_.Exception.Message)" }
                    }
                    $f += New-Finding -Category 'Malware' -Severity 'Critical' -Machine $hostN -Time $now `
                        -Title ("برنامهٔ مخربِ شناخته‌شده در حالِ اجرا — {0} | known-malicious program running — {0}{1}" -f $p.n, $(if ($ioc[$h]) { " ($($ioc[$h]))" } else { '' })) `
                        -Details ($det + $resp) -Key ("IOC|$hostN|$h")
                }
                continue
            }
            if ([string]$p.sg -eq 'HashMismatch') {
                if (& $isNew "tamper|$hostN|$h") { $f += New-Finding -Category 'Malware' -Severity 'Critical' -Machine $hostN -Time $now -Title ("فایلِ امضاشده دست‌کاری شده — {0} | signed file was tampered with — {0}" -f $p.n) -Details $det -Key ("SIGBAD|$hostN|$h") }
                continue
            }
            if ($office -contains $parN -and $shells -contains $nm) {
                if (& $isNew "office|$hostN|$($p.p)") { $f += New-Finding -Category 'Behavior' -Severity 'Critical' -Machine $hostN -Time $now -Title ("{0} یک {1} اجرا کرد (رفتارِ ماکروی مخرب) | {0} started {1} (malicious-macro behaviour)" -f $par.n, $p.n) -Details $det -Key ("OFFICE|$hostN|$($p.p)") }
                continue
            }
            if ($x -and $x -match $userDirs -and @('NotSigned', 'NotTrusted', 'UnknownError', 'Unknown') -contains [string]$p.sg) {
                if (& $isNew "unsigned|$hostN|$h") { $f += New-Finding -Category 'Behavior' -Severity 'Warning' -Machine $hostN -Time $now -Title ("برنامهٔ بدونِ امضا از پوشهٔ کاربر اجرا شده — {0} | unsigned program running from a user folder — {0}" -f $p.n) -Details $det -Key ("UNSIGNED|$hostN|$h") }
            }
        }
    }
    if ($script:edrChanged) {
        $keep = [ordered]@{}; foreach ($k in $seen.Keys) { try { if ([datetime]::Parse($seen[$k]) -gt $now.AddDays(-3)) { $keep[$k] = $seen[$k] } } catch { } }
        try { [IO.File]::WriteAllText($seenF, (ConvertTo-Json -InputObject $keep), (New-Object Text.UTF8Encoding($false))) } catch { }
    }
    return $f
}

# هر آشکارساز جدا اجرا می‌شود: خطای یکی (مثلاً «Access is denied» روی یک سیستم) بقیه را از کار نمی‌اندازد،
# و در لاگ نامِ همان آشکارساز و خطِ کد می‌آید. | each detector runs isolated: one failing (e.g. "Access is denied")
# no longer stops all detection, and the log names the detector and the line.
function Invoke-LBDetectorSafe {
    param([string]$Name, [scriptblock]$Body, $Config)
    try { return @(& $Body) }
    catch {
        $where = ''; try { $ii = $_.InvocationInfo; if ($ii) { $where = ' @ ' + [IO.Path]::GetFileName([string]$ii.ScriptName) + ':' + $ii.ScriptLineNumber } } catch { }
        try { Write-LogBokLog -Message ("آشکارساز {0} خطا داد (بقیه ادامه دادند) | detector {0} failed (others continued): {1}{2}" -f $Name, $_.Exception.Message, $where) -Level WARN -Config $Config } catch { }
        return @()
    }
}
function Invoke-LogBokDetectors {
    param($Config,[datetime]$Start)
    $all = @()
    $en = $Config.Enabled
    if ($en.Firewall)     { $all += Invoke-LBDetectorSafe 'Invoke-DetectFirewall' { Invoke-DetectFirewall -Config $Config -Start $Start } $Config }
    if ($en.Defender)     { $all += Invoke-LBDetectorSafe 'Invoke-DetectDefender' { Invoke-DetectDefender -Config $Config -Start $Start } $Config }
    if ($en.MassFile)     { $all += Invoke-LBDetectorSafe 'Invoke-DetectMassFile' { Invoke-DetectMassFile -Config $Config -Start $Start } $Config }
    if ($en.ActiveDir)    { $all += Invoke-LBDetectorSafe 'Invoke-DetectActiveDirectory' { Invoke-DetectActiveDirectory -Config $Config -Start $Start } $Config }
    if ($en.BruteForce)   { $all += Invoke-LBDetectorSafe 'Invoke-DetectBruteForce' { Invoke-DetectBruteForce -Config $Config -Start $Start } $Config }
    if ($en.SqlLogin)     { $all += Invoke-LBDetectorSafe 'Invoke-DetectSqlLogin' { Invoke-DetectSqlLogin -Config $Config -Start $Start } $Config }
    if ($en.IISAttack)    { $all += Invoke-LBDetectorSafe 'Invoke-DetectIISAttack' { Invoke-DetectIISAttack -Config $Config -Start $Start } $Config }
    if ($en.FtpAttack)    { $all += Invoke-LBDetectorSafe 'Invoke-DetectFtpAttack' { Invoke-DetectFtpAttack -Config $Config -Start $Start } $Config }
    if ($en.ServiceState) { $all += Invoke-LBDetectorSafe 'Invoke-DetectServiceState' { Invoke-DetectServiceState -Config $Config -Start $Start } $Config }
    if ($en.Tamper -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectTamper' { Invoke-DetectTamper -Config $Config -Start $Start } $Config }
    if ($en.Ransomware -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectRansomware' { Invoke-DetectRansomware -Config $Config -Start $Start } $Config }
    if ($en.FileScan -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectFileSuspicion' { Invoke-DetectFileSuspicion -Config $Config -Start $Start } $Config }
    if ($en.Policy -ne $false)   { $all += Invoke-LBDetectorSafe 'Invoke-DetectPolicy' { Invoke-DetectPolicy -Config $Config -Start $Start } $Config }
    if ($en.Scan -ne $false)     { $all += Invoke-LBDetectorSafe 'Invoke-DetectVuln' { Invoke-DetectVuln -Config $Config -Start $Start } $Config }
    if ($en.Tracking -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectTracking' { Invoke-DetectTracking -Config $Config -Start $Start } $Config }
    if ($en.FwGovernance -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectFwGovernance' { Invoke-DetectFwGovernance -Config $Config -Start $Start } $Config }
    if ($en.FIM -ne $false)      { $all += Invoke-LBDetectorSafe 'Invoke-DetectFim' { Invoke-DetectFim -Config $Config -Start $Start } $Config }
    if ($en.Guard -ne $false)    { $all += Invoke-LBDetectorSafe 'Invoke-DetectGuard' { Invoke-DetectGuard -Config $Config -Start $Start } $Config }
    if ($en.ADAttack -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectADAttacks' { Invoke-DetectADAttacks -Config $Config -Start $Start } $Config }
    if ($en.GPO -ne $false)      { $all += Invoke-LBDetectorSafe 'Invoke-DetectGPO' { Invoke-DetectGPO -Config $Config -Start $Start } $Config }
    if ($en.FileACL -ne $false)  { $all += Invoke-LBDetectorSafe 'Invoke-DetectFileACL' { Invoke-DetectFileACL -Config $Config -Start $Start } $Config }
    if ($en.MemberServer -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectMemberServer' { Invoke-DetectMemberServer -Config $Config -Start $Start } $Config }
    if ($en.Network -ne $false) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.Syslog.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-LBDetectorSafe 'Invoke-DetectSyslog' { Invoke-DetectSyslog -Config $Config -Start $Start } $Config } catch {}
    }
    if ($en.AppLog -ne $false) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.AppLogs.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-LBDetectorSafe 'Invoke-DetectAppLogs' { Invoke-DetectAppLogs -Config $Config -Start $Start } $Config } catch {}
    }
    if ($en.Custom -ne $false -and @($Config.CustomSources).Count) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.CustomSources.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-LBDetectorSafe 'Invoke-DetectCustom' { Invoke-DetectCustom -Config $Config -Start $Start } $Config } catch {}
    }
    if ($en.AppControl -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectAppControl' { Invoke-DetectAppControl -Config $Config -Start $Start } $Config }
    if ($en.Edr -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectProcesses' { Invoke-DetectProcesses -Config $Config -Start $Start } $Config }
    if ($en.Connectivity -ne $false) { $all += Invoke-LBDetectorSafe 'Invoke-DetectConnectivity' { Invoke-DetectConnectivity -Config $Config -Start $Start } $Config }
    return $all
}

# ------------------------------------------ قطعِ ارتباط با منابع (9020) --
function Invoke-DetectConnectivity {
    param($Config,[datetime]$Start)
    $f = @()
    foreach ($e in (Get-LogBokEvents -LogName 'Application' -Id 9020, 9021 -StartTime $Start -Config $Config | Where-Object { $_.ProviderName -eq 'LogBok' })) {
        $msg = Get-EvtMessage $e
        # کلیدِ پایدار از متنِ پیام (نه RecordId) تا یک قطعی چندبار هشدار نشود | stable key from the message text, not the record id
        $what = ($msg -replace '^CONNECTIVITY[^:]*:\s*', '').Trim()
        if ($e.Id -eq 9021) {
            $f += New-Finding -Category 'Connectivity' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'ارتباط دوباره برقرار شد | connection restored' -Details $msg -Key ("CONNOK|{0}|{1}|{2}" -f $e.MachineName, $what, $e.TimeCreated.ToString('yyyyMMddHH'))
        } else {
            $ttl = $(if ($msg -match 'still down') { 'قطعیِ ارتباط ادامه دارد (بیش از یک روز) | connection still down (more than a day)' } else { 'ارتباط با یک یا چند منبع برقرار نشد | connection to one or more sources failed' })
            $f += New-Finding -Category 'Connectivity' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $ttl -Details $msg -Key ("CONN|{0}|{1}|{2}" -f $e.MachineName, $what, $e.TimeCreated.ToString('yyyyMMdd'))
        }
    }
    return $f
}

Export-ModuleMember -Function *
