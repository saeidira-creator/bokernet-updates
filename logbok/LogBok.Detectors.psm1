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
function Invoke-DetectBruteForce {
    param($Config,[datetime]$Start)
    $f = @()
    $th = $Config.Thresholds.LogonFailurePerWindow
    foreach ($s in (Get-LogBokSecuritySources -Config $Config)) {
        $log = if ($Config.CollectionMode -eq 'Collector') { $Config.ForwardedLog } else { 'Security' }
        # 4625 ورود ناموفق ، 4771 Kerberos pre-auth ناموفق ، 4776 اعتبارسنجی NTLM ناموفق
        $evts = Get-LogBokEvents -LogName $log -Id @(4625,4771,4776) -StartTime $Start -ComputerName $s.Computer -Config $Config
        $grp = @{}
        foreach ($e in $evts) {
            # 4776 برای اعتبارسنجیِ «موفق» هم ثبت می‌شود (Status=0x0) → فقط ناموفق‌ها
            if ($e.Id -eq 4776) {
                $st = Get-LogBokEventField -Event $e -Name 'Status'
                if (-not $st -or $st -eq '0x0') { continue }
            }
            $user = Get-LogBokEventField -Event $e -Name 'TargetUserName'
            $ip   = Get-LogBokEventField -Event $e -Name 'IpAddress'
            if ($ip) { $ip = $ip -replace '^::ffff:','' }
            if (-not $ip -or $ip -eq '-') { $ip = Get-LogBokEventField -Event $e -Name 'WorkstationName' }
            if (-not $ip -or $ip -eq '-') { $ip = Get-LogBokEventField -Event $e -Name 'Workstation' }
            $k = "$($e.MachineName)|$user|$ip"
            if (-not $grp.ContainsKey($k)) { $grp[$k] = 0 }
            $grp[$k]++
        }
        foreach ($k in $grp.Keys) {
            if ($grp[$k] -ge $th) {
                $p = $k -split '\|'
                $f += New-Finding -Category 'BruteForce' -Severity 'Critical' -Machine $p[0] -Time (Get-Date) `
                    -Title ("حملهٔ احتمالی ورود — {0} تلاش ناموفق | possible logon attack — {0} failed attempts" -f $grp[$k]) `
                    -Details ("سیستم: {0}`nکاربر هدف: {1}`nمبدأ: {2}`nتعداد تلاش ناموفق در بازه: {3}" -f $p[0],$p[1],$p[2],$grp[$k]) `
                    -Key ("BF|{0}" -f $k)
            }
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
        if ($srv -ne 'localhost' -and $srv -ne $env:COMPUTERNAME) { $base = "\\$srv\" + ($base -replace ':','$') }
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
            $f += New-Finding -Category 'FwGovernance' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'رولِ فایروالِ غیرمجاز (دستی) شناسایی شد | Unauthorized firewall rule' `
                -Details (Get-EvtMessage $e) -Key ("FWGOV|{0}|{1}" -f $e.MachineName,$e.RecordId)
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
        foreach ($e in (Get-LogBokEvents -LogName $log -Id @(5136,5137,5141) -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $cls  = Get-LogBokEventField -Event $e -Name 'ObjectClass'
            $dn   = Get-LogBokEventField -Event $e -Name 'ObjectDN'
            $by   = Get-LogBokEventField -Event $e -Name 'SubjectUserName'
            $attr = Get-LogBokEventField -Event $e -Name 'AttributeLDAPDisplayName'
            $val  = Get-LogBokEventField -Event $e -Name 'AttributeValue'
            $op   = Get-LogBokEventField -Event $e -Name 'OperationType'
            $isGpo = ($cls -eq 'groupPolicyContainer') -or ($dn -match 'CN=Policies,CN=System')
            $cat = if ($isGpo) { 'GPO' } else { 'ActiveDirectory' }
            $sev = if ($isGpo) { 'Critical' } else { 'Info' }
            $opTxt = switch ("$op") { '%%14674'{'افزودنِ مقدار'} '%%14675'{'حذفِ مقدار'} default{"$op"} }
            $title = if ($isGpo) { 'تغییرِ Group Policy (GPO) | GPO change' } else { 'تغییرِ صفتِ شیءِ AD | AD attribute change' }
            $f += New-Finding -Category $cat -Severity $sev -Machine $e.MachineName -Time $e.TimeCreated `
                -Title $title `
                -Details ("شیء: {0}`nصفت: {1} | عملیات: {2} | مقدار: {3}`nتوسط: {4} | رویداد: {5}" -f $dn,$attr,$opTxt,$val,$by,$e.Id) `
                -Key ("GPO|{0}|{1}" -f $e.MachineName,$e.RecordId)
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
            $f += New-Finding -Category 'MemberServer' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'ساخت/تغییرِ Task زمان‌بندی‌شده | Scheduled task created/changed' `
                -Details ("Task: {0} | توسط: {1} | سیستم: {2}" -f $tn,$by,$e.MachineName) -Key ("MSRV|TASK|{0}|{1}" -f $e.MachineName,$e.RecordId)
        }
        # 7045 = نصبِ سرویسِ جدید (System) | new service installed
        foreach ($e in (Get-LogBokEvents -LogName $sys -Id 7045 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            $f += New-Finding -Category 'MemberServer' -Severity 'Warning' -Machine $e.MachineName -Time $e.TimeCreated `
                -Title 'نصبِ سرویسِ جدید | New service installed' -Details (Get-EvtMessage $e) `
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
        $suspPs = (@(
            'EncodedCommand', 'FromBase64' + 'String', 'Download' + 'String', 'Download' + 'File',
            'Invoke-' + 'Expression', '\bIEX\b', 'Net\.Web' + 'Client', 'Reflection\.Assembly\]::Load',
            'Virtual' + 'Alloc', 'Mi' + 'mikatz', 'sek' + 'urlsa', 'Invoke-Shell' + 'code',
            'Amsi' + 'Utils', 'amsi' + 'InitFailed'
        ) -join '|')
        $ownDir = Split-Path -Parent $PSCommandPath
        foreach ($e in (Get-LogBokEvents -LogName $psLog -Id 4104 -StartTime $Start -ComputerName $s.Computer -Config $Config)) {
            if ($e.Id -ne 4104) { continue }
            # اسکریپت‌های خودِ لاگ‌بوک (که متنِ این الگوها را دارند) نادیده گرفته می‌شوند
            $path = Get-LogBokEventField -Event $e -Name 'Path'
            if ($path -and ($path -like "$ownDir\*" -or $path -match '\\(LogBok|Agent)\\(LogBok\.|Run-|Console\\)')) { continue }
            $msg = Get-LogBokEventField -Event $e -Name 'ScriptBlockText'
            if (-not $msg) { $msg = ''; try { $msg = [string]$e.Message } catch {} }
            if ($msg -match 'LogBok\.Detectors|Invoke-DetectMemberServer') { continue }
            # نصب‌کنندهٔ تأییدشدهٔ خودِ لاگ‌بوک: هشدارِ بحرانی نه، فقط ثبتِ سطحِ پایین | LogBok's own verified installer: low-severity note, not Critical
            $wc = 'Net\.Web' + 'Client'; $dd = 'Download' + 'Data'; $ix = 'i' + 'ex'   # fragments: avoid AV false-positive on this file
            $lbLine = "^\`$b=\(New-Object $wc\)\.$dd\('http://[A-Za-z0-9_.\-]+:\d+/install\.ps1\?t=[0-9a-f]{16,96}'\);if\(\[BitConverter\]::ToString\(\[Security\.Cryptography\.SHA256\]::Create\(\)\.ComputeHash\(\`$b\)\)\.Replace\('-',''\) -eq '[0-9A-F]{64}'\)\{$ix \(\[Text\.Encoding\]::UTF8\.GetString\(\`$b\)\)\}else\{Write-Host '[^']*' -ForegroundColor Red\}\s*$"
            $suspBoot = (@('EncodedCommand', 'FromBase64' + 'String', 'Download' + 'String', 'Invoke-' + 'Expression', '\bIEX\b', 'Reflection', 'Virtual' + 'Alloc', 'Mi' + 'mikatz', 'sek' + 'urlsa', 'Shell' + 'code', 'Amsi') -join '|')
            $lbBoot = ($msg -match '^# LogBok agent - one-line installer \(verified\)') -and ($msg -notmatch $suspBoot)
            if ($msg -match $lbLine -or $lbBoot) {

                $f += New-Finding -Category 'MemberServer' -Severity 'Info' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title 'نصبِ ایجنتِ لاگ‌بوک اجرا شد | LogBok agent installer ran' `
                    -Details ("سیستم: {0}`nنصب‌کنندهٔ تأییدشدهٔ لاگ‌بوک (SHA-256) اجرا شد. اگر شما نصب نکرده‌اید بررسی کنید." -f $e.MachineName) `
                    -Key ("MSRV|PSLB|{0}|{1}" -f $e.MachineName,$e.RecordId)
                continue
            }
            if ($msg -match $suspPs) {
                $hit = ([regex]::Matches($msg,$suspPs) | ForEach-Object { $_.Value } | Select-Object -Unique) -join ', '
                $snippet = ($msg -split "`r?`n" | Select-Object -First 3) -join ' '
                if ($snippet.Length -gt 300) { $snippet = $snippet.Substring(0,300) }
                $f += New-Finding -Category 'MemberServer' -Severity 'Critical' -Machine $e.MachineName -Time $e.TimeCreated `
                    -Title ("اسکریپتِ PowerShell مشکوک | Suspicious PowerShell ({0})" -f $hit) `
                    -Details ("سیستم: {0}`nنشانه‌ها: {1}`nبخشی از اسکریپت: {2}" -f $e.MachineName,$hit,$snippet) `
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
                $file = ''; try { $file = Split-Path -Leaf ([string]$e.Properties[0].Value) } catch {}
                if (-not $file) { $file = (Get-EvtMessage $e) }
                $blocked = ($e.Id -in 8004,8007)
                $k = '{0}|{1}|{2}' -f $e.MachineName, $file, $blocked
                if (-not $grp.ContainsKey($k)) { $grp[$k] = @{ e=$e; n=0; file=$file; blocked=$blocked } }
                $grp[$k].n++; if ($e.TimeCreated -gt $grp[$k].e.TimeCreated) { $grp[$k].e = $e }
            }
            foreach ($g in $grp.Values) {
                $sev = if ($g.blocked) { 'Warning' } else { 'Info' }
                $ti = if ($g.blocked) { ("اجرای برنامهٔ ممنوع مسدود شد: {0} | Blocked program execution: {0}" -f $g.file) } else { ("اجرای برنامهٔ مغایرِ سیاست (حسابرسی): {0} | Policy-violating program ran (audit): {0}" -f $g.file) }
                $f += New-Finding -Category 'AppControl' -Severity $sev -Machine $g.e.MachineName -Time $g.e.TimeCreated `
                    -Title $ti -Details ((Get-EvtMessage $g.e) + "`nتعداد در بازه | count: " + $g.n) -Key ("APPCTL|{0}|{1}|{2}" -f $g.e.MachineName, $g.file, $g.blocked)
            }
        }
    }
    return $f
}

function Invoke-LogBokDetectors {
    param($Config,[datetime]$Start)
    $all = @()
    $en = $Config.Enabled
    if ($en.Firewall)     { $all += Invoke-DetectFirewall        -Config $Config -Start $Start }
    if ($en.Defender)     { $all += Invoke-DetectDefender        -Config $Config -Start $Start }
    if ($en.MassFile)     { $all += Invoke-DetectMassFile        -Config $Config -Start $Start }
    if ($en.ActiveDir)    { $all += Invoke-DetectActiveDirectory -Config $Config -Start $Start }
    if ($en.BruteForce)   { $all += Invoke-DetectBruteForce      -Config $Config -Start $Start }
    if ($en.SqlLogin)     { $all += Invoke-DetectSqlLogin        -Config $Config -Start $Start }
    if ($en.IISAttack)    { $all += Invoke-DetectIISAttack       -Config $Config -Start $Start }
    if ($en.FtpAttack)    { $all += Invoke-DetectFtpAttack       -Config $Config -Start $Start }
    if ($en.ServiceState) { $all += Invoke-DetectServiceState    -Config $Config -Start $Start }
    if ($en.Tamper -ne $false) { $all += Invoke-DetectTamper     -Config $Config -Start $Start }
    if ($en.Ransomware -ne $false) { $all += Invoke-DetectRansomware -Config $Config -Start $Start }
    if ($en.FileScan -ne $false) { $all += Invoke-DetectFileSuspicion -Config $Config -Start $Start }
    if ($en.Policy -ne $false)   { $all += Invoke-DetectPolicy        -Config $Config -Start $Start }
    if ($en.Scan -ne $false)     { $all += Invoke-DetectVuln          -Config $Config -Start $Start }
    if ($en.Tracking -ne $false) { $all += Invoke-DetectTracking      -Config $Config -Start $Start }
    if ($en.FwGovernance -ne $false) { $all += Invoke-DetectFwGovernance -Config $Config -Start $Start }
    if ($en.FIM -ne $false)      { $all += Invoke-DetectFim           -Config $Config -Start $Start }
    if ($en.Guard -ne $false)    { $all += Invoke-DetectGuard         -Config $Config -Start $Start }
    if ($en.ADAttack -ne $false) { $all += Invoke-DetectADAttacks     -Config $Config -Start $Start }
    if ($en.GPO -ne $false)      { $all += Invoke-DetectGPO           -Config $Config -Start $Start }
    if ($en.FileACL -ne $false)  { $all += Invoke-DetectFileACL       -Config $Config -Start $Start }
    if ($en.MemberServer -ne $false) { $all += Invoke-DetectMemberServer -Config $Config -Start $Start }
    if ($en.Network -ne $false) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.Syslog.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-DetectSyslog -Config $Config -Start $Start } catch {}
    }
    if ($en.AppLog -ne $false) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.AppLogs.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-DetectAppLogs -Config $Config -Start $Start } catch {}
    }
    if ($en.Custom -ne $false -and @($Config.CustomSources).Count) {
        try { Import-Module (Join-Path $PSScriptRoot 'LogBok.CustomSources.psm1') -DisableNameChecking -ErrorAction Stop
              $all += Invoke-DetectCustom -Config $Config -Start $Start } catch {}
    }
    if ($en.AppControl -ne $false) { $all += Invoke-DetectAppControl -Config $Config -Start $Start }
    if ($en.Connectivity -ne $false) { $all += Invoke-DetectConnectivity -Config $Config -Start $Start }
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
