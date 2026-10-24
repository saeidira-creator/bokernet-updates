# ==========================================================================
#  LogBok.Syslog.psm1 - سرورِ Syslog (UDP/514) + پارسرِ تجهیزاتِ شبکه
#  لاگِ سوییچ/روتر/فایروالِ سیسکو و سایرِ دستگاه‌ها را روی UDP دریافت، نرمال و
#  در انبارِ لاگ (همان NDJSON) ذخیره می‌کند. خطا/تلاشِ اتصال/ورودِ ناموفق را
#  تشخیص و به‌صورت یافته برمی‌گرداند (ایمیل/داشبورد).
#  وابسته به LogBok.Core و LogBok.Archive.
#  اجرا به دو شکل: سرویسِ گوش‌دهنده (Start-LBSyslogListener) یا پردازشِ دوره‌ایِ
#  صفِ دریافتی. برای سادگی و پایداری، لیسنر در یک اجرای جدا و سبک کار می‌کند.
# ==========================================================================

# شدتِ Syslog (0..7) | severity names
$script:SyslogSev = @('Emergency','Alert','Critical','Error','Warning','Notice','Info','Debug')

# تجزیهٔ یک پیامِ خامِ Syslog | parse one raw syslog line → record
function ConvertFrom-LBSyslog {
    param([string]$Raw,[string]$FromIp)
    $pri = $null; $msg = $Raw
    if ($Raw -match '^<(\d{1,3})>(.*)$') { $pri=[int]$Matches[1]; $msg=$Matches[2] }
    $sevNum = if ($null -ne $pri) { $pri % 8 } else { 6 }
    $facility = if ($null -ne $pri) { [int]([math]::Floor($pri/8)) } else { 1 }
    # تشخیصِ mnemonicِ سیسکو: %SYS-5-CONFIG_I، %SEC_LOGIN-4-LOGIN_FAILED و…
    $cmnem=''; $csev=$null
    if ($msg -match '%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+)') { $cmnem="$($Matches[1])-$($Matches[3])"; $csev=[int]$Matches[2] }
    [ordered]@{
        t    = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        host = $FromIp
        log  = 'Syslog'
        id   = if ($cmnem) { $cmnem } else { "sev$sevNum" }
        lvl  = $script:SyslogSev[$sevNum]
        prov = 'syslog'
        user = ''
        ip   = $FromIp
        rec  = 0
        fac  = $facility
        csev = $csev
        msg  = $msg.Trim()
    }
}

# الگوهای مهمِ تجهیزاتِ شبکه (سیسکو و عمومی) | notable network-device patterns
#  هر الگو: Name، Regex، Severity، Title
#  ترتیب مهم است (اولین تطابق): خاص‌ترها اول.
$script:SyslogRules = @(
    @{ N='AccountLockout'; Rx='locked out|account locked|%SEC_LOGIN-\d-(\w*LOCK\w*|QUIET_MODE_ON)'; Sev='Critical'; Title='قفل‌شدنِ حسابِ دستگاه | device account lockout' }
    @{ N='AuthAttack'; Rx='repeated login failures|%SEC_LOGIN-\d-QUIET_MODE_ON|AAA.*(failure|fail)'; Sev='Critical'; Title='تلاشِ مکررِ ورود به دستگاه | repeated login attempts' }
    @{ N='LoginSuccess'; Rx='LOGIN_SUCCESS|Accepted password|Login Success'; Sev='Info'; Title='ورودِ موفق به دستگاه | device login success' }
    @{ N='LoginFailed'; Rx='LOGIN_FAILED|AUTHENTICATION_FAILED|authentication failed|Login failed|Access denied|login attempt failed|Failed password'; Sev='Warning'; Title='ورودِ ناموفق به دستگاهِ شبکه | Network device login failed' }
    @{ N='ConfigChange'; Rx='%SYS-5-CONFIG_I|Configured from|%SYS-6-LOGGINGHOST|running-config'; Sev='Warning'; Title='تغییرِ پیکربندیِ دستگاه | device configuration changed' }
    @{ N='LinkDown'; Rx='%LINK-\d-UPDOWN.*\bdown\b|%LINEPROTO-\d-UPDOWN.*\bdown\b|Interface.*\bdown\b'; Sev='Warning'; Title='قطعِ اینترفیس | interface down' }
    @{ N='LinkUp'; Rx='%LINK-\d-UPDOWN.*\bup\b|%LINEPROTO-\d-UPDOWN.*\bup\b'; Sev='Info'; Title='اتصالِ اینترفیس | interface up' }
    @{ N='DeviceError'; Rx='%[A-Z0-9_]+-[0-2]-|CRASH|traceback|MALLOCFAIL|duplex mismatch'; Sev='Critical'; Title='خطای بحرانیِ دستگاه | critical device error' }
    @{ N='ConnAttempt'; Rx='%SEC-6-IPACCESSLOGP|\bdenied\b|\bDeny\b|%ASA-\d-106|connection attempt'; Sev='Info'; Title='تلاشِ اتصال/دسترسی | connection/access attempt' }
)

# ساختِ یافته از رکوردهای Syslogِ ذخیره‌شده در بازه | detect from archived syslog
function Invoke-DetectSyslog {
    param($Config,[datetime]$Start)
    $f = @()
    try { Import-Module (Join-Path (Split-Path $PSCommandPath -Parent) 'LogBok.Archive.psm1') -DisableNameChecking -ErrorAction Stop } catch { return $f }
    $recs = @(Search-LBArchive -Config $Config -From $Start -To (Get-Date) -Source syslog -Max 50000)
    # گروه‌بندیِ ورودِ ناموفق بر اساس دستگاه برای تشخیصِ حمله
    $failByHost = @{}
    $infoAgg = @{}   # موارد Info (مثل deny) تجمیع می‌شوند تا هزاران یافته ساخته نشود
    foreach ($r in $recs) {
        foreach ($rule in $script:SyslogRules) {
            if ($r.msg -match $rule.Rx) {
                if ($rule.N -in 'LoginFailed','AuthAttack') {
                    if (-not $failByHost.ContainsKey($r.host)) { $failByHost[$r.host]=0 }
                    $failByHost[$r.host]++
                }
                if ($rule.Sev -eq 'Info') {
                    $ak = "$($rule.N)|$($r.host)"
                    if (-not $infoAgg.ContainsKey($ak)) { $infoAgg[$ak] = @{ Rule=$rule; Rec=$r; N=0 } }
                    $infoAgg[$ak].N++
                } else {
                    $f += New-SyslogFinding -Rule $rule -Rec $r
                }
                break
            }
        }
    }
    foreach ($a in $infoAgg.Values) {
        $x = New-SyslogFinding -Rule $a.Rule -Rec $a.Rec
        $x.Title = "$($x.Title) ×$($a.N)"
        $x.Details = "تعداد در بازه | count: $($a.N)`n" + $x.Details
        $f += $x
    }
    # حملهٔ بروت‌فورس روی دستگاه: ورودِ ناموفقِ زیاد از یک دستگاه
    $th = if ($Config.Thresholds.SyslogLoginFailPerWindow) { [int]$Config.Thresholds.SyslogLoginFailPerWindow } else { 5 }
    # نامِ دستگاه‌های ثبت‌شده به‌جای IP | registered device names
    if ($Config.SyslogNames) { foreach ($x in $f) { $nm = $Config.SyslogNames[[string]$x.Machine]; if ($nm) { $x.Machine = "$nm ($($x.Machine))" } } }
    foreach ($h in $failByHost.Keys) { if ($failByHost[$h] -ge $th) {
        $f += [pscustomobject]@{ Category='Network'; Severity='Critical'; Machine=$h; Time=(Get-Date)
            Title=("حملهٔ احتمالی به دستگاهِ شبکه — {0} ورودِ ناموفق | network device brute force — {0} failed logons" -f $failByHost[$h])
            Details=("دستگاه/IP: {0}`nتعداد ورودِ ناموفق در بازه: {1}" -f $h,$failByHost[$h]); Key=("NETBF|{0}" -f $h) }
    } }
    return $f
}

function New-SyslogFinding {
    param($Rule,$Rec)
    [pscustomobject]@{
        Category='Network'; Severity=$Rule.Sev; Machine=$Rec.host; Time=$(if ($Rec.t -is [datetime]) { $Rec.t } else { try { [datetime]::Parse([string]$Rec.t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch { Get-Date } })
        Title=$Rule.Title
        Details=("دستگاه/IP: {0}`nشدت: {1}`nپیام: {2}" -f $Rec.host,$Rec.lvl,$Rec.msg)
        Key=("SYSLOG|{0}|{1}|{2}" -f $Rule.N,$Rec.host,($Rec.msg.Substring(0,[Math]::Min(50,$Rec.msg.Length))))
    }
}

# --- سرورِ گوش‌دهندهٔ UDP (اجرا در Run-Syslog.ps1) | UDP listener ----------
function Start-LBSyslogListener {
    param($Config,[int]$Port=514,[int]$RunSeconds=0)
    Import-Module (Join-Path (Split-Path $PSCommandPath -Parent) 'LogBok.Archive.psm1') -DisableNameChecking
    $dir = Get-LBArchiveDir -Config $Config
    # لیسنر در فایلِ جداگانهٔ syslog-*.ndjson می‌نویسد (بدونِ رقابت با موتور)
    $udp = New-Object System.Net.Sockets.UdpClient($Port)
    $udp.Client.ReceiveTimeout = 2000
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $deadline = if ($RunSeconds -gt 0) { (Get-Date).AddSeconds($RunSeconds) } else { [datetime]::MaxValue }
    $buffer = [System.Collections.Generic.List[string]]::new()
    $lastFlush = Get-Date
    Write-Host "LogBok Syslog listener on UDP/$Port ..." -ForegroundColor Green
    while ((Get-Date) -lt $deadline) {
        try {
            $bytes = $udp.Receive([ref]$ep)
            $raw = [System.Text.Encoding]::UTF8.GetString($bytes)
            $rec = ConvertFrom-LBSyslog -Raw $raw -FromIp $ep.Address.ToString()
            $buffer.Add(($rec | ConvertTo-Json -Compress -Depth 4))
        } catch [System.Net.Sockets.SocketException] { }  # timeout → ادامه
        catch { Start-Sleep -Milliseconds 200 }
        # نوشتنِ دسته‌ای هر ۵ ثانیه | batch flush
        if ($buffer.Count -ge 50 -or ((Get-Date) -gt $lastFlush.AddSeconds(5) -and $buffer.Count -gt 0)) {
            try {
                Add-LBArchiveLines -File (Join-Path $dir ("syslog-{0}.ndjson" -f (Get-LBDayName (Get-Date)))) -Lines $buffer.ToArray()
                $buffer.Clear()
            } catch {
                # دیسک/قفل: بافر نگه داشته می‌شود؛ اگر خیلی بزرگ شد قدیمی‌ها دور ریخته می‌شوند
                if ($buffer.Count -gt 20000) { $buffer.RemoveRange(0, $buffer.Count - 10000) }
            }
            $lastFlush = Get-Date
        }
    }
    if ($buffer.Count -gt 0) { try { Add-LBArchiveLines -File (Join-Path $dir ("syslog-{0}.ndjson" -f (Get-LBDayName (Get-Date)))) -Lines $buffer.ToArray() } catch {} }
    $udp.Close()
}

Export-ModuleMember -Function *
