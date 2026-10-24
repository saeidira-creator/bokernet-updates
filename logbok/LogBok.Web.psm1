# ==========================================================================
#  LogBok.Web.psm1 — کنسولِ وبِ لاگ‌بوک (API + فایل‌های رابط)
#  Local web console: an authenticated HTTP API over the engine, used by the
#  single-page UI in Web\. Everything the static dashboard could only show
#  can be opened, searched, configured and acted on here:
#   events with full detail + related raw logs + actions, raw log search,
#   incidents, alert profiles & email recipients, SMTP, log sources (Windows,
#   Active Directory, network devices, services, custom logs, credentials),
#   connectivity tests, login guard, jobs and settings.
#
#  امنیت | security:
#   • پیش‌فرض فقط روی localhost؛ حالتِ LAN اختیاری (Web.Listen='lan').
#   • احرازِ هویتِ یکپارچهٔ ویندوز (Negotiate/NTLM) و فقط اعضای Administrators
#     (یا Web.AllowedUsers/AllowedGroups).
#   • هر درخواستِ تغییر (POST) توکنِ X-LogBok-Token و Origin همان‌میزبان لازم دارد.
#   • همهٔ دادهٔ رویدادها در رابط با textContent نمایش داده می‌شود (نه HTML).
#   • هر تغییر با نامِ کاربر در Application (رویداد 9002) ثبت می‌شود.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:Root = Split-Path -Parent $PSCommandPath
$script:Token = $null
$script:TestMode = $false
$script:Version = '1.9.7'

function Import-LBWebModules {
    foreach ($m in 'LogBok.Core','LogBok.Lang','LogBok.License','LogBok.Findings','LogBok.Alerts','LogBok.Targets','LogBok.Connect','LogBok.Archive','LogBok.Mitre','LogBok.Guard','LogBok.Jobs','LogBok.Risk','LogBok.AgentPkg','LogBok.AgentIn','LogBok.AgentDeploy','LogBok.Endpoint','LogBok.Archive','LogBok.Reports','LogBok.Backup','LogBok.Playbook','LogBok.Sessions','LogBok.WebAuth','LogBok.Publish','LogBok.Update','LogBok.Remote') {
        $p = Join-Path $script:Root "$m.psm1"
        if (Test-Path $p) { try { Import-Module $p -DisableNameChecking -ErrorAction Stop -Global } catch { } }
    }
}
# Load a module only when its functions are missing, and always globally.
# Never re-import with -Force inside a request: that REMOVES the shared copy from the
# worker and breaks every other module that relies on it (e.g. Archive for User 360).
function Use-LBModule {
    param([string]$Name, [string]$Probe)
    if ($Probe -and (Get-Command $Probe -ErrorAction SilentlyContinue)) { return }
    $p = Join-Path $script:Root "$Name.psm1"
    if (Test-Path $p) { try { Import-Module $p -DisableNameChecking -Global -ErrorAction Stop } catch { } }
}

# --- متنِ دوزبانه | bilingual text (same rules as the dashboard) -------------
$script:FaLabels = [ordered]@{
  'تعداد ورودِ ناموفق در بازه'='Failed logons in window'; 'تعداد عملیات مخرب در بازه'='Destructive operations in window'
  'تعداد تلاش ناموفق در بازه'='Failed attempts in window'; 'مجموع ورود ناموفق در بازه'='Total failed logons in window'
  'کاربرانِ امتحان‌شده'='Users tried'; 'بخشی از اسکریپت'='Script excerpt'; 'نمونه فایل‌ها'='Sample files'
  'میانهٔ معمول'='Usual median'; 'مقدار فعلی'='Current value'; 'کاربر هدف'='Target user'; 'کل درخواست'='Total requests'
  'بارِ بلاک'='Block count'; 'در بازه'='In window'; 'سیستم'='Host'; 'مبدأ'='Source'; 'کاربر'='User'; 'توسط'='By'
  'کشور'='Country'; 'دستگاه'='Device'; 'مقدار'='Value'; 'دلیل'='Reason'; 'شیء'='Object'; 'شدت'='Severity'
  'پیام'='Message'; 'سرور'='Server'; 'پاکسازی'='Cleanup'; 'متریک'='Metric'; 'نوع'='Type'; 'منبع'='Source'
  'تلاش'='Attempts'; 'تا'='Until'; 'سرویس‌ها'='Services'; 'صفت'='Attribute'; 'عملیات'='Operation'; 'رویداد'='Event'
  'نشانه‌ها'='Indicators'; 'سند'='Document'; 'چاپگر'='Printer'; 'مولفه‌ها'='Components'; 'گروه'='Group'; 'عضو'='Member'
}
function Get-LBWebLang { param($Config) $l = [string]$Config.Language; if ($l -eq 'en') { 'en' } else { 'fa' } }
# عنوان‌های قدیمیِ فقط‌فارسی (یافته‌های ذخیره‌شده پیش از دوزبانه شدن) | legacy Persian-only titles
$script:FaTitles = @{ 'یک سرویس حیاتی متوقف/قطع شد' = 'A critical service stopped' }
function Format-LBTxt {
    param([string]$s, [string]$Lang)
    if (-not $s) { return $s }
    $parts = $s -split '\s\|\s', 2
    if ($parts.Count -eq 2) { $s = if ($Lang -eq 'en') { $parts[1] } else { $parts[0] } }
    elseif ($Lang -eq 'en' -and $script:FaTitles.ContainsKey($s.Trim())) { $s = $script:FaTitles[$s.Trim()] }
    if ($Lang -eq 'en') { $s = [regex]::Replace($s, '\s*\([^()]*[\u0600-\u06FF][^()]*\)', '') }
    return $s.Trim()
}
function Format-LBDetail {
    param([string]$s, [string]$Lang)
    if (-not $s -or $Lang -ne 'en') { return $s }
    $s = [regex]::Replace($s, '[\u0600-\u06FF][\u0600-\u06FF\u200c\u064b-\u0670 ]*/([A-Za-z][A-Za-z ]*)\s*:', '$1:')
    foreach ($k in $script:FaLabels.Keys) { $s = [regex]::Replace($s, '(?<![\u0600-\u06FF\u200c])' + [regex]::Escape($k) + '(?=\s*:)', $script:FaLabels[$k]) }
    $s = [regex]::Replace($s, '[\u0600-\u06FF][^|\n]*?\s\|\s', '')
    $s = [regex]::Replace($s, '\s*\([^()]*[\u0600-\u06FF][^()]*\)', '')
    return $s
}
function Get-LBCatTitle { param([string]$Key, [string]$Lang) try { $c = @{ Language = $Lang }; return (Get-LBCategoryTitle -Category $Key -Config $c) } catch { return $Key } }

# --- کمکی‌های HTTP | HTTP helpers --------------------------------------------
function Send-LBBytes {
    param($Ctx, [byte[]]$Bytes, [string]$Type, [int]$Status = 200, [string]$Download, [string]$Cookie)
    $r = $Ctx.Response
    try {
        $r.StatusCode = $Status
        $r.ContentType = $Type
        if ($Cookie) { try { $r.AppendHeader('Set-Cookie', $Cookie) } catch { $r.Headers['Set-Cookie'] = $Cookie } }
        if ($Download) { $r.Headers['Content-Disposition'] = 'attachment; filename="' + ($Download -replace '[^A-Za-z0-9_.\-]', '_') + '"' }
        $r.Headers['X-Content-Type-Options'] = 'nosniff'
        $r.Headers['X-Frame-Options'] = 'DENY'
        $r.Headers['Referrer-Policy'] = 'no-referrer'
        $r.Headers['Cache-Control'] = $(if ($Type -eq 'font/woff2') { 'public, max-age=604800' } else { 'no-store' })
        $r.Headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        $r.ContentLength64 = $Bytes.Length
        $r.OutputStream.Write($Bytes, 0, $Bytes.Length)
    } catch { } finally { try { $r.OutputStream.Close() } catch { } }
}
function Send-LBJson {
    param($Ctx, $Obj, [int]$Status = 200, [string]$Cookie)
    $json = ConvertTo-Json -InputObject $Obj -Depth 12 -Compress
    if ($null -eq $json) { $json = 'null' }
    Send-LBBytes -Ctx $Ctx -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($json)) -Type 'application/json; charset=utf-8' -Status $Status -Cookie $Cookie
}
function Read-LBBody {
    param($Ctx)
    $req = $Ctx.Request
    if (-not $req.HasEntityBody) { return $null }
    if ($req.ContentLength64 -gt 2MB) { throw 'body too large' }
    $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
    try { $txt = $sr.ReadToEnd() } finally { $sr.Dispose() }
    if (-not $txt) { return $null }
    return ($txt | ConvertFrom-Json)
}
function Get-LBQ { param($Ctx, [string]$Name, $Default = $null) $v = $Ctx.Request.QueryString[$Name]; if ($null -eq $v -or $v -eq '') { return $Default }; return [string]$v }
# وضعیتِ جاب‌ها کند است (Task Scheduler)؛ ۶۰ ثانیه نگه داشته می‌شود | job status is slow; cache 60s
# وضعیتِ جاب‌ها: کشِ ۶۰ ثانیه‌ای مشترک بینِ همهٔ کارگرها | job status: 60s cache shared by all workers
$script:JobCache = $null; $script:JobCacheAt = [datetime]::MinValue
function Get-LBWebJobs {
    param($Config, [switch]$Fresh)
    $sh = $global:LBWebShared
    if ($sh) { if (-not $Fresh -and $sh['Jobs'] -and $sh['JobsAt'] -gt (Get-Date).AddSeconds(-60)) { return $sh['Jobs'] } }
    elseif (-not $Fresh -and $script:JobCache -and $script:JobCacheAt -gt (Get-Date).AddSeconds(-60)) { return $script:JobCache }
    $j = @(); try { $j = @(Get-LBJobStatus -Config $Config -Role Engine) } catch { }
    if ($sh) { $sh['Jobs'] = $j; $sh['JobsAt'] = Get-Date } else { $script:JobCache = $j; $script:JobCacheAt = Get-Date }
    return $j
}
function Reset-LBWebJobs { if ($global:LBWebShared) { $global:LBWebShared['JobsAt'] = [datetime]::MinValue }; $script:JobCacheAt = [datetime]::MinValue }
# کشِ کوتاهِ عمومی برای پاسخ‌های کند (فایروال/سپر/ارتباط) | short shared cache for slow reads
function Get-LBWebCached {
    param([string]$Key, [int]$Seconds = 20, [scriptblock]$Get)
    $sh = $global:LBWebShared
    if ($sh -and $sh.ContainsKey("c:$Key") -and $sh["t:$Key"] -gt (Get-Date).AddSeconds(-$Seconds)) { return $sh["c:$Key"] }
    $v = & $Get
    if ($sh) { $sh["c:$Key"] = $v; $sh["t:$Key"] = Get-Date }
    return $v
}
function Clear-LBWebCached { param([string]$Key) if ($global:LBWebShared) { $global:LBWebShared["t:$Key"] = [datetime]::MinValue } }

# Fast AD/Security-log day aggregate for the Active Directory dashboard.
#  Streams the day's ndjson line-by-line and uses a cheap id regex so the 95%+ of
#  lines that are not AD-relevant (process creation, etc.) are skipped without a
#  full JSON parse. Only logon (4624) and failed logon (4625) lines are probed
#  further (hour / user). Far cheaper than parsing every record of a 30MB day file.
function Get-LBAdDayStats {
    param([Parameter(Mandatory)][string]$File)
    $r = [ordered]@{ fail = 0; logon = 0; created = 0; deleted = 0; modified = 0; groups = 0; gpo = 0; failByUser = @{}; hourHist = (New-Object int[] 24) }
    if (-not (Test-Path -LiteralPath $File)) { return $r }
    $createdIds = @{ 4720 = 1; 4741 = 1; 4727 = 1; 4731 = 1; 4754 = 1 }; $deletedIds = @{ 4726 = 1; 4730 = 1; 4743 = 1; 4734 = 1; 4758 = 1 }
    $modIds = @{ 4738 = 1; 4722 = 1; 4725 = 1; 4767 = 1; 4781 = 1 }; $grpIds = @{ 4728 = 1; 4732 = 1; 4733 = 1; 4756 = 1; 4729 = 1 }; $gpoIds = @{ 5136 = 1; 5137 = 1; 5141 = 1 }
    $rxId = [regex]'"id":(\d+)'; $rxUser = [regex]'"user":"([^"]*)"'; $rxHour = [regex]'"t":"[^"]*T(\d\d):'
    $fs = $null; $sr = $null
    try {
        $fs = New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        while ($null -ne ($ln = $sr.ReadLine())) {
            if ($ln.Length -lt 8) { continue }
            $m = $rxId.Match($ln); if (-not $m.Success) { continue }
            $id = [int]$m.Groups[1].Value
            if ($id -eq 4624) { $r.logon++; $mh = $rxHour.Match($ln); if ($mh.Success) { $h = [int]$mh.Groups[1].Value; if ($h -ge 0 -and $h -lt 24) { $r.hourHist[$h] = [int]$r.hourHist[$h] + 1 } } }
            elseif ($id -eq 4625) { $r.fail++; $mu = $rxUser.Match($ln); if ($mu.Success) { $u = $mu.Groups[1].Value; if ($u -and $u -ne '-') { $r.failByUser[$u] = [int]$r.failByUser[$u] + 1 } } }
            elseif ($createdIds.ContainsKey($id)) { $r.created++ }
            elseif ($deletedIds.ContainsKey($id)) { $r.deleted++ }
            elseif ($modIds.ContainsKey($id)) { $r.modified++ }
            elseif ($grpIds.ContainsKey($id)) { $r.groups++ }
            elseif ($gpoIds.ContainsKey($id)) { $r.gpo++ }
        }
    } catch { } finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
    return $r
}

function ConvertTo-LBIsoText { param($v) if ($v -is [datetime]) { return $v.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv) }; return [string]$v }
function Get-LBWebRange {
    param($Body, [int]$DefaultHours = 24)
    $to = Get-Date; $from = $to.AddHours(-$DefaultHours)
    $h = 0; if ($Body -and $Body.hours) { $h = [int]$Body.hours }
    if ($h -gt 0) { $from = $to.AddHours(-[math]::Min(8760, $h)) }
    elseif ($Body -and $Body.from) { $f = ConvertTo-LBDate ([string]$Body.from); if ($f) { $from = $f }; if ($Body.to) { $t = ConvertTo-LBDate ([string]$Body.to); if ($t) { $to = $t.AddDays(1).AddSeconds(-1) } } }
    if ($from -gt $to) { $x = $from; $from = $to; $to = $x }
    if (($to - $from).TotalDays -gt 366) { $from = $to.AddDays(-366) }
    return @{ From = $from; To = $to }
}
function Get-LBArr { param($v) return @(@($v) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }

function Write-LBWebAudit {
    param([string]$User, [string]$Message)
    try { if (-not [Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch { }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9002 -EntryType Information -Message ("LogBok web console: {0} — by {1}" -f $Message, $User) } catch { }
}

# --- مجوز | authorization ----------------------------------------------------
function Test-LBWebAuthorized {
    param($Ctx, $Config)
    if ($script:TestMode) { return @{ Ok = $true; User = 'test' } }
    $u = $Ctx.User
    if (-not $u -or -not $u.Identity -or -not $u.Identity.IsAuthenticated) { return @{ Ok = $false; User = '' } }
    $name = [string]$u.Identity.Name
    $w = $Config.Web
    if ($w -and @($w.AllowedUsers | Where-Object { $_ }) -contains $name) { return @{ Ok = $true; User = $name } }
    try {
        $wi = [Security.Principal.WindowsIdentity]$u.Identity
        $pr = New-Object Security.Principal.WindowsPrincipal($wi)
        if ($pr.IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')) { return @{ Ok = $true; User = $name } }
        foreach ($g in @($w.AllowedGroups | Where-Object { $_ })) {
            try { if ($g -match '^S-1-') { if ($pr.IsInRole([Security.Principal.SecurityIdentifier]$g)) { return @{ Ok = $true; User = $name } } } elseif ($pr.IsInRole([string]$g)) { return @{ Ok = $true; User = $name } } } catch { }
        }
    } catch { }
    return @{ Ok = $false; User = $name }
}

# --- ورود به کنسول | console login helpers ----------------------------------
function Get-LBMetaPublic {
    param($Config, [bool]$NeedSetup)
    $lang = 'fa'; try { $lang = Get-LBWebLang -Config $Config } catch { }
    $brand = $null; try { $brand = $Config.Brand } catch { }
    return [ordered]@{ authed = $false; needSetup = [bool]$NeedSetup; loginOn = $true; lang = $lang; host = $env:COMPUTERNAME; product = 'LogBok'; brand = $brand }
}
function Invoke-LBLoginSetup {
    param($Ctx, $Req, $Cfg, [string]$Sd, [bool]$NeedSetup)
    try {
        if (-not $NeedSetup) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'setup already done' } -Status 403; return }
        if (-not $Sd) { throw 'state dir unavailable' }
        $body = Read-LBBody -Ctx $Ctx
        $u = [string]$body.user; $p = [string]$body.password
        Add-LBWebUser -StateDir $Sd -Name $u -Password $p -Role 'admin' | Out-Null
        $ip = ''; try { $ip = [string]$Req.RemoteEndPoint.Address } catch { }
        $sid = New-LBWebSession -StateDir $Sd -User $u.Trim() -Role 'admin' -Via 'console' -Config $Cfg -Ip $ip
        $ac = Get-LBAuthConfig $Cfg
        $ck = ('lbsid={0}; Path=/; HttpOnly; SameSite=Strict; Max-Age={1}' -f $sid, ($ac.SessionHours * 3600))
        try { Write-LBWebAudit -User $u -Message 'console admin account created (first-run setup)' } catch { }
        Send-LBJson -Ctx $Ctx -Obj @{ ok = $true; user = $u.Trim(); role = 'admin' } -Cookie $ck
    } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
}
function Invoke-LBLogin {
    param($Ctx, $Req, $Cfg, [string]$Sd)
    try {
        if (-not $Sd) { throw 'state dir unavailable' }
        $body = Read-LBBody -Ctx $Ctx
        $u = ([string]$body.user).Trim(); $p = [string]$body.password
        if (-not $u -or -not $p) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'نام کاربری و رمز لازم است | username and password required' } -Status 400; return }
        $ip = ''; try { $ip = [string]$Req.RemoteEndPoint.Address } catch { }
        $key = ($u.ToLowerInvariant() + '|' + $ip) -replace '[^0-9a-z.:|_\-]', '_'
        $lock = Test-LBLoginLock -StateDir $Sd -Key $key -Config $Cfg
        if ($lock.locked) { Send-LBJson -Ctx $Ctx -Obj @{ error = ('تلاشِ بیش از حد؛ {0} ثانیه بعد دوباره امتحان کنید | too many attempts, retry in {0}s' -f $lock.wait); locked = $true; wait = $lock.wait } -Status 429; return }
        $ac = Get-LBAuthConfig $Cfg
        $okUser = ''; $okRole = ''; $via = ''
        if ($ac.Mode -ne 'windows') {
            $cu = Get-LBWebUser -StateDir $Sd -Name $u
            if ($cu -and -not $cu.disabled -and (Test-LBPwHash $p ([string]$cu.hash))) { $okUser = [string]$cu.name; $okRole = [string]$cu.role; $via = 'console' }
        }
        if (-not $okUser -and $ac.Mode -ne 'console') {
            $w = Test-LBWindowsLogin -User $u -Password $p -Config $Cfg
            if ($w.ok) { $okUser = [string]$w.name; $okRole = 'admin'; $via = 'windows' }
        }
        if (-not $okUser) {
            Add-LBLoginFail -StateDir $Sd -Key $key -Config $Cfg
            try { Write-LBWebAudit -User $u -Message ('failed console login from {0}' -f $ip) } catch { }
            Send-LBJson -Ctx $Ctx -Obj @{ error = 'نام کاربری یا رمز نادرست | invalid username or password' } -Status 401; return
        }
        Clear-LBLoginFail -StateDir $Sd -Key $key
        $rememberDays = 0; try { $rememberDays = [int]$body.rememberDays } catch { }
        # --- مرحلهٔ دوم (۲FA) فقط برای کاربرانِ کنسول که روشن کرده‌اند ---
        $tf = $null; if ($via -eq 'console') { try { $tf = Get-LBUser2FA -StateDir $Sd -Name $okUser } catch { } }
        if ($tf -and $tf.on) {
            $ticket = New-LB2FATicket -StateDir $Sd -User $okUser -Role $okRole
            $methods = @(); if ($tf.totp) { $methods += 'totp' }; if ($tf.email) { $methods += 'email' }
            $emailSent = $false
            if ($tf.email -and $tf.emailAddr) { $emailSent = Send-LBEmailOtp -StateDir $Sd -Id $ticket -Email $tf.emailAddr -Config $Cfg }
            $hint = ''; if ($tf.emailAddr) { $hint = ($tf.emailAddr -replace '^(.).*(@.*)$', '$1***$2') }
            Send-LBJson -Ctx $Ctx -Obj @{ ok = $false; twofa = $true; ticket = $ticket; methods = $methods; emailSent = $emailSent; emailHint = $hint }
            return
        }
        $sid = New-LBWebSession -StateDir $Sd -User $okUser -Role $okRole -Via $via -Config $Cfg -Ip $ip -Days $rememberDays
        $ck = ('lbsid={0}; Path=/; HttpOnly; SameSite=Strict; Max-Age={1}' -f $sid, $(if ($rememberDays -gt 0) { $rememberDays * 86400 } else { $ac.SessionHours * 3600 }))
        try { Write-LBWebAudit -User $okUser -Message ('console login ({0}) from {1}' -f $via, $ip) } catch { }
        Send-LBJson -Ctx $Ctx -Obj @{ ok = $true; user = $okUser; role = $okRole; via = $via } -Cookie $ck
    } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
}
# --- مرحلهٔ دومِ ورود | second login step (2FA code) ---
function Invoke-LB2FA {
    param($Ctx, $Req, $Cfg, [string]$Sd)
    try {
        if (-not $Sd) { throw 'state dir unavailable' }
        $body = Read-LBBody -Ctx $Ctx
        $tid = [string]$body.ticket; $code = [string]$body.code; $method = [string]$body.method; if (-not $method) { $method = 'totp' }
        $rememberDays = 0; try { $rememberDays = [int]$body.rememberDays } catch { }
        $ip = ''; try { $ip = [string]$Req.RemoteEndPoint.Address } catch { }
        $tk = Get-LB2FATicket -StateDir $Sd -Id $tid
        if (-not $tk) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'نشستِ ورود منقضی شد؛ دوباره وارد شوید | login step expired, sign in again' } -Status 401; return }
        $key = ('2fa|' + ([string]$tk.user).ToLowerInvariant() + '|' + $ip) -replace '[^0-9a-z.:|_\-]', '_'
        $lock = Test-LBLoginLock -StateDir $Sd -Key $key -Config $Cfg
        if ($lock.locked) { Send-LBJson -Ctx $Ctx -Obj @{ error = ('تلاشِ بیش از حد؛ {0} ثانیه بعد | too many attempts, {0}s' -f $lock.wait); locked = $true; wait = $lock.wait } -Status 429; return }
        if (-not (Test-LB2FACode -StateDir $Sd -Ticket $tk -Code $code -Method $method)) {
            Add-LBLoginFail -StateDir $Sd -Key $key -Config $Cfg
            Send-LBJson -Ctx $Ctx -Obj @{ error = 'کدِ دومرحله‌ای نادرست | invalid verification code' } -Status 401; return
        }
        Clear-LBLoginFail -StateDir $Sd -Key $key
        Remove-LB2FATicket -StateDir $Sd -Id $tid
        $ac = Get-LBAuthConfig $Cfg
        $sid = New-LBWebSession -StateDir $Sd -User ([string]$tk.user) -Role ([string]$tk.role) -Via 'console+2fa' -Config $Cfg -Ip $ip -Days $rememberDays
        $ck = ('lbsid={0}; Path=/; HttpOnly; SameSite=Strict; Max-Age={1}' -f $sid, $(if ($rememberDays -gt 0) { $rememberDays * 86400 } else { $ac.SessionHours * 3600 }))
        try { Write-LBWebAudit -User $tk.user -Message ('console login (2fa/{0}) from {1}' -f $method, $ip) } catch { }
        Send-LBJson -Ctx $Ctx -Obj @{ ok = $true; user = [string]$tk.user; role = [string]$tk.role } -Cookie $ck
    } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
}

# --- فایل‌های رابط | static UI files -----------------------------------------
$script:Static = @{
    '/'            = @('index.html','text/html; charset=utf-8')
    '/index.html'  = @('index.html','text/html; charset=utf-8')
    '/app.js'      = @('app.js','application/javascript; charset=utf-8')
    '/app.css'     = @('app.css','text/css; charset=utf-8')
    '/logo.svg'    = @('logo.svg','image/svg+xml')
    '/vazirmatn.woff2' = @('vazirmatn.woff2','font/woff2')
}
function Send-LBStatic {
    param($Ctx, [string]$Path)
    $e = $script:Static[$Path]
    if (-not $e) { return $false }
    if ($e[0] -eq 'logo.svg') {
        # همان نشانِ داشبورد با رنگ‌های برندِ config (بدونِ کاشیِ تیره) | identical to the dashboard logo, brand colors from config
        $br = $null; try { $br = (Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1') -Raw).Brand } catch { }
        $brass = '#C9A24B'; $mint = '#4FD1B5'
        if ($br -and [string]$br.Brass -match '^#[0-9A-Fa-f]{3,8}$') { $brass = [string]$br.Brass }
        if ($br -and [string]$br.Mint -match '^#[0-9A-Fa-f]{3,8}$') { $mint = [string]$br.Mint }
        $svg = @"
<svg viewBox="12 9 40 46" width="34" height="38" xmlns="http://www.w3.org/2000/svg" aria-label="LogBok">
<rect x="14" y="12" width="36" height="40" rx="4.5" fill="none" stroke="$brass" stroke-width="2.4"/>
<line x1="22" y1="12" x2="22" y2="52" stroke="$brass" stroke-width="1.5"/>
<line x1="27" y1="21" x2="45" y2="21" stroke="$brass" stroke-width="2.3" stroke-linecap="round"/>
<line x1="27" y1="40" x2="45" y2="40" stroke="$brass" stroke-width="2.3" stroke-linecap="round"/>
<line x1="27" y1="46" x2="39" y2="46" stroke="$brass" stroke-width="2.3" stroke-linecap="round"/>
<polyline points="27,30 31,30 34,23 38,38 41,30 45,30" fill="none" stroke="$mint" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
"@
        Send-LBBytes -Ctx $Ctx -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($svg)) -Type 'image/svg+xml'
        return $true
    }
    $f = Join-Path (Join-Path $script:Root 'Web') $e[0]
    if ($e[0] -eq 'logo.svg' -and -not (Test-Path $f)) { $f = Join-Path $script:Root 'logbok-logo.svg' }
    if (-not (Test-Path $f)) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'not found' } -Status 404; return $true }
    Send-LBBytes -Ctx $Ctx -Bytes ([IO.File]::ReadAllBytes($f)) -Type $e[1]
    return $true
}

# راهنمای ساده برای خطاهای رایجِ ایمیل | plain hint for common mail errors
function Get-LBMailHint {
    param([string]$Err, [int]$Port, [string]$Lang)
    $h = if ($Err -match 'Unable to connect|could not connect|timed out|timeout|refused|No such host|remote name could not|not known') {
        "سرورِ ایمیل از این سیستم در دسترس نیست: نامِ سرور، پورت ($Port) و فایروال/اینترنتِ خروجیِ این سرور را بررسی کنید | the mail server cannot be reached from this computer: check the server name, port ($Port) and this server's firewall / outbound internet"
    } elseif ($Err -match '535|rejected|Authentication|5\.7\.') {
        'نامِ کاربری یا گذرواژهٔ SMTP پذیرفته نشد (در برخی سرویس‌ها گذرواژهٔ مخصوصِ برنامه لازم است) | the SMTP user name or password was rejected (some providers need an app password)'
    } elseif ($Err -match 'certificate|SSL|TLS|handshake') {
        'اتصالِ امن برقرار نشد: پورتِ 465 با SSL، پورتِ 587 با STARTTLS (تیکِ SSL روشن) | the secure connection failed: use 465 with SSL, or 587 with STARTTLS (SSL ticked)'
    } else { 'تنظیماتِ سرورِ ایمیل را بررسی کنید | check the mail server settings' }
    return (Format-LBTxt -s $h -Lang $Lang)
}

# --- بازهٔ زمانی از query | time range from query -----------------------------
function Get-LBRange {
    param($Ctx)
    $to = Get-Date; $from = $to.AddHours(-24)
    $h = Get-LBQ $Ctx 'hours'
    if ($h -match '^\d+$') { $from = $to.AddHours(-[int]$h) }
    $f = Get-LBQ $Ctx 'from'; $t = Get-LBQ $Ctx 'to'
    if ($f) { try { $from = [datetime]::Parse($f, $script:Inv) } catch { } }
    if ($t) { try { $to = [datetime]::Parse($t, $script:Inv) } catch { } }
    return @{ From = $from; To = $to }
}

# جست‌وجوی انبار از جدید به قدیم | newest-first archive search
function Search-LBArchiveRecent {
    param($Config, [datetime]$From, [datetime]$To, [string]$HostName, [string]$User, [string]$EventId, [string]$Query, [string]$Source = 'all', [int]$Max = 200)
    $dir = Get-LBArchiveDir -Config $Config
    $out = New-Object System.Collections.Generic.List[object]
    $expr = $null; $plain = $null
    if ($Query) {
        if ($Query -match '\b(AND|OR|NOT)\b|[()"!*]') { $expr = ConvertTo-LBQueryExpr -Query $Query } else { $plain = $Query.ToLowerInvariant() }
    }
    $day = $To.Date
    $scanned = 0
    while ($day -ge $From.Date -and $out.Count -lt $Max) {
        $d = $day.ToString('yyyy-MM-dd', $script:Inv)
        $files = @()
        if ($Source -ne 'syslog')  { $files += (Join-Path $dir "events-$d.ndjson") }
        if ($Source -ne 'windows') { $files += (Join-Path $dir "syslog-$d.ndjson") }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($file in $files) {
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $recs = Get-LBArchiveDayRecords -File $file   # کشِ مشترکِ روز؛ تجزیهٔ JSON فقط یک‌بار | shared day cache, parsed once
            for ($i = $recs.Count - 1; $i -ge 0; $i--) {
                $r = $recs[$i]; $scanned++
                $tt = $r.time
                if (-not $tt -or $tt -lt $From -or $tt -gt $To) { continue }
                if ($plain -and ("$($r.host) $($r.id) $($r.lvl) $($r.user) $($r.ip) $($r.msg) $($r.log) $($r.prov)".ToLowerInvariant().IndexOf($plain) -lt 0)) { continue }
                if ($HostName -and ([string]$r.host) -notlike "*$HostName*") { continue }
                if ($User -and ([string]$r.user) -notlike "*$User*") { continue }
                if ($EventId -and "$($r.id)" -ne "$EventId") { continue }
                if ($expr) { $hay = ("$($r.t) $($r.host) $($r.id) $($r.lvl) $($r.user) $($r.ip) $($r.msg) $($r.log) $($r.prov)").ToLower(); if (-not (Test-LBQuery -Haystack $hay -Expr $expr)) { continue } }
                $r | Add-Member -NotePropertyName ts -NotePropertyValue $tt.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv) -Force
                $rows.Add($r)
                if ($rows.Count -ge ($Max * 2)) { break }
            }
        }
        foreach ($r in ($rows | Sort-Object ts -Descending)) { if ($out.Count -ge $Max) { break }; $out.Add($r) }
        $day = $day.AddDays(-1)
        if ($scanned -gt 3000000) { break }
    }
    return $out.ToArray()
}

# --- خروجیِ یافته برای رابط | finding → UI object ------------------------------
# --- یادداشتِ مدیر | admin notes (per event, or per event type with an optional custom title) ---
function Get-LBNotesFile { param([string]$StateDir) Join-Path $StateDir 'notes.json' }
function Get-LBNotes {
    param([string]$StateDir)
    $f = Get-LBNotesFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @{} }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return $h } } catch { }
    return @{}
}
function Set-LBNote {
    param([string]$StateDir, [string]$Key, [string]$Text, [string]$Title, [string]$By)
    $n = Get-LBNotes -StateDir $StateDir
    if (-not ($Text.Trim()) -and -not ($Title.Trim())) { $n.Remove($Key) }
    else { $n[$Key] = @{ text = $Text.Trim(); title = $Title.Trim(); by = $By; at = (Get-Date).ToString('o', $script:Inv) } }
    $f = Get-LBNotesFile -StateDir $StateDir; $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $n -Depth 5), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
# امضای «نوعِ رویداد»: دسته + عنوانِ انگلیسی با اعدادِ متغیر حذف‌شده | event-type signature
function Get-LBFindingSig {
    param($r)
    $t = Format-LBTxt -s ([string]$r.title) -Lang 'en'
    return ([string]$r.cat + '|' + ([regex]::Replace($t, '\d+', '#')).Trim()).ToLowerInvariant()
}

function ConvertTo-LBWebFinding {
    param($r, [string]$Lang, [switch]$Full, $Notes)
    $t = ConvertTo-LBLocal $r.t; if (-not $t) { $t = Get-Date }
    $o = [ordered]@{ id=[string]$r.id; time=$t.ToString('yyyy-MM-dd HH:mm:ss', $script:Inv); sev=[string]$r.sev; cat=[string]$r.cat
                     catTitle=(Get-LBCatTitle -Key ([string]$r.cat) -Lang $Lang); host=[string]$r.host; title=(Format-LBTxt -s ([string]$r.title) -Lang $Lang); mitre=[string]$r.mitre }
    if ($Notes -and $Notes.Count) {
        $sig = Get-LBFindingSig $r
        $nt = $Notes["t:$sig"]; $ne = $Notes["e:$($r.id)"]
        if ($nt -and $nt.title) { $o.origTitle = $o.title; $o.title = [string]$nt.title }
        $o.note = $(if ($ne -and $ne.text) { [string]$ne.text } elseif ($nt -and $nt.text) { [string]$nt.text } else { '' })
    }
    if ($Full) {
        $o.details = Format-LBDetail -s ([string]$r.det) -Lang $Lang
        $o.key = [string]$r.key
        $o.iso = $t.ToString('o', $script:Inv)
        $x = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { if ($p.Name -like 'x_*') { $x[$p.Name.Substring(2)] = [string]$p.Value } }
        $o.extra = $x
    }
    return $o
}

# موجودیت‌های قابلِ اقدام در یک یافته (IP، کاربر) | actionable entities
function Get-LBEntities {
    param($r)
    $txt = "{0}`n{1}" -f $r.title, $r.det
    $ips = @()
    foreach ($m in [regex]::Matches($txt, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) { $v = $m.Value; if ($v -notmatch '^(0\.|127\.|255\.)') { $ips += $v } }
    foreach ($p in $r.PSObject.Properties) { if ($p.Name -eq 'x_GuardIp' -and $p.Value) { $ips += [string]$p.Value } }
    $users = @()
    foreach ($m in [regex]::Matches($txt, '(?:کاربر[^:\n]*|[Uu]ser(?:name)?|Target user|Account|حساب)\s*[:=]\s*([^\s|,;]+)')) {
        $u = $m.Groups[1].Value.Trim(); if ($u -and $u -ne '-' -and $u -notlike '*$' -and $u -ne 'SYSTEM') { $users += $u }
    }
    return @{ Ips = @($ips | Select-Object -Unique | Select-Object -First 5); Users = @($users | Select-Object -Unique | Select-Object -First 5) }
}

# ---------------------------------------------------------------------------
#  مسیریابِ API | API router
# ---------------------------------------------------------------------------
# اعتبارنامه از بدنهٔ درخواست، وگرنه حسابِ ذخیره‌شدهٔ استقرار | credential from the request, else the saved deploy account
function Get-LBBodyCred {
    param($Body, [string]$StateDir, [string]$Saved = 'ad-deploy')
    if ($Body -and $Body.user -and $Body.password) {
        $sec = New-Object Security.SecureString; foreach ($ch in ([string]$Body.password).ToCharArray()) { $sec.AppendChar($ch) }
        return New-Object Management.Automation.PSCredential(([string]$Body.user).Trim(), $sec)
    }
    if ($Saved) { $f = Join-Path (Join-Path $StateDir 'creds') ($Saved + '.sec'); if (Test-Path $f) { return (Read-LBCredFile -File $f) } }
    return $null
}
# دامنهٔ ذخیره‌شده (domainId) یا ورودیِ دستی | a saved domain (domainId) or the typed server/user/password
function Resolve-LBWebAd {
    param($Body, [string]$StateDir)
    if ($Body -and $Body.domainId) {
        $c = Get-LBADDomainConn -StateDir $StateDir -Id ([string]$Body.domainId)
        $cr = $c.Credential
        if ($Body.user -and $Body.password) { $cr = Get-LBBodyCred -Body $Body -StateDir $StateDir -Saved '' }
        return [pscustomobject]@{ Server = $c.Server; Credential = $cr; CredName = $c.CredName; DomainId = [string]$Body.domainId }
    }
    $srv = ''; if ($Body) { $srv = ([string]$Body.server).Trim() }
    return [pscustomobject]@{ Server = $srv; Credential = (Get-LBBodyCred -Body $Body -StateDir $StateDir); CredName = 'ad-deploy'; DomainId = '' }
}
function ConvertTo-LBWebDomain {
    param($d, [string]$StateDir, [string]$Lang = 'fa')
    $st = $d.Stats
    return [ordered]@{ id=[string]$d.Id; fqdn=[string]$d.Fqdn; netbios=[string]$d.NetBios; dc=[string]$d.DC; server=[string]$d.Server; user=[string]$d.User; ready=($d.Ready -eq $true)
        lastCheck=[string]$d.LastCheck; lastError=[string]$d.LastError; hasCred=(Test-LBTargetCredential -Name ('ad-' + [string]$d.Id) -StateDir $StateDir)
        checks=@(Get-LBArr $d.Checks | ForEach-Object { [ordered]@{ check=[string]$_.check; ok=($_.ok -eq $true); detail=(Format-LBTxt -s ([string]$_.detail) -Lang $Lang); fix=(Format-LBTxt -s ([string]$_.fix) -Lang $Lang) } })
        stats=$(if ($st) { [ordered]@{ computers=[int]$st.Computers; servers=[int]$st.Servers; workstations=[int]$st.Workstations; dcs=[int]$st.DCs; disabled=[int]$st.Disabled; stale=[int]$st.Stale; ous=[int]$st.OUs; users=[int]$st.Users; groups=[int]$st.Groups } } else { $null })
        policies=@(Get-LBAgentPolicies -StateDir $StateDir | Where-Object { [string]$_.DomainId -eq [string]$d.Id }).Count }
}
function ConvertTo-LBWebWorkgroup {
    param($g, [string]$StateDir)
    $st = $g.Stats
    $ak = @{}; try { $k0 = Get-LBAgentKeys -StateDir $StateDir; foreach ($k in @($k0.Keys)) { if ([string]$k0[$k].Status -ne 'pending') { $ak[([string]$k).ToUpperInvariant()] = $true } } } catch { }
    $withAgent = 0
    $mach = @(Get-LBArr $g.Machines | ForEach-Object { $nm = [string]$_.name; if ($nm -and $ak[$nm.ToUpperInvariant()]) { $withAgent++ }
        [ordered]@{ name=$nm; address=[string]$_.address; smb=($_.smb -eq $true); winrm=($_.winrm -eq $true); agent=$(if ($nm -and $ak[$nm.ToUpperInvariant()]) { 'ok' } else { '' }); hasCred=$(if ($nm) { Test-LBTargetCredential -Name $nm -StateDir $StateDir } else { $false }) } })
    return [ordered]@{ id=[string]$g.Id; name=[string]$g.Name; range=[string]$g.Range; hostList=@(Get-LBArr $g.HostList); lastScan=[string]$g.LastScan
        hasCred=(Test-LBTargetCredential -Name ('wg-' + [string]$g.Id) -StateDir $StateDir); withAgent=$withAgent
        stats=$(if ($st) { [ordered]@{ total=[int]$st.Total; smb=[int]$st.Smb; winrm=[int]$st.WinRM } } else { @{ total=$mach.Count; smb=0; winrm=0 } }); machines=$mach }
}
function ConvertTo-LBWebPolicy {
    param($p)
    $gp = $p.Gpo
    return [ordered]@{ id=[string]$p.Id; name=[string]$p.Name; enabled=($p.Enabled -ne $false); method=[string]$p.Method; auto=($p.Auto -eq $true); type=[string]$p.Type
        ous=@(Get-LBArr $p.OUs); includeGroups=@(Get-LBArr $p.IncludeGroups); excludeGroups=@(Get-LBArr $p.ExcludeGroups); nameLike=[string]$p.NameLike; includeDisabled=($p.IncludeDisabled -eq $true)
        server=[string]$p.Server; collector=[string]$p.Collector; parallel=$(if ($p.Parallel) { [int]$p.Parallel } else { 6 }); reinstall=($p.Reinstall -eq $true); credName=[string]$p.CredName; domainId=[string]$p.DomainId; domain=[string]$p.Domain
        lastRun=[string]$p.LastRun; lastResult=$p.LastResult; lastError=[string]$p.LastError; lastErrorAt=[string]$p.LastErrorAt
        gpo=$(if ($gp -and $gp.Guid) { [ordered]@{ guid=[string]$gp.Guid; name=[string]$gp.Name; domain=[string]$gp.Domain; dc=[string]$gp.DC; links=@(Get-LBArr $gp.Links); published=[string]$gp.Published; version=[int]$gp.Version; stamp=[string]$gp.Stamp } } else { $null }) }
}
function ConvertFrom-LBWebPolicy {
    param($b)
    $h = @{ Name=([string]$b.name).Trim(); Enabled=($b.enabled -ne $false); Method=[string]$b.method; Auto=($b.auto -eq $true); Type=[string]$b.type
            OUs=@(Get-LBArr $b.ous); IncludeGroups=@(Get-LBArr $b.includeGroups); ExcludeGroups=@(Get-LBArr $b.excludeGroups); NameLike=([string]$b.nameLike).Trim(); IncludeDisabled=($b.includeDisabled -eq $true)
            Server=([string]$b.server).Trim(); Collector=([string]$b.collector).Trim(); Parallel=[math]::Max(1, [math]::Min(20, [int]$(if ($b.parallel) { $b.parallel } else { 6 }))); Reinstall=($b.reinstall -eq $true); CredName='ad-deploy' }
    if ($b.domainId) { $h.DomainId = [string]$b.domainId }
    if ($b.id) { $h.Id = [string]$b.id }
    return $h
}

function Invoke-LBWebApi {
    param($Ctx, [string]$Path, [string]$Method, [string]$User)
    $cfg = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
    $lang = Get-LBWebLang -Config $cfg
    $sd = Get-LBStateDir -Config $cfg -Root $script:Root
    $body = $null
    if ($Method -eq 'POST') { $body = Read-LBBody -Ctx $Ctx }

    switch ($Path) {
    # ---------------- عمومی | general ----------------
    '/api/meta' {
        $cats = @(); foreach ($k in (Get-LBCategoryKeys)) { $cats += [ordered]@{ key=$k; title=(Get-LBCatTitle -Key $k -Lang $lang) } }
        $role = 'admin'; try { $s = Get-LBWebUser -StateDir $sd -Name $User; if ($s) { $role = [string]$s.role } } catch { }
        $isVendor = $false; try { $isVendor = Test-LBIsVendor $script:Root } catch { }
        $loginOn = $false; try { $loginOn = [bool](Get-LBAuthConfig $cfg).Enabled } catch { }
        return [ordered]@{ user=$User; role=$role; authed=$true; loginOn=$loginOn; isVendor=$isVendor; lang=$lang; host=$env:COMPUTERNAME; version=$script:Version; token=$script:Token; mode=[string]$cfg.CollectionMode
                           categories=$cats; brand=$(if ($cfg.Brand) { [string]$cfg.Brand.NameEn } else { 'LogBok' }); serverIps=@(Get-LBServerIPs); agentVersion=$(try { Get-LBAgentVersion } catch { '' }) }
    }
    '/api/ad/dashboard' {
        $days = [math]::Max(1, [math]::Min(30, [int](Get-LBQ $Ctx 'days' 7)))
        $data = Get-LBWebCached -Key ("addash:$days") -Seconds 120 -Get {
            Use-LBModule 'LogBok.Archive' 'Get-LBArchiveDir'
            $dir = Get-LBArchiveDir -Config $cfg
            # per-day aggregate cache: past days never change, so compute once and reuse from disk.
            $cacheDir = Join-Path $sd 'ad-days'
            if (-not (Test-Path $cacheDir)) { try { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null } catch { } }
            $failByUser = @{}; $hourHist = New-Object int[] 24
            $acctCreated = 0; $acctDeleted = 0; $acctModified = 0; $grpChanges = 0; $gpoChanges = 0; $totalFail = 0; $totalLogon = 0
            $invc = [Globalization.CultureInfo]::InvariantCulture
            $today = (Get-Date).ToString('yyyy-MM-dd', $invc)
            for ($i = $days - 1; $i -ge 0; $i--) {
                $ds = (Get-Date).AddDays(-$i).ToString('yyyy-MM-dd', $invc)
                $f = Join-Path $dir ('events-{0}.ndjson' -f $ds)
                $cf = Join-Path $cacheDir ("$ds.json")
                $st = $null
                if ($ds -ne $today -and (Test-Path $cf)) { try { $st = (Get-Content -LiteralPath $cf -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { $st = $null } }
                if (-not $st) {
                    if (-not (Test-Path $f)) { continue }
                    $st = Get-LBAdDayStats -File $f
                    if ($ds -ne $today) { try { $st.hourHist = [object[]]@($st.hourHist | ForEach-Object { [int]$_ }); (ConvertTo-Json -InputObject $st -Depth 5 -Compress) | Set-Content -LiteralPath $cf -Encoding UTF8 } catch { } }
                }
                $totalFail += [int]$st.fail; $totalLogon += [int]$st.logon
                $acctCreated += [int]$st.created; $acctDeleted += [int]$st.deleted; $acctModified += [int]$st.modified
                $grpChanges += [int]$st.groups; $gpoChanges += [int]$st.gpo
                $hh = $st.hourHist; if ($hh -and $hh.PSObject.Properties['value']) { $hh = $hh.value }   # tolerate PS5.1 {value,Count} caches
                if ($hh) { $hha = @($hh); for ($h = 0; $h -lt [Math]::Min(24, $hha.Count); $h++) { $hourHist[$h] = [int]$hourHist[$h] + [int]$hha[$h] } }
                if ($st.failByUser) {
                    if ($st.failByUser -is [hashtable]) { foreach ($k in @($st.failByUser.Keys)) { $failByUser[$k] = [int]$failByUser[$k] + [int]$st.failByUser[$k] } }
                    else { foreach ($p in $st.failByUser.PSObject.Properties) { $failByUser[$p.Name] = [int]$failByUser[$p.Name] + [int]$p.Value } }
                }
            }
            $topFail = @($failByUser.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ user = $_.Key; n = $_.Value } })
            $hours = @(); for ($h = 0; $h -lt 24; $h++) { $hours += [int]$hourHist[$h] }
            [ordered]@{ days = $days; totalFail = $totalFail; totalLogon = $totalLogon; topFail = $topFail; byHour = $hours
                account = [ordered]@{ created = $acctCreated; deleted = $acctDeleted; modified = $acctModified; groups = $grpChanges; gpo = $gpoChanges } }
        }
        $uba = @(); try { $uf = Get-LBFindings -Config $cfg -From (Get-Date).AddDays(-7) -To (Get-Date) -Category @('UEBA') -Max 15; $uba = @($uf.Items | ForEach-Object { [ordered]@{ time = (ConvertTo-LBIsoText $_.Time); title = [string]$_.Title; machine = [string]$_.Machine; sev = [string]$_.Severity } }) } catch { }
        $data.uba = $uba
        return $data
    }
    '/api/summary' {
        $hours = [int](Get-LBQ $Ctx 'hours' 24)
        $st = Get-LBFindingStats -Config $cfg -From (Get-Date).AddHours(-$hours) -To (Get-Date)
        $cats = @(); foreach ($k in (Get-LBCategoryKeys)) { $c = $st.ByCategory[$k]; $cats += [ordered]@{ key=$k; title=(Get-LBCatTitle -Key $k -Lang $lang); n=$(if ($c) { $c.n } else { 0 }); crit=$(if ($c) { $c.crit } else { 0 }) } }
        $ntsS = Get-LBNotes -StateDir $sd
        $hostsTop = @($st.ByHost.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ host=$_.Key; n=$_.Value } })
        $g = $null; try { $g = Get-LBWebCached -Key 'guard' -Seconds 15 -Get { Get-LBGuardStatus -InstallDir $script:Root } } catch { }
        $conn = Get-LBConnectStatus -InstallDir $script:Root
        $cf = 0; $cw = 0; $ct = 0; if ($conn) { foreach ($t in @($conn.Targets)) { $ct++; if ($t.Status -eq 'Fail') { $cf++ } elseif ($t.Status -eq 'Warn') { $cw++ } } }
        $lic = Test-LogBokLicense -Config $cfg -NoClockUpdate
        $inc = @(); try { $inc = @(Get-LBIncidents -Config $cfg | Where-Object { $_.Status -ne 'Closed' }) } catch { }
        $jobs = @(Get-LBWebJobs -Config $cfg)
        $okCodes = @(0, 267009, 267011, 2147946720)
        $jobsBad = @($jobs | Where-Object { $_.Enabled -and ($_.State -eq 'Missing' -or ($_.LastCode -and ($okCodes -notcontains [long]$_.LastCode))) }).Count
        $srcN = @(Get-LBTargetList -StateDir $sd).Count
        return [ordered]@{
            hours=$hours; total=$st.Total; crit=$st.BySeverity.Critical; warn=$st.BySeverity.Warning; info=$st.BySeverity.Info
            categories=$cats; topHosts=$hostsTop; timeline=@($st.Timeline)
            latest=@($(foreach ($x in $st.Latest) { ConvertTo-LBWebFinding -r $x -Lang $lang -Notes $ntsS }))
            guard=[ordered]@{ blocked=$(if ($g) { $g.Blocked } else { 0 }); permanent=$(if ($g) { $g.Permanent } else { 0 }); watching=$(if ($g) { $g.Watching } else { 0 }); rules=$(if ($g) { $g.Rules } else { 0 }) }
            conn=[ordered]@{ targets=$ct; down=$cf; warn=$cw; generated=$(if ($conn) { [string]$conn.Generated } else { '' }) }
            license=[ordered]@{ valid=[bool]$lic.Valid; company=[string]$lic.Company; permanent=[bool]$lic.Permanent; expiry=[string]$lic.Expiry; reason=(Format-LBTxt -s (Get-LogBokLicenseReasonText -License $lic -Lang 'both') -Lang $lang); device=[string]$lic.DeviceCode }
            sessionsLive=$(try { $nS = 0; try { $nS += @(Get-LBLiveSessions | Where-Object { $_.st -eq 'Active' }).Count } catch { }; $pdS = Join-Path $sd 'push'; if (Test-Path $pdS) { foreach ($fS in @(Get-ChildItem $pdS -Recurse -Filter 'sessions.json' -File -ErrorAction SilentlyContinue)) { if ($fS.LastWriteTime -gt (Get-Date).AddMinutes(-10)) { try { $nS += @((Get-Content $fS.FullName -Raw | ConvertFrom-Json).Data | Where-Object { $_ -and $_.st -eq 'Active' }).Count } catch { } } } }; $nS } catch { 0 })
            incidentsOpen=$inc.Count; jobsOn=@($jobs | Where-Object Enabled).Count; jobsTotal=$jobs.Count; jobsBad=$jobsBad; sources=$srcN
        }
    }

    # ---------------- رویدادها | events (findings) ----------------
    '/api/findings' {
        $rg = Get-LBRange -Ctx $Ctx
        $cat = Get-LBQ $Ctx 'cat'; $cats = if ($cat) { @($cat -split ',') } else { @() }
        $res = Get-LBFindings -Config $cfg -From $rg.From -To $rg.To -Category $cats -Severity (Get-LBQ $Ctx 'sev') -HostName (Get-LBQ $Ctx 'host') -Text (Get-LBQ $Ctx 'q') -Skip ([int](Get-LBQ $Ctx 'skip' 0)) -Max ([math]::Min(500, [int](Get-LBQ $Ctx 'max' 100)))
        $nts = Get-LBNotes -StateDir $sd
        return [ordered]@{ total=$res.Total; items=@($res.Items | ForEach-Object { ConvertTo-LBWebFinding -r $_ -Lang $lang -Notes $nts }) }
    }
    '/api/finding' {
        $id = Get-LBQ $Ctx 'id'
        $r = Get-LBFinding -Config $cfg -Id $id
        if (-not $r) { return @{ __status = 404; error = 'not found' } }
        $nts = Get-LBNotes -StateDir $sd
        $o = ConvertTo-LBWebFinding -r $r -Lang $lang -Full -Notes $nts
        $sig = Get-LBFindingSig $r
        $nt = $nts["t:$sig"]; $ne = $nts["e:$($r.id)"]
        $o.sig = $sig
        $o.notes = [ordered]@{ eventText=$(if ($ne) { [string]$ne.text } else { '' }); eventBy=$(if ($ne) { [string]$ne.by } else { '' }); eventAt=$(if ($ne) { [string]$ne.at } else { '' })
                               typeText=$(if ($nt) { [string]$nt.text } else { '' }); typeTitle=$(if ($nt) { [string]$nt.title } else { '' }); typeBy=$(if ($nt) { [string]$nt.by } else { '' }); typeAt=$(if ($nt) { [string]$nt.at } else { '' }) }
        if (-not $o.origTitle) { $o.origTitle = $o.title }
        $t = ConvertTo-LBLocal $r.t; if (-not $t) { $t = Get-Date }
        $ent = Get-LBEntities -r $r
        $hostShort = ([string]$r.host -split '[ (]')[0]
        $related = @()
        try { $related = @(Search-LBArchiveRecent -Config $cfg -From $t.AddMinutes(-15) -To $t.AddMinutes(5) -HostName $hostShort -Max 150) } catch { }
        if ($ent.Ips.Count -or $ent.Users.Count) {
            $focus = @($related | Where-Object { $rr = $_; ($ent.Ips | Where-Object { [string]$rr.ip -eq $_ -or ([string]$rr.msg).Contains($_) }).Count -or ($ent.Users | Where-Object { [string]$rr.user -like "*$_*" }).Count })
            if ($focus.Count -ge 3) { $related = $focus }
        }
        $mitre = @(); try { foreach ($m in (Get-LBMitre -Category ([string]$r.cat))) { $mitre += [ordered]@{ id=$m.id; name=$m.n } } } catch { }
        $guard = @(); try { $blocks = @(Get-LBGuardBlocks -InstallDir $script:Root); foreach ($ip in $ent.Ips) { $b = $blocks | Where-Object { $_.Ip -eq $ip } | Select-Object -First 1; $guard += [ordered]@{ ip=$ip; blocked=[bool]$b; until=$(if ($b) { [string]$b.Until } else { '' }) } } } catch { }
        $inc = $null; try { $inc = Get-LBIncidents -Config $cfg | Where-Object { $_.Status -ne 'Closed' -and $_.Machine -eq $r.host -and $_.Category -eq $r.cat } | Select-Object -First 1 } catch { }
        $o.entities = [ordered]@{ ips=@($ent.Ips); users=@($ent.Users); guard=$guard }
        $o.mitreInfo = $mitre
        $o.incident = $(if ($inc) { [ordered]@{ id=$inc.Id; status=$inc.Status; owner=$inc.Owner; count=$inc.Count } } else { $null })
        $o.related = @($related | Select-Object -First 100 | ForEach-Object { [ordered]@{ t=[string]$_.ts; host=[string]$_.host; log=[string]$_.log; id=[string]$_.id; lvl=[string]$_.lvl; user=[string]$_.user; ip=[string]$_.ip; msg=[string]$_.msg; prov=[string]$_.prov; rec=[string]$_.rec } })
        $o.isSelf = (Test-LBIsSelf $hostShort)
        return $o
    }
    '/api/note' {
        $scope = [string]$body.scope; $txt = [string]$body.text; $ttl = [string]$body.title
        if ($txt.Length -gt 4000 -or $ttl.Length -gt 300) { throw 'note too long' }
        if ($scope -eq 'event') { $id = [string]$body.id; if ($id -notmatch '^[0-9a-f]{8,40}$') { throw 'invalid id' }; Set-LBNote -StateDir $sd -Key "e:$id" -Text $txt -Title '' -By $User }
        elseif ($scope -eq 'type') { $sg = [string]$body.sig; if (-not $sg -or $sg.Length -gt 400) { throw 'invalid type' }; Set-LBNote -StateDir $sd -Key "t:$sg" -Text $txt -Title $ttl -By $User }
        else { throw 'scope must be event or type' }
        Write-LBWebAudit -User $User -Message "admin note saved ($scope)"
        return @{ ok = $true }
    }
    '/api/logs' {
        $rg = Get-LBRange -Ctx $Ctx
        $items = @(Search-LBArchiveRecent -Config $cfg -From $rg.From -To $rg.To -HostName (Get-LBQ $Ctx 'host') -User (Get-LBQ $Ctx 'user') -EventId (Get-LBQ $Ctx 'id') -Query (Get-LBQ $Ctx 'q') -Source (Get-LBQ $Ctx 'source' 'all') -Max ([math]::Min(1000, [int](Get-LBQ $Ctx 'max' 200))))
        return [ordered]@{ count=$items.Count; items=@($items | ForEach-Object { [ordered]@{ t=[string]$_.ts; host=[string]$_.host; log=[string]$_.log; id=[string]$_.id; lvl=[string]$_.lvl; user=[string]$_.user; ip=[string]$_.ip; msg=[string]$_.msg; prov=[string]$_.prov; rec=[string]$_.rec } }) }
    }

    # ---------------- نشست‌ها | sessions (live + history) ----------------
    '/api/sessions' {
        # «live» (سرور + ایجنت‌ها) سریع است؛ «history» (رویدادها/آرشیو) سنگین است و جدا و با کش خوانده می‌شود
        # live (server + agents) is fast; history (events/archive) is heavy, served separately and cached
        $part = [string](Get-LBQ $Ctx 'part' 'all')
        $hours = [math]::Max(1, [math]::Min(24 * 31, [int](Get-LBQ $Ctx 'hours' 24)))
        $hostQ = [string](Get-LBQ $Ctx 'host' ''); $userQ = [string](Get-LBQ $Ctx 'user' '')
        $now = Get-Date
        $S0 = Get-LBAlertSettings -Config $cfg
        $selfName = ([string]$env:COMPUTERNAME).ToUpperInvariant()
        $toLive = { param($hn, $x, $src, $at)
            $lt = ConvertTo-LBLocal $x.lt; $dt = ConvertTo-LBLocal $x.dt
            [ordered]@{ host = $hn; id = [int]$x.id; user = [string]$x.u; type = [string]$x.k; station = [string]$x.s; state = [string]$x.st; device = [string]$x.cn; ip = [string]$x.ip
                        start = $(if ($lt) { $lt.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv) } else { '' }); minutes = $(if ($lt) { [int]($now - $lt).TotalMinutes } else { $null })
                        discMin = $(if ($dt) { [int]($now - $dt).TotalMinutes } else { $null }); idleMin = $(if ($null -ne $x.idle) { [int]([int]$x.idle / 60) } else { $null }); source = $src; seen = $at; canAct = ($src -ne 'events') } }
        $flagsOf = { param($x, [bool]$isLive, $perUser)
            $f = @()
            if (Test-LBPublicIp ([string]$x.ip)) { $f += 'external' }
            $st = ConvertTo-LBLocal ([string]$x.start); if ($st -and -not (Test-LBBusinessHours -S $S0 -Time $st)) { $f += 'afterhours' }
            if ($x.minutes -ge 720) { $f += 'long' }
            if ($isLive -and $x.state -eq 'Disconnected' -and $x.discMin -ge 120) { $f += 'forgotten' }
            if ($isLive -and $perUser) { $k = ([string]$x.user -replace '^.*\\', '').ToLowerInvariant(); if ($perUser[$k] -and $perUser[$k].Count -gt 1) { $f += 'multi' } }
            if ($x.elevated) { $f += 'admin' }
            return , $f }

        # ---------- live (سبک) | live (cheap): server + agents' last report ----------
        $liveOut = $null; $sumLive = $null
        if ($part -eq 'all' -or $part -eq 'live') {
            $live = New-Object System.Collections.Generic.List[object]
            try { foreach ($x in @(Get-LBLiveSessions)) { $live.Add((& $toLive $selfName ([pscustomobject]$x) 'self' $now.ToString('o', $script:Inv))) } } catch { }
            $pd = Join-Path $sd 'push'
            if (Test-Path $pd) {
                foreach ($d in @(Get-ChildItem $pd -Directory -ErrorAction SilentlyContinue)) {
                    $f = Join-Path $d.FullName 'sessions.json'; if (-not (Test-Path $f)) { continue }
                    $j = $null; try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                    $at = ConvertTo-LBLocal $j.At
                    $fresh = ($at -and ($now - $at).TotalMinutes -le 10)
                    foreach ($x in @($j.Data | Where-Object { $_ })) { $live.Add((& $toLive $d.Name.ToUpperInvariant() $x $(if ($fresh) { 'agent' } else { 'stale' }) ([string]$j.At))) }
                }
            }
            $liveF = @($live | Where-Object { (-not $hostQ -or $_.host -like "*$hostQ*") -and (-not $userQ -or $_.user -like "*$userQ*") })
            $perUser = @{}; foreach ($x in $liveF) { $k = ([string]$x.user -replace '^.*\\', '').ToLowerInvariant(); if (-not $perUser[$k]) { $perUser[$k] = @{} }; $perUser[$k][$x.host] = $true }
            $liveOut = @($liveF | Sort-Object @{ e = { $_.state -ne 'Active' } }, @{ e = { -[int]$_.minutes } } | ForEach-Object { $_.flags = (& $flagsOf $_ $true $perUser); $_ })
            $sumLive = [ordered]@{ live = @($liveOut | Where-Object { $_.state -eq 'Active' }).Count; disconnected = @($liveOut | Where-Object { $_.state -eq 'Disconnected' }).Count
                                   rdp = @($liveOut | Where-Object { $_.type -eq 'rdp' }).Count; users = @($liveOut | ForEach-Object { ([string]$_.user -replace '^.*\\', '').ToLowerInvariant() } | Select-Object -Unique).Count
                                   externalLive = @($liveOut | Where-Object { @($_.flags) -contains 'external' }).Count }
        }

        # ---------- history (سنگین، با کشِ ۹۰ ثانیه‌ایِ مشترک) | history (heavy, 90s shared cache) ----------
        $histOut = $null; $sumHist = $null; $histErr = ''
        if ($part -eq 'all' -or $part -eq 'history') {
            $ckey = "sessHist|$hours|$($hostQ.ToLowerInvariant())|$($userQ.ToLowerInvariant())"
            $packed = Get-LBWebCached -Key $ckey -Seconds 180 -Get {
                $err = ''; $rows = @()
                try { $hist = @(Get-LBSessionHistory -Config $cfg -From $now.AddHours(-$hours) -To $now -HostLike $hostQ -UserLike $userQ -Max 1500) } catch { $hist = @(); $err = $_.Exception.Message }
                # سیستم‌های بدونِ ایجنت: نشست‌های بازِ تازه (تخمینی) | hosts without an agent: recent open sessions (estimated)
                $openEst = @($hist | Where-Object { $_.how -eq 'open' -and ($now - $_.start).TotalHours -le 24 } | ForEach-Object {
                    $hn = ([string]$_.host -split '\.')[0].ToUpperInvariant()
                    [ordered]@{ host = $hn; id = 0; user = $_.user; type = $_.type; station = ''; state = $(if ($_.lastDisc) { 'Disconnected' } else { 'Active' }); device = $_.device; ip = $_.ip
                                start = $_.start.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv); minutes = [int]($now - $_.start).TotalMinutes; discMin = $(if ($_.lastDisc) { [int]($now - $_.lastDisc).TotalMinutes } else { $null }); idleMin = $null; source = 'events'; seen = ''; canAct = $false } })
                $rows = @($hist | Select-Object -First 1500 | ForEach-Object {
                    $mins = [int]((($(if ($_.end) { $_.end } else { $now })) - $_.start).TotalMinutes)
                    [ordered]@{ host = ([string]$_.host -split '\.')[0].ToUpperInvariant(); user = $_.user; type = $_.type; device = $_.device; ip = $_.ip; start = $_.start.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv)
                                end = $(if ($_.end) { $_.end.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv) } else { '' }); minutes = $mins; how = $_.how; disc = [int]$_.disc; elevated = [bool]$_.elevated } })
                [ordered]@{ rows = $rows; openEst = $openEst; err = $err; at = $now.ToString('o', $script:Inv) }
            }
            $histErr = [string]$packed.err
            $histOut = @($packed.rows | ForEach-Object { $_.flags = (& $flagsOf $_ $false $null); $_ })
            # نشست‌های تخمینیِ سیستم‌های بدونِ ایجنت را به live اضافه کن (اگر live هم خواسته شده) | add estimated open sessions to live
            if (($part -eq 'all') -and $liveOut -ne $null) {
                $agentNames = @{}; foreach ($lx in $liveOut) { $agentNames[[string]$lx.host] = $true }
                $extra = @($packed.openEst | Where-Object { -not $agentNames[[string]$_.host] -and [string]$_.host -ne $selfName } | ForEach-Object { $_.flags = (& $flagsOf $_ $true $null); $_ })
                if ($extra.Count) {
                    $liveOut = @($liveOut + $extra)
                    # پرچم‌ها و خلاصهٔ live را روی مجموعهٔ کامل (شاملِ تخمینی‌ها) دوباره حساب کن | recompute flags+summary over the merged set
                    $perUser2 = @{}; foreach ($x in $liveOut) { $k = ([string]$x.user -replace '^.*\\', '').ToLowerInvariant(); if (-not $perUser2[$k]) { $perUser2[$k] = @{} }; $perUser2[$k][$x.host] = $true }
                    $liveOut = @($liveOut | ForEach-Object { $_.flags = (& $flagsOf $_ $true $perUser2); $_ })
                    $sumLive = [ordered]@{ live = @($liveOut | Where-Object { $_.state -eq 'Active' }).Count; disconnected = @($liveOut | Where-Object { $_.state -eq 'Disconnected' }).Count
                                           rdp = @($liveOut | Where-Object { $_.type -eq 'rdp' }).Count; users = @($liveOut | ForEach-Object { ([string]$_.user -replace '^.*\\', '').ToLowerInvariant() } | Select-Object -Unique).Count
                                           externalLive = @($liveOut | Where-Object { @($_.flags) -contains 'external' }).Count }
                }
            }
            $sumHist = [ordered]@{ external = @($histOut | Where-Object { $_.how -ne 'open' -and @($_.flags) -contains 'external' }).Count; afterhours = @($histOut | Where-Object { @($_.flags) -contains 'afterhours' }).Count
                                   total = @($histOut).Count; avgMin = $(if (@($histOut).Count) { [int]((@($histOut | Where-Object { $_.end }) | Measure-Object minutes -Average).Average) } else { 0 }) }
        }

        if ($part -eq 'live') { return [ordered]@{ part = 'live'; hours = $hours; summary = $sumLive; live = @($liveOut); server = $selfName } }
        if ($part -eq 'history') { return [ordered]@{ part = 'history'; hours = $hours; summary = $sumHist; history = @($histOut); error = $histErr; server = $selfName } }
        # all (back-compat): both together
        $sum = [ordered]@{ live = $sumLive.live; disconnected = $sumLive.disconnected; rdp = $sumLive.rdp; users = $sumLive.users
                           external = ($sumLive.externalLive + $sumHist.external); afterhours = $sumHist.afterhours; total = $sumHist.total; avgMin = $sumHist.avgMin }
        return [ordered]@{ hours = $hours; summary = $sum; live = @($liveOut); history = @($histOut); error = $histErr; server = $selfName }
    }
    '/api/sessions/action' {
        $hn = ([string]$body.host).Trim().ToUpperInvariant(); $id = [int]$body.id; $act = [string]$body.action
        if ($act -notin 'logoff', 'disconnect', 'message') { throw 'invalid action' }
        if ($id -le 0) { throw 'invalid session' }
        if ($hn -eq ([string]$env:COMPUTERNAME).ToUpperInvariant()) {
            $out = Invoke-LBSessionAction -Id $id -Action $act -Text ([string]$body.text) -Title 'LogBok'
            Write-LBWebAudit -User $User -Message ("session {0} on {1}: {2}" -f $id, $hn, $act)
            return [ordered]@{ ok = $true; message = $out; queued = $false }
        }
        $q = Add-LBAgentAction -StateDir $sd -Hosts @($hn) -Type ("{0}-session" -f $act) -Arguments @{ id = $id; text = [string]$body.text } -By $User
        Write-LBWebAudit -User $User -Message ("session {0} on {1}: {2} (queued for agent)" -f $id, $hn, $act)
        return [ordered]@{ ok = $true; queued = $true }
    }

    # ---------------- اقدام روی رویداد | actions ----------------
    '/api/action' {
        $type = [string]$body.type; $val = ([string]$body.value).Trim(); $hostN = ([string]$body.host).Trim()
        switch ($type) {
            'block-ip' {
                $min = 0; if ($body.minutes) { $min = [int]$body.minutes }
                [void](Add-LBGuardManualBlock -InstallDir $script:Root -Ip $val -Minutes $min)
                Write-LBWebAudit -User $User -Message "blocked IP $val ($min min)"
                return @{ ok = $true; message = (Format-LBTxt -s "IP $val بلاک شد | IP $val blocked" -Lang $lang) }
            }
            'unblock-ip' {
                $n = Remove-LBGuardBlocks -InstallDir $script:Root -Ip @($val)
                Write-LBWebAudit -User $User -Message "unblocked IP $val"
                return @{ ok = $true; message = (Format-LBTxt -s "IP $val آزاد شد | IP $val unblocked" -Lang $lang) }
            }
            'whitelist-ip' {
                [void](Add-LBGuardListEntry -InstallDir $script:Root -List whitelist -Entry $val)
                Write-LBWebAudit -User $User -Message "whitelisted $val"
                return @{ ok = $true; message = (Format-LBTxt -s "$val به لیستِ سفید رفت | $val whitelisted" -Lang $lang) }
            }
            { $_ -in 'disable-user','enable-user','unlock-user' } {
                if ($val -notmatch '^[A-Za-z0-9_.\-\\@ ]{1,104}$') { throw 'نامِ کاربرِ نامعتبر | invalid user name' }
                $short = ($val -split '\\')[-1]
                $fn = switch ($type) { 'disable-user' { 'Disable-LogBokUser' } 'enable-user' { 'Enable-LogBokUser' } default { 'Unlock-LogBokUser' } }
                $done = $false; $how = ''
                # حسابِ دامنه: با ADSI | domain account via ADSI
                $joined = $false; try { $joined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
                if ($joined -and $body.domain -eq $true) {
                    $ds = New-Object DirectoryServices.DirectorySearcher(([adsi]''), "(&(objectCategory=person)(sAMAccountName=$($short -replace '[()*\\]',''))))")
                    $hit = $ds.FindOne()
                    if (-not $hit) { throw "کاربر در دامنه پیدا نشد | user not found in AD: $short" }
                    $de = $hit.GetDirectoryEntry()
                    $uac = [int]$de.Properties['userAccountControl'].Value
                    switch ($type) { 'disable-user' { $de.Properties['userAccountControl'].Value = ($uac -bor 2) } 'enable-user' { $de.Properties['userAccountControl'].Value = ($uac -band (-bnot 2)) } default { $de.Properties['lockoutTime'].Value = 0 } }
                    $de.CommitChanges(); $done = $true; $how = 'AD'
                } elseif (-not $hostN -or (Test-LBIsSelf (($hostN -split '[ (]')[0]))) {
                    Use-LBModule 'LogBok.Identity' 'Get-LogBokLocalUsers'
                    & $fn -User $short; $done = $true; $how = 'local'
                } else {
                    $h = ($hostN -split '[ (]')[0]
                    $p = @{ ComputerName = $h; ScriptBlock = { param($f,$u) $lbd = @((Join-Path $env:ProgramData 'Agent'), 'C:\Scripts\LogBok') | Where-Object { Test-Path (Join-Path $_ 'LogBok.Identity.psm1') } | Select-Object -First 1; if (-not $lbd) { throw 'LogBok agent not found on this computer' }; Import-Module (Join-Path $lbd 'LogBok.Identity.psm1') -Force -DisableNameChecking; & $f -User $u }; ArgumentList = @($fn, $short); ErrorAction = 'Stop' }
                    $cr = Get-LBTargetCredential -Computer $h -StateDir $sd; if ($cr) { $p.Credential = $cr }
                    [void](Invoke-Command @p); $done = $true; $how = "remote $h"
                }
                Write-LBWebAudit -User $User -Message "$type $val ($how)"
                return @{ ok = $done; message = (Format-LBTxt -s "انجام شد ($how) | done ($how)" -Lang $lang) }
            }
            'isolate-host' {
                $h = ($hostN -split '[ (]')[0]
                $keep = @(Get-LBServerIPs | Select-Object -First 1)
                if (-not $h -or (Test-LBIsSelf $h)) { throw 'ایزوله‌کردنِ خودِ سرورِ مدیریت از کنسولِ وب مجاز نیست | isolating the management server itself is not allowed here' }
                $p = @{ ComputerName = $h; ScriptBlock = { param($ip) $lbd = @((Join-Path $env:ProgramData 'Agent'), 'C:\Scripts\LogBok') | Where-Object { Test-Path (Join-Path $_ 'LogBok.Firewall.psm1') } | Select-Object -First 1; if (-not $lbd) { throw 'LogBok agent not found on this computer' }; Import-Module (Join-Path $lbd 'LogBok.Firewall.psm1') -Force -DisableNameChecking; Invoke-LogBokIsolate -AllowIp $ip -InstallDir $lbd }; ArgumentList = @($keep); ErrorAction = 'Stop' }
                $cr = Get-LBTargetCredential -Computer $h -StateDir $sd; if ($cr) { $p.Credential = $cr }
                [void](Invoke-Command @p)
                Write-LBWebAudit -User $User -Message "isolated host $h (management path $keep kept)"
                return @{ ok = $true; message = (Format-LBTxt -s "$h ایزوله شد (مسیرِ مدیریت باز ماند) | $h isolated (management path kept)" -Lang $lang) }
            }
            'restore-host' {
                $h = ($hostN -split '[ (]')[0]
                $p = @{ ComputerName = $h; ScriptBlock = { $lbd = @((Join-Path $env:ProgramData 'Agent'), 'C:\Scripts\LogBok') | Where-Object { Test-Path (Join-Path $_ 'LogBok.Firewall.psm1') } | Select-Object -First 1; if (-not $lbd) { throw 'LogBok agent not found on this computer' }; Import-Module (Join-Path $lbd 'LogBok.Firewall.psm1') -Force -DisableNameChecking; Restore-LogBokIsolate -InstallDir $lbd }; ErrorAction = 'Stop' }
                $cr = Get-LBTargetCredential -Computer $h -StateDir $sd; if ($cr) { $p.Credential = $cr }
                [void](Invoke-Command @p)
                Write-LBWebAudit -User $User -Message "restored host $h"
                return @{ ok = $true; message = (Format-LBTxt -s "ایزوله‌سازیِ $h برداشته شد | $h restored" -Lang $lang) }
            }
            'open-incident' {
                $r = Get-LBFinding -Config $cfg -Id ([string]$body.findingId)
                if (-not $r) { throw 'not found' }
                $f = [pscustomobject]@{ Machine=[string]$r.host; Category=[string]$r.cat; Title=[string]$r.title; Severity=$(if ($r.sev -eq 'Info') { 'Warning' } else { [string]$r.sev }); Key=[string]$r.key }
                [void](Update-LBIncidents -Config $cfg -Findings @($f))
                Write-LBWebAudit -User $User -Message "opened incident for $($r.host) / $($r.cat)"
                return @{ ok = $true; message = (Format-LBTxt -s 'رخداد ثبت شد | incident opened' -Lang $lang) }
            }
            default { throw "unknown action: $type" }
        }
    }

    # ---------------- رخدادها | incidents ----------------
    '/api/incidents' {
        $all = @(Get-LBIncidents -Config $cfg)
        $show = Get-LBQ $Ctx 'status' 'open'
        if ($show -eq 'open') { $all = @($all | Where-Object { $_.Status -ne 'Closed' }) }
        $mu = @(Get-LBAlertMutes -Config $cfg)
        return @{ items = @($all | Sort-Object LastSeen -Descending | Select-Object -First 300 | ForEach-Object {
            $pbI = Get-LBPlaybook -Category ([string]$_.Category) -Title ([string]$_.Title) -Lang $lang
            [ordered]@{ id=$_.Id; host=$_.Machine; cat=$_.Category; catTitle=(Get-LBCatTitle -Key ([string]$_.Category) -Lang $lang); title=(Format-LBTxt -s ([string]$_.Title) -Lang $lang); rawTitle=[string]$_.Title; sev=$_.Severity
                        urgency=[string]$pbI.Urgency; muted=($mu.Count -and (Test-LBAlertMuted -Mutes $mu -Finding ([pscustomobject]@{ Machine=$_.Machine; Category=$_.Category; Title=$_.Title })))
                        mitre=$_.Mitre; status=$_.Status; owner=$_.Owner; count=$_.Count; first=([string]$_.FirstSeen -replace 'T',' ' -replace '\.\d+.*$',''); last=([string]$_.LastSeen -replace 'T',' ' -replace '\.\d+.*$',''); note=[string]$_.Note } }) }
    }
    '/api/playbook' {
        $pb = Get-LBPlaybook -Category ([string]$body.cat) -Title ([string]$body.title) -Lang $lang
        return [ordered]@{ what=[string]$pb.What; why=[string]$pb.Why; do=@($pb.Do); normal=[string]$pb.Normal; urgency=[string]$pb.Urgency }
    }
    '/api/incident/mute' {
        # بی‌صداکردنِ ایمیل برای همین سیستم+عنوان (و بستنِ رخداد) | mute mail for this host+title for N days and close the incident
        $id = [string]$body.id; $inc = @(Get-LBIncidents -Config $cfg) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if (-not $inc) { throw 'incident not found' }
        $days = [math]::Max(0, [math]::Min(365, [int]$(if ($null -ne $body.days) { $body.days } else { 7 })))
        $scopeHost = $(if ($body.allHosts -eq $true) { '*' } else { [string]$inc.Machine })
        if ($body.unmute -eq $true) { [void](Remove-LBAlertMute -Config $cfg -HostName $scopeHost -Category ([string]$inc.Category) -Title ([string]$inc.Title)); Write-LBWebAudit -User $User -Message "alert unmuted: $($inc.Machine) / $($inc.Title)"; return @{ ok = $true } }
        [void](Add-LBAlertMute -Config $cfg -HostName $scopeHost -Category ([string]$inc.Category) -Title ([string]$inc.Title) -Days $days -By $User)
        [void](Set-LBIncident -Config $cfg -Id $id -Status 'Closed')
        Write-LBWebAudit -User $User -Message ("alert muted {0} days: {1} / {2}" -f $days, $scopeHost, $inc.Title)
        return @{ ok = $true }
    }
    '/api/alerts/mutes' {
        if ($Method -eq 'POST' -and $body.remove) { [void](Remove-LBAlertMute -Config $cfg -HostName ([string]$body.host) -Category ([string]$body.cat) -Title ([string]$body.title)) }
        return @{ items = @(Get-LBAlertMutes -Config $cfg | ForEach-Object { [ordered]@{ host=[string]$_.host; cat=[string]$_.cat; title=(Format-LBTxt -s ([string]$_.title) -Lang $lang); rawTitle=[string]$_.title; until=[string]$_.until; by=[string]$_.by } }) }
    }
    '/api/incident' {
        $id = [string]$body.id
        $p = @{ Config = $cfg; Id = $id }
        if ($body.status) { $p.Status = [string]$body.status }
        if ($null -ne $body.owner) { $p.Owner = [string]$body.owner }
        [void](Set-LBIncident @p)
        if ($null -ne $body.note) {
            $inc = @(Get-LBIncidents -Config $cfg); foreach ($i in $inc) { if ($i.Id -eq $id) { $i | Add-Member -NotePropertyName Note -NotePropertyValue ([string]$body.note) -Force } }; Save-LBIncidents -Config $cfg -Incidents $inc
        }
        Write-LBWebAudit -User $User -Message "incident $id updated (status=$($body.status) owner=$($body.owner))"
        return @{ ok = $true }
    }

    # ---------------- هشدار و ایمیل | alerts & mail ----------------
    '/api/alerts' {
        $S = Get-LBAlertSettings -Config $cfg
        return [ordered]@{
            profiles = @($S.Profiles | ForEach-Object { [ordered]@{ id=[string]$_.Id; name=[string]$_.Name; enabled=($_.Enabled -ne $false); categories=@(Get-LBArr $_.Categories); minSeverity=$(if ($_.MinSeverity) { [string]$_.MinSeverity } else { 'Critical' }); hosts=@(Get-LBArr $_.Hosts); keywords=@(Get-LBArr $_.Keywords); recipients=@(Get-LBArr $_.Recipients); throttleMinutes=$(if ($_.ThrottleMinutes) { [int]$_.ThrottleMinutes } else { 15 }); businessHours=$(if ($_.BusinessHours) { [string]$_.BusinessHours } else { 'any' }); builtin=($_.Builtin -eq $true); delivery=$(if ([string]$_.Delivery -eq 'digest') { 'digest' } else { 'instant' }); digestMinutes=$(if ($_.DigestMinutes) { [int]$_.DigestMinutes } else { 60 }) } })
            defaultToMailTo = $S.DefaultToMailTo
            mailConfigured = (Test-LBMailConfigured -Config $cfg)
            defaultsAvailable = @(Get-LBDefaultAlertProfiles).Count
            businessHours = [ordered]@{ days=@($S.BhDays); start=$S.BhStart; end=$S.BhEnd }
            history = @(Get-LBAlertHistory -Config $cfg -Max 2000)
        }
    }
    '/api/alerts/profile' {
        $S = Get-LBAlertSettings -Config $cfg
        $rcpt = @(Get-LBArr ($body.recipients))
        foreach ($e in $rcpt) { if ($e -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "ایمیلِ نامعتبر | invalid email: $e" } }
        if (-not ([string]$body.name).Trim()) { throw 'نامِ پروفایل لازم است | profile name required' }
        $id = [string]$body.id; if (-not $id) { $id = 'p' + [guid]::NewGuid().ToString('N').Substring(0, 8) }
        $p = @{ Id=$id; Name=([string]$body.name).Trim(); Enabled=($body.enabled -ne $false); Categories=@(Get-LBArr $body.categories)
                MinSeverity=$(if ([string]$body.minSeverity -in 'Critical','Warning','Info') { [string]$body.minSeverity } else { 'Critical' })
                Hosts=@(Get-LBArr $body.hosts); Keywords=@(Get-LBArr $body.keywords); Recipients=$rcpt
                ThrottleMinutes=[math]::Max(1, [int]$(if ($body.throttleMinutes) { $body.throttleMinutes } else { 15 }))
                BusinessHours=$(if ([string]$body.businessHours -in 'any','inside','outside') { [string]$body.businessHours } else { 'any' })
                Delivery=$(if ([string]$body.delivery -eq 'digest') { 'digest' } else { 'instant' }); DigestMinutes=[math]::Max(5, [int]$(if ($body.digestMinutes) { $body.digestMinutes } else { 60 })) }
        $prev = $S.Profiles | Where-Object { [string]$_.Id -eq $id } | Select-Object -First 1
        if ($prev -and $prev.Builtin -eq $true) { $p.Builtin = $true; $p.Edited = $true; $p.Rev = $prev.Rev }
        $list = @(@($S.Profiles | Where-Object { [string]$_.Id -ne $id }) + $p)
        [void](Set-LBSetting -Path 'Alerts.Profiles' -Value $list -StateDir $sd)
        Write-LBWebAudit -User $User -Message "alert profile saved: $($p.Name) → $($rcpt -join ', ')"
        return @{ ok = $true; id = $id }
    }
    '/api/alerts/defaults' {
        $n = Initialize-LBDefaultAlerts -StateDir $sd -Restore
        Write-LBWebAudit -User $User -Message "default alert profiles restored: $n added"
        return @{ ok = $true; added = $n }
    }
    '/api/alerts/profile/delete' {
        $S = Get-LBAlertSettings -Config $cfg
        $id = [string]$body.id
        [void](Set-LBSetting -Path 'Alerts.Profiles' -Value @($S.Profiles | Where-Object { [string]$_.Id -ne $id }) -StateDir $sd)
        Write-LBWebAudit -User $User -Message "alert profile deleted: $id"
        return @{ ok = $true }
    }
    '/api/alerts/options' {
        if ($null -ne $body.defaultToMailTo) { [void](Set-LBSetting -Path 'Alerts.DefaultToMailTo' -Value ([bool]$body.defaultToMailTo) -StateDir $sd) }
        if ($body.businessHours) {
            $bh = $body.businessHours
            if ([string]$bh.start -notmatch '^\d{2}:\d{2}$' -or [string]$bh.end -notmatch '^\d{2}:\d{2}$') { throw 'ساعت باید HH:mm باشد | time must be HH:mm' }
            [void](Set-LBSetting -Path 'Alerts.BusinessHours' -Value @{ Days=@(Get-LBArr $bh.days); Start=[string]$bh.start; End=[string]$bh.end } -StateDir $sd)
        }
        Write-LBWebAudit -User $User -Message 'alert options updated'
        return @{ ok = $true }
    }
    '/api/mail' {
        if ($Method -eq 'GET') {
            $m = $cfg.Mail
            return [ordered]@{ smtpServer=[string]$m.SmtpServer; port=[int]$m.Port; useSsl=[bool]$m.UseSsl; from=[string]$m.From; to=@(Get-LBArr $m.To); user=[string]$m.User; subjectTag=[string]$m.SubjectTag; hasPassword=(Test-Path (Join-Path $script:Root 'smtp.sec')) }
        }
        $to = @(Get-LBArr $body.to)
        foreach ($e in @($to + $body.from)) { if ($e -and $e -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "ایمیلِ نامعتبر | invalid email: $e" } }
        $sd2 = $sd
        foreach ($pair in @(@('SmtpServer',[string]$body.smtpServer),@('Port',[int]$body.port),@('UseSsl',[bool]$body.useSsl),@('From',[string]$body.from),@('To',$to),@('User',[string]$body.user),@('SubjectTag',[string]$body.subjectTag))) {
            [void](Set-LBSetting -Path ("Mail." + $pair[0]) -Value $pair[1] -StateDir $sd2)
        }
        if ($body.password) {
            $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
            [void](Set-LogBokMailSecret -Password $sec -Root $script:Root)
        }
        Write-LBWebAudit -User $User -Message "mail settings updated (server=$($body.smtpServer), to=$($to -join ', '))"
        return @{ ok = $true }
    }
    '/api/mail/test' {
        $to = @(Get-LBArr $body.to); if (-not $to.Count) { $to = @(Get-LBArr $cfg.Mail.To) }
        $okm = $false; $err = ''
        try { $okm = [bool](Send-LogBokMail -Subject 'Test / آزمایش' -Body ("<p>LogBok test email from {0} — ایمیلِ آزمایشیِ لاگ‌بوک</p>" -f $env:COMPUTERNAME) -Html -To $to -Config $cfg) } catch { $err = $_.Exception.Message }
        if (-not $okm -and -not $err) { $err = [string](Get-LBLastMailError) }
        if (-not $okm -and $err) { $err = $err + ' — ' + (Get-LBMailHint -Err $err -Port ([int]$cfg.Mail.Port) -Lang $lang) }
        if (-not $okm -and -not $err) { $err = (Format-LBTxt -s 'ارسال نشد؛ لاگِ موتور را ببینید | not sent; see the engine log' -Lang $lang) }
        return @{ ok = $okm; error = $err; to = $to }
    }

    # ---------------- منابعِ لاگ | log sources ----------------
    '/api/sources' {
        $conn = Get-LBConnectStatus -InstallDir $script:Root
        $byT = @{}; if ($conn) { foreach ($t in @($conn.Targets)) { $byT[[string]$t.Target] = $t } }
        $list = @(Get-LBTargetList -StateDir $sd | ForEach-Object {
            $addr = if ($_.Address) { [string]$_.Address } else { [string]$_.Name }
            $cs = $byT[$addr]
            [ordered]@{ name=[string]$_.Name; address=[string]$_.Address; kind=[string]$_.Kind; roles=@(Get-LBArr $_.Roles); ports=@($_.Ports | Where-Object { $_ }); monitor=[string]$_.Monitor
                        deviceType=[string]$_.DeviceType; source=[string]$_.Source; os=[string]$_.Os; notes=[string]$_.Notes; enabled=($_.Enabled -ne $false); added=[string]$_.Added
                        hasCred=(Test-LBTargetCredential -Name ([string]$_.Name) -StateDir $sd)
                        custom=@($_.Custom | Where-Object { $_ } | ForEach-Object { [ordered]@{ id=[string]$_.Id; type=[string]$_.Type; name=[string]$_.Name; log=[string]$_.Log; ids=@($_.Ids | Where-Object { $_ }); path=[string]$_.Path; keywords=@(Get-LBArr $_.Keywords); severity=[string]$_.Severity; alert=($_.Alert -ne $false) } })
                        status=$(if ($cs) { [string]$cs.Status } else { '' })
                        channels=@($(if ($cs) { @($cs.Channels | ForEach-Object { [ordered]@{ channel=[string]$_.Channel; ok=[bool]$_.Ok; state=[string]$_.State; ms=[int]$_.Ms; detail=(Format-LBTxt -s ([string]$_.Detail) -Lang $lang); reason=(Format-LBTxt -s ([string]$_.Reason) -Lang $lang); remedy=(Format-LBTxt -s ([string]$_.Remedy) -Lang $lang) } }) } else { @() })) } })
        $self = $null; if ($conn) { $self = @($conn.Targets) | Where-Object { $_.Self } | Select-Object -First 1 }
        return [ordered]@{ items=$list; serverIps=@(Get-LBServerIPs); hasDefaultCred=(Test-LBTargetCredential -Name '_default' -StateDir $sd); generated=$(if ($conn) { [string]$conn.Generated } else { '' })
                           self=$(if ($self) { [ordered]@{ name=[string]$self.Target; status=[string]$self.Status; channels=@($self.Channels | ForEach-Object { [ordered]@{ channel=[string]$_.Channel; ok=[bool]$_.Ok; state=[string]$_.State; detail=(Format-LBTxt -s ([string]$_.Detail) -Lang $lang); reason=(Format-LBTxt -s ([string]$_.Reason) -Lang $lang); remedy=(Format-LBTxt -s ([string]$_.Remedy) -Lang $lang) } }) } } else { $null })
                           mode=[string]$cfg.CollectionMode }
    }
    '/api/sources/add' {
        $kind = [string]$body.kind; if ($kind -notin 'Windows','NetworkDevice','Linux','Service') { $kind = 'Windows' }
        $name = ([string]$body.name).Trim(); $addr = ([string]$body.address).Trim()
        if (-not $name -and $addr) { $name = ($addr -split '\.')[0]; if ($addr -match '^\d+\.\d+\.\d+\.\d+$') { $name = $addr -replace '\.', '-' } }
        $roles = @(Get-LBArr $body.roles)
        if ($body.detectRoles -eq $true -and $kind -eq 'Windows') { try { $roles += @(Find-LBTargetRoles -Address $(if ($addr) { $addr } else { $name })) } catch { } }
        $ports = @(@($body.ports) | Where-Object { "$_" -match '^\d+$' } | ForEach-Object { [int]$_ })
        $p = @{ Name=$name; Address=$addr; Kind=$kind; Roles=@($roles | Select-Object -Unique); Ports=$ports; By=$User; Source='manual' }
        if ($body.monitor) { $p.Monitor = [string]$body.monitor }
        if ($body.deviceType) { $p.DeviceType = [string]$body.deviceType }
        if ($body.notes) { $p.Notes = [string]$body.notes }
        $t = Add-LBTarget @p
        if ($body.user -and $body.password) {
            $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
            [void](Set-LBTargetCredential -Name $name -Credential (New-Object Management.Automation.PSCredential([string]$body.user, $sec)) -StateDir $sd)
        }
        # آزمونِ فوری | immediate connectivity test of the new source
        $res = @()
        try { $cfg2 = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1'); $res = @(Test-LBConnectivity -Config $cfg2 -InstallDir $script:Root -Save -Only @($(if ($addr) { $addr } else { $name }))) } catch { }
        $hint = @(); if ($kind -eq 'NetworkDevice') { $hint = @(Get-LBSyslogHint -DeviceType ([string]$body.deviceType)) }
        return [ordered]@{ ok=$true; name=$name; roles=@($t.Roles); syslogHint=$hint
                           test=@($res | ForEach-Object { [ordered]@{ channel=[string]$_.Channel; ok=[bool]$_.Ok; state=[string]$_.State; ms=[int]$_.Ms; detail=(Format-LBTxt -s ([string]$_.Detail) -Lang $lang); reason=(Format-LBTxt -s ([string]$_.Reason) -Lang $lang); remedy=(Format-LBTxt -s ([string]$_.Remedy) -Lang $lang) } }) }
    }
    '/api/sources/remove' { $ok = Remove-LBTarget -Name ([string]$body.name) -By $User; return @{ ok = $ok } }
    '/api/sources/enable' { Set-LBTargetEnabled -Name ([string]$body.name) -Enabled ([bool]$body.enabled); Write-LBWebAudit -User $User -Message "source $($body.name) enabled=$($body.enabled)"; return @{ ok = $true } }
    '/api/sources/cred' {
        $n = ([string]$body.name).Trim(); if (-not $n) { throw 'name required' }
        if ($body.clear -eq $true) { Remove-LBTargetCredential -Name $n -StateDir $sd; Write-LBWebAudit -User $User -Message "credential cleared for $n"; return @{ ok = $true } }
        if (-not $body.user -or -not $body.password) { throw 'نام‌کاربری و گذرواژه لازم است | user and password required' }
        $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
        [void](Set-LBTargetCredential -Name $n -Credential (New-Object Management.Automation.PSCredential([string]$body.user, $sec)) -StateDir $sd)
        Write-LBWebAudit -User $User -Message "credential set for $n (user $($body.user))"
        return @{ ok = $true }
    }
    '/api/sources/custom' {
        if ([string]$body.target -eq '__self__') {
            # لاگِ سفارشی روی خودِ این سرور: سرور به‌عنوانِ منبعِ محلی ثبت می‌شود (بدونِ خواندنِ راه‌دور)
            $selfName = $env:COMPUTERNAME; if (-not $selfName) { $selfName = ([Net.Dns]::GetHostName() -split '\.')[0] }
            if (-not (Get-LBTargetList -StateDir $sd | Where-Object { $_.Name -eq $selfName })) { [void](Add-LBTarget -Name $selfName -Address 'localhost' -Kind 'Windows' -Monitor 'none' -Source 'self' -By $User) }
            $body.target = $selfName
        }
        $p = @{ Target=[string]$body.target; Type=$(if ([string]$body.type -eq 'File') { 'File' } else { 'EventLog' }); Name=([string]$body.name).Trim()
                Ids=@(@($body.ids) | Where-Object { "$_" -match '^\d+$' } | ForEach-Object { [int]$_ }); Keywords=@(Get-LBArr $body.keywords)
                Severity=$(if ([string]$body.severity -in 'Critical','Warning','Info') { [string]$body.severity } else { 'Warning' }); Alert=($body.alert -ne $false) }
        if ($body.log) { $p.Log = ([string]$body.log).Trim() }
        if ($body.path) { $p.Path = ([string]$body.path).Trim() }
        if (-not $p.Name) { $p.Name = $(if ($p.Log) { $p.Log } else { Split-Path $p.Path -Leaf }) }
        $c = Add-LBCustomSource @p
        Write-LBWebAudit -User $User -Message "custom log added on $($p.Target): $($p.Type) $($p.Log)$($p.Path)"
        return @{ ok = $true; id = $c.Id }
    }
    '/api/sources/custom/remove' { Remove-LBCustomSource -Target ([string]$body.target) -Id ([string]$body.id); Write-LBWebAudit -User $User -Message "custom log removed on $($body.target): $($body.id)"; return @{ ok = $true } }
    '/api/sources/test' {
        $only = @(Get-LBArr $body.names)
        $res = if ($only.Count) { @(Test-LBConnectivity -Config $cfg -InstallDir $script:Root -Save -Only $only) } else { @(Test-LBConnectivity -Config $cfg -InstallDir $script:Root -Save) }
        return @{ ok = $true; count = $res.Count; failed = @($res | Where-Object { -not $_.Ok }).Count }
    }
    '/api/sources/channels' {
        # فهرستِ کانال‌های رویدادِ یک سیستم (برای انتخابِ «لاگِ سفارشی») | event channels on a host
        $h = Get-LBQ $Ctx 'host' 'localhost'
        $p = @{ ListLog = '*'; ErrorAction = 'Stop' }
        if (-not (Test-LBIsSelf $h)) { $p.ComputerName = $h; $cr = Get-LBTargetCredential -Computer $h -StateDir $sd; if ($cr) { $p.Credential = $cr } }
        $logs = @(Get-WinEvent @p | Where-Object { $_.RecordCount -gt 0 -or $_.IsEnabled } | Sort-Object LogName | Select-Object -First 1500 | ForEach-Object { [ordered]@{ name=$_.LogName; count=[long]$_.RecordCount; enabled=[bool]$_.IsEnabled } })
        return @{ items = $logs }
    }

    # ---------------- اکتیودایرکتوری | Active Directory ----------------
    '/api/ad/status' {
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        $res = @(Test-LBADConnection -Server $ad.Server -Credential $ad.Credential)
        return @{ items = @($res | ForEach-Object { [ordered]@{ target=[string]$_.Target; channel=[string]$_.Channel; ok=[bool]$_.Ok; state=[string]$_.State; ms=[int]$_.Ms; detail=(Format-LBTxt -s ([string]$_.Detail) -Lang $lang); reason=(Format-LBTxt -s ([string]$_.Reason) -Lang $lang); remedy=(Format-LBTxt -s ([string]$_.Remedy) -Lang $lang) } }) }
    }
    '/api/ad/discover' {
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        $type = if ([string]$body.type -in 'All','Servers','Workstations','DCs') { [string]$body.type } else { 'All' }
        $p = @{ Type=$type; Server=$ad.Server; SearchBase=([string]$body.searchBase).Trim(); NameLike=([string]$body.nameLike).Trim(); Max=5000 }
        if ($ad.Credential) { $p.Credential = $ad.Credential }
        if ($body.includeDisabled -eq $true) { $p.IncludeDisabled = $true }
        $items = @(Find-LBADComputers @p)
        $st = @{}; foreach ($x in @(Get-LBAgentStatus -StateDir $sd)) { $st[([string]$x.Name).ToUpperInvariant()] = $x }
        $seen = @{}; try { $ak = Get-LBAgentKeys -StateDir $sd; foreach ($k in @($ak.Keys)) { if ([string]$ak[$k].Status -ne 'pending') { $seen[([string]$k).ToUpperInvariant()] = $true } } } catch { }
        return @{ count = $items.Count; items = @($items | ForEach-Object { $s2 = $st[([string]$_.Name).ToUpperInvariant()]
            [ordered]@{ name=$_.Name; address=$_.Address; os=$_.Os; isDC=[bool]$_.IsDC; enabled=[bool]$_.Enabled; lastLogon=[string]$_.LastLogon; ou=[string]$_.OU; added=[bool]$_.Added
                        agent=$(if ($seen[([string]$_.Name).ToUpperInvariant()]) { 'ok' } elseif ($s2) { $(if ($s2.Ok -eq $true) { 'ok' } elseif ($s2.Ok -eq $false) { 'failed' } else { [string]$s2.Step }) } else { '' }) } }) }
    }
    '/api/ad/ous' {
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        return @{ items = @(Get-LBADOUs -Server $ad.Server -Credential $ad.Credential) }
    }
    '/api/ad/domains' { return @{ items = @(Get-LBADDomains -StateDir $sd | Sort-Object { [string]$_.Fqdn } | ForEach-Object { ConvertTo-LBWebDomain $_ $sd $lang }) } }
    '/api/ad/domain/connect' {
        # اتصال + بررسی + خواندنِ آمار + ذخیرهٔ دائمی | connect, check, read inventory, persist
        $cr = $null; if ($body.user -and $body.password) { $cr = Get-LBBodyCred -Body $body -StateDir $sd -Saved '' }
        $id = ([string]$body.id).Trim(); if ($id -and $id -notmatch '^[A-Za-z0-9]{1,20}$') { throw 'invalid id' }
        if (-not $id -and -not $cr -and -not ([string]$body.server).Trim()) { throw 'آدرسِ DC و حسابِ دامنه را وارد کنید | enter the DC address and a domain account' }
        $r = Connect-LBADDomain -StateDir $sd -Id $id -Server ([string]$body.server).Trim() -Credential $cr
        if ($r.Ok) { Write-LBWebAudit -User $User -Message "AD domain connected/saved: $($r.Domain.Fqdn) via $($r.Domain.Server)" }
        return [ordered]@{ ok=[bool]$r.Ok; error=(Format-LBTxt -s ([string]$r.Error) -Lang $lang); domain=$(if ($r.Domain) { ConvertTo-LBWebDomain $r.Domain $sd $lang } else { $null })
                           checks=@($r.Checks | ForEach-Object { [ordered]@{ check=$_.check; ok=$_.ok; detail=(Format-LBTxt -s ([string]$_.detail) -Lang $lang); fix=(Format-LBTxt -s ([string]$_.fix) -Lang $lang) } }) }
    }
    '/api/ad/domain/delete' {
        $d = Get-LBADDomain -StateDir $sd -Id ([string]$body.id)
        if (-not $d) { return @{ ok = $true } }
        Remove-LBADDomain -StateDir $sd -Id ([string]$d.Id)
        Write-LBWebAudit -User $User -Message "AD domain removed: $($d.Fqdn)"
        return @{ ok = $true }
    }
    '/api/ad/import' {
        $comps = @($body.computers | Where-Object { $_ -and $_.name } | ForEach-Object { [pscustomobject]@{ Name=[string]$_.name; Address=[string]$_.address; IsDC=[bool]$_.isDC; Os=[string]$_.os } })
        if ($body.user -and $body.password) {
            $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
            if ($body.saveAsDefault -eq $true) { [void](Set-LBTargetCredential -Name '_default' -Credential (New-Object Management.Automation.PSCredential([string]$body.user, $sec)) -StateDir $sd) }
        }
        # از فهرستِ دامنه: اگر حسابِ پیش‌فرض نیست، حسابِ همان دامنه برای خواندنِ لاگ استفاده شود | from a saved domain: use its account for remote log reading when no default exists
        if ($body.domainId -and -not (Test-LBTargetCredential -Name '_default' -StateDir $sd)) { try { $dcn = Get-LBADDomainConn -StateDir $sd -Id ([string]$body.domainId); if ($dcn.Credential) { [void](Set-LBTargetCredential -Name '_default' -Credential $dcn.Credential -StateDir $sd) } } catch { } }
        $n = Import-LBADComputers -Computers $comps -DetectRoles:($body.detectRoles -eq $true) -InstallDir $script:Root -By $User
        Write-LBWebAudit -User $User -Message "imported $n computers from Active Directory"
        return @{ ok = $true; imported = $n }
    }

    '/api/wg/groups' { return @{ items = @(Get-LBWorkgroups -StateDir $sd | Sort-Object { [string]$_.Name } | ForEach-Object { ConvertTo-LBWebWorkgroup $_ $sd }) } }
    '/api/wg/connect' {
        # اسکن + ذخیرهٔ دائمیِ گروه و حسابِ مشترک | scan + persist group and shared credential
        $cr = $null; if ($body.user -and $body.password) { $cr = Get-LBBodyCred -Body $body -StateDir $sd -Saved '' }
        $id = ([string]$body.id).Trim(); if ($id -and $id -notmatch '^[A-Za-z0-9]{1,20}$') { throw 'invalid id' }
        $hosts = @(Get-LBArr $body.hosts | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        if (-not $id -and -not ([string]$body.range).Trim() -and -not $hosts.Count) { throw 'محدودهٔ IP یا فهرستِ سیستم‌ها را وارد کنید | enter an IP range or a list of computers' }
        $r = Connect-LBWorkgroup -StateDir $sd -Id $id -Name ([string]$body.name).Trim() -Range ([string]$body.range).Trim() -Hosts $hosts -Credential $cr -NoScan:($body.noScan -eq $true)
        if ($r.Ok) { Write-LBWebAudit -User $User -Message "workgroup scanned/saved: $($r.Group.Name) ($($r.Group.Stats.Total) alive)" }
        return [ordered]@{ ok=[bool]$r.Ok; group=$(if ($r.Group) { ConvertTo-LBWebWorkgroup $r.Group $sd } else { $null }) }
    }
    '/api/wg/delete' {
        $g = Get-LBWorkgroup -StateDir $sd -Id ([string]$body.id)
        if (-not $g) { return @{ ok = $true } }
        Remove-LBWorkgroup -StateDir $sd -Id ([string]$g.Id)
        Write-LBWebAudit -User $User -Message "workgroup removed: $($g.Name)"
        return @{ ok = $true }
    }
    '/api/wg/install' {
        Assert-LBRemotePush -StateDir $sd
        $g = Get-LBWorkgroup -StateDir $sd -Id ([string]$body.id)
        if (-not $g) { throw 'workgroup not found' }
        $comps = @($body.computers | Where-Object { $_ -and ($_.name -or $_.address) } | ForEach-Object { [pscustomobject]@{ Name=$(if ($_.name) { [string]$_.name } else { ([string]$_.address) -replace '\.', '-' }); Address=[string]$_.address } })
        if (-not $comps.Count) { throw 'هیچ سیستمی انتخاب نشده | no computers selected' }
        # هر سیستمِ workgroup به‌عنوانِ منبع ثبت می‌شود و حسابِ مشترکِ گروه را به ارث می‌برد | register + share group credential
        foreach ($c in $comps) { if (-not (Get-LBTargetList -StateDir $sd | Where-Object { $_.Name -eq $c.Name })) { $pp = @{ Name=$c.Name; Kind='Windows'; Monitor='remote'; Source='workgroup'; By=$User }; if ($c.Address) { $pp.Address = $c.Address }; [void](Add-LBTarget @pp) } }
        $b = Start-LBAgentBatch -InstallDir $script:Root -StateDir $sd -Computers $comps -Collector ([string]$body.collector) -CredName (Get-LBWorkgroupCredName $g.Id) -Parallel 6
        Write-LBWebAudit -User $User -Message "workgroup agent install started: $($g.Name) ($($comps.Count) computers)"
        return [ordered]@{ ok=$true; queued=$(if ($b) { $b.Count } else { 0 }) }
    }

    # ---------------- مهاجرتِ سرور و پشتیبانِ هویتِ ایجنت‌ها | server migration + agent identity backup ----------------
    '/api/agent/move-server' {
        # به همهٔ ایجنت‌های فعال (یا انتخاب‌شده) فرمانِ set-server می‌رود؛ ایجنت اول نشانیِ تازه را می‌آزماید
        $names = @(Get-LBArr $body.names | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        $ips = @(Get-LBArr $body.ips | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        if (-not $names.Count -and -not $ips.Count) { throw 'نام یا IPِ سرورِ جدید لازم است | new server name or IP required' }
        $hosts = @(Get-LBArr $body.hosts | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ })
        if (-not $hosts.Count) { $ak = Get-LBAgentKeys -StateDir $sd; $hosts = @($ak.Keys | Where-Object { [string]$ak[$_].Status -eq 'active' }) }
        if (-not $hosts.Count) { throw 'هیچ ایجنتِ فعالی نیست | no active agents' }
        $n = Add-LBAgentAction -StateDir $sd -Hosts $hosts -Type 'set-server' -Arguments @{ names = $names; ips = $ips; port = [int]$body.port } -By $User
        Write-LBWebAudit -User $User -Message ("agents told to move to server {0} ({1} hosts)" -f (($names + $ips) -join ','), $hosts.Count)
        return [ordered]@{ ok=$true; queued=$hosts.Count }
    }
    '/api/agent/backup/settings' {
        if ($Method -eq 'POST') {
            $path = ([string]$body.path).Trim()
            if ($path -and $path -notmatch '^([A-Za-z]:\\|\\\\)[^<>"|?*]{1,240}$') { throw 'مسیرِ پوشه نامعتبر است | invalid folder path' }
            if ($path) { [void](Set-LBSetting -Path 'Backup.Path' -Value $path -StateDir $sd) } else { [void](Set-LBSetting -Path 'Backup.Path' -Remove -StateDir $sd) }
            if ($body.passphrase) { if (([string]$body.passphrase).Length -lt 8) { throw 'عبارتِ عبور دست‌کم ۸ نویسه | passphrase must be at least 8 characters' }; [void](Set-LBSetting -Path 'Backup.PassEnc' -Value (Protect-LBMachine ([string]$body.passphrase)) -StateDir $sd) }
            [void](Set-LBSetting -Path 'Backup.Email' -Value ($body.email -eq $true) -StateDir $sd)
            $eto = @(Get-LBArr $body.emailTo | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' })
            if ($eto.Count) { [void](Set-LBSetting -Path 'Backup.EmailTo' -Value $eto -StateDir $sd) } else { [void](Set-LBSetting -Path 'Backup.EmailTo' -Remove -StateDir $sd) }
            [void](Set-LBSetting -Path 'Backup.LastRun' -Remove -StateDir $sd)
            Write-LBWebAudit -User $User -Message "agent backup settings saved (path=$path, email=$($body.email -eq $true))"
        }
        $o = Get-LBSettingsOverlay -StateDir $sd; $bk = $o['Backup']; if (-not ($bk -is [hashtable])) { $bk = @{} }
        return [ordered]@{ path=[string]$bk['Path']; hasPass=[bool]$bk['PassEnc']; email=($bk['Email'] -eq $true); emailTo=@(Get-LBArr $bk['EmailTo']); defaultTo=@(Get-LBArr $cfg.Mail.To); lastRun=[string]$bk['LastRun']; lastFile=[string]$bk['LastFile']; lastError=[string]$bk['LastError']; lastMail=[string]$bk['LastMail']; lastMailError=[string]$bk['LastMailError'] }
    }
    '/api/agent/backup/export' {
        if (-not $body.passphrase) { throw 'عبارتِ عبور لازم است | passphrase required' }
        $r = New-LBAgentBackup -StateDir $sd -Passphrase ([string]$body.passphrase)
        Write-LBWebAudit -User $User -Message ("agent backup exported ({0} agents, {1} credentials)" -f $r.Agents, $r.Creds)
        return [ordered]@{ ok=$true; name=('LogBok-Agents-{0}.lbk' -f (Get-Date).ToString('yyyyMMdd-HHmm', $script:Inv)); data=[Convert]::ToBase64String($r.Bytes); agents=[int]$r.Agents; creds=[int]$r.Creds }
    }
    '/api/agent/backup/now' {
        $o = Get-LBSettingsOverlay -StateDir $sd; $bk = $o['Backup']
        if (-not ($bk -is [hashtable]) -or -not $bk['PassEnc'] -or (-not $bk['Path'] -and $bk['Email'] -ne $true)) { throw 'اول عبارتِ عبور و پوشه یا ایمیل را ذخیره کنید | save the passphrase and a folder or e-mail first' }
        [void](Set-LBSetting -Path 'Backup.LastRun' -Remove -StateDir $sd)
        $m = Invoke-LBAutoBackup -StateDir $sd -InstallDir $script:Root
        if ($m -match '^backup failed') { throw $m }
        return [ordered]@{ ok=$true; message=[string]$m }
    }
    '/api/agent/restore' {
        # فایلِ .lbk به‌صورتِ base64 در بدنه | the .lbk file as base64
        if (-not $body.data -or -not $body.passphrase) { throw 'فایل و عبارتِ عبور لازم است | file and passphrase required' }
        $bytes = [Convert]::FromBase64String([string]$body.data)
        if ($bytes.Length -gt 64MB) { throw 'file too large' }
        $n = Restore-LBAgentBackup -StateDir $sd -Bytes $bytes -Passphrase ([string]$body.passphrase) -Replace:($body.replace -eq $true)
        try { [void](Update-LBAgentPackages -InstallDir $script:Root -Config $cfg -Force) } catch { }
        Write-LBWebAudit -User $User -Message ("agent backup restored from {0}: {1} agents, {2} credentials, {3} files" -f $n.from, $n.agents, $n.creds, $n.files)
        return [ordered]@{ ok=$true; agents=[int]$n.agents; creds=[int]$n.creds; files=[int]$n.files; from=[string]$n.from; created=[string]$n.created }
    }

    # ---------------- سپرِ ورود | login guard ----------------
    '/api/guard' {
        if ($Method -eq 'POST') {
            $op = [string]$body.op; $v = ([string]$body.value).Trim()
            switch ($op) {
                'block'        { $m = 0; if ($body.minutes) { $m = [int]$body.minutes }; [void](Add-LBGuardManualBlock -InstallDir $script:Root -Ip $v -Minutes $m) }
                'unblock'      { [void](Remove-LBGuardBlocks -InstallDir $script:Root -Ip @($v) -ResetHistory) }
                'white-add'    { [void](Add-LBGuardListEntry -InstallDir $script:Root -List whitelist -Entry $v) }
                'white-remove' { Remove-LBGuardListEntry -InstallDir $script:Root -List whitelist -Entry $v }
                'black-add'    { [void](Add-LBGuardListEntry -InstallDir $script:Root -List blacklist -Entry $v) }
                'black-remove' { Remove-LBGuardListEntry -InstallDir $script:Root -List blacklist -Entry $v }
                default { throw "unknown op: $op" }
            }
            Clear-LBWebCached -Key 'guard'
            Write-LBWebAudit -User $User -Message "guard $op $v"
            return @{ ok = $true }
        }
        $s = Get-LBWebCached -Key 'guard' -Seconds 15 -Get { Get-LBGuardStatus -InstallDir $script:Root }
        $set = Get-LBGuardSettings -Config $cfg
        return [ordered]@{
            status=[ordered]@{ blocked=$s.Blocked; permanent=$s.Permanent; watching=$s.Watching; rules=$s.Rules; geoMode=[string]$s.GeoMode; lastRun=[string]$s.LastRun; feedIps=$s.FeedIps; sharedIps=$s.SharedIps }
            blocks=@(Get-LBGuardBlocks -InstallDir $script:Root | ForEach-Object { [ordered]@{ ip=$_.Ip; country=[string]$_.Country; reason=[string]$_.Reason; source=[string]$_.Source; since=[string]$_.Since; until=[string]$_.Until; count=$_.Count; users=(@($_.Users) -join ', ') } })
            whitelist=@(([string]$s.LocalWhitelist -split ',\s*') | Where-Object { $_ }) + @($set.Whitelist)
            blacklist=@(([string]$s.LocalBlacklist -split ',\s*') | Where-Object { $_ }) + @($set.Blacklist)
            settings=[ordered]@{ maxFailed=$set.MaxFailedAttempts; window=$set.AttemptWindowMinutes; block=$set.BlockMinutes; factor=$set.EscalationFactor; permanentAfter=$set.PermanentAfterBlocks; webMax=$set.WebMaxFailures
                                 rdp=$set.ProtectRDP; logon=$set.ProtectWindowsLogon; sql=$set.ProtectSQL; ftp=$set.ProtectFTP; web=$set.ProtectWeb; ssh=$set.ProtectSSH; lan=$set.AutoWhitelistLan; geo=[string]$set.GeoMode
                                 allowed=@($set.AllowedCountries); blocked=@($set.BlockedCountries) }
        }
    }

    # ---------------- ارتباط‌ها و جاب‌ها | connectivity & jobs ----------------
    # ---------------- ایجنت‌ها | agents ----------------
    '/api/agents' {
        $ci = Get-LBCollectorInfo -Config $cfg
        $conn = Get-LBConnectStatus -InstallDir $script:Root
        $byT = @{}; if ($conn) { foreach ($x in @($conn.Targets)) { $byT[[string]$x.Target] = $x } }
        $tl = @(Get-LBTargetList -StateDir $sd)
        $akeys = @{}; try { $akeys = Get-LBAgentKeys -StateDir $sd } catch { }
        $items = @(Get-LBAgentStatus -StateDir $sd | ForEach-Object {
            $nm = [string]$_.Name; $tg = $tl | Where-Object { $_.Name -eq $nm } | Select-Object -First 1
            # ایجنتِ تأییدشده‌ای که قبلاً داده فرستاده دیگر «در حالِ نصب» نیست (وضعیتِ قدیمیِ فایل نادیده)؛ نسخه هم از آخرین ارسال
            # an approved agent that has already sent data is no longer "installing" (stale step ignored); version from its last report
            $kA = $akeys[$nm.ToUpperInvariant()]; $plA = $null; try { $plA = Get-LBPushLast -StateDir $sd -HostName $nm } catch { }
            $stepA = [string]$_.Step; $okA = $_.Ok
            if ($kA -and [string]$kA.Status -eq 'active' -and -not $kA.Reenroll -and $plA -and $null -eq $okA -and $stepA -notin 'uninstalling', 'uninstalled') { $stepA = 'done'; $okA = $true }
            $verA = if ($plA -and $plA.Version) { [string]$plA.Version } elseif ($kA) { [string]$kA.Version } else { '' }
            $addr = if ($_.Address) { [string]$_.Address } elseif ($tg -and $tg.Address) { [string]$tg.Address } else { $nm }
            $cs = $byT[$addr]; if (-not $cs) { $cs = $byT[$nm] }
            [ordered]@{ name=$nm; address=$addr; method=[string]$_.Method; kind=$(if ($_.Kind) { [string]$_.Kind } elseif ($tg) { [string]$tg.Kind } else { 'Windows' })
                        step=$stepA; ok=$okA; message=(Format-LBTxt -s ([string]$_.Message) -Lang $lang); updated=$(if ($_.Updated -is [datetime]) { $_.Updated.ToString('yyyy-MM-ddTHH:mm:ss', $script:Inv) } else { [string]$_.Updated }); collector=[string]$_.Collector; fix=[string]$_.Fix; tried=@($_.Tried | Where-Object { $_ } | ForEach-Object { [string]$_ })
                        conn=$(if ($cs) { [string]$cs.Status } else { '' }); hasCred=(Test-LBTargetCredential -Name $nm -StateDir $sd); source=($null -ne $tg)
                        approval=$(if ($akeys[$nm.ToUpperInvariant()]) { $k0 = $akeys[$nm.ToUpperInvariant()]; $(if ($k0.Reenroll) { 'pending-reenroll' } else { [string]$k0.Status }) } else { '' })
                        version=$verA
                        perf=$(try { $pl = Get-LBPushLast -StateDir $sd -HostName $nm; if ($pl -and $pl.Perf) { [ordered]@{ cpu=[double]$pl.Perf.CpuSeconds; sec=[double]$pl.Perf.Seconds; mem=[int]$pl.Perf.MemMB } } else { $null } } catch { $null })
                        lastSeen=$(try { $pl2 = Get-LBPushLast -StateDir $sd -HostName $nm; if ($pl2) { [string]$pl2.At } else { '' } } catch { '' }) } })
        # ایجنت‌هایی که ثبت‌نام کرده‌اند ولی وضعیتِ نصب ندارند (مثلاً نصبِ دستی یا GPO) | enrolled agents without an install-status file (manual/GPO installs)
        foreach ($kn in @($akeys.Keys)) {
            if ($items | Where-Object { ([string]$_.name).ToUpperInvariant() -eq ([string]$kn).ToUpperInvariant() }) { continue }
            $k1 = $akeys[$kn]; $pl3 = $null; try { $pl3 = Get-LBPushLast -StateDir $sd -HostName $kn } catch { }
            $items += [ordered]@{ name=[string]$kn; address=[string]$k1.Ip; method=$(if ($k1.Status -eq 'revoked') { 'package' } else { 'package' }); kind='Windows'; step='enrolled'; ok=$true; message=''; updated=[string]$k1.Enrolled; collector=''; conn=''; hasCred=$false; source=$false
                                  approval=$(if ($k1.Reenroll) { 'pending-reenroll' } else { [string]$k1.Status }); version=$(if ($pl3 -and $pl3.Version) { [string]$pl3.Version } else { [string]$k1.Version }); perf=$null; lastSeen=$(if ($pl3) { ConvertTo-LBIsoText $pl3.At } else { '' }) }
        }
        $inv = @(); $invPath = Join-Path $sd 'inventory.json'
        if (Test-Path $invPath) { try { $inv = @(Get-Content $invPath -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch { } }
        foreach ($i in $inv) { if ($i.Computer -and -not ($items | Where-Object { $_.name -eq [string]$i.Computer })) { $cs = $byT[[string]$i.Computer]; $items += [ordered]@{ name=[string]$i.Computer; address=[string]$i.Computer; method='deploy'; kind='Windows'; step='done'; ok=$true; message=''; updated=[string]$i.InstalledAt; collector=''; conn=$(if ($cs) { [string]$cs.Status } else { '' }); hasCred=(Test-LBTargetCredential -Name ([string]$i.Computer) -StateDir $sd); source=$true } } }
        $win = @($tl | Where-Object { $_.Kind -eq 'Windows' -and $_.Monitor -ne 'none' } | ForEach-Object { [ordered]@{ name=[string]$_.Name; address=[string]$_.Address; hasCred=(Test-LBTargetCredential -Name ([string]$_.Name) -StateDir $sd) } })
        $pk = Join-Path $script:Root '_Agents'
        $build = ''; try { $bt = Join-Path $script:Root '_Agents\build.txt'; if (Test-Path $bt) { $build = (Get-Content $bt -Raw).Trim() } } catch { }
        $sum = @{ total = $items.Count; ok = @($items | Where-Object { $_.ok -eq $true }).Count; failed = @($items | Where-Object { $_.ok -eq $false }).Count; busy = @($items | Where-Object { $null -eq $_.ok -and $_.step -ne 'waiting' }).Count }
        return [ordered]@{ items=@($items | Sort-Object { [string]$_.updated } -Descending); summary=$sum; build=$build
                           collector=[ordered]@{ host=$ci.Host; fqdn=$ci.Fqdn; domain=$ci.Domain; ips=@($ci.Ips); names=@($ci.Names); account=$ci.Account; default=$ci.Default; override=[string]$ci.Override }
                           hasDeployCred=(Test-LBTargetCredential -Name 'ad-deploy' -StateDir $sd)
                           enroll=$(try { $enr = Get-LBEnrollInfo -StateDir $sd; [ordered]@{ valid=(Test-LBEnrollValid $enr); expires=[string]$enr.Expires; uses=[int]$enr.Uses; maxUses=[int]$enr.MaxUses; days=[int]$enr.Days; requireApproval=[bool]$enr.RequireApproval } } catch { $null })
                           packageSha=$(try { $zf = Join-Path $script:Root '_Agents\Windows\LogBok-Agent.zip'; if (Test-Path $zf) { (Get-FileHash -Path $zf -Algorithm SHA256).Hash } else { '' } } catch { '' })
                           signer=$(try { $c0 = Get-LBCodeSigningCert; if ($c0) { [string]$c0.Subject } else { '' } } catch { '' })
                           syslogPort=(Get-LBSyslogPort -Config $cfg); windowsSources=$win; hasDefaultCred=(Test-LBTargetCredential -Name '_default' -StateDir $sd)
                           packagesDir=$pk; packagesReady=(Test-Path (Join-Path $pk 'Windows\LogBok-Agent.zip'))
                           installCmd=$(try { $enr2 = Get-LBEnrollInfo -StateDir $sd; $ip8 = 8687; if ($cfg.Agent -and $cfg.Agent.IngestPort) { $ip8 = [int]$cfg.Agent.IngestPort }; if (Test-LBEnrollValid $enr2) { Get-LBBootstrapCommand -Server $ci.Default -Port $ip8 -Token ([string]$enr2.Token) -Config $cfg -InstallDir $script:Root } else { '' } } catch { '' })
                           remotePush=(Test-LBRemotePushAllowed -StateDir $sd)
                           ingestPort=$(try { if ($cfg.Agent -and $cfg.Agent.IngestPort) { [int]$cfg.Agent.IngestPort } else { 8687 } } catch { 8687 }) }
    }
    '/api/agent/prepare' {
        # دانلودِ بستهٔ دستی: سیستم (اختیاری) به‌عنوانِ منبع ثبت می‌شود تا پس از نصب پایش شود
        $kind = $(if ([string]$body.kind -eq 'Linux') { 'Linux' } else { 'Windows' })
        $name = ([string]$body.name).Trim(); $addr = ([string]$body.address).Trim()
        if (-not $name -and $addr) { $name = $(if ($addr -match '^\d+\.\d+\.\d+\.\d+$') { $addr -replace '\.', '-' } else { ($addr -split '\.')[0] }) }
        if ($name) {
            if (-not (Get-LBTargetList -StateDir $sd | Where-Object { $_.Name -eq $name })) {
                $p = @{ Name=$name; Kind=$kind; Monitor=$(if ($kind -eq 'Linux') { 'syslog' } else { 'remote' }); Source='agent'; By=$User }
                if ($addr) { $p.Address = $addr }
                [void](Add-LBTarget @p)
            }
            if ($kind -eq 'Windows' -and $body.user -and $body.password) {
                $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
                [void](Set-LBTargetCredential -Name $name -Credential (New-Object Management.Automation.PSCredential([string]$body.user, $sec)) -StateDir $sd)
            }
            Set-LBAgentStatus -StateDir $sd -Name $name -Fields @{ Method=$(if ($kind -eq 'Linux') { 'linux' } else { 'package' }); Kind=$kind; Address=$addr; Step='waiting'; Ok=$null; Collector=[string]$body.collector
                Message='بسته آماده شد؛ پس از نصب روی سیستم، «آزمون» را بزنید | package downloaded — after installing it on the computer press Test' }
            Write-LBWebAudit -User $User -Message "agent package ($kind) prepared for $name"
        }
        return [ordered]@{ ok=$true; name=$name }
    }
    '/api/agent/push' {
        Assert-LBRemotePush -StateDir $sd
        $name = ([string]$body.name).Trim(); $addr = ([string]$body.address).Trim()
        if (-not $name -and $addr) { $name = $(if ($addr -match '^\d+\.\d+\.\d+\.\d+$') { $addr -replace '\.', '-' } else { ($addr -split '\.')[0] }) }
        if (-not $name) { throw 'نام یا آدرسِ سیستم لازم است | computer name or address required' }
        if ($body.user -and $body.password) {
            $sec = New-Object Security.SecureString; foreach ($ch in ([string]$body.password).ToCharArray()) { $sec.AppendChar($ch) }
            if (-not (Get-LBTargetList -StateDir $sd | Where-Object { $_.Name -eq $name })) { $p = @{ Name=$name; Kind='Windows'; Monitor='remote'; Source='agent'; By=$User }; if ($addr) { $p.Address = $addr }; [void](Add-LBTarget @p) }
            [void](Set-LBTargetCredential -Name $name -Credential (New-Object Management.Automation.PSCredential([string]$body.user, $sec)) -StateDir $sd)
        }
        Set-LBAgentStatus -StateDir $sd -Name $name -Fields @{ Method='push'; Kind='Windows'; Address=$addr; Step='queued'; Ok=$null; Collector=[string]$body.collector; Message='در صف | queued' }
        Start-LBAgentPush -InstallDir $script:Root -StateDir $sd -Name $name -Address $addr -Collector ([string]$body.collector)
        Write-LBWebAudit -User $User -Message "agent push started for $name ($addr)"
        return [ordered]@{ ok=$true; name=$name }
    }
    '/api/agent/collector' {
        # نشانیِ سرور برای ایجنت‌ها (خالی = خودکار از نام/IPِ همین سرور) | collector override; blank = automatic
        $c = ([string]$body.collector).Trim()
        if ($c -and -not (Test-LBAgentAddress $c)) { throw "invalid address: $c" }
        if ($c) { [void](Set-LBSetting -Path 'Agent.Collector' -Value $c -StateDir $sd) } else { [void](Set-LBSetting -Path 'Agent.Collector' -Remove -StateDir $sd) }
        $cfg2 = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
        [void](Update-LBAgentPackages -InstallDir $script:Root -Config $cfg2 -Force)
        Write-LBWebAudit -User $User -Message "agent collector set to '$c' (blank = automatic); packages rebuilt"
        return [ordered]@{ ok=$true; default=(Get-LBCollectorInfo -Config $cfg2).Default }
    }
    '/api/agent/rebuild' { [void](Update-LBAgentPackages -InstallDir $script:Root -Config $cfg -Force); return @{ ok = $true } }
    '/api/agent/batch' {
        Assert-LBRemotePush -StateDir $sd
        $comps = @($body.computers | Where-Object { $_ -and $_.name } | ForEach-Object { [pscustomobject]@{ Name=[string]$_.name; Address=[string]$_.address; IsDC=[bool]$_.isDC; Os=[string]$_.os } })
        if (-not $comps.Count) { throw 'هیچ سیستمی انتخاب نشده | no computers selected' }
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        if (-not $ad.DomainId -and $body.user -and $body.password) { [void](Set-LBTargetCredential -Name 'ad-deploy' -Credential (Get-LBBodyCred -Body $body -StateDir $sd) -StateDir $sd) }
        try { [void](Import-LBADComputers -Computers $comps -InstallDir $script:Root -By $User) } catch { }
        $b = Start-LBAgentBatch -InstallDir $script:Root -StateDir $sd -Computers $comps -Collector ([string]$body.collector) -CredName $ad.CredName -Parallel 6
        Write-LBWebAudit -User $User -Message "agent batch install started for $($comps.Count) computers"
        return [ordered]@{ ok=$true; queued=$(if ($b) { $b.Count } else { 0 }) }
    }
    '/api/ad/groups' {
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        $items = @(Get-LBADGroups -Like ([string]$body.like) -Server $ad.Server -Credential $ad.Credential)
        return @{ items = @($items | ForEach-Object { [ordered]@{ name=$_.Name; sam=$_.Sam; dn=$_.Dn; description=$_.Description } }) }
    }
    '/api/agent/ready' {
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd
        return @{ items = @(Test-LBAgentDeployReady -Server $ad.Server -Credential $ad.Credential | ForEach-Object { [ordered]@{ check=$_.check; ok=$_.ok; detail=(Format-LBTxt -s ([string]$_.detail) -Lang $lang); fix=(Format-LBTxt -s ([string]$_.fix) -Lang $lang) } }) }
    }
    '/api/agent/remote-push' {
        $on = ($body.enabled -eq $true)
        if ($on) { [void](Set-LBSetting -Path 'Agent.RemotePush' -Value $true -StateDir $sd) } else { [void](Set-LBSetting -Path 'Agent.RemotePush' -Remove -StateDir $sd) }
        Write-LBWebAudit -User $User -Message ("remote push (WinRM/SMB/WMI) {0}" -f $(if ($on) { 'ENABLED' } else { 'disabled' }))
        return @{ ok = $true; enabled = $on }
    }
    '/api/agent/joinfile' {
        $enr3 = Get-LBEnrollInfo -StateDir $sd
        if (-not (Test-LBEnrollValid $enr3)) { throw 'توکنِ نصب آماده نیست | install token not ready' }
        $ip9 = 8687; if ($cfg.Agent -and $cfg.Agent.IngestPort) { $ip9 = [int]$cfg.Agent.IngestPort }
        $ln = Get-LBBootstrapLine -Server ((Get-LBCollectorInfo -Config $cfg).Default) -Port $ip9 -Token ([string]$enr3.Token) -InstallDir $script:Root -Config $cfg
        return @{ ok = $true; name = 'LogBok-Join.cmd'; text = (Get-LBJoinCmd -Line $ln) }
    }
    # نصبِ امن روی کلِ دامنه: یک سیاستِ GPO برای همهٔ سیستم‌ها؛ هیچ پورتی روی کلاینت‌ها لازم نیست
    # secure domain-wide install: one GPO policy for all computers; clients pull, no inbound port needed
    '/api/ad/secure-rollout' {
        $d = Get-LBADDomain -StateDir $sd -Id ([string]$body.domainId)
        if (-not $d) { throw 'دامنه پیدا نشد | domain not found' }
        $ex = @(Get-LBAgentPolicies -StateDir $sd | Where-Object { [string]$_.DomainId -eq [string]$d.Id -and [string]$_.Name -like 'LogBok*All computers*' }) | Select-Object -First 1
        $h = @{ Name = ('LogBok — All computers ({0})' -f [string]$d.Fqdn); Enabled = $true; Method = 'gpo'; Auto = $true; Type = 'All'; OUs = @(Get-LBArr $body.ous); IncludeGroups = @(); ExcludeGroups = @(Get-LBArr $body.excludeGroups); NameLike = ''; IncludeDisabled = $false; Collector = ([string]$body.collector).Trim(); Parallel = 6; Reinstall = $false; DomainId = [string]$d.Id }
        if ($ex) { $h.Id = [string]$ex.Id }
        $p = Set-LBAgentPolicy -StateDir $sd -Policy $h
        $g = Publish-LBAgentGpo -Policy $p -InstallDir $script:Root -StateDir $sd
        Write-LBWebAudit -User $User -Message "secure domain rollout (GPO) for $($d.Fqdn): $($g.Name)"
        return [ordered]@{ ok = $true; id = [string]$p.Id; gpo = [ordered]@{ guid = $g.Guid; name = $g.Name; links = @($g.Links); version = $g.Version } }
    }
    '/api/agent/policies' { return @{ items = @(Get-LBAgentPolicies -StateDir $sd | ForEach-Object { ConvertTo-LBWebPolicy $_ }) } }
    '/api/agent/policy' {
        $h = ConvertFrom-LBWebPolicy $body
        if (-not $body.domainId -and $body.user -and $body.password) { [void](Set-LBTargetCredential -Name 'ad-deploy' -Credential (Get-LBBodyCred -Body $body -StateDir $sd) -StateDir $sd) }
        $p = Set-LBAgentPolicy -StateDir $sd -Policy $h
        Write-LBWebAudit -User $User -Message "agent deployment policy saved: $($p.Name) ($($p.Method), auto=$($p.Auto))"
        return [ordered]@{ ok=$true; id=[string]$p.Id }
    }
    '/api/agent/policy/preview' {
        $h = ConvertFrom-LBWebPolicy $body
        if (-not $h.Id) { $h.Id = 'preview' }
        $ad = Resolve-LBWebAd -Body $body -StateDir $sd; $cr = $ad.Credential; if ($ad.DomainId) { $h.Server = $ad.Server }
        $all = @(Get-LBAgentPolicyTargets -Policy $h -StateDir $sd -Credential $cr)
        $st = @{}; foreach ($x in @(Get-LBAgentStatus -StateDir $sd)) { $st[[string]$x.Name] = $x }
        return [ordered]@{ count=$all.Count; items=@($all | Select-Object -First 1000 | ForEach-Object { $s2 = $st[[string]$_.Name]; [ordered]@{ name=$_.Name; address=$_.Address; os=$_.Os; ou=$_.OU; isDC=[bool]$_.IsDC; enabled=[bool]$_.Enabled; lastLogon=[string]$_.LastLogon; agent=$(if ($s2) { $(if ($s2.Ok -eq $true) { 'ok' } elseif ($s2.Ok -eq $false) { 'failed' } else { [string]$s2.Step }) } else { '' }) } }) }
    }
    '/api/agent/policy/run' {
        $p = Get-LBAgentPolicy -StateDir $sd -Id ([string]$body.id)
        if (-not $p) { throw 'policy not found' }
        $out = [ordered]@{ ok=$true; push=$null; gpo=$null; gpoError='' }
        if ($p.Method -eq 'gpo' -or $p.Method -eq 'both') {
            try { $g = Publish-LBAgentGpo -Policy $p -InstallDir $script:Root -StateDir $sd; $out.gpo = [ordered]@{ guid=$g.Guid; name=$g.Name; links=@($g.Links); version=$g.Version } }
            catch { $out.gpoError = $_.Exception.Message; Update-LBAgentPolicyField -StateDir $sd -Id ([string]$p.Id) -Fields @{ LastError = $out.gpoError; LastErrorAt = (Get-Date).ToString('o') } }
            $p = Get-LBAgentPolicy -StateDir $sd -Id ([string]$body.id)
        }
        $out.pushOff = -not (Test-LBRemotePushAllowed -StateDir $sd)
        if (($p.Method -eq 'push' -or $p.Method -eq 'both') -and -not $out.pushOff) { $r = Invoke-LBAgentPolicy -Policy $p -InstallDir $script:Root -StateDir $sd; $out.push = [ordered]@{ matched=$r.Matched; installed=$r.Installed; queued=$r.Queued; skipped=$r.Skipped } }
        Write-LBWebAudit -User $User -Message "agent deployment policy run: $($p.Name)"
        return $out
    }
    '/api/agent/policy/delete' {
        $p = Get-LBAgentPolicy -StateDir $sd -Id ([string]$body.id)
        if (-not $p) { return @{ ok = $true } }
        $gr = ''
        if ($p.Gpo -and $p.Gpo.Guid -and $body.removeGpo -ne $false) { try { [void](Remove-LBAgentGpo -Policy $p -StateDir $sd) } catch { $gr = $_.Exception.Message } }
        if ($gr) { throw ("GPO حذف نشد؛ سیاست نگه داشته شد | GPO could not be removed, policy kept: " + $gr) }
        Remove-LBAgentPolicy -StateDir $sd -Id ([string]$p.Id)
        Write-LBWebAudit -User $User -Message "agent deployment policy deleted: $($p.Name)"
        return @{ ok = $true }
    }
    '/api/agent/policy/gpo-remove' {
        $p = Get-LBAgentPolicy -StateDir $sd -Id ([string]$body.id)
        if (-not $p) { throw 'policy not found' }
        [void](Remove-LBAgentGpo -Policy $p -StateDir $sd)
        Write-LBWebAudit -User $User -Message "agent GPO removed for policy $($p.Name)"
        return @{ ok = $true }
    }
    '/api/uba' {
        $rules = @('offhours-user', 'offhours-host', 'firsttime-host', 'firsttime-remote', 'firsttime-proc', 'firsttime-priv')
        $modes = @('off', 'alert', 'ask', 'auto'); $acts = @('none', 'blockip', 'disableuser', 'isolate')
        if ($Method -eq 'POST') {
            if ($null -ne $body.enabled) { [void](Set-LBSetting -Path 'Uba.Enabled' -Value ([bool]$body.enabled) -StateDir $sd) }
            if ($body.rules) {
                foreach ($p in $body.rules.PSObject.Properties) {
                    if ($rules -notcontains $p.Name) { continue }
                    $rv = $p.Value
                    $mode = [string]$rv.mode; if ($mode -and ($modes -contains $mode)) { [void](Set-LBSetting -Path ("Uba.Rules.$($p.Name).mode") -Value $mode -StateDir $sd) }
                    $act = [string]$rv.action; if ($act -and ($acts -contains $act)) { [void](Set-LBSetting -Path ("Uba.Rules.$($p.Name).action") -Value $act -StateDir $sd) }
                }
            }
            Write-LBWebAudit -User $User -Message 'UBA analytics settings changed'
            return @{ ok = $true }
        }
        $u = $cfg.Uba
        $enabled = -not ($u -and $u.Enabled -eq $false)
        $outRules = [ordered]@{}
        foreach ($r in $rules) {
            $mode = 'alert'; $act = 'none'
            try { if ($u -and $u.Rules) { $rr = if ($u.Rules -is [hashtable]) { $u.Rules[$r] } else { $u.Rules.$r }; if ($rr) { if ($rr.mode) { $mode = [string]$rr.mode }; if ($rr.action) { $act = [string]$rr.action } } } } catch { }
            $outRules[$r] = [ordered]@{ mode = $mode; action = $act }
        }
        return [ordered]@{ enabled = $enabled; rules = $outRules; modes = $modes; actions = $acts }
    }
    # ---------------- Mail Security (email security module) ----------------
    '/api/mail/overview' {
        Use-LBModule 'LogBok.MailSecurity' 'Get-LBMailRecipients'
        $days = [math]::Max(1, [math]::Min(30, [int](Get-LBQ $Ctx 'days' 7)))
        $ev = @(); try { $ev = @(Get-LBMailEvents -StateDir $sd -Days $days) } catch { }
        $byDay = [ordered]@{}; for ($i = $days - 1; $i -ge 0; $i--) { $byDay[(Get-Date).AddDays(-$i).ToString('MM-dd', $script:Inv)] = 0 }
        $bySrc = @{}; $byTo = @{}; $byCat = [ordered]@{ MailSpam = 0; MailPhish = 0; MailAuth = 0; MailAttach = 0 }
        foreach ($e in $ev) {
            $t = ConvertTo-LBDate ([string]$e.t); if ($t) { $k = $t.ToString('MM-dd', $script:Inv); if ($byDay.Contains($k)) { $byDay[$k] = [int]$byDay[$k] + 1 } }
            $c = [string]$e.cat; if ($byCat.Contains($c)) { $byCat[$c] = [int]$byCat[$c] + 1 }
            $ip = [string]$e.ip; if ($ip) { $bySrc[$ip] = [int]$bySrc[$ip] + 1 }
            $to = [string]$e.to; if ($to) { $byTo[$to] = [int]$byTo[$to] + 1 }
        }
        $q = @(); try { $q = @(Get-LBMailQuarantine -StateDir $sd -Max 2000) } catch { }
        $exch = $false; try { $exch = Test-LBMailExchangePresent } catch { }
        return [ordered]@{
            days = $days; total = $ev.Count; quarantined = @($q | Where-Object { [string]$_.status -eq 'held' }).Count; exchange = $exch
            byDay = @($byDay.GetEnumerator() | ForEach-Object { [ordered]@{ day = $_.Key; n = $_.Value } })
            byCat = $byCat
            topSources = @($bySrc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { [ordered]@{ ip = $_.Key; n = $_.Value } })
            topTargets = @($byTo.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { [ordered]@{ mailbox = $_.Key; n = $_.Value } })
            recent = @($ev | Sort-Object { [string]$_.t } -Descending | Select-Object -First 25 | ForEach-Object { [ordered]@{ time = (ConvertTo-LBIsoText (ConvertTo-LBDate ([string]$_.t))); cat = [string]$_.cat; sev = [string]$_.sev; from = [string]$_.from; to = [string]$_.to; ip = [string]$_.ip; subject = [string]$_.subject; score = [int]$_.score } })
        }
    }
    '/api/mail/quarantine' {
        Use-LBModule 'LogBok.MailSecurity' 'Get-LBMailRecipients'
        if ($Method -eq 'POST') {
            $id = [string]$body.id; $act = [string]$body.action
            if ($act -notin 'release', 'delete') { throw 'action must be release or delete' }
            $st = if ($act -eq 'release') { 'released' } else { 'deleted' }
            $ok = $false; try { $ok = Set-LBMailQuarantineStatus -StateDir $sd -Id $id -Status $st } catch { throw $_.Exception.Message }
            Write-LBWebAudit -User $User -Message ("mail quarantine {0}: {1}" -f $act, $id)
            return @{ ok = [bool]$ok }
        }
        $q = @(); try { $q = @(Get-LBMailQuarantine -StateDir $sd -Max 500) } catch { }
        return [ordered]@{ items = @($q | ForEach-Object { [ordered]@{ id = [string]$_.id; at = (ConvertTo-LBIsoText (ConvertTo-LBDate ([string]$_.at))); from = [string]$_.from; to = [string]$_.to; ip = [string]$_.ip; subject = [string]$_.subject; score = [int]$_.score; reasons = @($_.reasons); status = [string]$_.status; server = [string]$_.server; msgId = [string]$_.msgId } }) }
    }
    '/api/mail/settings' {
        if ($Method -eq 'POST') {
            if ($null -ne $body.spamScore) { [void](Set-LBSetting -Path 'MailSecurity.SpamScore' -Value ([math]::Max(1, [math]::Min(100, [int]$body.spamScore))) -StateDir $sd) }
            if ($null -ne $body.quarantineScore) { [void](Set-LBSetting -Path 'MailSecurity.QuarantineScore' -Value ([math]::Max(1, [math]::Min(100, [int]$body.quarantineScore))) -StateDir $sd) }
            if ($null -ne $body.enabled) { [void](Set-LBSetting -Path 'Enabled.MailSec' -Value ([bool]$body.enabled) -StateDir $sd) }
            if ($null -ne $body.useShared) { [void](Set-LBSetting -Path 'MailSecurity.UseSharedBlocklist' -Value ([bool]$body.useShared) -StateDir $sd) }
            if ($null -ne $body.abuseKey) { [void](Set-LBSetting -Path 'MailSecurity.AbuseIpdbKey' -Value ([string]$body.abuseKey) -StateDir $sd) }
            if ($null -ne $body.blockedAttachments) { [void](Set-LBSetting -Path 'MailSecurity.BlockedAttachments' -Value @(@($body.blockedAttachments) | ForEach-Object { ([string]$_).TrimStart('.').ToLowerInvariant() } | Where-Object { $_ -match '^[a-z0-9]{1,8}$' }) -StateDir $sd) }
            if ($null -ne $body.blockSenders) { [void](Set-LBSetting -Path 'MailSecurity.BlockSenders' -Value @(@($body.blockSenders) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ }) -StateDir $sd) }
            if ($null -ne $body.allowSenders) { [void](Set-LBSetting -Path 'MailSecurity.AllowSenders' -Value @(@($body.allowSenders) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ }) -StateDir $sd) }
            Write-LBWebAudit -User $User -Message 'Mail Security settings changed'
            return @{ ok = $true }
        }
        $m = $cfg.MailSecurity
        return [ordered]@{
            enabled = ($cfg.Enabled.MailSec -ne $false)
            spamScore = $(if ($m -and $m.SpamScore) { [int]$m.SpamScore } else { 50 })
            quarantineScore = $(if ($m -and $m.QuarantineScore) { [int]$m.QuarantineScore } else { 70 })
            useShared = $(if ($m) { $m.UseSharedBlocklist -ne $false } else { $true })
            abuseKey = $(if ($m) { [string]$m.AbuseIpdbKey } else { '' })
            blockedAttachments = @(if ($m) { $m.BlockedAttachments } else { @() })
            blockSenders = @(if ($m) { $m.BlockSenders } else { @() })
            allowSenders = @(if ($m) { $m.AllowSenders } else { @() })
        }
    }
    '/api/mail/recipients' {
        Use-LBModule 'LogBok.MailSecurity' 'Get-LBMailRecipients'
        $r = $null; try { $r = Get-LBMailRecipients } catch { $r = [ordered]@{ exchange = $false; mailboxes = @(); databases = @() } }
        return [ordered]@{ exchange = [bool]$r.exchange; mailboxes = @($r.mailboxes); databases = @($r.databases) }
    }
    '/api/mail/preview' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Use-LBModule 'LogBok.MailSecurity' 'Get-LBMailRecipients'
        $subject = [string]$body.subject; $sender = [string]$body.sender; $msgid = [string]$body.messageId
        $mbx = $(if ([string]$body.mailbox) { [string]$body.mailbox } else { 'all' }); $db = [string]$body.database
        $exch = $false; try { $exch = Test-LBMailExchangePresent } catch { }
        if (-not $subject -and -not $sender -and -not $msgid) { throw 'need a subject, sender or message id' }
        $rows = @(); try { $rows = @(Find-LBMailMessages -Config $cfg -Subject $subject -Sender $sender -MessageId $msgid -Mailbox $mbx -Database $db) } catch { }
        return [ordered]@{ ok = $true; exchange = [bool]$exch; rows = @($rows); count = @($rows).Count }
    }
    '/api/mail/purge' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Use-LBModule 'LogBok.MailSecurity' 'Get-LBMailRecipients'
        $subject = [string]$body.subject; $sender = [string]$body.sender; $msgid = [string]$body.messageId
        $mode = $(if ([string]$body.mode -eq 'hard') { 'hard' } else { 'soft' }); $mbx = $(if ([string]$body.mailbox) { [string]$body.mailbox } else { 'all' }); $db = [string]$body.database
        if (-not $subject -and -not $sender -and -not $msgid) { throw 'need a subject, sender or message id' }
        $exch = $false; try { $exch = Test-LBMailExchangePresent } catch { }
        Write-LBWebAudit -User $User -Message ("mail purge requested mode={0} mailbox={1} db={2} subject='{3}' sender='{4}'" -f $mode, $mbx, $db, $subject, $sender)
        if ($exch) {
            $r = Remove-LBMailboxMessage -StateDir $sd -Config $cfg -Subject $subject -Sender $sender -MessageId $msgid -Mode $mode -Mailbox $mbx -Database $db
            return [ordered]@{ ok = (@($r.errors).Count -eq 0); dispatched = 'local'; removed = [int]$r.removed; method = [string]$r.method; errors = @($r.errors) }
        }
        else {
            # Exchange is not on this (console) server; the purge must run on the Exchange
            # server where the LogBok agent + Exchange Management Shell are present.
            try { $qid = Add-LBMailQuarantine -StateDir $sd -Item @{ from = $sender; subject = $subject; mode = $mode; mailbox = $mbx; status = 'purge-pending'; by = $User } } catch { }
            return [ordered]@{ ok = $false; dispatched = 'none'; error = 'Exchange is not installed on this console server. Run the purge from the LogBok agent on the Exchange server (or install Exchange here). The request was recorded.' }
        }
    }
    '/api/agent/enroll' {
        if ($Method -eq 'POST') {
            $enr = Get-LBEnrollInfo -StateDir $sd -Rotate:($body.rotate -eq $true)
            if ($null -ne $body.days) { $enr.Days = [math]::Max(1, [math]::Min(365, [int]$body.days)); if ($body.rotate -ne $true) { $enr.Expires = (ConvertTo-LBDate ([string]$enr.Created)).AddDays($enr.Days).ToString('o', $script:Inv) } }
            if ($null -ne $body.maxUses) { $enr.MaxUses = [math]::Max(1, [math]::Min(100000, [int]$body.maxUses)) }
            if ($null -ne $body.requireApproval) { $enr.RequireApproval = ($body.requireApproval -eq $true) }
            if ($null -ne $body.autoApproveDomain) { $enr.AutoApproveDomain = ($body.autoApproveDomain -eq $true) }
            if ($body.revoke -eq $true) { $enr.Revoked = $true }
            Save-LBEnrollInfo -StateDir $sd -Info $enr
            if ($body.rotate -eq $true -or $body.revoke -eq $true -or $null -ne $body.days) { [void](Update-LBAgentPackages -InstallDir $script:Root -Config $cfg -Force) }
            Write-LBWebAudit -User $User -Message ("agent enrollment updated: rotate={0} revoke={1} days={2} max={3} approval={4}" -f ($body.rotate -eq $true), ($body.revoke -eq $true), $enr.Days, $enr.MaxUses, $enr.RequireApproval)
        }
        $enr = Get-LBEnrollInfo -StateDir $sd
        return [ordered]@{ valid=(Test-LBEnrollValid $enr); expires=[string]$enr.Expires; uses=[int]$enr.Uses; maxUses=[int]$enr.MaxUses; days=[int]$enr.Days; requireApproval=[bool]$enr.RequireApproval }
    }
    '/api/agent/uninstall-code' {
        $nm = ([string]$body.name).Trim()
        $c = Get-LBAgentUninstallCode -StateDir $sd -HostName $nm
        if (-not $c) { throw 'این سیستم کلیدِ ثبت‌شده ندارد | no enrolled key for this computer' }
        Write-LBWebAudit -User $User -Message "uninstall code viewed for agent $nm"
        return @{ ok = $true; code = $c }
    }
    '/api/agent/approve' {
        $act = [string]$body.action; if ($act -notin 'approve','revoke','approve-reenroll') { throw 'bad action' }
        Set-LBAgentKeyStatus -StateDir $sd -HostName ([string]$body.name) -Action $act
        if ($act -ne 'revoke') { Set-LBAgentStatus -StateDir $sd -Name ([string]$body.name).ToUpperInvariant() -Fields @{ Approval = 'active'; Message = 'تأیید شد | approved' } }
        else { Set-LBAgentStatus -StateDir $sd -Name ([string]$body.name).ToUpperInvariant() -Fields @{ Approval = 'revoked'; Ok = $false; Step = 'revoked'; Message = 'ابطال شد؛ رویدادهایش پذیرفته نمی‌شود | revoked: its events are rejected' } }
        Write-LBWebAudit -User $User -Message "agent $($body.name): $act"
        return @{ ok = $true }
    }
    '/api/agent/remove' {
        $nm = ([string]$body.name).Trim().ToUpperInvariant(); if ($nm -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { throw 'invalid name' }
        [void](Add-LBAgentAction -StateDir $sd -Hosts @($nm) -Type 'uninstall' -By $User)
        # نشانِ دائمی تا آشتیِ سرور دوباره نصبش نکند | mark removed so server reconcile never reinstalls it
        try { $akR = Get-LBAgentKeys -StateDir $sd; if ($akR.ContainsKey($nm)) { $akR[$nm].Removed = $true; Save-LBAgentKeys -StateDir $sd -Keys $akR } } catch { }
        Set-LBAgentStatus -StateDir $sd -Name $nm -Fields @{ Step = 'uninstalling'; Ok = $null; Message = 'فرمانِ حذف فرستاده شد؛ ایجنت در اولین ارتباط خودش را کامل پاک می‌کند | uninstall sent; the agent will fully remove itself on its next contact' }
        Write-LBWebAudit -User $User -Message "remote uninstall queued for agent $nm"
        return @{ ok = $true }
    }
    '/api/agent/clear-queue' {
        $nm = ([string]$body.name).Trim().ToUpperInvariant(); if ($nm -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { throw 'invalid name' }
        $allA = @(Get-LBAgentActions -StateDir $sd)
        $keepA = @($allA | Where-Object { -not (((([string]$_.Host).ToUpperInvariant()) -eq $nm) -and (@('queued','sent') -contains [string]$_.Status)) })
        $nClr = $allA.Count - $keepA.Count
        if ($nClr -gt 0) { Save-LBAgentActions -StateDir $sd -Actions $keepA }
        Write-LBWebAudit -User $User -Message ("cleared {0} queued command(s) for agent {1}" -f $nClr, $nm)
        return @{ ok = $true; cleared = $nClr }
    }
    '/api/agent/forget' {
        $nm = ([string]$body.name).Trim(); if ($nm -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { throw 'invalid name' }
        Remove-LBAgentStatus -StateDir $sd -Name $nm
        # کلید و داده‌های دریافتیِ آن سیستم هم پاک می‌شود تا هشدارِ «تماس نگرفته» تمام شود | drop its key + received data so "not reported" stops
        try { $ak = Get-LBAgentKeys -StateDir $sd; if ($ak.ContainsKey($nm.ToUpperInvariant())) { $ak.Remove($nm.ToUpperInvariant()); Save-LBAgentKeys -StateDir $sd -Keys $ak } } catch { }
        try { $pd = Join-Path (Join-Path $sd 'push') $nm.ToUpperInvariant(); if (Test-Path $pd) { Remove-Item $pd -Recurse -Force -ErrorAction SilentlyContinue } } catch { }
        try { [void](Remove-LBTarget -Name $nm -InstallDir $script:Root) } catch { }
        Write-LBWebAudit -User $User -Message "agent forgotten: $nm (status, key, received data, source)"
        return @{ ok = $true }
    }
    # ---------------- گزارش‌ها | reports ----------------
    '/api/reports' {
        $c = Get-LBReportCatalog -Lang $lang
        $sch = @(Get-LBReportSchedules -StateDir $sd | ForEach-Object { [ordered]@{ id=[string]$_.Id; name=[string]$_.Name; reports=@($_.Reports); recipients=@($_.Recipients); freq=[string]$_.Freq; range=[string]$_.Range; day=[int]$_.Day; hour=[int]$_.Hour; enabled=($_.Enabled -ne $false); hostLike=[string]$_.HostLike; lastRun=(ConvertTo-LBIsoText $_.LastRun); lastResult=[string]$_.LastResult } })
        $mc = $false; try { $mc = [bool](Test-LBMailConfigured -Config $cfg) } catch { }
        return [ordered]@{ categories=$c.categories; reports=$c.reports; schedules=$sch; mailConfigured=$mc }
    }
    '/api/report/run' {
        $rg = Get-LBWebRange -Body $body
        $r = Invoke-LBReport -Config $cfg -Id ([string]$body.id) -From $rg.From -To $rg.To -HostLike ([string]$body.host).Trim() -UserLike ([string]$body.user).Trim() -Text ([string]$body.text).Trim() -Max 2000 -Lang $lang
        return $r
    }
    '/api/report/schedule' {
        $h = @{ Name=[string]$body.name; Reports=@(Get-LBArr $body.reports); Recipients=@(Get-LBArr $body.recipients); Freq=[string]$body.freq; Range=[string]$body.range; Day=[int]$body.day; Hour=[int]$body.hour; Enabled=($body.enabled -ne $false); Lang=$lang; HostLike=[string]$body.hostLike }
        if ($body.id) { $h.Id = [string]$body.id }
        $s = Set-LBReportSchedule -StateDir $sd -Item $h -By $User
        Write-LBWebAudit -User $User -Message ("report schedule saved: {0} ({1}, {2} reports → {3})" -f $s.Name, $s.Freq, @($s.Reports).Count, (@($s.Recipients) -join ', '))
        return [ordered]@{ ok=$true; id=[string]$s.Id }
    }
    '/api/report/schedule/delete' { Remove-LBReportSchedule -StateDir $sd -Id ([string]$body.id); Write-LBWebAudit -User $User -Message "report schedule deleted: $($body.id)"; return @{ ok = $true } }
    '/api/report/schedule/run' {
        $res = @(Invoke-LBScheduledReports -Config $cfg -OnlyId ([string]$body.id) -Force)
        Write-LBWebAudit -User $User -Message "report schedule sent now: $($body.id)"
        return [ordered]@{ ok=$true; result=$(if ($res.Count) { [string]$res[0].result } else { '' }); files=$(if ($res.Count) { [int]$res[0].files } else { 0 }) }
    }
    '/api/user/recent' {
        $hr = [int](Get-LBQ $Ctx 'hours' 24); if ($hr -lt 1 -or $hr -gt 168) { $hr = 24 }
        return @{ items = @(Get-LBWebCached -Key ("recentusers-$hr") -Seconds 300 -Get { Get-LBRecentUsers -Config $cfg -Hours $hr } | Where-Object { $_ }) }
    }
    '/api/user/activity' {
        $rg = Get-LBWebRange -Body $body -DefaultHours 168
        return (Get-LBUserActivity -Config $cfg -User ([string]$body.user) -From $rg.From -To $rg.To -Lang $lang -Max 600)
    }
    # ---------------- مدیریتِ اندپوینت | endpoint management ----------------
    '/api/endpoint/policies' {
        $keys = @{}; try { $keys = Get-LBAgentKeys -StateDir $sd } catch { }
        $rev = @{}; foreach ($k in @($keys.Keys)) { if ([string]$keys[$k].Status -eq 'revoked') { $rev[([string]$k).ToUpperInvariant()] = $true } }
        $hosts = @(@($keys.Keys) + @(Get-LBAgentStatus -StateDir $sd | Where-Object { [string]$_.Step -ne 'uninstalled' } | ForEach-Object { [string]$_.Name }) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpperInvariant() } | Where-Object { -not $rev[$_] } | Select-Object -Unique | Sort-Object)
        $pols = @(Get-LBEndpointPolicies -StateDir $sd)
        $stat = @{}
        foreach ($h in $hosts) {
            $ps = $null; $pf = Join-Path (Get-LBPushDir -StateDir $sd -HostName $h) 'policy-status.json'
            if (Test-Path $pf) { try { $ps = Get-Content $pf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
            $eff = Get-LBEffectivePolicy -StateDir $sd -HostName $h -Policies $pols
            $stat[$h] = [ordered]@{ host=$h; want=[string]$eff.rev; have=$(if ($ps) { [string]$ps.Rev } else { '' }); at=$(if ($ps) { [string]$ps.At } else { '' }); applied=($ps -and [string]$ps.Rev -eq [string]$eff.rev)
                                    rules=$(if ($ps -and $ps.Data.appblock) { [int]$ps.Data.appblock.rules } else { 0 }); errors=@($(if ($ps -and $ps.Data.appblock) { @($ps.Data.appblock.errors) } else { @() }) + $(if ($ps -and $ps.Data.guardError) { @([string]$ps.Data.guardError) } else { @() }) | Where-Object { $_ })
                                    items=@($(if ($ps -and $ps.Data.appblock) { @($ps.Data.appblock.items) } else { @() }) | Where-Object { $_ } | ForEach-Object { [ordered]@{ policy=[string]$_.policy; program=[string]$_.program; paths=@($_.paths); active=[bool]$_.active } })
                                    guard=$(if ($eff.guard) { [string]$eff.guard.name } else { '' }); appBlocks=@($eff.appBlocks | ForEach-Object { [string]$_.name }); appLaunch=$(if ($eff.appLaunch) { ('{0} ({1}/{2})' -f $eff.appLaunch.name, $eff.appLaunch.mode, $eff.appLaunch.list) } else { '' }) }
        }
        $items = @($pols | Sort-Object { [string]$_.Type }, { [string]$_.Name } | ForEach-Object {
            $p = $_; $cmX = Get-LBHostAdInfoMap -StateDir $sd; $tg = @($hosts | Where-Object { Test-LBPolicyTarget -Policy $p -HostName $_ -Info $cmX[([string]$_).ToUpperInvariant()] })
            [ordered]@{ id=[string]$p.Id; name=[string]$p.Name; type=[string]$p.Type; enabled=($p.Enabled -ne $false); priority=[int]$p.Priority; note=[string]$p.Note
                        targets=[ordered]@{ all=[bool]$p.Targets.All; hosts=@(Get-LBArr $p.Targets.Hosts); patterns=@(Get-LBArr $p.Targets.Patterns); includeServer=[bool]$p.Targets.IncludeServer; exceptHosts=@(Get-LBArr $p.Targets.ExceptHosts); exceptPatterns=@(Get-LBArr $p.Targets.ExceptPatterns); ous=@(Get-LBArr $p.Targets.OUs); exceptOus=@(Get-LBArr $p.Targets.ExceptOUs); groups=@(Get-LBArr $p.Targets.Groups); exceptGroups=@(Get-LBArr $p.Targets.ExceptGroups) }
                        settings=$p.Settings; updated=(ConvertTo-LBIsoText $p.Updated); by=[string]$p.By; hosts=$tg; applied=@($tg | Where-Object { $stat[$_].applied }).Count } })
        $srv = $null; try { $sp = Join-Path $sd 'policy.json'; if (Test-Path $sp) { $sj = Get-Content $sp -Raw -Encoding UTF8 | ConvertFrom-Json; $srv = [ordered]@{ rev=[string]$sj.status.rev; at=(ConvertTo-LBIsoText $sj.status.at); rules=$(if ($sj.status.appblock) { [int]$sj.status.appblock.rules } else { 0 }) } } } catch { }
        return [ordered]@{ items=$items; hosts=$hosts; postureChecks=@(Get-LBPostureCatalog -Lang $lang); status=@($hosts | ForEach-Object { $stat[$_] }); server=[ordered]@{ name=([Environment]::MachineName).ToUpperInvariant(); applied=$srv } }
    }
    '/api/endpoint/policy' {
        $t = $body.targets; $s = ConvertTo-LBHashtable $body.settings; if (-not ($s -is [hashtable])) { $s = @{} }
        $h = @{ Name=([string]$body.name).Trim(); Type=[string]$body.type; Enabled=($body.enabled -ne $false); Priority=[int]$body.priority; Note=([string]$body.note).Trim()
                Targets=@{ All=($t.all -eq $true); Hosts=@(Get-LBArr $t.hosts); Patterns=@(Get-LBArr $t.patterns); IncludeServer=($t.includeServer -eq $true); ExceptHosts=@(Get-LBArr $t.exceptHosts); ExceptPatterns=@(Get-LBArr $t.exceptPatterns); OUs=@(Get-LBArr $t.ous); ExceptOUs=@(Get-LBArr $t.exceptOus); Groups=@(Get-LBArr $t.groups); ExceptGroups=@(Get-LBArr $t.exceptGroups) }; Settings=$s }
        if ($body.id) { $h.Id = [string]$body.id }
        if (-not $h.Targets.All -and -not $h.Targets.Hosts.Count -and -not $h.Targets.Patterns.Count -and -not $h.Targets.IncludeServer -and -not $h.Targets.OUs.Count -and -not $h.Targets.Groups.Count) { throw 'حداقل یک سیستم را انتخاب کنید | choose at least one computer' }
        $p = Set-LBEndpointPolicy -StateDir $sd -Policy $h -By $User
        Write-LBWebAudit -User $User -Message ("endpoint policy saved: {0} ({1}) targets: all={2} hosts={3} patterns={4} server={5}" -f $p.Name, $p.Type, $p.Targets.All, (@($p.Targets.Hosts) -join ','), (@($p.Targets.Patterns) -join ','), $p.Targets.IncludeServer)
        return [ordered]@{ ok=$true; id=[string]$p.Id }
    }
    '/api/endpoint/policy/delete' {
        $id = [string]$body.id; $p = @(Get-LBEndpointPolicies -StateDir $sd | Where-Object { [string]$_.Id -eq $id }) | Select-Object -First 1
        Remove-LBEndpointPolicy -StateDir $sd -Id $id
        Write-LBWebAudit -User $User -Message ("endpoint policy deleted: {0}" -f $(if ($p) { $p.Name } else { $id }))
        return @{ ok = $true }
    }
    '/api/endpoint/apps' {
        # برنامه‌های دارای ترافیکِ شبکه، از موجودیِ ایجنت‌ها (netapps) | network-active programs from agent inventories
        $want = ([string]$body.host).Trim().ToUpperInvariant()
        $sdp = Join-Path $sd 'push'; $hostsOut = @(); $agg = @{}
        $cm = Get-LBHostAdInfoMap -StateDir $sd
        if (Test-Path $sdp) {
            foreach ($d in @(Get-ChildItem -Path $sdp -Directory -ErrorAction SilentlyContinue)) {
                $hn = $d.Name.ToUpperInvariant(); if ($want -and $hn -ne $want) { continue }
                $ij = Join-Path $d.FullName 'inventory.json'; if (-not (Test-Path $ij)) { continue }
                $inv = $null; try { $inv = Get-Content $ij -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                $na = @(); if ($inv.Data -and $inv.Data.netapps) { $na = @($inv.Data.netapps) }
                $ad = $cm[$hn]
                $hostsOut += [ordered]@{ host=$hn; at=[string]$inv.At; ou=$(if ($ad) { [string]$ad.ou } else { '' }); groups=@($(if ($ad) { Get-LBArr $ad.groups } else { @() })); apps=@($na | ForEach-Object { [ordered]@{ n=[string]$_.n; p=[string]$_.p; c=[int]$_.c; inet=[int]$_.inet; r=@(Get-LBArr $_.r); u=[string]$_.u } }) }
                foreach ($a in $na) { $k = ([string]$a.n).ToLowerInvariant(); if (-not $k) { continue }
                    if (-not $agg.ContainsKey($k)) { $agg[$k] = [ordered]@{ n=[string]$a.n; hosts=@(); inetHosts=@(); paths=@(); users=@() } }
                    $g = $agg[$k]; if ($g.hosts -notcontains $hn) { $g.hosts += $hn }; if ([int]$a.inet -gt 0 -and $g.inetHosts -notcontains $hn) { $g.inetHosts += $hn }
                    if ($a.p -and $g.paths -notcontains [string]$a.p -and $g.paths.Count -lt 5) { $g.paths += [string]$a.p }
                    if ($a.u -and $g.users -notcontains [string]$a.u -and $g.users.Count -lt 10) { $g.users += [string]$a.u } }
            }
        }
        # سیاست‌های فعلیِ مسدودسازی برای نشانِ «قبلاً مسدود» | current appblock policies for the "already blocked" marker
        $blocked = @{}; foreach ($pol in @(Get-LBEndpointPolicies -StateDir $sd | Where-Object { $_.Type -eq 'appblock' -and $_.Enabled -ne $false })) { foreach ($pr in @($pol.Settings.Programs)) { $k2 = ([IO.Path]::GetFileName([string]$pr)).ToLowerInvariant(); if ($k2) { $blocked[$k2] = [string]$pol.Name } } }
        return [ordered]@{ hosts=@($hostsOut | Sort-Object { $_.host }); apps=@($agg.Values | ForEach-Object { $_.blockedBy = [string]$blocked[([string]$_.n).ToLowerInvariant()]; $_ } | Sort-Object { -$_.inetHosts.Count }, { -$_.hosts.Count }, { $_.n }) }
    }
    '/api/endpoint/fleet' {
        $sdp = Join-Path $sd 'push'; $rows = @()
        if (Test-Path $sdp) {
            foreach ($d in @(Get-ChildItem -Path $sdp -Directory -ErrorAction SilentlyContinue)) {
                $rj = { param($f) $p = Join-Path $d.FullName $f; if (Test-Path $p) { try { return (Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }; return $null }
                $pos = & $rj 'posture.json'; $pat = & $rj 'patches.json'; $hl = & $rj 'health.json'; $inv = & $rj 'inventory.json'
                if (-not $pos -and -not $pat -and -not $inv) { continue }
                $miss = @(); if ($pat) { $miss = @($pat.Data.missing | Where-Object { $_ }) }
                $rows += [ordered]@{ host=$d.Name; os=$(if ($inv) { [string]$inv.Data.os.n } else { '' }); score=$(if ($pos) { [int]$pos.Data.score } else { $null }); failed=$(if ($pos) { @($pos.Data.checks | Where-Object { $_.ok -eq $false } | ForEach-Object { [string]$_.id }) } else { @() })
                                     postureAt=$(if ($pos) { ConvertTo-LBIsoText $pos.At } else { '' }); missing=$miss.Count; security=@($miss | Where-Object { $_.security }).Count; patchError=$(if ($pat) { [string]$pat.Data.error } else { '' })
                                     patchAt=$(if ($pat) { ConvertTo-LBIsoText $pat.Data.at } else { '' }); lastInstall=$(if ($pat -and $pat.Data.lastInstall) { $pat.Data.lastInstall } else { $null }); reboot=$(if ($hl) { [bool]$hl.Data.rebootPending } else { $false }) }
            }
        }
        $sc = @($rows | Where-Object { $null -ne $_.score }); $avg = if ($sc.Count) { [int](($sc | Measure-Object -Property score -Average).Average) } else { $null }
        return [ordered]@{ items=@($rows | Sort-Object { [int]$(if ($null -eq $_.score) { 101 } else { $_.score }) }); avgScore=$avg; missingTotal=(@($rows | ForEach-Object { $_.missing }) | Measure-Object -Sum).Sum; postureChecks=@(Get-LBPostureCatalog -Lang $lang) }
    }
    '/api/agent/action' {
        $type = [string]$body.type
        $hosts = @(Get-LBArr $body.hosts)
        if (-not $hosts.Count) { throw 'هیچ سیستمی انتخاب نشده | no computers selected' }
        $args0 = ConvertTo-LBHashtable $body.args; if (-not ($args0 -is [hashtable])) { $args0 = @{} }
        $new = @(Add-LBAgentAction -StateDir $sd -Hosts $hosts -Type $type -Arguments $args0 -By $User)
        Write-LBWebAudit -User $User -Message ("agent action '{0}' queued for {1}" -f $type, ($hosts -join ', '))
        return [ordered]@{ ok=$true; queued=$new.Count; ids=@($new | ForEach-Object { [string]$_.Id }) }
    }
    '/api/agent/actions' {
        $hn = [string](Get-LBQ $Ctx 'name' '')
        $a = @(Get-LBAgentActions -StateDir $sd -HostName $hn | Sort-Object { [string]$_.Created } -Descending | Select-Object -First 200)
        return @{ items = @($a | ForEach-Object { [ordered]@{ id=[string]$_.Id; host=[string]$_.Host; type=[string]$_.Type; args=$_.Args; status=[string]$_.Status; ok=$_.Ok; output=[string]$_.Output; created=(ConvertTo-LBIsoText $_.Created); sent=(ConvertTo-LBIsoText $_.SentAt); done=(ConvertTo-LBIsoText $_.DoneAt); by=[string]$_.By } }) }
    }
    '/api/agent/detail' {
        $hn = ([string](Get-LBQ $Ctx 'name' '')).ToUpperInvariant()
        if ($hn -notmatch '^[A-Z0-9_.\-]{1,63}$') { throw 'invalid name' }
        $hd = Get-LBPushDir -StateDir $sd -HostName $hn
        $rd = { param($f) $p = Join-Path $hd $f; if (Test-Path $p) { try { return (Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }; return $null }
        $inv = & $rd 'inventory.json'; $hl = & $rd 'health.json'; $ps = & $rd 'policy-status.json'; $last = & $rd 'last.json'; $pos = & $rd 'posture.json'; $pat = & $rd 'patches.json'
        $eff = Get-LBEffectivePolicy -StateDir $sd -HostName $hn
        $k = $null; try { $k = (Get-LBAgentKeys -StateDir $sd)[$hn] } catch { }
        return [ordered]@{ name=$hn; inventory=$inv; health=$hl; policyStatus=$ps; last=$last; posture=$pos; patches=$pat; lang=$lang
                           effective=[ordered]@{ rev=[string]$eff.rev; appBlocks=@($eff.appBlocks | ForEach-Object { [ordered]@{ id=$_.id; name=$_.name; programs=@($_.programs); scope=$_.scope } }); guard=$(if ($eff.guard) { [string]$eff.guard.name } else { '' }); appLaunch=$(if ($eff.appLaunch) { [ordered]@{ name=[string]$eff.appLaunch.name; mode=[string]$eff.appLaunch.mode; list=[string]$eff.appLaunch.list; programs=@($eff.appLaunch.programs) } } else { $null }) }
                           applied=($ps -and [string]$ps.Rev -eq [string]$eff.rev); approval=$(if ($k) { [string]$k.Status } else { '' }); payload=(Get-LBServerPayloadHash -InstallDir $script:Root)
                           actions=@(Get-LBAgentActions -StateDir $sd -HostName $hn | Sort-Object { [string]$_.Created } -Descending | Select-Object -First 30 | ForEach-Object { [ordered]@{ id=[string]$_.Id; type=[string]$_.Type; args=$_.Args; status=[string]$_.Status; ok=$_.Ok; output=[string]$_.Output; created=(ConvertTo-LBIsoText $_.Created); done=(ConvertTo-LBIsoText $_.DoneAt); by=[string]$_.By } }) }
    }
    '/api/inventory/software' {
        $q = [string](Get-LBQ $Ctx 'q' '')
        $rows = @(Find-LBSoftware -StateDir $sd -Query $q -Max 5000)
        $grp = @($rows | Group-Object { $_.name } | Sort-Object Count -Descending | Select-Object -First 500 | ForEach-Object { [ordered]@{ name=$_.Name; publisher=[string]$_.Group[0].publisher; count=$_.Count; versions=@($_.Group | ForEach-Object { $_.version } | Select-Object -Unique); hosts=@($_.Group | ForEach-Object { $_.host } | Select-Object -Unique) } })
        $nInv = 0; try { $nInv = @(Get-ChildItem -Path (Get-LBPushDir -StateDir $sd) -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'inventory.json') }).Count } catch { }
        return [ordered]@{ items=$grp; total=$rows.Count; computers=$nInv }
    }
    '/api/connectivity' {
        $c = Get-LBConnectStatus -InstallDir $script:Root
        $mg = @(); try { $mg = @(Get-LBWebCached -Key 'mgmt' -Seconds 30 -Get { @(Test-LBMgmtAllow -Config $cfg -InstallDir $script:Root) } | ForEach-Object { [ordered]@{ name=$_.Name; ports=$_.Ports; remote=$_.Remote; enabled=[bool]$_.Enabled } }) } catch { }
        if (-not $c) { return @{ generated=''; targets=@(); mgmt=$mg } }
        return [ordered]@{ generated=[string]$c.Generated; mgmt=$mg; targets=@($c.Targets | ForEach-Object { [ordered]@{ target=[string]$_.Target; name=$(if ($_.Name) { [string]$_.Name } else { [string]$_.Target }); kind=[string]$_.Kind; roles=@(Get-LBArr $_.Roles); self=[bool]$_.Self; status=[string]$_.Status
            channels=@($_.Channels | ForEach-Object { [ordered]@{ channel=[string]$_.Channel; ok=[bool]$_.Ok; state=[string]$_.State; ms=[int]$_.Ms; detail=(Format-LBTxt -s ([string]$_.Detail) -Lang $lang); reason=(Format-LBTxt -s ([string]$_.Reason) -Lang $lang); remedy=(Format-LBTxt -s ([string]$_.Remedy) -Lang $lang) } }) } }) }
    }
    '/api/jobs' {
        $okCodes = @(0, 267009, 267011, 2147946720)
        return @{ items = @(Get-LBWebJobs -Config $cfg -Fresh:($null -ne (Get-LBQ $Ctx 'fresh')) | ForEach-Object { [ordered]@{ name=$_.Name; task=$_.Task; enabled=[bool]$_.Enabled; state=[string]$_.State
            last=$(if ($_.LastRun) { $_.LastRun.ToString('yyyy-MM-dd HH:mm', $script:Inv) } else { '' }); next=$(if ($_.NextRun -and $_.NextRun.Year -gt 2000) { $_.NextRun.ToString('yyyy-MM-dd HH:mm', $script:Inv) } else { '' })
            code=$(if ($null -ne $_.LastCode) { ('0x{0:X}' -f [long]$_.LastCode) } else { '' }); healthy=(-not $_.LastCode -or $okCodes -contains [long]$_.LastCode); purpose=$(if ($lang -eq 'en') { [string]$_.En } else { [string]$_.Fa }) } }) }
    }
    '/api/jobs/run' {
        $n = [string]$body.name
        $j = Get-LBJobStatus -Config $cfg -Role Engine | Where-Object { $_.Name -eq $n } | Select-Object -First 1
        if (-not $j) { throw "job not found: $n" }
        Start-ScheduledTask -TaskName $j.Task -TaskPath '\LogBok\' -ErrorAction Stop
        Reset-LBWebJobs
        Write-LBWebAudit -User $User -Message "job $n started"
        return @{ ok = $true }
    }

    # ---------------- تنظیمات | settings ----------------
    '/api/settings' {
        $allowed = @('Language','CollectionMode','CollectorFqdn','AlertThrottleMinutes','ArchiveRetentionDays',
                     'Management.AdminIPs','Management.AllowFromLan','Management.AllowRDP','Management.AllowWinRM','Management.AllowWEF','Management.AllowSMB','Management.ExtraPorts',
                     'Connectivity.Enabled','Connectivity.TimeoutMs','Web.Listen','Web.Port',
                     'Guard.MaxFailedAttempts','Guard.AttemptWindowMinutes','Guard.BlockMinutes','Guard.EscalationFactor','Guard.PermanentAfterBlocks','Guard.WebMaxFailures','Guard.GeoMode','Guard.AllowedCountries','Guard.BlockedCountries',
                     'Thresholds.LogonFailurePerWindow','Thresholds.SqlFailurePerWindow','Thresholds.IISErrorPerWindow','Thresholds.FtpFailurePerWindow','Thresholds.MassFilePerWindow','Thresholds.WindowMinutes')
        if ($Method -eq 'POST') {
            $changed = @()
            foreach ($p in $body.PSObject.Properties) {
                if ($allowed -notcontains $p.Name -and $p.Name -notlike 'Jobs.*') { throw "setting not allowed: $($p.Name)" }
                $v = $p.Value
                if ($p.Name -eq 'CollectionMode' -and $v -notin 'Local','Collector','Remote') { throw 'invalid CollectionMode' }
                if ($p.Name -eq 'Language' -and $v -notin 'fa','en','both') { throw 'invalid Language' }
                if ($p.Name -eq 'Web.Listen' -and $v -notin 'local','lan') { throw 'invalid Web.Listen' }
                if ($p.Name -eq 'Guard.GeoMode' -and $v -notin 'Off','AllowOnly','BlockListed') { throw 'invalid GeoMode' }
                if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = @(Get-LBArr $v) }
                [void](Set-LBSetting -Path $p.Name -Value $v -StateDir $sd)
                $changed += "$($p.Name)=$v"
            }
            Write-LBWebAudit -User $User -Message ("settings changed: " + ($changed -join '; '))
            return @{ ok = $true; restart = (@($changed | Where-Object { $_ -like 'Web.*' }).Count -gt 0) }
        }
        $m = $cfg.Management; $w = $cfg.Web; $g = $cfg.Guard; $th = $cfg.Thresholds
        return [ordered]@{
            Language=[string]$cfg.Language; CollectionMode=[string]$cfg.CollectionMode; CollectorFqdn=[string]$cfg.CollectorFqdn; AlertThrottleMinutes=[int]$cfg.AlertThrottleMinutes; ArchiveRetentionDays=[int]$(if ($cfg.ArchiveRetentionDays) { $cfg.ArchiveRetentionDays } else { 180 })
            Management=[ordered]@{ AdminIPs=@(Get-LBArr $m.AdminIPs); AllowFromLan=($m.AllowFromLan -ne $false); AllowRDP=($m.AllowRDP -ne $false); AllowWinRM=($m.AllowWinRM -ne $false); AllowWEF=($m.AllowWEF -ne $false); AllowSMB=($m.AllowSMB -eq $true); ExtraPorts=@($m.ExtraPorts | Where-Object { $_ }) }
            Web=[ordered]@{ Listen=$(if ($w.Listen) { [string]$w.Listen } else { 'local' }); Port=$(if ($w.Port) { [int]$w.Port } else { 8686 }) }
            Guard=[ordered]@{ MaxFailedAttempts=[int]$g.MaxFailedAttempts; AttemptWindowMinutes=[int]$g.AttemptWindowMinutes; BlockMinutes=[int]$g.BlockMinutes; EscalationFactor=[double]$g.EscalationFactor; PermanentAfterBlocks=[int]$g.PermanentAfterBlocks; WebMaxFailures=[int]$g.WebMaxFailures; GeoMode=[string]$g.GeoMode; AllowedCountries=@(Get-LBArr $g.AllowedCountries); BlockedCountries=@(Get-LBArr $g.BlockedCountries) }
            Thresholds=[ordered]@{ LogonFailurePerWindow=[int]$th.LogonFailurePerWindow; SqlFailurePerWindow=[int]$th.SqlFailurePerWindow; IISErrorPerWindow=[int]$th.IISErrorPerWindow; FtpFailurePerWindow=[int]$th.FtpFailurePerWindow; MassFilePerWindow=[int]$th.MassFilePerWindow; WindowMinutes=[int]$th.WindowMinutes }
            Jobs=$(if ($cfg.Jobs) { $o = [ordered]@{}; foreach ($k in ($cfg.Jobs.Keys | Sort-Object)) { $o[$k] = [bool]$cfg.Jobs[$k] }; $o } else { @{} })
        }
    }
    # ---------------- به‌روزرسانی | updates ----------------
    '/api/update/status' {
        $st = [ordered]@{ isVendor = $false; publishedVersion = ''; publishedAt = ''; history = @() }
        try { $st = Get-LBPublishStatus -InstallDir $script:Root } catch { }
        $serverVer = ''; try { $vf = Join-Path $sd 'server-version.txt'; if (Test-Path $vf) { $serverVer = (Get-Content $vf -Raw).Trim() } } catch { }
        $up = $cfg.Update; if (-not $up) { $up = @{} }
        return [ordered]@{
            isVendor         = [bool]$st.isVendor
            canIssue         = ([bool]$st.isVendor -and (Test-Path (Join-Path $script:Root 'Tools\LogBok.Issuer.psm1')))
            installedVersion = $script:Version
            serverVersion    = $serverVer
            publishedVersion = [string]$st.publishedVersion; publishedAt = [string]$st.publishedAt
            feed             = $(if ($up.ServerFeed) { [string]$up.ServerFeed } else { '' })
            enabled          = $(if ($up.Enabled -eq $false) { $false } else { $true })
            intervalHours    = $(if ($up.IntervalHours) { [int]$up.IntervalHours } else { 6 })
            history          = @($st.history)
        }
    }
    '/api/update/publish' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        $r = Invoke-LBPublishUpdate -InstallDir $script:Root -Version ([string]$body.version) -Notes ([string]$body.notes) -CopyTo ([string]$body.copyTo) -By $User
        Write-LBWebAudit -User $User -Message ("update published v{0}" -f $r.version)
        return $r
    }
    '/api/update/pull' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Use-LBModule 'LogBok.Update' 'Invoke-LBServerUpdate'
        $feed = ''; try { $feed = [string]$cfg.Update.ServerFeed } catch { }
        if (-not $feed) { return @{ ok = $false; error = 'فیدِ آپدیت تنظیم نشده | no update feed configured' } }
        $r = $null; try { $r = Invoke-LBServerUpdate -InstallDir $script:Root -Config $cfg } catch { return @{ ok = $false; error = $_.Exception.Message } }
        Write-LBWebAudit -User $User -Message 'manual server update pull'
        if ($null -eq $r) { return @{ ok = $true; changed = 0; note = 'نسخهٔ تازه‌ای نبود یا رد شد | up to date or rejected' } }
        return @{ ok = $true; changed = @($r).Count; files = @($r) }
    }
    '/api/update/settings' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        $feed = [string]$body.feed
        if ($feed) { if ($feed -notmatch '^(https?://|\\\\|[A-Za-z]:\\)') { throw 'آدرسِ فید باید HTTPS یا مسیرِ شبکه باشد | feed must be HTTPS or a UNC/path' }; [void](Set-LBSetting -Path 'Update.ServerFeed' -Value $feed -StateDir $sd) }
        else { [void](Set-LBSetting -Path 'Update.ServerFeed' -Remove -StateDir $sd) }
        if ($null -ne $body.enabled) { [void](Set-LBSetting -Path 'Update.Enabled' -Value ($body.enabled -eq $true) -StateDir $sd) }
        if ($body.intervalHours) { $iv = [int]$body.intervalHours; if ($iv -lt 1) { $iv = 1 }; if ($iv -gt 168) { $iv = 168 }; [void](Set-LBSetting -Path 'Update.IntervalHours' -Value $iv -StateDir $sd) }
        Write-LBWebAudit -User $User -Message 'update feed settings changed'
        return @{ ok = $true }
    }
    # ---------------- صدورِ لایسنس (فقط سرورِ سازنده) | license issuing (vendor server only) ----------------
    '/api/license/issue' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        $issuer = Join-Path $script:Root 'Tools\LogBok.Issuer.psm1'
        if (-not (Test-Path $issuer) -or -not (Test-LBIsVendor $script:Root)) { return @{ __status = 403; error = 'این سرور اجازهٔ صدورِ لایسنس ندارد | not a license-issuing (vendor) server' } }
        try { Import-Module $issuer -Force -DisableNameChecking -Global -ErrorAction Stop } catch { return @{ ok = $false; error = $_.Exception.Message } }
        $company = [string]$body.company
        $device  = [string]$body.device
        $mode    = [string]$body.mode   # permanent | days | date
        $expires = 'never'
        if ($mode -eq 'days') { $days = [int]$body.days; if ($days -lt 1) { $days = 365 }; $expires = (Get-Date).Date.AddDays($days).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
        elseif ($mode -eq 'date') { $expires = [string]$body.expiry }
        $limits = @{
            Clients           = [math]::Max(0, [int]$body.clients)
            FileServers       = [math]::Max(0, [int]$body.fileServers)
            IIS               = [math]::Max(0, [int]$body.iis)
            SQL               = [math]::Max(0, [int]$body.sql)
            DomainControllers = [math]::Max(0, [int]$body.dc)
        }
        $text = $null
        try { $text = New-LogBokLicenseText -Company $company -Device $device -Expires $expires -Limits $limits } catch { return @{ ok = $false; error = $_.Exception.Message } }
        $file = ''; try { $file = Save-LogBokIssuedLicense -Company $company -Text $text } catch { }
        Write-LBWebAudit -User $User -Message ("license issued: {0} / device {1} / expires {2}" -f $company, ([string]$device).ToUpperInvariant(), $expires)
        return @{ ok = $true; license = $text; expires = $expires; file = [string]$file }
    }
    '/api/license/issued' {
        $issuer = Join-Path $script:Root 'Tools\LogBok.Issuer.psm1'
        if (-not (Test-Path $issuer) -or -not (Test-LBIsVendor $script:Root)) { return @{ __status = 403; error = 'not a vendor server' } }
        try { Import-Module $issuer -Force -DisableNameChecking -Global -ErrorAction Stop } catch { }
        $rows = @()
        try { $csv = Join-Path (Get-LBIssuedDir) 'issued-ledger.csv'; if (Test-Path $csv) { $rows = @(Import-Csv -Path $csv) } } catch { }
        $out = @($rows | ForEach-Object { [ordered]@{ issued = [string]$_.Issued; company = [string]$_.Company; device = [string]$_.Device; expires = [string]$_.Expires; limits = [string]$_.Limits } })
        if ($out.Count -gt 1) { [array]::Reverse($out) }
        return @{ rows = @($out | Select-Object -First 200) }
    }
    # ---------------- کاربرانِ کنسول | console users ----------------
    '/api/users' {
        return @{ users = @(Get-LBWebUserList -StateDir $sd); mode = [string](Get-LBAuthConfig $cfg).Mode }
    }
    '/api/users/add' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Add-LBWebUser -StateDir $sd -Name ([string]$body.name) -Password ([string]$body.password) -Role ([string]$body.role) | Out-Null
        Write-LBWebAudit -User $User -Message ("console user added: {0}" -f $body.name)
        return @{ ok = $true }
    }
    '/api/users/password' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Set-LBWebUserPassword -StateDir $sd -Name ([string]$body.name) -Password ([string]$body.password) | Out-Null
        Write-LBWebAudit -User $User -Message ("console user password reset: {0}" -f $body.name)
        return @{ ok = $true }
    }
    '/api/users/state' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        $dis = $null; if ($null -ne $body.disabled) { $dis = [bool]$body.disabled }
        Set-LBWebUserState -StateDir $sd -Name ([string]$body.name) -Role ([string]$body.role) -Disabled $dis | Out-Null
        Write-LBWebAudit -User $User -Message ("console user updated: {0}" -f $body.name)
        return @{ ok = $true }
    }
    '/api/users/remove' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Remove-LBWebUser -StateDir $sd -Name ([string]$body.name) | Out-Null
        Write-LBWebAudit -User $User -Message ("console user removed: {0}" -f $body.name)
        return @{ ok = $true }
    }
    '/api/users/2fa/disable' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Disable-LBUser2FA -StateDir $sd -Name ([string]$body.name) -Which 'all' | Out-Null
        Write-LBWebAudit -User $User -Message ("2FA reset for: {0}" -f $body.name)
        return @{ ok = $true }
    }
    # ---------------- احراز دومرحله‌ایِ کاربرِ جاری | current user's 2FA ----------------
    '/api/me/2fa' {
        $me = $null; try { $me = Get-LBWebUser -StateDir $sd -Name $User } catch { }
        if (-not $me) { return @{ isConsoleUser = $false; on = $false; totp = $false; email = $false; emailAddr = '' } }
        $s = Get-LBUser2FA -StateDir $sd -Name $User
        return @{ isConsoleUser = $true; on = [bool]$s.on; totp = [bool]$s.totp; email = [bool]$s.email; emailAddr = [string]$s.emailAddr }
    }
    '/api/me/2fa/totp/start' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        $r = Start-LBUserTotp -StateDir $sd -Name $User
        return @{ ok = $true; secret = [string]$r.secret; uri = [string]$r.uri }
    }
    '/api/me/2fa/totp/confirm' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Confirm-LBUserTotp -StateDir $sd -Name $User -Code ([string]$body.code) | Out-Null
        Write-LBWebAudit -User $User -Message 'enabled TOTP 2FA'
        return @{ ok = $true }
    }
    '/api/me/2fa/email' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Set-LBUserEmail2FA -StateDir $sd -Name $User -Email ([string]$body.email) -Enable ($body.enable -eq $true) | Out-Null
        Write-LBWebAudit -User $User -Message ("email 2FA " + $(if ($body.enable -eq $true) { 'enabled' } else { 'disabled' }))
        return @{ ok = $true }
    }
    '/api/me/2fa/disable' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Disable-LBUser2FA -StateDir $sd -Name $User -Which ([string]$(if ($body.which) { $body.which } else { 'all' })) | Out-Null
        Write-LBWebAudit -User $User -Message 'disabled 2FA'
        return @{ ok = $true }
    }
    # ---------------- دسترسیِ راه‌دور | remote access (LAN / internet NAT) ----------------
    '/api/remote' {
        Use-LBModule 'LogBok.Remote' 'Get-LBRemoteStatus'
        $r = $null; try { $r = Get-LBRemoteStatus -Config $cfg } catch { $r = @{ mode = 'local'; error = $_.Exception.Message } }
        return $r
    }
    '/api/remote/apply' {
        if ($Method -ne 'POST') { return @{ __status = 405; error = 'POST only' } }
        Use-LBModule 'LogBok.Remote' 'Get-LBRemoteStatus'
        $mode = [string]$body.mode; if ($mode -notin @('local', 'lan', 'internet')) { throw 'invalid mode' }
        $ext = [int]$body.externalPort
        $ips = @(Get-LBArr $body.allowedIps)
        $port = 8686; try { if ($cfg.Web -and $cfg.Web.Port) { $port = [int]$cfg.Web.Port } } catch { }
        $r = Set-LBRemoteAccess -Config $cfg -StateDir $sd -Mode $mode -ExternalPort $ext -AllowedIps $ips -Port $port
        Write-LBWebAudit -User $User -Message ("remote access set to {0} (ext {1})" -f $mode, $ext)
        return $r
    }
    default { return @{ __status = 404; error = "unknown endpoint: $Path" } }
    }
}

# ---------------------------------------------------------------------------
#  پردازشِ یک درخواست | handle one request
# ---------------------------------------------------------------------------
function Invoke-LBWebRequest {
    param($Ctx)
    $req = $Ctx.Request
    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod
    $cfg = $null; try { $cfg = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1') -Raw } catch { $cfg = @{} }
    $loginOn = $false; try { $loginOn = [bool](Get-LBAuthConfig $cfg).Enabled } catch { $loginOn = $false }
    $sd = $null; try { $sd = Get-LBStateDir -Config $cfg -Root $script:Root } catch { }

    # ---- فایل‌های رابط (بدونِ داده) همیشه سرو می‌شوند؛ سپس JS از /api/meta می‌پرسد ----
    if ($method -eq 'GET' -and $path -notlike '/api/*') {
        if (-not (Send-LBStatic -Ctx $Ctx -Path $path)) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'not found' } -Status 404 }
        return
    }
    if ($path -notlike '/api/*') { Send-LBJson -Ctx $Ctx -Obj @{ error = 'not found' } -Status 404; return }
    if ($method -ne 'GET' -and $method -ne 'POST') { Send-LBJson -Ctx $Ctx -Obj @{ error = 'method not allowed' } -Status 405; return }

    # ---- هم‌میزبانیِ هر POST (شاملِ ورود) | same-origin guard for every POST ----
    if ($method -eq 'POST') {
        $origin = $req.Headers['Origin']
        if ($origin) { try { $o = [Uri]$origin; if ($o.Authority -ne $req.Url.Authority) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'cross-origin request rejected' } -Status 403; return } } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = 'bad origin' } -Status 403; return } }
    }

    $authUser = ''; $authRole = 'admin'
    if ($loginOn) {
        $sid = Get-LBCookie -Request $req -Name 'lbsid'
        $sess = $null; if ($sid -and $sd) { $sess = Get-LBWebSession -StateDir $sd -Id $sid -Config $cfg -Slide }
        $needSetup = $true; if ($sd) { try { $needSetup = Test-LBNeedsSetup $sd } catch { } }
        # نقاطِ بازِ قبل از ورود | endpoints reachable before login
        if ($path -eq '/api/setup' -and $method -eq 'POST') { Invoke-LBLoginSetup -Ctx $Ctx -Req $req -Cfg $cfg -Sd $sd -NeedSetup $needSetup; return }
        elseif ($path -eq '/api/login' -and $method -eq 'POST') { Invoke-LBLogin -Ctx $Ctx -Req $req -Cfg $cfg -Sd $sd; return }
        elseif ($path -eq '/api/login/2fa' -and $method -eq 'POST') { Invoke-LB2FA -Ctx $Ctx -Req $req -Cfg $cfg -Sd $sd; return }
        elseif ($path -eq '/api/logout' -and $method -eq 'POST') {
            if ($sid -and $sd) { try { Remove-LBWebSession -StateDir $sd -Id $sid } catch { } }
            Send-LBJson -Ctx $Ctx -Obj @{ ok = $true } -Cookie 'lbsid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'; return
        }
        elseif ($path -eq '/api/meta' -and $method -eq 'GET' -and -not $sess) {
            Send-LBJson -Ctx $Ctx -Obj (Get-LBMetaPublic -Config $cfg -NeedSetup $needSetup); return
        }
        # بقیهٔ API نیازمندِ نشستِ معتبر | everything else needs a valid session
        if (-not $sess) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'auth'; authed = $false; needSetup = $needSetup } -Status 401; return }
        $authUser = [string]$sess.user; $authRole = [string]$sess.role
    }
    else {
        # ---- ورود خاموش: مجوزدهیِ یکپارچهٔ ویندوز (رفتارِ قبلی) ----
        $auth = Test-LBWebAuthorized -Ctx $Ctx -Config $cfg
        if (-not $auth.Ok) {
            $msg = "Access denied: only local Administrators can use the LogBok console ($($auth.User)) / فقط مدیرانِ این سرور"
            Send-LBBytes -Ctx $Ctx -Bytes ([Text.Encoding]::UTF8.GetBytes($msg)) -Type 'text/plain; charset=utf-8' -Status 403
            return
        }
        $authUser = $auth.User
    }

    # ---- ضدِ CSRF: توکنِ هم‌نشست | CSRF token on authenticated POSTs ----
    if ($method -eq 'POST') {
        $tok = $req.Headers['X-LogBok-Token']
        if ($tok -ne $script:Token) { Send-LBJson -Ctx $Ctx -Obj @{ error = 'invalid token — reload the page / صفحه را دوباره باز کنید' } -Status 403; return }
    }
    # ---- نقشِ فقط‌خواندنی چیزی را تغییر نمی‌دهد | read-only role may not POST ----
    if ($authRole -eq 'viewer' -and $method -eq 'POST' -and $path -ne '/api/logout') {
        Send-LBJson -Ctx $Ctx -Obj @{ error = 'read-only account / حسابِ فقط‌خواندنی اجازهٔ تغییر ندارد' } -Status 403; return
    }
    # دانلودِ بستهٔ ایجنت | agent package downloads (binary, not JSON)
    if ($method -eq 'GET' -and $path -eq '/api/report/csv') {
        try {
            $cfgR = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
            $q = $req.QueryString
            $rb = [pscustomobject]@{ hours = [int]$q['hours']; from = [string]$q['from']; to = [string]$q['to'] }
            $rg = Get-LBWebRange -Body $rb
            $rid = [string]$q['id']; if ($rid -notmatch '^[a-z0-9\-]{2,40}$') { throw 'invalid report' }
            $r = Invoke-LBReport -Config $cfgR -Id $rid -From $rg.From -To $rg.To -HostLike ([string]$q['host']) -UserLike ([string]$q['user']) -Text ([string]$q['text']) -Max 100000 -Lang (Get-LBWebLang -Config $cfgR)
            $bytes = (New-Object Text.UTF8Encoding($true)).GetPreamble() + (New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-LBReportCsv $r))
            Send-LBBytes -Ctx $Ctx -Bytes ([byte[]]$bytes) -Type 'text/csv; charset=utf-8' -Download ('LogBok-{0}-{1}.csv' -f $rid, (Get-Date).ToString('yyyyMMdd-HHmm', $script:Inv))
            Write-LBWebAudit -User $authUser -Message "report exported: $rid"
        } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
        return
    }
    # فایلِ تنظیمِ ایجنتِ EXE برای همین سرور (نشانی + توکنِ ثبت‌نام) | LogBokAgent.config for this server (address + enrollment token)
    if ($method -eq 'GET' -and $path -eq '/api/agent/native/config') {
        try {
            $cfgC = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
            $sdC = Get-LBStateDir -Config $cfgC -Root $script:Root
            $enrC = Get-LBEnrollInfo -StateDir $sdC
            if (-not (Test-LBEnrollValid $enrC)) { throw 'توکنِ نصب آماده نیست (در «تنظیماتِ ایجنت» بسازید/تمدید کنید) | install token not ready (create or renew it under Agent settings)' }
            $ciC = Get-LBCollectorInfo -Config $cfgC
            $colC = [string]$req.QueryString['collector']
            if ($colC -and -not (Test-LBAgentAddress $colC)) { throw "invalid collector: $colC" }
            if (-not $colC) { $colC = [string]$ciC.Default }
            $ipsC = @($ciC.Ips); if ($colC -match '^\d+\.\d+\.\d+\.\d+$' -and $ipsC -notcontains $colC) { $ipsC = @($colC) + $ipsC }
            $namesC = @(@($colC) + @($ciC.Names) | Where-Object { $_ -and $_ -notmatch '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -Unique)
            $portC = 8687; try { if ($cfgC.Agent -and $cfgC.Agent.IngestPort) { $portC = [int]$cfgC.Agent.IngestPort } } catch { }
            $txtC = @(
                ('# LogBokAgent.config - LogBok server: {0} - created {1}' -f $env:COMPUTERNAME, (Get-Date).ToString('yyyy-MM-dd HH:mm', $script:Inv)),
                '# Put this file next to LogBokAgent.exe. The enrollment token is removed automatically after the first connection.',
                ('Collector = {0}' -f $colC),
                ('CollectorNames = {0}' -f ($namesC -join ', ')),
                ('CollectorIps = {0}' -f ($ipsC -join ', ')),
                ('IngestPort = {0}' -f $portC),
                ('EnrollToken = {0}' -f ([string]$enrC.Token -replace '[^0-9a-fA-F]', ''))
            ) -join "`r`n"
            Send-LBBytes -Ctx $Ctx -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($txtC + "`r`n")) -Type 'application/octet-stream' -Download 'LogBokAgent.config'
            Write-LBWebAudit -User $authUser -Message 'LogBokAgent.config (EXE agent) downloaded'
        } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
        return
    }
    if ($method -eq 'GET' -and ($path -eq '/api/agent/package' -or $path -eq '/api/agent/linux')) {
        try {
            $col = [string]$req.QueryString['collector']
            if ($col -and -not (Test-LBAgentAddress $col)) { throw "invalid collector: $col" }
            if ($path -eq '/api/agent/package') {
                $cfgP = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
                $zf = Join-Path $script:Root '_Agents\Windows\LogBok-Agent.zip'
                if (-not $col) { [void](Update-LBAgentPackages -InstallDir $script:Root -Config $cfgP) }
                $bytes = if (-not $col -and (Test-Path $zf)) { [IO.File]::ReadAllBytes($zf) } else { New-LBAgentZip -InstallDir $script:Root -Collector $col }
                Send-LBBytes -Ctx $Ctx -Bytes $bytes -Type 'application/zip' -Download 'LogBok-Agent.zip'
            } else {
                $cfgL = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1')
                $sh = New-LBLinuxAgentScript -Collector $col -Config $cfgL
                Send-LBBytes -Ctx $Ctx -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($sh)) -Type 'text/x-shellscript; charset=utf-8' -Download 'install-logbok-agent.sh'
            }
            Write-LBWebAudit -User $authUser -Message "agent package downloaded: $path"
        } catch { Send-LBJson -Ctx $Ctx -Obj @{ error = $_.Exception.Message } -Status 400 }
        return
    }
    # درخواست‌های GET به /api/mail و /api/guard هم مجاز است | GET+POST share some routes
    try {
        $res = Invoke-LBWebApi -Ctx $Ctx -Path $path -Method $method -User $authUser
        $st = 200
        if ($res -is [System.Collections.IDictionary] -and $res.Contains('__status')) { $st = [int]$res['__status']; $res.Remove('__status') }
        Send-LBJson -Ctx $Ctx -Obj $res -Status $st
    } catch {
        $m = $_.Exception.Message
        try { Write-LogBokLog -Message ("web console error on {0}: {1}" -f $path, $m) -Level WARN } catch { }
        Send-LBJson -Ctx $Ctx -Obj @{ error = $m } -Status 400
    }
}

# ---------------------------------------------------------------------------
#  سرور | server loop
# ---------------------------------------------------------------------------
function Initialize-LBWebWorker {
    param([string]$Token, [bool]$TestMode)
    $script:Token = $Token; $script:TestMode = $TestMode
    if (-not $script:WorkerReady) { Import-LBWebModules; $script:WorkerReady = $true }
}

function Start-LBWebServer {
    param([int]$Port = 8686, [ValidateSet('local','lan')][string]$Listen = 'local', [switch]$TestMode, [int]$MaxRequests = 0, [int]$Workers = 6)
    $script:TestMode = [bool]$TestMode
    $b = New-Object byte[] 24; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
    $script:Token = -join ($b | ForEach-Object { $_.ToString('x2') })
    Import-LBWebModules
    $l = New-Object Net.HttpListener
    if ($Listen -eq 'lan') { $l.Prefixes.Add("http://+:$Port/") }
    else { $l.Prefixes.Add("http://localhost:$Port/"); $l.Prefixes.Add("http://127.0.0.1:$Port/") }
    # وقتی ورودِ کاربر/رمز روشن است، لیسنر باید Anonymous باشد تا صفحهٔ ورود در دسترس باشد؛
    # کنترلِ دسترسی با نشستِ کوکی انجام می‌شود. در غیرِ این صورت، احرازِ یکپارچهٔ ویندوز.
    $loginOn = $false; try { $lc = Get-LogBokConfig -Path (Join-Path $script:Root 'config.psd1') -Raw; $loginOn = [bool](Get-LBAuthConfig $lc).Enabled } catch { $loginOn = $false }
    if ($TestMode -or $loginOn) { $l.AuthenticationSchemes = [Net.AuthenticationSchemes]::Anonymous }
    else { $l.AuthenticationSchemes = [Net.AuthenticationSchemes]::IntegratedWindowsAuthentication }
    $l.Start()

    # کارگرهای موازی: درخواستِ کند (مثلاً آزمونِ ارتباط) بقیهٔ تب‌ها را معطل نمی‌کند
    # parallel workers: one slow request no longer blocks every other tab
    $shared = [hashtable]::Synchronized(@{})
    $global:LBWebShared = $shared
    $pool = $null
    if ($Workers -gt 1) {
        try {
            $iss = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            if ([Environment]::OSVersion.Platform -eq 'Win32NT') { try { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass } catch { } }
            $iss.Variables.Add((New-Object Management.Automation.Runspaces.SessionStateVariableEntry('LBWebShared', $shared, 'LogBok web shared cache')))
            [void]$iss.ImportPSModule([string[]]@((Join-Path $script:Root 'LogBok.Core.psm1'), (Join-Path $script:Root 'LogBok.Web.psm1')))
            $pool = [runspacefactory]::CreateRunspacePool(1, $Workers, $iss, $Host)
            $pool.Open()
        } catch { Write-Host ("worker pool unavailable, serving sequentially: {0}" -f $_.Exception.Message); $pool = $null }
    }
    Write-Host ("LogBok web console listening on {0} (auth: {1}, workers: {2})" -f (($l.Prefixes | ForEach-Object { $_ }) -join ', '), $l.AuthenticationSchemes, $(if ($pool) { $Workers } else { 1 }))
    $worker = @'
param($c, $t, $m)
try {
    if ($m -and $env:LB_WEB_MOCKS -and -not $global:LBMocked) { . $env:LB_WEB_MOCKS; $global:LBMocked = $true }
    Initialize-LBWebWorker -Token $t -TestMode $m; Invoke-LBWebRequest -Ctx $c }
catch { try { $c.Response.StatusCode = 500; $c.Response.Close() } catch { } }
'@
    $busy = New-Object System.Collections.ArrayList
    $n = 0
    # گرم‌کردنِ کش: امروز و دیروز در پس‌زمینه تجزیه می‌شوند تا اولین گزارش/جست‌وجو معطل نشود
    # warm-up: parse today and yesterday in the background so the first report/search is instant
    # هر کارگر یک‌بار گرم می‌شود: کامپایلِ APIِ نشست‌ها (WTS) و تجزیهٔ آرشیوِ امروز/دیروز، تا اولین کلیکِ کاربر معطل نشود
    # warm EVERY worker once at startup: compile the sessions (WTS) type and parse today/yesterday, so the first click isn't slow
    if ($pool) {
        for ($wi = 0; $wi -lt $Workers; $wi++) {
            try {
                $wu = [powershell]::Create(); $wu.RunspacePool = $pool
                [void]$wu.AddScript({
                    param($t, $m, $doArchive)
                    try { Initialize-LBWebWorker -Token $t -TestMode $m } catch { }
                    try { [void](Initialize-LBWts) } catch { }
                    if ($doArchive) { try { $cfgW = Get-LogBokConfig; $dirW = Get-LBArchiveDir -Config $cfgW; foreach ($dd in 0, 1) { $fW = Join-Path $dirW ('events-' + (Get-Date).AddDays(-$dd).ToString('yyyy-MM-dd') + '.ndjson'); if (Test-Path $fW) { [void](Get-LBArchiveDayRecords -File $fW) } } } catch { } }
                    Start-Sleep -Milliseconds 250   # نگه‌داشتنِ کوتاهِ رانسپیس تا کارگرِ دیگری همین را دوباره کامپایل نکند | briefly hold the runspace so another job lands on a different one
                }).AddArgument($script:Token).AddArgument([bool]$TestMode).AddArgument([bool]($wi -eq 0))
                [void]$busy.Add(@{ P = $wu; H = $wu.BeginInvoke() })
            } catch { }
        }
    }
    try {
        while ($l.IsListening) {
            $ctx = $null
            try { $ctx = $l.GetContext() } catch { break }
            for ($i = $busy.Count - 1; $i -ge 0; $i--) {
                $x = $busy[$i]
                if ($x.H.IsCompleted) { try { [void]$x.P.EndInvoke($x.H) } catch { }; $x.P.Dispose(); $busy.RemoveAt($i) }
            }
            if ($pool) {
                $ps = [powershell]::Create(); $ps.RunspacePool = $pool
                [void]$ps.AddScript($worker).AddArgument($ctx).AddArgument($script:Token).AddArgument([bool]$script:TestMode)
                [void]$busy.Add(@{ P = $ps; H = $ps.BeginInvoke() })
            } else {
                try { Invoke-LBWebRequest -Ctx $ctx } catch { try { Send-LBJson -Ctx $ctx -Obj @{ error = $_.Exception.Message } -Status 500 } catch { } }
            }
            $n++
            if ($MaxRequests -gt 0 -and $n -ge $MaxRequests) { break }
        }
    } finally {
        $deadline = (Get-Date).AddSeconds(60)
        foreach ($x in @($busy)) { while (-not $x.H.IsCompleted -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }; try { [void]$x.P.EndInvoke($x.H) } catch { }; try { $x.P.Dispose() } catch { } }
        if ($pool) { try { $pool.Close(); $pool.Dispose() } catch { } }
        try { $l.Stop(); $l.Close() } catch { }
    }
}

Export-ModuleMember -Function Start-LBWebServer, Initialize-LBWebWorker, Invoke-LBWebRequest, Invoke-LBWebApi, Format-LBTxt, Format-LBDetail, Search-LBArchiveRecent, Get-LBEntities, ConvertTo-LBWebFinding
