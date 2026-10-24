# ==========================================================================
#  Run-Realtime.ps1 - اجراکنندهٔ بلادرنگ (هر ۲ دقیقه توسط Task Scheduler)
#  یافته‌های بحرانی (حمله، خاموشی فایروال/دیفندر، قفل کاربر، توقف سرویس،
#  حذف انبوه فایل) را بلافاصله و با ضدِسیل ایمیل می‌کند.
# ==========================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')      -Force
Import-Module (Join-Path $root 'LogBok.Detectors.psm1') -Force
Import-Module (Join-Path $root 'LogBok.License.psm1')   -Force

$cfg   = Get-LogBokConfig
$state = Get-LogBokState -Config $cfg

# --- بررسی لایسنس | license gate ---
$lic = Test-LogBokLicense -Config $cfg
if (-not $lic.Valid) {
    Write-LogBokLog -Message "لایسنس نامعتبر ($($lic.Reason)) — موتور متوقف شد. | License invalid: $($lic.Reason)" -Level ERROR -Config $cfg
    # مشکلِ لایسنس روزی یک‌بار ایمیل می‌شود (نه هر ۱۵ دقیقه)؛ خطای موقتِ خواندنِ سخت‌افزار فقط اگر بیش از ۲۴ ساعت ادامه یابد
    $mailIt = $true
    if ($lic.Reason -eq 'DeviceUnknown') {
        if (-not $state.ContainsKey('DeviceUnknownSince')) { $state['DeviceUnknownSince'] = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture); Save-LogBokState -State $state -Config $cfg }
        $since = ConvertTo-LBDate ([string]$state['DeviceUnknownSince'])
        if ($since -and $since -gt (Get-Date).AddHours(-24)) { $mailIt = $false }
    }
    if ($mailIt -and (Test-LogBokThrottle -Key "license::$($lic.Reason)" -State $state -Config $cfg -Minutes 1440)) {
        $msg = (Get-LogBokLicenseReasonText -License $lic -Lang 'both') +
               "`r`n`r`nفعال‌سازی: C:\Scripts\LogBok\LogBok-Activate.ps1 (یا کنسول ← فعال‌سازی) | Activate: LogBok-Activate.ps1 or Console → Activation"
        Send-LogBokMail -Subject "⚠ License problem / مشکل لایسنس" -Body $msg -Config $cfg | Out-Null
        Set-LogBokThrottle -Key "license::$($lic.Reason)" -State $state
        Save-LogBokState -State $state -Config $cfg
    }
    return
}

if ($state.ContainsKey('DeviceUnknownSince')) { $state.Remove('DeviceUnknownSince') }

# بازهٔ بررسی: از زمان آخرین اجرا (یا ۱۰ دقیقهٔ اخیر در اولین بار)
$lastRun = $null
if ($state.ContainsKey('LastRealtimeRun')) { $v = $state['LastRealtimeRun']; $lastRun = if ($v -is [datetime]) { $v } else { ConvertTo-LBDate ([string]$v) } }
if (-not $lastRun -or $lastRun -lt (Get-Date).AddHours(-6)) { $lastRun = (Get-Date).AddMinutes(-10) }   # خاموشیِ طولانی: سیلِ رویدادِ قدیمی نه
# کمی هم‌پوشانی برای از دست نرفتن رویداد
$start = $lastRun.AddMinutes(-1)

Write-LogBokLog -Message "اجرای بلادرنگ؛ بازه از $start" -Config $cfg

try {
    # همیشه آرایه؛ با یک یافتهٔ تنها، += بعدی خطای op_Addition می‌داد | always an array: a single finding made later += fail (op_Addition)
    $findings = @(Invoke-LogBokDetectors -Config $cfg -Start $start)
} catch {
    Write-LogBokLog -Message "خطا در آشکارسازها: $($_.Exception.Message)" -Level ERROR -Config $cfg
    $findings = @()
}

# تحلیل رفتار (UEBA) — فقط خواندن خط‌پایه، بدون به‌روزرسانی | read-only anomalies
if ($cfg.Enabled.Behavior -ne $false) {
    try {
        Import-Module (Join-Path $root 'LogBok.Behavior.psm1') -Force
        $findings += @(Get-LogBokAnomalies -Config $cfg -Start $start)
    } catch { Write-LogBokLog -Message "خطا در تحلیل رفتار: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# لاگ‌های فایلیِ سفارشی (افزوده از کنسول/وب) | custom text-file logs
if (@($cfg.CustomSources | Where-Object { $_ -and [string]$_.Type -eq 'File' }).Count) {
    try { Import-Module (Join-Path $root 'LogBok.CustomSources.psm1') -Force -DisableNameChecking; $findings += @(Invoke-LBCustomFiles -Config $cfg) }
    catch { Write-LogBokLog -Message "خطا در لاگ‌های فایلیِ سفارشی: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# سلامت و امنیتِ سیستم‌های دارای ایجنت (هر مشکل روزی یک‌بار) | endpoint health & security findings
if (Test-Path (Join-Path (Get-LBStateDir -Config $cfg) 'push')) {
    try { Import-Module (Join-Path $root 'LogBok.Reports.psm1') -Force -DisableNameChecking; $findings += @(Get-LBEndpointFindings -Config $cfg) }
    catch { Write-LogBokLog -Message "خطا در سلامتِ سیستم‌ها: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# امنیتِ ایمیل (Exchange) — فقط روی سروری که Exchange نصب دارد | Mail Security (runs only on an Exchange server)
if ($cfg.Enabled.MailSec -ne $false) {
    try {
        Import-Module (Join-Path $root 'LogBok.MailSecurity.psm1') -Force -DisableNameChecking
        foreach ($x in @(Invoke-LBMailSecurityCycle -StateDir (Get-LBStateDir -Config $cfg) -Config $cfg -Start $start)) {
            $ft = $start; if (-not [datetime]::TryParse([string]$x.Time, [ref]$ft)) { $ft = Get-Date }
            $findings += (New-Finding -Category $x.Category -Severity $x.Severity -Machine $x.Machine -Time $ft -Title $x.Title -Details $x.Details -Key $x.Key)
        }
    } catch { Write-LogBokLog -Message "خطا در امنیتِ ایمیل: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# به‌روزرسانیِ خودکارِ سرور از فیدِ سازنده (HTTPS یا اشتراک) — امضاشده، با پشتیبان و بازگشتِ خودکار
# server self-update from the vendor feed (signed, backed up, auto-rollback on failure)
try {
    $feed = ''; try { $feed = [string]$cfg.Update.ServerFeed } catch { }
    if ($feed -and $cfg.Update.Enabled -ne $false) {
        $iv = if ($cfg.Update -and [int]$cfg.Update.IntervalHours -gt 0) { [int]$cfg.Update.IntervalHours } else { 6 }
        if (Test-LogBokThrottle -Key 'server-update' -State $state -Config $cfg -Minutes ($iv * 60)) {
            Import-Module (Join-Path $root 'LogBok.Update.psm1') -Force -DisableNameChecking
            $upd = Invoke-LBServerUpdate -InstallDir $root -Config $cfg
            if ($upd -and $upd.Count) { Write-LogBokLog -Message ("سرور به‌روزرسانی شد: {0} فایل | server self-updated: {1}" -f $upd.Count, ($upd -join ',')) -Config $cfg }
            Set-LogBokThrottle -Key 'server-update' -State $state; Save-LogBokState -State $state -Config $cfg
        }
    }
} catch { Write-LogBokLog -Message "خطا در به‌روزرسانیِ سرور: $($_.Exception.Message)" -Level WARN -Config $cfg }

# موتور همبستگی: ترکیبِ چند یافته در یک الگوی حمله | multi-stage correlation
if ($cfg.Enabled.Correlation -ne $false) {
    try {
        Import-Module (Join-Path $root 'LogBok.Correlation.psm1') -Force
        $corr = @(Invoke-LBCorrelation -Findings $findings)
        if ($corr.Count) { $findings += $corr }
    } catch { Write-LogBokLog -Message "خطا در همبستگی: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# غنی‌سازیِ شهرت/جغرافیای IP روی یافته‌های حمله | threat-intel IP enrichment
if ($cfg.Intel -and $cfg.Intel.Enabled) {
    try {
        Import-Module (Join-Path $root 'LogBok.Intel.psm1') -Force
        $attackCats = 'BruteForce','SqlLogin','IISAttack','FtpAttack'
        $findings = @($findings | ForEach-Object { if ($_.Category -in $attackCats) { Add-LBIntel -Config $cfg -Finding $_ } else { $_ } })
    } catch { Write-LogBokLog -Message "خطا در غنی‌سازیِ IP: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# برچسبِ MITRE روی یافته‌ها | tag findings with MITRE techniques
try { Import-Module (Join-Path $root 'LogBok.Mitre.psm1') -Force; $findings = @($findings | Add-LBMitreTag) } catch {}

# سپرِ مشترک: IPی که روی یک سیستم بلاک شد، برای همهٔ سیستم‌ها منتشر می‌شود (dist)
if ($cfg.Enabled.Guard -ne $false -and -not ($cfg.Guard -and $cfg.Guard.ShareBlocks -eq $false)) {
    try {
        Import-Module (Join-Path $root 'LogBok.Guard.psm1') -Force -DisableNameChecking
        $sharedN = Publish-LBGuardShared -InstallDir $root -Findings $findings -Config $cfg
    } catch { Write-LogBokLog -Message "خطا در سپرِ مشترک: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# امتیازِ ریسکِ کاربر/سیستم (UEBA) | risk scoring
if ($cfg.Enabled.Risk -ne $false) {
    try { Import-Module (Join-Path $root 'LogBok.Risk.psm1') -Force; Update-LBRisk -Config $cfg -Findings $findings | Out-Null }
    catch { Write-LogBokLog -Message "خطا در امتیازِ ریسک: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# میزِ رخداد: گروه‌بندیِ یافته‌ها در رخدادها | incident workbench
if ($cfg.Enabled.Incidents -ne $false) {
    try { Update-LBIncidents -Config $cfg -Findings $findings | Out-Null }
    catch { Write-LogBokLog -Message "خطا در میزِ رخداد: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# انبارِ جست‌وجوپذیرِ لاگ | searchable log archive
if ($cfg.Enabled.Archive -ne $false) {
    try {
        Import-Module (Join-Path $root 'LogBok.Archive.psm1') -Force
        $n = Invoke-LBArchiveIngest -Config $cfg -Start $start
        Write-LogBokLog -Message "انبارِ لاگ: $n رویداد افزوده شد" -Config $cfg
    } catch { Write-LogBokLog -Message "خطا در انبارِ لاگ: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

# تاریخچهٔ یافته‌ها با شناسه (برای باز کردنِ جزئیات در کنسولِ وب) | findings history
try { Import-Module (Join-Path $root 'LogBok.Findings.psm1') -Force -DisableNameChecking; [void](Save-LBFindings -Config $cfg -Findings $findings) }
catch { Write-LogBokLog -Message "خطا در ذخیرهٔ تاریخچهٔ یافته‌ها: $($_.Exception.Message)" -Level WARN -Config $cfg }

# ارسالِ هشدار طبقِ پروفایل‌های هشدار (گیرنده‌ها، شدت، دسته، سیستم، ساعتِ کاری)؛
# بدونِ پروفایل: مثلِ قبل، موارد بحرانی به Mail.To | routed alerts per alert profile
$critical = @($findings | Where-Object { $_.Severity -eq 'Critical' })
$sent = 0
try {
    Import-Module (Join-Path $root 'LogBok.Alerts.psm1') -Force -DisableNameChecking
    $sent = Send-LBRoutedAlerts -Config $cfg -Findings $findings -State $state
} catch { Write-LogBokLog -Message "خطا در ارسالِ هشدار: $($_.Exception.Message)" -Level WARN -Config $cfg }

$state['LastRealtimeRun'] = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
Save-LogBokState -State $state -Config $cfg
Write-LogBokLog -Message "پایان اجرای بلادرنگ؛ یافته=$($findings.Count) بحرانی=$($critical.Count) ایمیل=$sent" -Config $cfg
