# ==========================================================================
#  Run-Report.ps1 - گزارش‌گیر دوره‌ای (روزانه توسط جابِ DailyReport)
#  برای هر دسته‌ای که یافته دارد یک گزارش HTML جداگانه می‌سازد و:
#   - Report.Mode = 'Summary'     → یک ایمیلِ خلاصهٔ همهٔ دسته‌ها + پیوستِ گزارش‌های جداگانه (پیش‌فرض)
#   - Report.Mode = 'PerCategory' → برای هر دستهٔ دارای یافته یک ایمیلِ جداگانه
#  دسته‌های بدونِ یافته ایمیل نمی‌شوند (قبلاً روزانه ~۳۰ ایمیلِ خالی می‌رفت).
#  اجرای دستی برای بازهٔ دلخواه:  .\Run-Report.ps1 -Hours 168   (هفت روز)
# ==========================================================================
param([int]$Hours = 24, [switch]$NoMail)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')      -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.Detectors.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.License.psm1')   -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.Lang.psm1')      -Force -DisableNameChecking
function Enc($s){ if($null -eq $s){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$cfg = Get-LogBokConfig
$licGate = Test-LogBokLicense -Config $cfg
if (-not $licGate.Valid) { Write-LogBokLog -Message "License invalid ($($licGate.Reason)) — report aborted." -Level ERROR -Config $cfg; return }

$lang = Get-LogBokLang -Config $cfg
$isEn = $lang -eq 'en'
function L($fa,$en){ if ($isEn) { $en } elseif ($lang -eq 'fa') { $fa } else { "$fa / $en" } }
$dir = if ($isEn) { 'ltr' } else { 'rtl' }; $al = if ($isEn) { 'left' } else { 'right' }; $opp = if ($isEn) { 'right' } else { 'left' }
$b = if ($cfg.Brand) { $cfg.Brand } else { @{} }
$ink = if ($b.InkTeal) { $b.InkTeal } else { '#0E2529' }; $brass = if ($b.Brass) { $b.Brass } else { '#C9A24B' }; $mint = if ($b.Mint) { $b.Mint } else { '#4FD1B5' }
$bname = if ($b.NameEn) { $b.NameEn } else { 'LogBok' }
$mode = if ($cfg.Report -and $cfg.Report.Mode) { [string]$cfg.Report.Mode } else { 'Summary' }

$start = (Get-Date).AddHours(-$Hours)
$now = Get-LBDate 'yyyy-MM-dd HH:mm'
Write-LogBokLog -Message "گزارش‌گیری برای $Hours ساعت اخیر" -Config $cfg

try { $findings = @(Invoke-LogBokDetectors -Config $cfg -Start $start) }
catch { Write-LogBokLog -Message "خطا در آشکارسازها: $($_.Exception.Message)" -Level ERROR -Config $cfg; $findings = @() }

# تحلیل رفتار (UEBA) + به‌روزرسانیِ روزانهٔ خط‌پایه | anomalies + baseline learning
if ($cfg.Enabled.Behavior -ne $false) {
    try { Import-Module (Join-Path $root 'LogBok.Behavior.psm1') -Force -DisableNameChecking
          $findings += Get-LogBokAnomalies -Config $cfg -Start $start -UpdateBaseline }
    catch { Write-LogBokLog -Message "خطا در تحلیل رفتار: $($_.Exception.Message)" -Level WARN -Config $cfg }
}
try { Import-Module (Join-Path $root 'LogBok.Mitre.psm1') -Force -DisableNameChecking; $findings = @($findings | Add-LBMitreTag) } catch {}

$sevColor = @{ Critical='#C53030'; Warning='#B7791F'; Info='#2B6CB0' }
$sevTxt   = @{ Critical=(L 'بحرانی' 'Critical'); Warning=(L 'هشدار' 'Warning'); Info=(L 'اطلاع' 'Info') }
$css = @"
body{margin:0;padding:22px;background:#f2f5f6;font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:$dir;text-align:$al;color:#13272B}
.sheet{max-width:1100px;margin:0 auto;background:#fff;border:1px solid #e1e7e9;border-radius:12px;overflow:hidden}
.hd{background:$ink;color:#fff;padding:16px 22px;display:flex;align-items:center;gap:12px}
.hd .t{font-size:17px;font-weight:700}.hd .s{font-size:12px;opacity:.75}
.body{padding:18px 22px}
.kpis{display:flex;gap:10px;margin:0 0 16px;flex-wrap:wrap}
.kpi{flex:1;min-width:110px;background:#f6f8f9;border-radius:10px;padding:10px 14px}
.kpi .v{font-size:22px;font-weight:700}.kpi .l{font-size:11px;color:#6b7c80}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{background:#f0f4f5;color:#40565b;font-weight:600;text-align:$al;padding:8px;border-bottom:2px solid #e1e7e9}
td{padding:8px;border-bottom:1px solid #eef1f2;vertical-align:top;text-align:$al}
.sev{display:inline-block;border-radius:20px;padding:1px 9px;color:#fff;font-size:11px;white-space:nowrap}
.det{white-space:pre-wrap;color:#4a5d61;font-family:Consolas,monospace;font-size:11.5px}
.mitre{display:inline-block;background:#eef3ff;color:#2B4C9B;border-radius:4px;padding:0 5px;font-size:10.5px;margin-$($al):4px}
.foot{color:#8a999c;font-size:11px;padding:10px 22px;border-top:1px solid #eef1f2;background:#fafbfb}
"@
$logo = "<img src='data:image/png;base64,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' width='34' height='37' alt='LogBok'>"   # the BokerNet logo

function New-Page($title, $kpis, $content) {
@"
<!DOCTYPE html><html dir="$dir"><head><meta charset="utf-8"><title>$(Enc $title)</title><style>$css</style></head><body>
<div class="sheet">
 <div class="hd">$logo<div><div class="t">$(Enc $title)</div><div class="s">$(L 'بازه' 'Range'): $Hours $(L 'ساعت اخیر' 'hours') · $now · $(Enc $env:COMPUTERNAME)</div></div></div>
 <div class="body">$kpis$content</div>
 <div class="foot">$(L 'تولیدشده توسط' 'Generated by') $bname — BokerNet</div>
</div></body></html>
"@
}
function New-Kpis($items) {
    $c = @($items | Where-Object Severity -eq 'Critical').Count; $w = @($items | Where-Object Severity -eq 'Warning').Count
    "<div class='kpis'><div class='kpi'><div class='v' style='color:#C53030'>$c</div><div class='l'>$(L 'بحرانی' 'Critical')</div></div><div class='kpi'><div class='v' style='color:#B7791F'>$w</div><div class='l'>$(L 'هشدار' 'Warning')</div></div><div class='kpi'><div class='v'>$(@($items).Count)</div><div class='l'>$(L 'کل' 'Total')</div></div></div>"
}

if (-not (Test-Path $cfg.Paths.Reports)) { New-Item -ItemType Directory -Path $cfg.Paths.Reports -Force | Out-Null }
$stamp = Get-LBDate 'yyyy-MM-dd_HH-mm'
$files = @(); $summaryRows = ''; $sentCount = 0

foreach ($cat in (Get-LBCategoryKeys)) {
    $items = @($findings | Where-Object { $_.Category -eq $cat } | Sort-Object Time -Descending)
    if ($items.Count -eq 0) { continue }
    $title = Get-LBCategoryTitle -Category $cat -Config $cfg
    $rows = ''
    foreach ($it in ($items | Select-Object -First 2000)) {
        $t = if ($it.Time -is [datetime]) { Get-LBDate 'yyyy-MM-dd HH:mm:ss' $it.Time } else { [string]$it.Time }
        $mt = if ($it.Mitre) { "<span class='mitre'>$(Enc $it.Mitre)</span>" } else { '' }
        $rows += "<tr><td><span class='sev' style='background:$($sevColor[[string]$it.Severity])'>$($sevTxt[[string]$it.Severity])</span></td><td style='white-space:nowrap'>$t</td><td>$(Enc $it.Machine)</td><td>$(Enc $it.Title)$mt</td><td class='det'>$(Enc $it.Details)</td></tr>"
    }
    $tbl = "<table><thead><tr><th>$(L 'سطح' 'Severity')</th><th>$(L 'زمان' 'Time')</th><th>$(L 'سیستم' 'Host')</th><th>$(L 'رویداد' 'Event')</th><th>$(L 'جزئیات' 'Details')</th></tr></thead><tbody>$rows</tbody></table>"
    $html = New-Page "$bname — $title" (New-Kpis $items) $tbl
    $file = Join-Path $cfg.Paths.Reports ("{0}_{1}.html" -f $cat,$stamp)
    $html | Set-Content -Path $file -Encoding UTF8
    $files += $file
    $crit = @($items | Where-Object Severity -eq 'Critical').Count; $warn = @($items | Where-Object Severity -eq 'Warning').Count
    $summaryRows += "<tr><td style='font-weight:600'>$(Enc $title)</td><td style='color:#C53030;font-weight:700'>$crit</td><td style='color:#B7791F'>$warn</td><td>$($items.Count)</td><td class='det'>$(Enc (($items | Select-Object -First 1).Title))</td></tr>"
    if ($mode -eq 'PerCategory' -and -not $NoMail) {
        if (Send-LogBokMail -Subject ("{0} — {1}:{2} {3}:{4}" -f $title,(L 'بحرانی' 'critical'),$crit,(L 'هشدار' 'warning'),$warn) -Body $html -Html -Attachments @($file) -Config $cfg) { $sentCount++ }
    }
}

# ایمیلِ خلاصه | summary mail
if ($mode -ne 'PerCategory' -and -not $NoMail) {
    $content = if ($summaryRows) {
        "<table><thead><tr><th>$(L 'دسته' 'Category')</th><th>$(L 'بحرانی' 'Critical')</th><th>$(L 'هشدار' 'Warning')</th><th>$(L 'کل' 'Total')</th><th>$(L 'آخرین مورد' 'Latest')</th></tr></thead><tbody>$summaryRows</tbody></table><p style='color:#6b7c80;font-size:12px'>$(L 'جزئیاتِ هر دسته در فایلِ پیوست' 'Full details per category are attached.')</p>"
    } else { "<p style='color:#0E8F79;font-weight:600'>$(L 'در این بازه موردی ثبت نشد ✓' 'No findings in this period ✓')</p>" }
    $sum = New-Page ("$bname — " + (L 'گزارشِ روزانه' 'Daily report')) (New-Kpis $findings) $content
    $sumFile = Join-Path $cfg.Paths.Reports ("Summary_{0}.html" -f $stamp)
    $sum | Set-Content -Path $sumFile -Encoding UTF8
    $c = @($findings | Where-Object Severity -eq 'Critical').Count; $w = @($findings | Where-Object Severity -eq 'Warning').Count
    $att = @($files | Select-Object -First 25)
    if (Send-LogBokMail -Subject ("{0} — {1}:{2} {3}:{4}" -f (L 'گزارش روزانه' 'Daily report'),(L 'بحرانی' 'critical'),$c,(L 'هشدار' 'warning'),$w) -Body $sum -Html -Attachments $att -Config $cfg) { $sentCount++ }
}

# پاک‌سازی گزارش‌های قدیمی
$keep = if ($cfg.ReportRetentionDays) { [int]$cfg.ReportRetentionDays } else { 90 }
Get-ChildItem -Path $cfg.Paths.Reports -Filter '*.html' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne 'dashboard.html' -and $_.LastWriteTime -lt (Get-Date).AddDays(-$keep) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-LogBokLog -Message "گزارش‌گیری تمام شد؛ $($files.Count) گزارش، $sentCount ایمیل" -Config $cfg
