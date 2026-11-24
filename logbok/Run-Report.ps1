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
