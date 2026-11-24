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
$logo = "<img src='data:image/png;base64,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' width='44' height='36' alt='LogBok'>"   # the BokerNet logo

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
