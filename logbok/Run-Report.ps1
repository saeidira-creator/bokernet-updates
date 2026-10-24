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
$logo = "<svg width='30' height='34' viewBox='12 9 40 46'><rect x='14' y='12' width='36' height='40' rx='4.5' fill='none' stroke='$brass' stroke-width='2.4'/><line x1='22' y1='12' x2='22' y2='52' stroke='$brass' stroke-width='1.5'/><polyline points='27,30 31,30 34,23 38,38 41,30 45,30' fill='none' stroke='$mint' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/></svg>"

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
