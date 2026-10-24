# ==========================================================================
#  Run-Compliance.ps1 - گزارشِ انطباق (Compliance report)
#  یافته‌های بازهٔ موردنظر را به کنترل‌های یک چارچوب نگاشت می‌کند و یک گزارشِ
#  HTMLِ دوزبانه با وضعیتِ هر کنترل (یافته دارد؟ چند مورد؟) می‌سازد و ایمیل می‌کند.
#  مثال:  .\Run-Compliance.ps1 -Framework ISO27001 -Days 30
# ==========================================================================
param([ValidateSet('ISO27001','PCI-DSS','HIPAA','GDPR','SOX','Local')][string]$Framework='Local',[int]$Days=30,[switch]$NoMail,
      [switch]$Scheduled)   # -Scheduled: همهٔ چارچوب‌های Schedule.ComplianceFrameworks (توسط جابِ هفتگی)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')      -Force
Import-Module (Join-Path $root 'LogBok.Detectors.psm1') -Force
Import-Module (Join-Path $root 'LogBok.License.psm1')   -Force
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
function Enc($s){ if($null -eq $s){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$cfg = Get-LogBokConfig
$lic = Test-LogBokLicense -Config $cfg
if (-not $lic.Valid) { Write-Host "License invalid ($($lic.Reason)) — aborted." -ForegroundColor Red; return }

# اجرای زمان‌بندی‌شده: هر چارچوبِ config یک گزارش (فراخوانیِ بازگشتیِ همین اسکریپت)
if ($Scheduled) {
    $fws = @('Local'); $d = 7
    if ($cfg.Schedule) {
        if ($cfg.Schedule.ComplianceFrameworks) { $fws = @($cfg.Schedule.ComplianceFrameworks) }
        if ($cfg.Schedule.ComplianceDays) { $d = [int]$cfg.Schedule.ComplianceDays }
    }
    foreach ($fw in $fws) {
        try { & $MyInvocation.MyCommand.Path -Framework $fw -Days $d -NoMail:$NoMail }
        catch { Write-LogBokLog -Message "Compliance $fw : $($_.Exception.Message)" -Level ERROR -Config $cfg }
    }
    return
}

# نامِ دستهٔ یافته ← کلیدِ Enabled در config (برخی هم‌نام نیستند)
$catSwitch = @{ ActiveDirectory='ActiveDir'; Vulnerability='Scan'; FileSuspicion='FileScan'; ServiceHealth='Scan'
                Anomaly='Behavior'; Watchlist='Tracking'; AdminAction='Tracking'; AppChange='Tracking' }
function Test-CatActive($c){
    $k = if ($catSwitch.ContainsKey($c)) { $catSwitch[$c] } else { $c }
    if ($cfg.Enabled.ContainsKey($k)) { return ($cfg.Enabled[$k] -ne $false) }
    return $true
}

$tplFile = Join-Path $root 'compliance-templates.psd1'
if (-not (Test-Path $tplFile)) { throw "قالبِ انطباق یافت نشد: compliance-templates.psd1" }
$tpls = Import-PowerShellDataFile -Path $tplFile
if (-not $tpls.ContainsKey($Framework)) { throw "چارچوبِ ناشناخته: $Framework" }
$tpl = $tpls[$Framework]

$start = (Get-Date).AddDays(-$Days)
$findings = @()
try { $findings = Invoke-LogBokDetectors -Config $cfg -Start $start } catch {}
if ($cfg.Enabled.Behavior -ne $false) { try { Import-Module (Join-Path $root 'LogBok.Behavior.psm1') -Force; $findings += Get-LogBokAnomalies -Config $cfg -Start $start } catch {} }

$brand = if ($cfg.Brand) { $cfg.Brand } else { @{ NameEn='LogBok'; Brass='#C9A24B'; Mint='#4FD1B5'; InkTeal='#0E2529' } }
$ink = if ($brand.InkTeal) { $brand.InkTeal } else { '#0E2529' }
$rows=''; $covered=0
foreach ($ctl in $tpl.Controls) {
    $items = @($findings | Where-Object { $_.Category -in $ctl.cats })
    $crit  = @($items | Where-Object Severity -eq 'Critical').Count
    $n = $items.Count
    # «پوشش»: کنترلی که سازوکارِ پایشش فعال است «تحت‌پوشش» است؛ یافته‌ها شواهدِ آن.
    $active = $true
    foreach($c in $ctl.cats){ if(-not (Test-CatActive $c)){ $active=$false } }
    if ($active) { $covered++ }
    $state = if (-not $active) { @{t='پایش غیرفعال';c='#D64550'} }
             elseif ($crit -gt 0) { @{t="$crit یافتهٔ بحرانی";c='#B7791F'} }
             elseif ($n -gt 0) { @{t="$n یافته";c='#B7791F'} }
             else { @{t='بدون یافته (پایش فعال)';c='#0E8F79'} }
    $rows += "<tr><td class='id'>$(Enc $ctl.id)</td><td>$(Enc $ctl.name)</td><td class='mut'>$([string]::Join('، ',$ctl.cats))</td><td style='color:$($state.c);white-space:nowrap'>$($state.t)</td></tr>"
}
$pct = [int]($covered*100/[Math]::Max(1,$tpl.Controls.Count))

$html=@"
<!DOCTYPE html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<title>گزارش انطباق — $($tpl.Title)</title>
<style>
 body{font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:rtl;color:#13272B;background:#f4f6f8;margin:0;padding:24px;line-height:1.8}
 .sheet{max-width:900px;margin:0 auto;background:#fff;border-radius:14px;padding:34px 40px;box-shadow:0 2px 12px #0001}
 .hd{display:flex;align-items:center;gap:12px;border-bottom:2px solid $($brand.Brass);padding-bottom:16px;margin-bottom:8px}
 .hd .t{font-size:20px;font-weight:700;color:$ink} .hd .s{font-size:13px;color:#667}
 .sum{display:flex;gap:16px;margin:18px 0}
 .kpi{flex:1;background:#f6f8fa;border-radius:10px;padding:14px;text-align:center}
 .kpi .v{font-size:26px;font-weight:700}.kpi .l{font-size:12px;color:#667}
 table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
 th,td{text-align:right;padding:8px 8px;border-bottom:1px solid #e3e8ea} th{background:$ink;color:#fff;font-weight:500;font-size:12px}
 .id{font-weight:600;white-space:nowrap} .mut{color:#889;font-size:12px}
 .foot{color:#99a;font-size:11px;margin-top:20px}
</style></head><body><div class="sheet">
  <div class="hd">
    <svg width="40" height="40" viewBox="8 8 48 48" aria-hidden="true"><rect x="14" y="12" width="36" height="40" rx="4.5" fill="none" stroke="$($brand.Brass)" stroke-width="2.4"/><line x1="22" y1="12" x2="22" y2="52" stroke="$($brand.Brass)" stroke-width="1.5"/><line x1="27" y1="21" x2="45" y2="21" stroke="$($brand.Brass)" stroke-width="2.3" stroke-linecap="round"/><polyline points="27,30 31,30 34,23 38,38 41,30 45,30" fill="none" stroke="$($brand.Mint)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div><div class="t">گزارش انطباق — $(Enc $tpl.Title)</div><div class="s">بازهٔ $Days روز اخیر · تاریخ: $((Get-Date).ToString('yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture))</div></div>
  </div>
  <div class="sum">
    <div class="kpi"><div class="v" style="color:$ink">$pct%</div><div class="l">پوششِ کنترل‌ها</div></div>
    <div class="kpi"><div class="v">$($tpl.Controls.Count)</div><div class="l">کل کنترل‌ها</div></div>
    <div class="kpi"><div class="v" style="color:#0E8F79">$covered</div><div class="l">تحت‌پوشش</div></div>
  </div>
  <table><thead><tr><th>کنترل</th><th>شرح</th><th>دسته‌های پایش</th><th>وضعیت</th></tr></thead><tbody>$rows</tbody></table>
  <p class="foot">این گزارش شواهدِ پایشِ خودکار است و جایگزینِ ممیزیِ رسمی نیست. © BokerNet — $($brand.NameEn)</p>
</div></body></html>
"@
if (-not (Test-Path $cfg.Paths.Reports)) { New-Item -ItemType Directory -Path $cfg.Paths.Reports -Force | Out-Null }
$out = Join-Path $cfg.Paths.Reports ("Compliance_{0}_{1}.html" -f $Framework,(Get-Date).ToString('yyyy-MM-dd_HH-mm',[Globalization.CultureInfo]::InvariantCulture))
$html | Set-Content -Path $out -Encoding UTF8
Write-Host "گزارش انطباق ساخته شد | Compliance report: $out" -ForegroundColor Green
if (-not $NoMail) { try { Send-LogBokMail -Subject "گزارش انطباق $Framework — پوشش $pct%" -Body $html -Html -Attachments @($out) -Config $cfg | Out-Null } catch {} }
