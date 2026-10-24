# ==========================================================================
#  Run-ADReport.ps1 - ساخت گزارشِ وضعیتِ اکتیودایرکتوری (HTML) و ایمیل
#  روی سرور/DC با RSAT اجرا شود. مثال:  .\Run-ADReport.ps1 -StaleDays 90
# ==========================================================================
param([int]$StaleDays=90,[switch]$NoMail)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')      -Force
Import-Module (Join-Path $root 'LogBok.ADReports.psm1') -Force
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
function Enc($s){ if($null -eq $s){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$cfg = Get-LogBokConfig
$brand = if ($cfg.Brand) { $cfg.Brand } else { @{ NameEn='LogBok'; Brass='#C9A24B'; Mint='#4FD1B5'; InkTeal='#0E2529' } }
$ink = if ($brand.InkTeal) { $brand.InkTeal } else { '#0E2529' }

if (-not (Test-LBADModule)) {
    Write-Host "ماژولِ ActiveDirectory در دسترس نیست. این گزارش باید روی DC یا سیستمی با RSAT اجرا شود." -ForegroundColor Yellow
    return
}

$stale = @(Get-LBStaleAccounts -Days $StaleDays)
$dislk = @(Get-LBDisabledLocked)
$pwRep = @(Get-LBPasswordReport)
$priv  = @(Get-LBPrivilegedMembers)
$neverExp = @($pwRep | Where-Object { $_.PasswordNeverExpires })

function Tbl($rows,$cols){ $h='<tr>'; foreach($c in $cols){$h+="<th>$($c.h)</th>"}; $h+='</tr>'; foreach($r in $rows){ $h+='<tr>'; foreach($c in $cols){ $h+="<td>$(Enc ($r.($c.p)))</td>" }; $h+='</tr>' }; if(-not $rows){ $h+="<tr><td colspan='$($cols.Count)' style='text-align:center;color:#889'>—</td></tr>" }; return $h }

$sStale = Tbl ($stale|Select-Object -First 200) @(@{h='کاربر';p='SamAccountName'},@{h='نام';p='Name'},@{h='آخرین ورود';p='LastLogonDate'})
$sDis   = Tbl ($dislk|Select-Object -First 200) @(@{h='کاربر';p='SamAccountName'},@{h='نام';p='Name'},@{h='وضعیت';p='State'})
$sNever = Tbl ($neverExp|Select-Object -First 200) @(@{h='کاربر';p='SamAccountName'},@{h='نام';p='Name'},@{h='آخرین تغییرِ رمز';p='PasswordLastSet'})
$sPriv  = Tbl ($priv) @(@{h='گروه';p='Group'},@{h='عضو';p='Member'},@{h='نام';p='Name'},@{h='نوع';p='Class'})

$html=@"
<!DOCTYPE html><html dir="rtl" lang="fa"><head><meta charset="utf-8"><title>گزارش وضعیت AD — LogBok</title>
<style>
 body{font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:rtl;color:#13272B;background:#f4f6f8;margin:0;padding:24px;line-height:1.8}
 .sheet{max-width:960px;margin:0 auto;background:#fff;border-radius:14px;padding:32px 38px;box-shadow:0 2px 12px #0001}
 .hd{display:flex;align-items:center;gap:12px;border-bottom:2px solid $($brand.Brass);padding-bottom:14px;margin-bottom:6px}
 .hd .t{font-size:20px;font-weight:700;color:$ink}
 .sum{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
 .kpi{flex:1;min-width:120px;background:#f6f8fa;border-radius:10px;padding:12px;text-align:center}
 .kpi .v{font-size:24px;font-weight:700}.kpi .l{font-size:12px;color:#667}
 h2{font-size:15px;color:$ink;margin:20px 0 6px;border-right:3px solid $($brand.Brass);padding-right:8px}
 table{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}
 th,td{text-align:right;padding:6px 8px;border-bottom:1px solid #e3e8ea} th{background:$ink;color:#fff;font-weight:500}
 .foot{color:#99a;font-size:11px;margin-top:18px}
</style></head><body><div class="sheet">
  <div class="hd"><svg width="38" height="38" viewBox="8 8 48 48" aria-hidden="true"><rect x="14" y="12" width="36" height="40" rx="4.5" fill="none" stroke="$($brand.Brass)" stroke-width="2.4"/><polyline points="27,30 31,30 34,23 38,38 41,30 45,30" fill="none" stroke="$($brand.Mint)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div><div class="t">گزارش وضعیت اکتیودایرکتوری</div><div style="font-size:12px;color:#667">تاریخ: $((Get-Date).ToString('yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture)) · آستانهٔ راکد: $StaleDays روز</div></div></div>
  <div class="sum">
    <div class="kpi"><div class="v" style="color:#B7791F">$($stale.Count)</div><div class="l">حساب راکد</div></div>
    <div class="kpi"><div class="v">$($dislk.Count)</div><div class="l">غیرفعال/قفل</div></div>
    <div class="kpi"><div class="v" style="color:#D64550">$($neverExp.Count)</div><div class="l">رمزِ بی‌انقضا</div></div>
    <div class="kpi"><div class="v">$($priv.Count)</div><div class="l">عضوِ گروه‌های ممتاز</div></div>
  </div>
  <h2>حساب‌های راکد (بیش از $StaleDays روز بدونِ ورود)</h2><table>$sStale</table>
  <h2>حساب‌های غیرفعال و قفل‌شده</h2><table>$sDis</table>
  <h2>رمزهای بی‌انقضا (ریسکِ امنیتی)</h2><table>$sNever</table>
  <h2>اعضای گروه‌های ممتاز</h2><table>$sPriv</table>
  <p class="foot">© BokerNet — $($brand.NameEn)</p>
</div></body></html>
"@
if (-not (Test-Path $cfg.Paths.Reports)) { New-Item -ItemType Directory -Path $cfg.Paths.Reports -Force | Out-Null }
$out = Join-Path $cfg.Paths.Reports ("AD-State_{0}.html" -f (Get-Date).ToString('yyyy-MM-dd_HH-mm',[Globalization.CultureInfo]::InvariantCulture))
$html | Set-Content -Path $out -Encoding UTF8
Write-Host "گزارش وضعیت AD ساخته شد | AD state report: $out" -ForegroundColor Green
if (-not $NoMail) { try { Send-LogBokMail -Subject "گزارش وضعیت AD — راکد:$($stale.Count) بی‌انقضا:$($neverExp.Count)" -Body $html -Html -Attachments @($out) -Config $cfg | Out-Null } catch {} }
