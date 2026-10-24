# ==========================================================================
#  Run-LicenseWatch.ps1 - پایشِ روزانهٔ انقضای لایسنس‌ها
#  هر روز اجرا می‌شود؛ از ۳۰ روز قبل از انقضا، هفته‌ای یک‌بار به مدیران ایمیل می‌زند.
#  Daily job; from 30 days before expiry, mails admins once a week.
#  دستی | manual:  .\Run-LicenseWatch.ps1 -Force   (ارسالِ فوری)
#                  .\Run-LicenseWatch.ps1 -List    (فقط نمایش)
# ==========================================================================
param([switch]$Force,[switch]$List)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')         -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.LicenseWatch.psm1') -Force -DisableNameChecking
$cfg = Get-LogBokConfig
try {
    $r = Invoke-LBLicenseWatch -Config $cfg -Root $root -Force:$Force -NoMail:$List
    $r.Items | Sort-Object DaysLeft | Format-Table Name, Type, Expiry, DaysLeft, Status -AutoSize | Out-String | Write-Host
    if ($r.Sent) { Write-LogBokLog -Message "LicenseWatch: ایمیلِ یادآوریِ تمدید ارسال شد ($($r.Alerting.Count) مورد)" -Config $cfg }
    elseif ($r.Alerting.Count -gt 0) { Write-LogBokLog -Message "LicenseWatch: $($r.Alerting.Count) مورد در بازهٔ هشدار؛ یادآوریِ این هفته قبلاً ارسال شده" -Config $cfg }
} catch {
    Write-LogBokLog -Message "LicenseWatch error: $($_.Exception.Message)" -Level ERROR -Config $cfg
    exit 1
}
