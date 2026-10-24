# ==========================================================================
#  Run-Syslog.ps1 - سرویسِ گوش‌دهندهٔ Syslog (UDP) برای تجهیزاتِ شبکه
#  به‌صورت یک تسکِ زمان‌بندی‌شده (با SYSTEM) دائم اجرا می‌شود و لاگِ سوییچ/روتر/
#  فایروالِ سیسکو و… را در انبار می‌ریزد. موتورِ بلادرنگ سپس از انبار تحلیل می‌کند.
#  پورت و فعال‌بودن از config خوانده می‌شود.  مثال دستی:  .\Run-Syslog.ps1 -RunSeconds 60
# ==========================================================================
param([int]$Port,[int]$RunSeconds=0)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')   -Force
Import-Module (Join-Path $root 'LogBok.Syslog.psm1') -Force

$cfg = Get-LogBokConfig
Import-Module (Join-Path $root 'LogBok.Jobs.psm1') -Force -DisableNameChecking
if (-not (Test-LBJobEnabled $cfg 'Syslog')) { Write-Host 'Syslog در config غیرفعال است (Jobs.Syslog).' -ForegroundColor Yellow; return }
if (-not $Port) { $Port = if ($cfg.Syslog.Port) { [int]$cfg.Syslog.Port } else { 514 } }

try {
    Start-LBSyslogListener -Config $cfg -Port $Port -RunSeconds $RunSeconds
} catch {
    Write-LogBokLog -Message "خطا در سرورِ Syslog: $($_.Exception.Message)" -Level ERROR -Config $cfg
}
