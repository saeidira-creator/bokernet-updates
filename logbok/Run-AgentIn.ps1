# ==========================================================================
#  Run-AgentIn.ps1 — دریافتِ رویداد از ایجنت‌ها (همیشه روشن؛ Task Scheduler، SYSTEM)
#  ایجنت‌ها رویدادهای امضاشده را به TCP 8687 همین سرور می‌فرستند.
# ==========================================================================
param([int]$MaxRequests = 0)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')     -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'LogBok.Targets.psm1')  -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'LogBok.AgentPkg.psm1') -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'LogBok.AgentIn.psm1')  -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'LogBok.Endpoint.psm1') -Force -DisableNameChecking -Global
$cfg = Get-LogBokConfig
$sd = Get-LBStateDir -Config $cfg
$port = 8687; if ($cfg.Agent -and $cfg.Agent.IngestPort) { $port = [int]$cfg.Agent.IngestPort }
# رولِ فایروال (جزوِ مسیرِ محافظت‌شده هم هست) | firewall rule (also part of the protected management path)
try {
    if (-not (Get-NetFirewallRule -DisplayName 'LogBok-AgentIn' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'LogBok-AgentIn' -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Enabled True -Profile Any -ErrorAction Stop | Out-Null
    }
} catch { & netsh advfirewall firewall add rule name="LogBok-AgentIn" dir=in action=allow protocol=TCP localport=$port profile=any 2>$null | Out-Null }
[void](Get-LBEnrollInfo -StateDir $sd)
Write-LogBokLog -Message ("دریافتِ رویداد از ایجنت‌ها روی پورتِ {0} | agent intake on TCP {0}" -f $port) -Config $cfg
try { Start-LBAgentInServer -Port $port -StateDir $sd -InstallDir $root -MaxRequests $MaxRequests }
catch { Write-LogBokLog -Message ("دریافتِ رویداد از ایجنت‌ها اجرا نشد: {0} | agent intake failed" -f $_.Exception.Message) -Level ERROR -Config $cfg; exit 1 }
