# ==========================================================================
#  Run-Guard.ps1 - login guard (LogBok-Guard job, as SYSTEM)
#  event-driven: on each failed logon (RDP/Windows/SQL/SSH) or deletion of a guard firewall rule
#  it runs immediately; also every 5 minutes to clear expired blocks, IIS/FTP logs,
#  country/feed updates and the shared guard.
#  Event-driven login guard: blocks attacking IPs in Windows Firewall.
# ==========================================================================
param([switch]$Housekeeping)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    Import-Module (Join-Path $root 'LogBok.Core.psm1')  -Force -DisableNameChecking
    Import-Module (Join-Path $root 'LogBok.Guard.psm1') -Force -DisableNameChecking
    $cfg = Get-LogBokConfig
    if ($cfg.Jobs -and $cfg.Jobs.ContainsKey('Guard') -and $cfg.Jobs.Guard -eq $false) { return }
    $r = Invoke-LBGuard -Config $cfg -InstallDir $root -Housekeeping:$Housekeeping
    if ($r.Blocked -gt 0 -or $r.Unblocked -gt 0) {
        Write-LogBokLog -Message ("Guard: blocked={0} unblocked={1} rules={2} addresses={3}" -f $r.Blocked, $r.Unblocked, $r.Rules.Rules, $r.Rules.Addresses) -Config $cfg
    }
} catch {
    try { Write-LogBokLog -Message "Guard error: $($_.Exception.Message)" -Level WARN -Config $cfg } catch { }
}
