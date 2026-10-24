# ==========================================================================
#  Run-Web.ps1 — کنسولِ وبِ لاگ‌بوک (همیشه روشن؛ با Task Scheduler و SYSTEM)
#  آدرس: http://localhost:8686/  (پورت/حالتِ LAN در config → Web)
#  اولین اجرا: تاریخچهٔ یافته‌های ۲۴ ساعتِ اخیر ساخته می‌شود تا رابط خالی نباشد،
#  و میان‌برِ «LogBok Console» روی دسکتاپ ساخته می‌شود.
# ==========================================================================
param([switch]$TestMode, [int]$MaxRequests = 0)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1') -Force -DisableNameChecking -Global
Import-Module (Join-Path $root 'LogBok.Web.psm1')  -Force -DisableNameChecking

$cfg = Get-LogBokConfig
$w = if ($cfg.Web) { $cfg.Web } else { @{} }
if ($w.Enabled -eq $false) { Write-LogBokLog -Message 'کنسولِ وب خاموش است (Web.Enabled=$false)' -Config $cfg; return }
$port = if ($w.Port) { [int]$w.Port } else { 8686 }
$listen = if ([string]$w.Listen -eq 'lan') { 'lan' } else { 'local' }

# پرکردنِ اولیهٔ تاریخچه (یک‌بار) | one-time backfill of the findings history
try {
    Import-Module (Join-Path $root 'LogBok.Findings.psm1') -Force -DisableNameChecking -Global
    $fd = Get-LBFindingsDir -Config $cfg
    if (-not (Get-ChildItem $fd -Filter '*.ndjson' -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path $root 'LogBok.Detectors.psm1') -Force -DisableNameChecking -Global
        Import-Module (Join-Path $root 'LogBok.Mitre.psm1') -Force -DisableNameChecking -Global
        $f = @(Invoke-LogBokDetectors -Config $cfg -Start (Get-Date).AddHours(-24))
        try { $f = @($f | Add-LBMitreTag) } catch { }
        $n = Save-LBFindings -Config $cfg -Findings $f
        Write-LogBokLog -Message "کنسولِ وب: تاریخچهٔ اولیه ساخته شد ($n یافته)" -Config $cfg
    }
} catch { Write-LogBokLog -Message "کنسولِ وب: پرکردنِ اولیه ناموفق: $($_.Exception.Message)" -Level WARN -Config $cfg }

# میان‌برِ دسکتاپ | desktop shortcut (Public Desktop)
if (-not $TestMode) {
    try {
        $lnk = 'C:\Users\Public\Desktop\LogBok Console.url'
        $want = "[InternetShortcut]`r`nURL=http://localhost:$port/`r`nIconFile=$env:SystemRoot\System32\shell32.dll`r`nIconIndex=13`r`n"
        if (-not (Test-Path $lnk) -or ([IO.File]::ReadAllText($lnk) -ne $want)) { [IO.File]::WriteAllText($lnk, $want, [Text.Encoding]::ASCII) }
    } catch { }
}

# بسته‌های آمادهٔ ایجنت برای کپیِ دستی | ready-made agent packages under _Agents
if (-not $TestMode) {
    try {
        Import-Module (Join-Path $root 'LogBok.Alerts.psm1') -Force -DisableNameChecking -Global
        $na = Initialize-LBDefaultAlerts -StateDir (Get-LBStateDir -Config $cfg)
        if ($na) { Write-LogBokLog -Message ("{0} پروفایلِ هشدارِ پیش‌فرض ساخته شد | default alert profiles created: {0}" -f $na) -Config $cfg }
        Import-Module (Join-Path $root 'LogBok.AgentPkg.psm1') -Force -DisableNameChecking -Global
        if (Update-LBAgentPackages -InstallDir $root -Config $cfg) { Write-LogBokLog -Message ("بسته‌های ایجنت ساخته شد: {0} | agent packages built" -f (Join-Path $root '_Agents')) -Config $cfg }
    } catch { Write-LogBokLog -Message "بستهٔ ایجنت: $($_.Exception.Message)" -Level WARN -Config $cfg }
}

Write-LogBokLog -Message ("کنسولِ وب روی پورتِ {0} ({1}) | web console on port {0} ({1})" -f $port, $listen) -Config $cfg
try { Start-LBWebServer -Port $port -Listen $listen -TestMode:$TestMode -MaxRequests $MaxRequests }
catch {
    Write-LogBokLog -Message ("کنسولِ وب اجرا نشد: {0} | web console failed: {0}" -f $_.Exception.Message) -Level ERROR -Config $cfg
    exit 1
}
