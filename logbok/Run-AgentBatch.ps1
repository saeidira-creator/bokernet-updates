# ==========================================================================
#  Run-AgentBatch.ps1 — نصبِ ایجنت روی چند سیستم به‌صورتِ موازی
#  (کنسولِ وب یا سیاستِ استقرار آن را اجرا می‌کند؛ هر سیستم در فرایندِ Run-AgentPush جدا)
#  ورودی: state\agents\<id>.batch  —  وضعیتِ هر سیستم در state\agents\<Name>.json
# ==========================================================================
param([Parameter(Mandatory)][string]$BatchFile)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1') -Force -DisableNameChecking
$cfg = Get-LogBokConfig
if (-not (Test-Path $BatchFile)) { return }
$b = Get-Content $BatchFile -Raw -Encoding UTF8 | ConvertFrom-Json
$runner = Join-Path $root 'Run-AgentPush.ps1'
$max = [math]::Max(1, [int]$b.Parallel)
$items = @($b.Items)
Write-LogBokLog -Message ("نصبِ گروهیِ ایجنت: {0} سیستم، {1} هم‌زمان | agent batch {2}: {0} computers, {1} in parallel" -f $items.Count, $max, $b.Id) -Config $cfg
$running = New-Object System.Collections.ArrayList
foreach ($it in $items) {
    while (@($running | Where-Object { -not $_.HasExited }).Count -ge $max) { Start-Sleep -Seconds 2 }
    $n = [string]$it.Name; if ($n -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { continue }
    $a = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`" -Name $n"
    if ($it.Address -and [string]$it.Address -match '^[A-Za-z0-9_.\-:]{1,255}$') { $a += " -Address $($it.Address)" }
    if ($b.Collector -and [string]$b.Collector -match '^[A-Za-z0-9_.\-:]{1,255}$') { $a += " -Collector $($b.Collector)" }
    if ($b.CredName -and [string]$b.CredName -match '^[A-Za-z0-9_.\-]{1,100}$') { $a += " -CredName $($b.CredName)" }
    try { [void]$running.Add((Start-Process -FilePath 'powershell.exe' -ArgumentList $a -WindowStyle Hidden -PassThru)) } catch { }
}
$deadline = (Get-Date).AddMinutes(30)
while (@($running | Where-Object { -not $_.HasExited }).Count -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
Write-LogBokLog -Message ("نصبِ گروهیِ ایجنت پایان یافت | agent batch {0} finished" -f $b.Id) -Config $cfg
