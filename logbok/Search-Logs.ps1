# ==========================================================================
#  Search-Logs.ps1 - جست‌وجو در انبارِ لاگ و خروجیِ HTML
#  نتیجهٔ جست‌وجو را هم در کنسول نشان می‌دهد و هم یک صفحهٔ HTML می‌سازد و باز می‌کند.
#  مثال:
#   .\Search-Logs.ps1 -Text "administrator" -Days 7
#   .\Search-Logs.ps1 -EventId 4625 -Computer DC01 -Days 3 -Max 1000
# ==========================================================================
param(
    [int]$Days=1,[datetime]$From,[datetime]$To,
    [string]$Computer,[string]$User,[string]$EventId,[string]$Text,
    [string]$Query,   # جست‌وجوی پیشرفته: 'admin AND (fail* OR denied) NOT 10.0.0.5'
    [int]$Max=500,[switch]$NoOpen
)
$ErrorActionPreference='Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')    -Force
Import-Module (Join-Path $root 'LogBok.Archive.psm1') -Force
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
function Enc($s){ if($null -eq $s){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$cfg = Get-LogBokConfig
if (-not $From) { $From = (Get-Date).AddDays(-$Days) }
if (-not $To)   { $To   = (Get-Date) }

if ($Query) {
    $res = @(Search-LBArchiveQuery -Config $cfg -From $From -To $To -Query $Query -Max $Max)
} else {
    $p = @{ Config=$cfg; From=$From; To=$To; Max=$Max }
    if ($Computer){$p.Computer=$Computer}; if($User){$p.User=$User}; if($EventId){$p.EventId=$EventId}; if($Text){$p.Text=$Text}
    $res = @(Search-LBArchive @p)
}

Write-Host ("{0} رکورد یافت شد | {0} records" -f $res.Count) -ForegroundColor Green
$res | Select-Object -First 25 t,host,id,user,ip,msg | Format-Table -Auto | Out-Host

$rows=''
foreach($r in $res){ $rows += "<tr><td class='mut' style='white-space:nowrap'>$(Enc $r.t)</td><td>$(Enc $r.host)</td><td class='mut'>$(Enc $r.log)</td><td>$($r.id)</td><td>$(Enc $r.user)</td><td>$(Enc $r.ip)</td><td>$(Enc $r.msg)</td></tr>" }
$brass='#C9A24B'
$html=@"
<!DOCTYPE html><html dir="rtl" lang="fa"><head><meta charset="utf-8"><title>LogBok — جست‌وجوی لاگ</title>
<style>
 body{font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:rtl;background:#0E2529;color:#EAF0EE;margin:0;padding:20px}
 h1{font-size:17px;font-weight:600;border-bottom:1px solid #27484E;padding-bottom:10px}
 .q{color:#9FB3B0;font-size:12px;margin-bottom:12px}
 table{width:100%;border-collapse:collapse;font-size:12px}
 th,td{text-align:right;padding:6px 8px;border-bottom:1px solid #1E3A3F;vertical-align:top}
 th{color:#9FB3B0;font-weight:500} td:last-child{max-width:460px;white-space:pre-wrap;word-break:break-word}
 .mut{color:#9FB3B0}
</style></head><body>
<h1>LogBok — نتیجهٔ جست‌وجوی لاگ ($($res.Count) رکورد)</h1>
<div class="q">بازه: $($From.ToString('yyyy-MM-dd HH:mm')) تا $($To.ToString('yyyy-MM-dd HH:mm')) · فیلترها: سیستم=$(Enc $Computer) کاربر=$(Enc $User) EventID=$EventId متن=$(Enc $Text)</div>
<table><thead><tr><th>زمان</th><th>سیستم</th><th>لاگ</th><th>ID</th><th>کاربر</th><th>IP</th><th>پیام</th></tr></thead><tbody>$rows</tbody></table>
</body></html>
"@
if (-not (Test-Path $cfg.Paths.Reports)) { New-Item -ItemType Directory -Path $cfg.Paths.Reports -Force | Out-Null }
$out = Join-Path $cfg.Paths.Reports ("Search_{0}.html" -f (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss',[Globalization.CultureInfo]::InvariantCulture))
$html | Set-Content -Path $out -Encoding UTF8
Write-Host "خروجی HTML: $out" -ForegroundColor Cyan
if (-not $NoOpen) { try { Start-Process $out } catch {} }
