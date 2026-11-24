# ==========================================================================
#  Run-Dashboard.ps1 - داشبورد زندهٔ HTML (برند لاگ‌بوک، دوزبانه، RTL)
#  همه‌چیز یکجا: وضعیت کلی، لایسنس، ایجنت‌ها، دسته‌ها و آخرین رویدادها.
#  هر ۵ دقیقه بازساخته و صفحه هر ۲ دقیقه رفرش می‌شود.
# ==========================================================================
param([int]$Hours = 24)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
# قلمِ وزیرمتن را از پوشهٔ Web جاسازی می‌کنیم تا داشبورد همه‌جا با قلمِ برند دیده شود | embed Vazirmatn so the dashboard shows the brand font everywhere
$fontCss = ''
try {
    $wf = Join-Path $root 'Web\vazirmatn.woff2'
    if (Test-Path $wf) {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($wf))
        $fontCss = "@font-face{font-family:'Vazirmatn';src:url(data:font/woff2;base64,$b64) format('woff2');font-weight:100 900;font-style:normal;font-display:swap}"
    }
} catch { }
Import-Module (Join-Path $root 'LogBok.Core.psm1')      -Force
Import-Module (Join-Path $root 'LogBok.Detectors.psm1') -Force
Import-Module (Join-Path $root 'LogBok.License.psm1')   -Force
Import-Module (Join-Path $root 'LogBok.Lang.psm1')      -Force -DisableNameChecking
function Enc($s){ if($null -eq $s){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$s) }

$cfg = Get-LogBokConfig
$brand = if ($cfg.Brand) { $cfg.Brand } else { @{ NameFa='لاگ‌بوک'; NameEn='LogBok'; Tagline=''; Accent='#F4B740' } }
$lic = Test-LogBokLicense -Config $cfg -NoClockUpdate
$start = (Get-Date).AddHours(-$Hours)

$findings = @()
try { $findings = @(Invoke-LogBokDetectors -Config $cfg -Start $start) } catch {}
if ($cfg.Enabled.Behavior -ne $false) { try { Import-Module (Join-Path $root 'LogBok.Behavior.psm1') -Force; $findings += Get-LogBokAnomalies -Config $cfg -Start $start } catch {} }

$crit = @($findings | Where-Object Severity -eq 'Critical').Count
$warn = @($findings | Where-Object Severity -eq 'Warning').Count
$info = @($findings | Where-Object Severity -eq 'Info').Count

$inv = @(); $invFile = Join-Path $root 'state\inventory.json'
if (Test-Path $invFile) { try { $inv = @(Get-Content $invFile -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch {} }
# وضعیتِ جاب‌ها و انقضای لایسنس‌ها | jobs status + license expiry
$jobs = @(); try { Import-Module (Join-Path $root 'LogBok.Jobs.psm1') -Force -DisableNameChecking; $jobs = @(Get-LBJobStatus -Config $cfg -Role Engine) } catch {}
$licItems = @(); try { Import-Module (Join-Path $root 'LogBok.LicenseWatch.psm1') -Force -DisableNameChecking; $licItems = @(Get-LBLicenseItems -Config $cfg -Root $root | Sort-Object { if ($null -eq $_.DaysLeft) { 99999 } else { $_.DaysLeft } }) } catch {}

# برچسبِ MITRE + رخدادها + آمارِ انبار | mitre tags, incidents, archive stats
try { Import-Module (Join-Path $root 'LogBok.Mitre.psm1') -Force; $findings = @($findings | Add-LBMitreTag) } catch {}
$incidents = @(); try { $incidents = @(Get-LBIncidents -Config $cfg | Where-Object { $_.Status -ne 'Closed' } | Sort-Object LastSeen -Descending | Select-Object -First 12) } catch {}
$arch = $null; try { Import-Module (Join-Path $root 'LogBok.Archive.psm1') -Force; $arch = Get-LBArchiveStats -Config $cfg } catch {}
$toprisk = @(); try { Import-Module (Join-Path $root 'LogBok.Risk.psm1') -Force; $toprisk = @(Get-LBTopRisk -Config $cfg -Top 8) } catch {}

# زبانِ رابط از config | UI language from config: 'fa' | 'en' | 'both'
$lang = if ($cfg.Language) { [string]$cfg.Language } else { 'both' }
$isEn = ($lang -eq 'en')
$catTitle = [ordered]@{}; foreach ($k in (Get-LBCategoryKeys)) { $catTitle[$k] = Get-LBCategoryTitle -Category $k -Config $cfg }
# برچسب‌های رابط | UI strings
function L($fa,$en){ if ($isEn) { return $en } elseif ($lang -eq 'fa') { return $fa } else { return "$fa / $en" } }
# متنِ دوزبانهٔ «فارسی | English» → فقط نیمهٔ زبانِ رابط؛ در حالتِ انگلیسی پرانتزهای فارسی هم حذف می‌شوند
function Txt([string]$s){
  if (-not $s -or $lang -eq 'both') { return $s }
  $parts = $s -split '\s\|\s', 2
  if ($parts.Count -eq 2) { $s = if ($isEn) { $parts[1] } else { $parts[0] } }
  if ($isEn) { $s = [regex]::Replace($s, '\s*\([^()]*[\u0600-\u06FF][^()]*\)', '') }
  return $s.Trim()
}
# جزئیاتِ یافته در حالتِ انگلیسی: برچسب‌های فارسی → انگلیسی، «فارسی | English» → English
$script:FaLabels = [ordered]@{
  'تعداد ورودِ ناموفق در بازه'='Failed logons in window'; 'تعداد عملیات مخرب در بازه'='Destructive operations in window'
  'تعداد تلاش ناموفق در بازه'='Failed attempts in window'; 'مجموع ورود ناموفق در بازه'='Total failed logons in window'
  'کاربرانِ امتحان‌شده'='Users tried'; 'بخشی از اسکریپت'='Script excerpt'; 'نمونه فایل‌ها'='Sample files'
  'میانهٔ معمول'='Usual median'; 'مقدار فعلی'='Current value'; 'کاربر هدف'='Target user'; 'کل درخواست'='Total requests'
  'بارِ بلاک'='Block count'; 'در بازه'='In window'; 'سیستم'='Host'; 'مبدأ'='Source'; 'کاربر'='User'; 'توسط'='By'
  'کشور'='Country'; 'دستگاه'='Device'; 'مقدار'='Value'; 'دلیل'='Reason'; 'شیء'='Object'; 'شدت'='Severity'
  'پیام'='Message'; 'سرور'='Server'; 'پاکسازی'='Cleanup'; 'متریک'='Metric'; 'نوع'='Type'; 'منبع'='Source'
  'تلاش'='Attempts'; 'تا'='Until'; 'سرویس‌ها'='Services'; 'صفت'='Attribute'; 'عملیات'='Operation'; 'رویداد'='Event'
  'نشانه‌ها'='Indicators'; 'سند'='Document'; 'چاپگر'='Printer'; 'مولفه‌ها'='Components'; 'گروه'='Group'; 'عضو'='Member'
}
function TxtD([string]$s){
  if (-not $s -or -not $isEn) { return $s }
  $s = [regex]::Replace($s, '[\u0600-\u06FF][\u0600-\u06FF\u200c\u064b-\u0670 ]*/([A-Za-z][A-Za-z ]*)\s*:', '$1:')
  foreach ($k in $script:FaLabels.Keys) { $s = [regex]::Replace($s, '(?<![\u0600-\u06FF\u200c])' + [regex]::Escape($k) + '(?=\s*:)', $script:FaLabels[$k]) }
  $s = [regex]::Replace($s, '[\u0600-\u06FF][^|\n]*?\s\|\s', '')
  $s = [regex]::Replace($s, '\s*\([^()]*[\u0600-\u06FF][^()]*\)', '')
  return $s
}
$dirAttr  = if ($isEn) { 'ltr' } else { 'rtl' }
$langAttr = if ($isEn) { 'en' } else { 'fa' }
$alignAttr = if ($isEn) { 'left' } else { 'right' }

# وضعیت کلی | overall posture (the one bold element)
if ($crit -gt 0) { $hero='توجه فوری لازم است'; $heroEn='Immediate attention'; $hc='var(--crit)' }
elseif ($warn -gt 0) { $hero='نیازمند بررسی'; $heroEn='Needs review'; $hc='var(--warn)' }
else { $hero='وضعیت عادی'; $heroEn='All clear'; $hc='var(--mint)' }

# نشانِ «دفتر + نبض» (رنگ‌ها از currentColor می‌آیند تا در دو حالت درست بماند)
$brass = $brand.Brass; if(-not $brass){$brass='#C9A24B'}
$mint  = $brand.Mint;  if(-not $mint){$mint='#4FD1B5'}
$logo = @"
<img src="data:image/png;base64,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" width="34" height="37" alt="LogBok">
"@
$defTheme = if($brand.Theme -eq 'light'){'light'}else{'dark'}

$licRows=''
foreach($role in @('Clients','FileServers','IIS','SQL','DomainControllers')){
  $limit= if($lic.Limits.ContainsKey($role)){$lic.Limits[$role]}else{'∞'}
  $used=@($inv|Where-Object{$_.Role -eq $role}).Count
  $over=($limit -ne '∞' -and $used -gt $limit)
  $bar= if($limit -ne '∞' -and $limit -gt 0){[math]::Min(100,[int]($used*100/$limit))}else{4}
  $licRows+="<tr><td>$role</td><td class='num'>$used / $limit</td><td style='width:120px'><div class='bar'><i style='width:$bar%;background:$(if($over){'var(--crit)'}else{'var(--mint)'})'></i></div></td></tr>"
}
$agentRows=''
foreach($a in $inv){
  $ia = if($a.InstalledAt -is [datetime]){ Get-LBDate 'yyyy-MM-dd HH:mm' $a.InstalledAt } else { ([string]$a.InstalledAt) -replace 'T',' ' }
  $agentRows+="<tr><td>$(Enc $a.Computer)</td><td><span class='chip'>$(Enc $a.Role)</span></td><td class='muted num'>$(Enc $ia)</td></tr>" }
if(-not $agentRows){ $agentRows="<tr><td colspan='3' class='muted' style='text-align:center'>— $(L 'بدون ایجنت' 'no agents yet') —</td></tr>" }

# جاب‌ها | jobs
# کدهای عادیِ تسک: 0 موفق، 0x41301 در حالِ اجرا، 0x41303 هنوز اجرا نشده، 0x800710E0 اجرای تکراری رد شد چون نمونهٔ قبلی هنوز در حالِ اجراست
$okCodes = @(0, 267009, 267011, 2147946720)
$jobRows=''
foreach($j in $jobs){
  $jc = if(-not $j.Enabled){'var(--line)'}elseif($j.State -eq 'Missing'){'var(--crit)'}elseif($j.LastCode -and ($okCodes -notcontains [long]$j.LastCode)){'var(--warn)'}else{'var(--mint)'}
  $jst = if(-not $j.Enabled){ L 'خاموش (config)' 'off (config)' } else { switch($j.State){'Running'{L 'در حال اجرا' 'running'} 'Ready'{L 'آماده' 'ready'} 'Disabled'{L 'غیرفعال' 'disabled'} 'Missing'{L 'ساخته نشده' 'missing'} default{$j.State}} }
  $lr = if($j.LastRun){ Get-LBDate 'MM-dd HH:mm' $j.LastRun } else { '—' }
  $nr = if($j.NextRun -and $j.NextRun.Year -gt 2000){ Get-LBDate 'MM-dd HH:mm' $j.NextRun } else { '—' }
  $jobRows+="<tr><td><span class='sev' style='background:$jc'></span>$(Enc $j.Name)</td><td class='muted'>$(Enc $(if($isEn){$j.En}else{$j.Fa}))</td><td>$jst</td><td class='num muted'>$lr</td><td class='num muted'>$nr</td></tr>"
}
if(-not $jobRows){ $jobRows="<tr><td colspan='5' class='muted' style='text-align:center'>—</td></tr>" }
$jobsOn = @($jobs | Where-Object Enabled).Count

# لایسنس‌ها (انقضا) | license expiry
$licWatchRows=''; $soonest=$null
$warnDays = if($cfg.LicenseWatch -and $cfg.LicenseWatch.WarnDays){[int]$cfg.LicenseWatch.WarnDays}else{30}
foreach($it in $licItems){
  $dl = $it.DaysLeft
  $lc = if($it.Status -in 'Expired','Invalid'){'var(--crit)'}elseif($it.Status -eq 'Warning'){'var(--warn)'}else{'var(--mint)'}
  $pct = if($null -ne $dl){ [math]::Max(3,[math]::Min(100,[int](([double][math]::Max(0,$dl))*100/365))) } else { 3 }
  $txt = if($it.Status -eq 'Invalid'){ L 'نامعتبر' 'invalid' } elseif($null -eq $dl){ '—' } elseif($dl -lt 0){ L "$(-$dl) روز گذشته" "$(-$dl)d ago" } else { L "$dl روز" "$dl d" }
  if($it.Status -in 'Warning','Expired','Invalid' -and -not $soonest){ $soonest=$it }
  $licWatchRows+="<tr><td>$(Enc (Txt $it.Name))<div class='muted' style='font-size:11px'>$(Enc $it.Type)</div></td><td class='num muted'>$(Enc $it.Expiry)</td><td style='width:120px'><div class='bar'><i style='width:$pct%;background:$lc'></i></div></td><td class='num' style='color:$lc;white-space:nowrap'>$txt</td></tr>"
}
if(-not $licWatchRows){ $licWatchRows="<tr><td colspan='4' class='muted' style='text-align:center'>—</td></tr>" }
$licBanner = if($soonest){
  $bt = if($soonest.Status -eq 'Warning'){ L "لایسنسِ «$(Enc (Txt $soonest.Name))» $($soonest.DaysLeft) روز دیگر منقضی می‌شود — برای تمدید اقدام کنید." "License '$(Enc (Txt $soonest.Name))' expires in $($soonest.DaysLeft) days — please renew." }
        else { L "لایسنسِ «$(Enc (Txt $soonest.Name))» منقضی/نامعتبر است — اقدام کنید." "License '$(Enc (Txt $soonest.Name))' is expired/invalid — action required." }
  "<a class='banner' href='#lic' onclick='lbShow(""lic"");return false;'><b>!</b> $bt</a>"
} else { '' }

$tiles=''
$ti=0
foreach($k in $catTitle.Keys){
  $items=@($findings|Where-Object Category -eq $k); $c=@($items|Where-Object Severity -eq 'Critical').Count
  $dot= if($c -gt 0){'var(--crit)'}elseif($items.Count -gt 0){'var(--warn)'}else{'var(--line)'}
  # کاشیِ خالی غیرقابل‌کلیک؛ کاشیِ دارای رویداد به بخشِ خودش می‌پرد
  if($items.Count -gt 0){
    $tiles+="<a class='tile' href='#events' onclick='lbCat(""$k"");return false;'><span class='dot' style='background:$dot'></span><div class='tl'>$($catTitle[$k])</div><div class='tv'>$($items.Count)</div></a>"
  } else {
    $tiles+="<div class='tile tile-empty'><span class='dot' style='background:$dot'></span><div class='tl'>$($catTitle[$k])</div><div class='tv'>0</div></div>"
  }
  $ti++
}

# شناسهٔ هر یافته برای باز کردن در کنسولِ وب | finding id → web console link
$webPort = 8686; if ($cfg.Web -and $cfg.Web.Port) { $webPort = [int]$cfg.Web.Port }
$webOn = -not ($cfg.Web -and $cfg.Web.Enabled -eq $false)
try { Import-Module (Join-Path $root 'LogBok.Findings.psm1') -Force -DisableNameChecking } catch { $webOn = $false }
$sections=''
foreach($k in $catTitle.Keys){
  $items=@($findings|Where-Object Category -eq $k|Sort-Object Time -Descending|Select-Object -First 40)
  if($items.Count -eq 0){continue}
  $rows=''
  foreach($it in $items){
    $sc= switch($it.Severity){'Critical'{'var(--crit)'}'Warning'{'var(--warn)'}default{'var(--info)'}}
    $mt = if($it.PSObject.Properties.Name -contains 'Mitre' -and $it.Mitre){"<span class='mitre'>$(Enc $it.Mitre)</span>"}else{''}
    $sv = switch([string]$it.Severity){'Critical'{L 'بحرانی' 'Critical'}'Warning'{L 'هشدار' 'Warning'}default{L 'اطلاع' 'Info'}}
    $tm = if($it.Time -is [datetime]){ Get-LBDate 'yyyy-MM-dd HH:mm:ss' $it.Time } else { [string]$it.Time }
    $fid = ''; if ($webOn) { try { $fid = Get-LBFindingId $it } catch { } }
    $rows+="<tr class='erow' data-sev='$($it.Severity)' data-id='$fid'><td style='white-space:nowrap'><span class='sev' style='background:$sc'></span>$sv</td><td class='muted num' style='white-space:nowrap'>$tm</td><td>$(Enc $it.Machine)</td><td>$(Enc (Txt $it.Title)) $mt</td><td class='muted'>$(Enc (TxtD $it.Details))</td></tr>"
  }
  $sections+="<section class='panel' id='sec-$k' data-cat='$k'><h2>$($catTitle[$k]) <span class='count'>$($items.Count)</span></h2><table class='grid'><thead><tr><th>$(L 'سطح' 'Severity')</th><th>$(L 'زمان' 'Time')</th><th>$(L 'سیستم' 'Host')</th><th>$(L 'رویداد' 'Event')</th><th>$(L 'جزئیات' 'Details')</th></tr></thead><tbody>$rows</tbody></table></section>"
}

$licPill = if($lic.Valid){"<span class='pill ok'>$(L 'معتبر' 'Valid')$(if($lic.Permanent){' · ' + (L 'دائمی' 'permanent')})</span>"}else{"<span class='pill bad'>$(Enc $lic.Reason)</span>"}

# پنلِ رخدادهای باز | open incidents panel
$incRows=''
foreach($i in $incidents){
  $sc= if($i.Severity -eq 'Critical'){'var(--crit)'}else{'var(--warn)'}
  $stt= switch($i.Status){'Investigating'{L 'در حال بررسی' 'Investigating'}'Closed'{L 'بسته' 'Closed'}default{L 'باز' 'Open'}}
  $incRows+="<tr><td class='muted' style='white-space:nowrap'>$(Enc $i.Id)</td><td><span class='sev' style='background:$sc'></span>$(Enc $i.Machine)</td><td>$(Enc $(if($isEn -and (Txt $i.Title) -match '[\u0600-\u06FF]' -and $catTitle[[string]$i.Category]){ $catTitle[[string]$i.Category] } else { Txt $i.Title }))</td><td class='muted'>$(Enc $i.Mitre)</td><td class='num'>$($i.Count)</td><td>$stt</td></tr>"
}
if(-not $incRows){ $incRows="<tr><td colspan='6' class='muted' style='text-align:center'>— $(L 'رخدادِ بازی نیست' 'no open incidents') —</td></tr>" }
# سپرِ ورود | login guard panel
$gBlocks = @($findings | Where-Object { $_.Category -eq 'Guard' -and $_.PSObject.Properties.Name -contains 'GuardAction' -and $_.GuardAction -eq 'block' } | Sort-Object Time -Descending)
$gPerm = @($gBlocks | Where-Object { $_.GuardUntil -eq 'permanent' }).Count
$gIps = @($gBlocks | ForEach-Object { $_.GuardIp } | Select-Object -Unique).Count
$gHosts = @($gBlocks | ForEach-Object { $_.Machine } | Select-Object -Unique).Count
$gCountry = @($gBlocks | Where-Object { $_.GuardCountry -and $_.GuardCountry -ne '-' } | Group-Object GuardCountry | Sort-Object Count -Descending | Select-Object -First 6)
$gMax = if ($gCountry.Count) { [math]::Max(1, $gCountry[0].Count) } else { 1 }
$gCtyRows = ''
foreach ($g in $gCountry) { $gw = [int]($g.Count * 100 / $gMax); $gCtyRows += "<tr><td style='width:60px'>$(Enc $g.Name)</td><td><div class='bar'><i style='width:$gw%;background:var(--brass)'></i></div></td><td class='num' style='width:40px'>$($g.Count)</td></tr>" }
if (-not $gCtyRows) { $gCtyRows = "<tr><td colspan='3' class='muted' style='text-align:center'>— $(L 'کشوری ثبت نشده (GeoMode خاموش)' 'no country data (GeoMode off)') —</td></tr>" }
$gRows = ''
foreach ($g in ($gBlocks | Select-Object -First 12)) {
  $tm = if ($g.Time -is [datetime]) { Get-LBDate 'MM-dd HH:mm' $g.Time } else { [string]$g.Time }
  $un = if ($g.GuardUntil -eq 'permanent') { "<span style='color:var(--crit)'>$(L 'دائمی' 'permanent')</span>" } else { $gu=[string]$g.GuardUntil; try { Enc (Get-LBDate 'MM-dd HH:mm' ([datetime]::Parse($gu,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime())) } catch { Enc ($gu -replace 'T',' ' -replace 'Z','') } }
  $gRows += "<tr><td class='num muted'>$tm</td><td>$(Enc $g.Machine)</td><td class='num'>$(Enc $g.GuardIp)</td><td>$(Enc $g.GuardCountry)</td><td class='muted'>$(Enc $g.GuardReason) · $(Enc $g.GuardSource)</td><td class='num'>$un</td></tr>"
}
if (-not $gRows) { $gRows = "<tr><td colspan='6' class='muted' style='text-align:center'>— $(L 'در این بازه IPی بلاک نشد' 'no IPs blocked in this period') —</td></tr>" }

$archLine = if($arch){ L "انبارِ لاگ: $($arch.Events) رویداد در $($arch.Days) روز · $($arch.SizeMB)MB" "Log store: $($arch.Events) events · $($arch.Days) days · $($arch.SizeMB) MB" } else { L 'انبارِ لاگ: —' 'Log store: —' }

# پنلِ پرخطرترین موجودیت‌ها | top-risk entities panel
$riskRows=''
foreach($r in $toprisk){
  $bw=[math]::Min(100,$r.Score)
  $rc= if($r.Score -ge 60){'var(--crit)'}elseif($r.Score -ge 25){'var(--warn)'}else{'var(--mint)'}
  $riskRows+="<tr><td>$(Enc $r.Entity)</td><td style='width:140px'><div class='bar'><i style='width:$bw%;background:$rc'></i></div></td><td class='num' style='width:50px'>$($r.Score)</td><td style='width:60px'>$(Enc (Txt $r.Level))</td></tr>"
}
if(-not $riskRows){ $riskRows="<tr><td colspan='4' class='muted' style='text-align:center'>— $(L 'دادهٔ ریسکی نیست' 'no risk data yet') —</td></tr>" }

# ---------- داده‌های تبِ سپرِ ورود و نمای کلی | login-guard tab + overview data ----------
$gStat = $null; $gSet = $null; $gActive = @()
try {
  Import-Module (Join-Path $root 'LogBok.Guard.psm1') -Force -DisableNameChecking
  $gSet = Get-LBGuardSettings -Config $cfg
  $gStat = Get-LBGuardStatus -InstallDir $root
  $gActive = @(Get-LBGuardBlocks -InstallDir $root)
} catch {}
function IsoLocal([string]$s){
  if (-not $s) { return '—' }
  if ($s -eq 'permanent') { return (L 'دائمی' 'permanent') }
  try { return (Get-LBDate 'MM-dd HH:mm' ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime())) } catch { return $s }
}
$gActRows=''
foreach($b in $gActive){
  $un = if($b.Until -eq 'permanent'){"<span style='color:var(--crit)'>$(L 'دائمی' 'permanent')</span>"}else{Enc (IsoLocal $b.Until)}
  $cty = if($b.Country){$b.Country}else{'-'}
  $gActRows+="<tr><td class='num'>$(Enc $b.Ip)</td><td>$(Enc $cty)</td><td class='muted'>$(Enc $b.Reason) · $(Enc $b.Source)</td><td class='num muted'>$(Enc (IsoLocal $b.Since))</td><td class='num'>$un</td><td class='num'>$(Enc $b.Count)</td><td class='muted'>$(Enc (@($b.Users) -join ', '))</td></tr>"
}
if(-not $gActRows){ $gActRows="<tr><td colspan='7' class='muted' style='text-align:center'>— $(L 'در حالِ حاضر هیچ IPی بلاک نیست' 'no IPs are blocked right now') —</td></tr>" }
$gProt=''; $gRule='—'; $gGeo='—'; $gWork='—'; $gWhite='—'; $gBlack='—'; $gLan='—'; $gShare='—'; $gFeed='—'
if($gSet){
  foreach($pp in @(@('ProtectRDP','RDP'),@('ProtectWindowsLogon',(L 'ورودِ ویندوز' 'Windows logon')),@('ProtectSQL','SQL Server'),@('ProtectFTP','FTP'),@('ProtectWeb',(L 'وب (IIS)' 'Web (IIS)')),@('ProtectSSH','SSH'))){
    $on = [bool]$gSet.($pp[0])
    $gProt += "<span class='chip $(if($on){'on'}else{'off'})'>$(if($on){'✓'}else{'✕'}) $($pp[1])</span> "
  }
  $gRule = L "$($gSet.MaxFailedAttempts) تلاشِ ناموفق در $($gSet.AttemptWindowMinutes) دقیقه ← بلاکِ $($gSet.BlockMinutes) دقیقه‌ای؛ هر تکرار ×$($gSet.EscalationFactor)؛ بعد از $($gSet.PermanentAfterBlocks) بار ← دائمی · وب: $($gSet.WebMaxFailures) خطای 401" "$($gSet.MaxFailedAttempts) failed logons within $($gSet.AttemptWindowMinutes) min → blocked $($gSet.BlockMinutes) min; ×$($gSet.EscalationFactor) on each repeat; permanent after $($gSet.PermanentAfterBlocks) blocks · web: $($gSet.WebMaxFailures) × 401"
  $gGeo = switch($gSet.GeoMode){
    'AllowOnly'   { (L 'فقط کشورهای مجاز: ' 'only these countries may log on: ') + (@($gSet.AllowedCountries) -join ', ') }
    'BlockListed' { (L 'کشورهای بلاک‌شده: ' 'blocked countries: ') + (@($gSet.BlockedCountries) -join ', ') }
    default       { L 'خاموش (GeoMode = Off)' 'off (GeoMode = Off)' }
  }
  $gWork = if($gSet.WorkHoursEnabled){ "$($gSet.WorkStart)–$($gSet.WorkEnd) · " + (@($gSet.WorkDays) -join ', ') } else { L 'خاموش' 'off' }
  $wl = @(@($gSet.Whitelist) + @(([string]$gStat.LocalWhitelist) -split ',\s*') | Where-Object { $_ } | Select-Object -Unique)
  $bl = @(@($gSet.Blacklist) + @(([string]$gStat.LocalBlacklist) -split ',\s*') | Where-Object { $_ } | Select-Object -Unique)
  if($wl.Count){ $gWhite = Enc ($wl -join ', ') }
  if($bl.Count){ $gBlack = Enc ($bl -join ', ') }
  $gLan = if($gSet.AutoWhitelistLan){ L 'شبکهٔ داخلی (LAN) خودکار در لیستِ سفید است و هرگز بلاک نمی‌شود' 'internal network (LAN) is always whitelisted and never blocked' } else { L 'خاموش' 'off' }
  $gShare = if($gSet.ShareBlocks){ L 'روشن — بلاکِ هر سیستم به بقیه هم می‌رسد' 'on — a block on one host is shared with the others' } else { L 'خاموش' 'off' }
  $gFeed = if(@($gSet.FeedUrls).Count){ L "$(@($gSet.FeedUrls).Count) فید · $($gStat.FeedIps) IP" "$(@($gSet.FeedUrls).Count) feeds · $($gStat.FeedIps) IPs" } else { L 'هیچ فیدی تعریف نشده' 'no feeds configured' }
}
$gNow   = if($gStat){ [int]$gStat.Blocked } else { 0 }
$gPermN = if($gStat){ [int]$gStat.Permanent } else { 0 }
$gWatch = if($gStat){ [int]$gStat.Watching } else { 0 }
$gRulesN= if($gStat){ [int]$gStat.Rules } else { 0 }
$gLast  = if($gStat){ IsoLocal ([string]$gStat.LastRun) } else { '—' }

# آخرین رویدادهای بحرانی | latest critical events (overview)
$critRows=''
foreach($c in @($findings | Where-Object Severity -eq 'Critical' | Sort-Object Time -Descending | Select-Object -First 8)){
  $tm = if($c.Time -is [datetime]){ Get-LBDate 'MM-dd HH:mm' $c.Time } else { [string]$c.Time }
  $critRows+="<tr><td class='num muted' style='white-space:nowrap'>$tm</td><td>$(Enc $c.Machine)</td><td>$(Enc (Txt $c.Title))</td></tr>"
}
if(-not $critRows){ $critRows="<tr><td colspan='3' class='muted' style='text-align:center'>— $(L 'رویدادِ بحرانی‌ای نیست' 'no critical events') —</td></tr>" }
$jobsBad = @($jobs | Where-Object { $_.Enabled -and ($_.State -eq 'Missing' -or ($_.LastCode -and ($okCodes -notcontains [long]$_.LastCode))) }).Count

# فیلترهای تبِ رویدادها | events-tab filter chips
$catChips = "<button class='fchip' data-cat='' onclick='lbCat("""")'>$(L 'همهٔ دسته‌ها' 'All categories') <span class='count'>$($findings.Count)</span></button>"
foreach($k in $catTitle.Keys){
  $n = @($findings | Where-Object Category -eq $k).Count
  if($n -gt 0){ $catChips += "<button class='fchip' data-cat='$k' onclick='lbCat(""$k"")'>$($catTitle[$k]) <span class='count'>$n</span></button>" }
}
$sevChips = "<button class='fchip' data-sev='' onclick='lbSev("""")'>$(L 'همهٔ سطح‌ها' 'All levels')</button>" +
            "<button class='fchip' data-sev='Critical' onclick='lbSev(""Critical"")'><span class='sev' style='background:var(--crit)'></span>$(L 'بحرانی' 'Critical') <span class='count'>$crit</span></button>" +
            "<button class='fchip' data-sev='Warning' onclick='lbSev(""Warning"")'><span class='sev' style='background:var(--warn)'></span>$(L 'هشدار' 'Warning') <span class='count'>$warn</span></button>" +
            "<button class='fchip' data-sev='Info' onclick='lbSev(""Info"")'><span class='sev' style='background:var(--info)'></span>$(L 'اطلاع' 'Info') <span class='count'>$info</span></button>"
$brandSub = if($isEn){ "<div class='en'>Security Package</div>" } else { "<div class='en'>$($brand.NameFa)</div>" }
$footName = if($isEn){ $brand.NameEn } elseif($lang -eq 'fa'){ $brand.NameFa } else { "$($brand.NameEn) ($($brand.NameFa))" }
# ---------- وضعیتِ ارتباط | connectivity status ----------
$conn = $null
try { Import-Module (Join-Path $root 'LogBok.Connect.psm1') -Force -DisableNameChecking; $conn = Get-LBConnectStatus -InstallDir $root } catch {}
$connTargets = @(); $connFail = 0; $connWarn = 0; $connGen = ''
if ($conn) {
  $connTargets = @($conn.Targets)
  $connGen = IsoLocal ([string]$conn.Generated)
  foreach ($t in $connTargets) { if ($t.Status -eq 'Fail') { $connFail++ } elseif ($t.Status -eq 'Warn') { $connWarn++ } }
}
$connCards = ''
foreach ($t in $connTargets) {
  $tcol = switch ($t.Status) { 'Fail' {'var(--crit)'} 'Warn' {'var(--warn)'} default {'var(--mint)'} }
  $tlabel = switch ($t.Status) { 'Fail' { L 'قطع' 'Down' } 'Warn' { L 'هشدار' 'Warning' } default { L 'برقرار' 'Connected' } }
  $selfTag = if ($t.Self) { " <span class='chip'>" + (L 'این سرور' 'this server') + "</span>" } else { '' }
  $rows = ''
  foreach ($c in @($t.Channels)) {
    $mk = if (-not $c.Ok) { 'var(--crit)' } elseif ($c.State -eq 'Warn') { 'var(--warn)' } else { 'var(--mint)' }
    $ms = if ($c.Ms) { "<span class='muted num'>$($c.Ms)ms</span>" } else { '' }
    $why = ''
    if (-not $c.Ok -and $c.Reason) {
      $rsn = Txt ([string]$c.Reason); $rmd = Txt ([string]$c.Remedy)
      $why = "<div class='why'>$(Enc $rsn)" + $(if($rmd){"<div class='rmd'>$(L 'راهِ‌حل' 'Fix'): $(Enc $rmd)</div>"}else{''}) + "</div>"
    }
    $rows += "<tr><td style='width:16px'><span class='sev' style='background:$mk'></span></td><td style='white-space:nowrap'>$(Enc $c.Channel)</td><td>$(Enc (Txt ([string]$c.Detail)))$why</td><td style='text-align:end'>$ms</td></tr>"
  }
  $connCards += "<div class='card'><h3><span>$(Enc $t.Target)$selfTag</span><span class='pill' style='background:$tcol;color:#fff'>$tlabel</span></h3><table class='grid ctbl'><tbody>$rows</tbody></table></div>"
}
if (-not $connCards) { $connCards = "<div class='card empty'>— $(L 'هنوز آزمونِ ارتباطی اجرا نشده (هر ۱۵ دقیقه خودکار؛ یا از کنسول گزینهٔ ۱۹)' 'no connectivity test has run yet (every 15 min automatically, or console option 19)') —</div>" }
$connStatusLabel = if ($connFail) { L 'مشکل در ارتباط' 'connectivity problem' } elseif ($connWarn) { L 'با هشدار' 'with warnings' } elseif ($conn) { L 'همه برقرار' 'all connected' } else { L 'اجرا نشده' 'not run yet' }
# وضعیتِ رول‌های همیشه‌بازِ مدیریت | management allow-rules status
$mgRows = ''; $mgOkN = 0; $mgTotN = 0
try {
  $mg = @(Test-LBMgmtAllow -Config $cfg -InstallDir $root); $mgTotN = $mg.Count; $mgOkN = @($mg | Where-Object Enabled).Count
  foreach ($m in $mg) {
    $mk = if ($m.Enabled) { 'var(--mint)' } else { 'var(--crit)' }
    $mgRows += "<tr><td style='width:16px'><span class='sev' style='background:$mk'></span></td><td>$(Enc $m.Name)</td><td class='num muted'>$(Enc $m.Ports)</td><td class='muted'>$(Enc $m.Remote)</td><td>$(if($m.Enabled){L 'فعال' 'active'}else{L 'نیست' 'missing'})</td></tr>"
  }
} catch {}
if (-not $mgRows) { $mgRows = "<tr><td colspan='5' class='muted' style='text-align:center'>—</td></tr>" }

function Badge($n,$color){ if([int]$n -gt 0){ "<span class='b' style='background:$color'>$n</span>" } else { '' } }

$html=@"
<!DOCTYPE html><html dir="$dirAttr" lang="$langAttr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$($brand.NameEn) — Dashboard</title>
<style>
$fontCss
 /* پالتِ دفتر+نبض — حالتِ تاریک (پیش‌فرض) | ledger+pulse, dark */
 :root{
   --bg:#0B1322;--surface:#111B2E;--surface2:#172338;--line:#223150;
   --ink:#E5EAF4;--muted:#8A97B2;--brass:#7B96FF;--mint:#2FD0A0;
   --crit:#FF5A6E;--warn:#F2B33D;--info:#57B4FF;--okpill:#2FD0A0;--pilltext:#0B1322}
 /* حالتِ روشن | light */
 :root[data-theme="light"]{
   --bg:#F2F4F8;--surface:#FFFFFF;--surface2:#F5F7FB;--line:#E1E6EF;
   --ink:#172033;--muted:#5E6A82;--brass:#3456E0;--mint:#0B9A73;
   --crit:#D3364B;--warn:#B26B00;--info:#1F77C8;--okpill:#0B9A73;--pilltext:#FFFFFF}
 *{box-sizing:border-box} html,body{max-width:100%} body{margin:0;overflow-x:clip;background:var(--bg);color:var(--ink);font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:$dirAttr;transition:background .2s,color .2s}
 /* نوارِ کناری ثابت: با اسکرول از دید خارج نمی‌شود | fixed sidebar: stays visible while scrolling */
 .rail{position:fixed;top:0;bottom:0;inset-inline-start:0;width:220px;background:var(--surface);border-inline-end:1px solid var(--line);padding:18px 14px;overflow-y:auto;z-index:30}
 .brand{display:flex;align-items:center;gap:7px;margin-bottom:6px}
 .brand .nm{font-size:20px;font-weight:600;letter-spacing:.5px} .brand .en{color:var(--muted);font-size:12px}
 .tag{color:var(--muted);font-size:12px;line-height:1.7;margin:10px 0 18px;border-bottom:1px solid var(--line);padding-bottom:14px}
 .navi{margin-top:14px}
 .navi a{display:flex;align-items:center;gap:6px;color:var(--muted);text-decoration:none;font-size:13px;padding:7px 10px;border-radius:8px;margin:1px 0;border-inline-start:3px solid transparent;cursor:pointer}
 .navi a:hover{background:var(--surface2);color:var(--ink)} .navi a.on{background:var(--surface2);color:var(--ink);font-weight:600;border-inline-start-color:var(--brass)}
 .navi .b{margin-inline-start:auto;font-size:10.5px;color:#fff;border-radius:999px;padding:0 7px;font-weight:600;line-height:17px}
 .navi .grp{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);opacity:.7;margin:16px 10px 4px}
 .main{margin-inline-start:220px;padding:22px 26px;min-width:0}
 .topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
 .live{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
 .live .d{width:7px;height:7px;border-radius:50%;background:var(--mint)}
 .tog{background:var(--surface2);color:var(--ink);border:1px solid var(--line);border-radius:999px;font-size:12px;padding:6px 13px;cursor:pointer;font-family:inherit}
 .tog:hover{border-color:var(--brass)}
 /* هر بخش یک تب | one tab per section */
 .view{display:none} .view.on{display:block;animation:lbfade .18s ease}
 @keyframes lbfade{from{opacity:.35}to{opacity:1}}
 .vh{margin:2px 0 16px} .vh h1{font-size:20px;margin:0 0 4px;font-weight:600} .vh p{margin:0;font-size:13px;color:var(--muted);line-height:1.7}
 .hero{display:flex;align-items:center;justify-content:space-between;background:var(--surface);border:1px solid var(--line);border-inline-start:4px solid $hc;border-radius:14px;padding:18px 22px;margin-bottom:18px}
 .hero .st{font-size:24px;font-weight:600;color:$hc} .hero .se{color:var(--muted);font-size:13px} .hero .ts{color:var(--muted);font-size:12px;text-align:end}
 .kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}
 .kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px}
 .kpi.go{cursor:pointer;transition:border-color .15s} .kpi.go:hover{border-color:var(--brass)}
 .kpi .v{font-size:30px;font-weight:600} .kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
 .cols{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
 .card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
 .cols > .card{margin-bottom:0}
 .card h3{margin:0 0 12px;font-size:14px;color:var(--muted);font-weight:500;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
 .card h3 > span:first-child{color:var(--ink);font-weight:600}
 .more{font-size:12px;color:var(--brass);text-decoration:none;cursor:pointer;margin-inline-start:auto} .more:hover{text-decoration:underline}
 td.num{white-space:nowrap}
 table{width:100%;border-collapse:collapse;font-size:13px} th,td{text-align:$alignAttr;padding:7px 8px;border-bottom:1px solid var(--line)}
 th{color:var(--muted);font-weight:500;font-size:12px} .num{font-variant-numeric:tabular-nums} .muted{color:var(--muted)}
 .bar{background:var(--surface2);border-radius:6px;height:8px;overflow:hidden} .bar i{display:block;height:8px;border-radius:6px}
 .chip{display:inline-block;background:var(--surface2);border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:11.5px;color:var(--ink);margin:2px 0}
 .chip.on{border-color:var(--mint);color:var(--mint)} .chip.off{opacity:.55}
 .pill{border-radius:20px;padding:2px 12px;font-size:12px;color:var(--pilltext);font-weight:600} .pill.ok{background:var(--okpill)} .pill.bad{background:var(--crit);color:#fff}
 .kv{display:grid;grid-template-columns:max-content 1fr;gap:9px 16px;font-size:13px;align-items:baseline} .kv .k{color:var(--muted)}
 .hint{font-size:12px;color:var(--muted);margin-top:12px;line-height:1.8}
 .hint code{background:var(--surface2);border:1px solid var(--line);border-radius:6px;padding:1px 7px;font-size:11.5px;direction:ltr;unicode-bidi:isolate}
 .tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-bottom:8px}
 .tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px;display:flex;flex-direction:column;gap:2px;position:relative;text-decoration:none;color:inherit;transition:border-color .15s,transform .1s}
 a.tile{cursor:pointer} a.tile:hover{border-color:var(--brass);transform:translateY(-1px)}
 .tile-empty{opacity:.55} .tile .dot{width:8px;height:8px;border-radius:50%;position:absolute;top:12px;inset-inline-end:12px} .tile .tl{padding-inline-end:14px;color:var(--muted);font-size:12px} .tile .tv{font-size:22px;font-weight:600}
 .fbar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 10px}
 .fchip{display:inline-flex;align-items:center;gap:5px;background:var(--surface2);color:var(--ink);border:1px solid var(--line);border-radius:999px;padding:4px 11px;font-size:12px;cursor:pointer;font-family:inherit}
 .fchip:hover{border-color:var(--brass)} .fchip.on{border-color:var(--brass);background:color-mix(in srgb,var(--brass) 20%,var(--surface2))}
 .fchip .sev{margin:0}
 .search{width:100%;background:var(--surface2);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:9px 12px;font-family:inherit;font-size:13px;margin:0 0 12px}
 .search:focus{outline:none;border-color:var(--brass)}
 .erow.hide{display:none}
 th.sortable{cursor:pointer;user-select:none} th.sortable:hover{color:var(--ink)}
 th .arw{opacity:.6;font-size:10px;margin-inline-start:4px}
 tbody tr.clk{cursor:pointer} tbody tr.sel{background:var(--surface2)}
 tbody tr.exp td{white-space:pre-wrap!important;max-width:none!important;word-break:break-word}
 .panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
 .panel h2{display:flex;align-items:center;gap:8px;font-size:15px;margin:0 0 10px;font-weight:500}
 .count{background:var(--surface2);border:1px solid var(--line);border-radius:20px;padding:1px 9px;font-size:12px;color:var(--muted)}
 .pfilter{margin-inline-start:auto;background:var(--surface2);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:4px 9px;font-family:inherit;font-size:12px;width:170px}
 .pfilter:focus{outline:none;border-color:var(--brass)}
 .card h3 .more + .pfilter{margin-inline-start:8px}
 .banner{display:flex;align-items:center;gap:10px;background:var(--surface);background:color-mix(in srgb,var(--warn) 14%,var(--surface));border:1px solid var(--warn);border-radius:12px;padding:10px 14px;margin-bottom:14px;color:var(--ink);text-decoration:none;font-size:13px}
 .banner b{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--warn);color:var(--pilltext);font-size:13px;flex:0 0 22px}
 .grid td:last-child{max-width:420px;white-space:pre-wrap;word-break:break-word}
 .sev{display:inline-block;width:8px;height:8px;border-radius:50%;margin-inline-end:6px}
 .mitre{display:inline-block;background:var(--surface2);border:1px solid var(--line);border-radius:6px;padding:0 6px;font-size:10px;color:var(--muted);font-variant-numeric:tabular-nums;margin-inline-start:4px}
 .empty{text-align:center;color:var(--muted);padding:26px}
 .ctbl td{padding:6px 8px;vertical-align:top} .ctbl .why{margin-top:4px;font-size:12px;color:var(--crit)} .ctbl .why .rmd{color:var(--muted);margin-top:2px}
 @media(max-width:1100px){.kpis{grid-template-columns:repeat(3,1fr)}}
 /* صفحهٔ باریک: نوارِ کناری به نوارِ تبِ چسبان در بالا تبدیل می‌شود | narrow: sticky top tab bar */
 @media(max-width:860px){
   .rail{position:sticky;top:0;bottom:auto;width:auto;padding:8px 10px;border-inline-end:0;border-bottom:1px solid var(--line)}
   .rail .brand,.rail .tag,.navi .grp{display:none}
   .navi{display:flex;gap:4px;overflow-x:auto;margin:0}
   .navi a{white-space:nowrap;margin:0;border-inline-start:0;border-bottom:2px solid transparent;border-radius:6px}
   .navi a.on{border-bottom-color:var(--brass)}
   .main{margin-inline-start:0;padding:16px}
   .kpis{grid-template-columns:repeat(2,1fr)} .cols{grid-template-columns:1fr} .cols > .card{margin-bottom:0}
   .hero{flex-direction:column;align-items:flex-start;gap:8px} .hero .ts{text-align:start}
   .card,.panel{overflow-x:auto} .grid td:last-child{max-width:none} .kv{grid-template-columns:1fr}
 }
</style></head><body>
 <aside class="rail">
   <div class="brand">$logo<div><div class="nm">Log<span style="color:var(--brass)">Bok</span></div>$brandSub</div></div>
   $(if($brand.Tagline){"<div class=tag>$($brand.Tagline)</div>"})
   <nav class="navi">
     <a href="#overview" data-v="overview" onclick="lbShow('overview');return false;">$(L 'نمای کلی' 'Overview')</a>
     <a href="#incidents" data-v="incidents" onclick="lbShow('incidents');return false;">$(L 'میزِ رخداد' 'Incidents')$(Badge $incidents.Count 'var(--warn)')</a>
     <a href="#events" data-v="events" onclick="lbShow('events');return false;">$(L 'رویدادها' 'Events')$(Badge $crit 'var(--crit)')</a>
     <a href="#guard" data-v="guard" onclick="lbShow('guard');return false;">$(L 'سپرِ ورود' 'Login guard')$(Badge $gNow 'var(--crit)')</a>
     <a href="#connect" data-v="connect" onclick="lbShow('connect');return false;">$(L 'ارتباط‌ها' 'Connections')$(Badge $connFail 'var(--crit)')</a>
     <div class="grp">$(L 'سامانه' 'System')</div>
     <a href="#lic" data-v="lic" onclick="lbShow('lic');return false;">$(L 'لایسنس‌ها' 'Licenses')$(if($soonest){Badge 1 'var(--warn)'})</a>
     <a href="#jobs" data-v="jobs" onclick="lbShow('jobs');return false;">$(L 'جاب‌ها' 'Jobs')$(Badge $jobsBad 'var(--warn)')</a>
     <a href="#agents" data-v="agents" onclick="lbShow('agents');return false;">$(L 'ایجنت‌ها' 'Agents')</a>
   </nav>
 </aside>
 <main class="main">
   <div class="topbar">
     <span class="live"><span class="d"></span>$(L 'زنده · آخرین به‌روزرسانی' 'Live · updated') $((Get-Date).ToString('HH:mm',[Globalization.CultureInfo]::InvariantCulture))</span>
     <span>$(if($webOn){"<a class='tog' style='text-decoration:none;margin-inline-end:6px' href='http://localhost:$webPort/'>$(L 'کنسولِ وب ←' 'Open web console →')</a>"})<button class="tog" id="tog" onclick="lbToggle()">$(L 'روشن / تاریک' 'Light / dark')</button></span>
   </div>
   $licBanner

   <!-- ============ نمای کلی | Overview ============ -->
   <section class="view" id="v-overview">
     <div class="hero">
       <div><div class="st">$(if($isEn){$heroEn}else{$hero})</div><div class="se">$(L "بازهٔ $Hours ساعت اخیر" "last $Hours hours")</div></div>
       <div class="ts">$($brand.NameEn)<br>$((Get-Date).ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture))</div>
     </div>
     <div class="kpis">
       <div class="kpi go" onclick="lbShow('events');lbSev('Critical')"><div class="v" style="color:var(--crit)">$crit</div><div class="l">$(L 'بحرانی' 'Critical')</div></div>
       <div class="kpi go" onclick="lbShow('events');lbSev('Warning')"><div class="v" style="color:var(--warn)">$warn</div><div class="l">$(L 'هشدار' 'Warning')</div></div>
       <div class="kpi go" onclick="lbShow('events');lbSev('Info')"><div class="v" style="color:var(--info)">$info</div><div class="l">$(L 'اطلاع' 'Info')</div></div>
       <div class="kpi go" onclick="lbShow('guard')"><div class="v" style="color:var(--crit)">$gNow</div><div class="l">$(L 'IPِ بلاک‌شده' 'Blocked IPs')</div></div>
       <div class="kpi go" onclick="lbShow('jobs')"><div class="v" style="color:var(--mint)">$jobsOn<span class="muted" style="font-size:16px"> / $($jobs.Count)</span></div><div class="l">$(L 'جابِ فعال' 'Active jobs')</div></div>
     </div>
     <div class="card"><h3><span>$(L 'دسته‌ها' 'Categories')</span><span class="muted" style="font-size:11px">$Hours h · $(L 'روی هر دسته کلیک کنید تا رویدادهایش باز شود' 'click a category to open its events')</span></h3><div class="tiles">$tiles</div></div>
     <div class="cols">
       <div class="card"><h3><span>$(L 'آخرین رویدادهای بحرانی' 'Latest critical events')</span><a class="more" onclick="lbShow('events');lbSev('Critical')">$(L 'همه ←' 'All →')</a></h3>
         <table><thead><tr><th>$(L 'زمان' 'Time')</th><th>$(L 'سیستم' 'Host')</th><th>$(L 'رویداد' 'Event')</th></tr></thead><tbody>$critRows</tbody></table></div>
       <div class="card"><h3><span>$(L 'سلامتِ سامانه' 'System health')</span></h3>
         <div class="kv">
           <div class="k">$(L 'لایسنس' 'License')</div><div>$licPill <a class="more" onclick="lbShow('lic')">$(L 'جزئیات' 'details')</a></div>
           <div class="k">$(L 'رخدادِ باز' 'Open incidents')</div><div>$($incidents.Count) <a class="more" onclick="lbShow('incidents')">$(L 'میزِ رخداد' 'incidents')</a></div>
           <div class="k">$(L 'جاب‌ها' 'Jobs')</div><div>$(L "$jobsOn از $($jobs.Count) فعال" "$jobsOn of $($jobs.Count) on")$(if($jobsBad){" · <span style='color:var(--warn)'>$(L "$jobsBad نیازمندِ بررسی" "$jobsBad need attention")</span>"}) <a class="more" onclick="lbShow('jobs')">$(L 'جاب‌ها' 'jobs')</a></div>
           <div class="k">$(L 'سپرِ ورود' 'Login guard')</div><div>$(L "$gNow IP بلاک · $gRulesN رولِ فایروال · آخرین اجرا $gLast" "$gNow IPs blocked · $gRulesN firewall rules · last run $gLast") <a class="more" onclick="lbShow('guard')">$(L 'سپر' 'guard')</a></div>
           <div class="k">$(L 'ارتباط‌ها' 'Connections')</div><div>$(L "$(@($connTargets).Count) هدف · $connStatusLabel" "$(@($connTargets).Count) targets · $connStatusLabel") <a class="more" onclick="lbShow('connect')">$(L 'ارتباط‌ها' 'connections')</a></div>
           <div class="k">$(L 'انبارِ لاگ' 'Log store')</div><div class="muted">$archLine</div>
           <div class="k">$(L 'ایجنت‌ها' 'Agents')</div><div>$($inv.Count)</div>
         </div></div>
     </div>
   </section>

   <!-- ============ میزِ رخداد | Incidents ============ -->
   <section class="view" id="v-incidents">
     <div class="vh"><h1>$(L 'میزِ رخداد' 'Incidents')</h1><p>$(L 'رویدادهای هم‌جنس در یک «رخداد» جمع می‌شوند تا یک‌جا بررسی و بسته شوند؛ کنارش پرخطرترین کاربران، سیستم‌ها و IPها بر اساسِ امتیازِ ریسکِ تجمعی.' 'Related events are grouped into one incident so they can be reviewed and closed together, next to the riskiest users, hosts and IPs by accumulated risk score.')</p></div>
     <div class="card"><h3><span>$(L 'رخدادهای باز' 'Open incidents')</span><span class="count">$($incidents.Count)</span></h3>
       <table class="grid"><thead><tr><th>$(L 'شناسه' 'ID')</th><th>$(L 'سیستم' 'Host')</th><th>$(L 'عنوان' 'Title')</th><th>MITRE</th><th>$(L 'تعداد' 'Count')</th><th>$(L 'وضعیت' 'Status')</th></tr></thead><tbody>$incRows</tbody></table>
       <div class="hint">$(L 'بستن یا تغییرِ وضعیتِ رخداد: کنسولِ مدیریت' 'Close or change an incident: management console') <code>C:\Scripts\LogBok\Console\LogBok-Console.ps1</code></div></div>
     <div class="cols">
       <div class="card"><h3><span>$(L 'پرخطرترین‌ها' 'Top risk')</span><span class="muted" style="font-size:11px">UEBA</span></h3>
         <table><thead><tr><th>$(L 'موجودیت' 'Entity')</th><th>$(L 'ریسک' 'Risk')</th><th>$(L 'امتیاز' 'Score')</th><th>$(L 'سطح' 'Level')</th></tr></thead><tbody>$riskRows</tbody></table>
         <div class="hint">$(L 'امتیاز با هر رویداد بالا می‌رود و با گذشتِ زمان کم‌کم محو می‌شود.' 'The score rises with each event and fades gradually over time.')</div></div>
       <div class="card"><h3><span>$(L 'انبارِ لاگ' 'Log store')</span></h3>
         <div class="kv"><div class="k">$(L 'وضعیت' 'Status')</div><div>$archLine</div></div>
         <div class="hint">$(L 'جست‌وجو در کلِ تاریخچه:' 'Search the whole history:') <code>Search-Logs.ps1</code></div></div>
     </div>
   </section>

   <!-- ============ رویدادها | Events ============ -->
   <section class="view" id="v-events">
     <div class="vh"><h1>$(L 'رویدادها' 'Events')</h1><p>$(L "همهٔ یافته‌های $Hours ساعتِ اخیر، دسته‌بندی‌شده. با سطح، دسته یا جست‌وجو فیلتر کنید؛ روی هر ردیف کلیک کنید تا کاملش را ببینید." "All findings from the last $Hours hours by category. Filter by level, category or search; click a row to expand it.")</p></div>
     <input class="search" id="lbsearch" type="search" placeholder="$(L 'جست‌وجو در رویدادها…' 'Search events…')" oninput="lbApplyEv()" aria-label="search events">
     <div class="fbar">$sevChips</div>
     <div class="fbar">$catChips</div>
     $sections
     <div class="card empty" id="evnone" style="display:none">— $(L 'رویدادی با این فیلتر نیست' 'no events match this filter') —</div>
   </section>

   <!-- ============ سپرِ ورود | Login guard ============ -->
   <section class="view" id="v-guard">
     <div class="vh"><h1>$(L 'سپرِ ورود' 'Login guard')</h1><p>$(L 'IPهایی که پشتِ سرِ هم رمزِ اشتباه می‌زنند (RDP، ورودِ ویندوز، SQL، FTP، وب، SSH) خودکار در فایروالِ ویندوز بلاک می‌شوند. اگر رولِ بلاک پاک یا دست‌کاری شود، چند ثانیه بعد خودش برمی‌گردد.' 'IPs that keep failing to log on (RDP, Windows logon, SQL, FTP, web, SSH) are blocked automatically in Windows Firewall. If a block rule is deleted or tampered with, it is restored within seconds.')</p></div>
     <div class="kpis">
       <div class="kpi"><div class="v" style="color:var(--crit)">$gNow</div><div class="l">$(L 'هم‌اکنون بلاک' 'Blocked now')</div></div>
       <div class="kpi"><div class="v">$gPermN</div><div class="l">$(L 'بلاکِ دائمی' 'Permanent')</div></div>
       <div class="kpi"><div class="v" style="color:var(--warn)">$gWatch</div><div class="l">$(L 'زیرِ نظر (تلاشِ ناموفق)' 'Being watched')</div></div>
       <div class="kpi"><div class="v">$($gBlocks.Count)</div><div class="l">$(L "بلاک در $Hours ساعت" "Blocks in $Hours h")</div></div>
       <div class="kpi"><div class="v" style="color:var(--mint)">$gRulesN</div><div class="l">$(L 'رولِ فایروال' 'Firewall rules')</div></div>
     </div>
     <div class="card"><h3><span>$(L 'هم‌اکنون بلاک' 'Blocked right now')</span><span class="count">$($gActive.Count)</span></h3>
       <table class="grid"><thead><tr><th>IP</th><th>$(L 'کشور' 'Country')</th><th>$(L 'دلیل · منبع' 'Reason · source')</th><th>$(L 'از' 'Since')</th><th>$(L 'تا' 'Until')</th><th>$(L 'بارِ بلاک' 'Blocks')</th><th>$(L 'کاربرانِ امتحان‌شده' 'Users tried')</th></tr></thead><tbody>$gActRows</tbody></table></div>
     <div class="cols">
       <div class="card"><h3><span>$(L 'تنظیماتِ محافظت' 'Protection settings')</span><span class="muted" style="font-size:11px">config.psd1 → Guard</span></h3>
         <div class="kv">
           <div class="k">$(L 'قاعده' 'Rule')</div><div>$gRule</div>
           <div class="k">$(L 'سرویس‌های محافظت‌شده' 'Protected services')</div><div>$gProt</div>
           <div class="k">$(L 'بلاکِ کشوری' 'Country blocking')</div><div>$gGeo</div>
           <div class="k">$(L 'ساعتِ کاری' 'Work hours')</div><div>$gWork</div>
           <div class="k">$(L 'اشتراکِ بلاک' 'Shared blocks')</div><div>$gShare</div>
           <div class="k">$(L 'فیدِ تهدید' 'Threat feeds')</div><div>$gFeed</div>
           <div class="k">$(L 'آخرین اجرا' 'Last run')</div><div class="num">$gLast</div>
         </div></div>
       <div class="card"><h3><span>$(L 'لیستِ سفید و سیاه' 'Whitelist &amp; blacklist')</span></h3>
         <div class="kv">
           <div class="k">LAN</div><div>$gLan</div>
           <div class="k">$(L 'لیستِ سفید' 'Whitelist')</div><div class="num">$gWhite</div>
           <div class="k">$(L 'لیستِ سیاه' 'Blacklist')</div><div class="num">$gBlack</div>
         </div>
         <div class="hint">$(L 'بلاک/آزادکردنِ IP و افزودن به لیستِ سفید یا سیاه: کنسولِ مدیریت، گزینهٔ ۱۷' 'Block/unblock an IP or edit the white/black lists: management console, option 17') <code>Console\LogBok-Console.ps1 → 17</code></div></div>
     </div>
     <div class="card"><h3><span>$(L 'بلاک‌های اخیر' 'Recent blocks')</span><span class="muted" style="font-size:11px">$(L "$Hours ساعتِ اخیر · $gIps IP · $gPerm دائمی · روی $gHosts سیستم" "last $Hours h · $gIps IPs · $gPerm permanent · on $gHosts hosts")</span></h3>
       <div class="cols" style="margin-bottom:0;grid-template-columns:2fr 1fr">
         <table class="grid"><thead><tr><th>$(L 'زمان' 'Time')</th><th>$(L 'سیستم' 'Host')</th><th>IP</th><th>$(L 'کشور' 'Country')</th><th>$(L 'دلیل' 'Reason')</th><th>$(L 'تا' 'Until')</th></tr></thead><tbody>$gRows</tbody></table>
         <table><thead><tr><th>$(L 'کشور' 'Country')</th><th>$(L 'سهم' 'Share')</th><th>#</th></tr></thead><tbody>$gCtyRows</tbody></table>
       </div></div>
   </section>

   <!-- ============ ارتباط‌ها | Connections ============ -->
   <section class="view" id="v-connect">
     <div class="vh"><h1>$(L 'ارتباط‌ها' 'Connections')</h1><p>$(L 'لاگ‌بوک برای جمع‌آوریِ لاگ و مدیریت باید به سیستم‌ها و سرویس‌ها وصل شود. این‌جا وضعیتِ هر مسیر (DNS، پورت، WinRM، خواندنِ رویداد از راه دور، WEF) را می‌بینید؛ اگر برقرار نشد، دلیل و راهِ‌حلش نوشته شده. هر ۱۵ دقیقه خودکار آزموده می‌شود (یا از کنسول گزینهٔ ۱۹).' 'To collect logs and manage machines, LogBok must reach them. Here is the status of each path (DNS, ports, WinRM, remote event-log read, WEF); when one fails, the reason and the fix are shown. Tested automatically every 15 minutes (or console option 19).')</p></div>
     <div class="kpis">
       <div class="kpi"><div class="v">$(@($connTargets).Count)</div><div class="l">$(L 'هدف' 'Targets')</div></div>
       <div class="kpi"><div class="v" style="color:var(--mint)">$(@($connTargets | Where-Object { $_.Status -eq 'OK' }).Count)</div><div class="l">$(L 'برقرار' 'Connected')</div></div>
       <div class="kpi"><div class="v" style="color:var(--warn)">$connWarn</div><div class="l">$(L 'هشدار' 'Warning')</div></div>
       <div class="kpi"><div class="v" style="color:var(--crit)">$connFail</div><div class="l">$(L 'قطع' 'Down')</div></div>
       <div class="kpi"><div class="v" style="color:var(--mint)">$mgOkN<span class="muted" style="font-size:16px"> / $mgTotN</span></div><div class="l">$(L 'رولِ همیشه‌باز' 'Always-open rules')</div></div>
     </div>
     <div class="card"><h3><span>$(L 'مسیرِ مدیریتِ محافظت‌شده' 'Protected management path')</span><span class="muted" style="font-size:11px">$(L 'وقتی فایروال روشن/ریست می‌شود این رول‌ها اول ساخته می‌شوند تا ارتباطِ خودِ لاگ‌بوک قطع نشود' 'these rules are asserted before any firewall enable/reset so LogBok never cuts its own path')</span></h3>
       <table class="grid"><thead><tr><th></th><th>$(L 'کانال' 'Channel')</th><th>$(L 'پورت' 'Ports')</th><th>$(L 'از' 'From')</th><th>$(L 'وضعیت' 'State')</th></tr></thead><tbody>$mgRows</tbody></table>
       <div class="hint">$(L 'IP مدیرها را در config.psd1 → Management → AdminIPs بگذارید تا فقط آن‌ها باز باشند و هرگز بلاک نشوند.' 'Set admin IPs under config.psd1 → Management → AdminIPs so only they are open and never blocked.') <code>C:\Scripts\LogBok\config.psd1</code></div></div>
     <div class="muted" style="font-size:12px;margin:2px 0 12px">$(L 'آخرین آزمون' 'Last test'): $connGen</div>
     $connCards
   </section>

   <!-- ============ لایسنس‌ها | Licenses ============ -->
   <section class="view" id="v-lic">
     <div class="vh"><h1>$(L 'لایسنس‌ها' 'Licenses')</h1><p>$(L 'لایسنسِ لاگ‌بوکِ همین سرور، به‌علاوهٔ تاریخِ انقضای گواهی‌های SSL، فعال‌سازیِ ویندوز و لایسنس‌هایی که در config ثبت کرده‌اید. از چند روز مانده به انقضا هشدار ایمیل می‌شود.' 'This server''s LogBok license, plus expiry of SSL certificates, Windows activation and any licenses listed in config. Email reminders start a few days before expiry.')</p></div>
     <div class="card" id="lic"><h3><span>$(L 'لایسنس‌ها و انقضا' 'Licenses &amp; expiry')</span>$licPill</h3>
       <div class="muted" style="font-size:12px;margin-bottom:10px">$($brand.NameEn): $(Enc $lic.Company) · $(L 'کد دستگاه' 'device code'): <span class="num">$(Enc $lic.DeviceCode)</span> · $(L "هشدارِ هفتگی از $warnDays روز قبل" "weekly reminder from $warnDays days before expiry")$(if($lic.Legacy -and $lic.Valid){' · ' + (L 'لایسنسِ قدیمی (بدونِ قفلِ دستگاه)' 'legacy license (not device-bound)')})$(if(-not $lic.Valid){'<br>' + (Enc (Get-LogBokLicenseReasonText -License $lic -Lang $(if($isEn){'en'}else{'fa'})))})</div>
       <table><thead><tr><th>$(L 'سرویس' 'Service')</th><th>$(L 'انقضا' 'Expiry')</th><th></th><th>$(L 'مانده' 'Left')</th></tr></thead><tbody>$licWatchRows</tbody></table></div>
     <div class="cols">
       <div class="card"><h3><span>$(L 'سهمیهٔ لایسنس' 'Seat quota')</span></h3>
         <table><thead><tr><th>$(L 'نقش' 'Role')</th><th>$(L 'مصرف' 'Used')</th><th></th></tr></thead><tbody>$licRows</tbody></table></div>
       <div class="card"><h3><span>$(L 'تمدید و فعال‌سازی' 'Renew &amp; activate')</span></h3>
         <div class="kv">
           <div class="k">$(L 'دارنده' 'Licensee')</div><div>$(Enc $lic.Company)</div>
           <div class="k">$(L 'انقضا' 'Expiry')</div><div>$(if($lic.Permanent){L 'دائمی' 'permanent'}else{Enc $lic.Expiry})</div>
           <div class="k">$(L 'کد دستگاه' 'Device code')</div><div class="num">$(Enc $lic.DeviceCode)</div>
         </div>
         <div class="hint">$(L 'برای تمدید یا تعویض: میان‌برِ «LogBok Activation» روی دسکتاپ را باز کنید؛ کدِ دستگاه را بفرستید و لایسنسِ تازه را همان‌جا بچسبانید.' 'To renew or replace: open the “LogBok Activation” shortcut on the desktop, send the device code and paste the new license there.')</div></div>
     </div>
   </section>

   <!-- ============ جاب‌ها | Jobs ============ -->
   <section class="view" id="v-jobs">
     <div class="vh"><h1>$(L 'جاب‌ها' 'Jobs')</h1><p>$(L 'کارهای زمان‌بندی‌شدهٔ لاگ‌بوک در Task Scheduler (پوشهٔ \LogBok\). واچ‌داگ هر ۲ دقیقه بررسی می‌کند و جابِ پاک‌شده یا ازکارافتاده را دوباره می‌سازد.' 'LogBok''s scheduled tasks in Task Scheduler (folder \LogBok\). The watchdog checks every 2 minutes and rebuilds any job that was deleted or broken.')</p></div>
     <div class="card"><h3><span>$(L 'وضعیتِ جاب‌ها' 'Job status')</span><span class="muted" style="font-size:11px">$(L "$jobsOn از $($jobs.Count) فعال" "$jobsOn of $($jobs.Count) on")</span></h3>
       <table><thead><tr><th>$(L 'جاب' 'Job')</th><th>$(L 'کار' 'Purpose')</th><th>$(L 'وضعیت' 'State')</th><th>$(L 'آخرین' 'Last')</th><th>$(L 'بعدی' 'Next')</th></tr></thead><tbody>$jobRows</tbody></table>
       <div class="hint">$(L 'خاموش‌کردنِ یک جاب: در config.psd1 بخشِ Jobs مقدارش را $false کنید؛ ظرفِ ۲ دقیقه اعمال می‌شود.' 'To turn a job off: set it to $false under Jobs in config.psd1; applied within 2 minutes.') <code>C:\Scripts\LogBok\config.psd1</code></div></div>
   </section>

   <!-- ============ ایجنت‌ها | Agents ============ -->
   <section class="view" id="v-agents">
     <div class="vh"><h1>$(L 'ایجنت‌ها' 'Agents')</h1><p>$(L 'سیستم‌هایی که لاگ‌بوک رویشان نصب شده و لاگشان به این سرور می‌رسد.' 'Machines with LogBok installed that send their logs to this server.')</p></div>
     <div class="card"><h3><span>$(L 'ایجنت‌های نصب‌شده' 'Installed agents')</span><span class="count">$($inv.Count)</span></h3>
       <table><thead><tr><th>$(L 'سیستم' 'Host')</th><th>$(L 'نقش' 'Role')</th><th>$(L 'نصب' 'Installed')</th></tr></thead><tbody>$agentRows</tbody></table>
       <div class="hint">$(L 'افزودنِ سیستمِ تازه:' 'Add machines:') <code>LogBok-Deploy-Clients.ps1</code> $(L 'یا کنسولِ مدیریت' 'or the management console')</div></div>
   </section>

   <p class="muted" style="font-size:12px;margin-top:22px">© BokerNet — $footName</p>
 </main>
<script>
 var LB_DEFAULT='$defTheme';
 var LB_TD='$(L 'تاریک' 'Dark')', LB_TL='$(L 'روشن' 'Light')';
 function lbApply(t){try{document.documentElement.setAttribute('data-theme',t);var b=document.getElementById('tog');if(b)b.textContent=(t==='light'?'☾ '+LB_TD:'☀ '+LB_TL);}catch(e){}}
 function lbToggle(){var cur=document.documentElement.getAttribute('data-theme')||LB_DEFAULT;var nx=(cur==='light'?'dark':'light');lbApply(nx);try{localStorage.setItem('logbok-theme',nx);}catch(e){}}
 (function(){var t=LB_DEFAULT;try{var s=localStorage.getItem('logbok-theme');if(s)t=s;}catch(e){}lbApply(t);})();

 /* تب‌ها | tabs */
 var LB_VIEWS=['overview','incidents','events','guard','connect','lic','jobs','agents'];
 var LB_ALIAS={top:'overview',cats:'overview',inc:'incidents'};
 function lbView(){
   var h=(location.hash||'').replace('#','');
   if(LB_ALIAS[h])h=LB_ALIAS[h];
   if(h.indexOf('sec-')===0)return 'events';
   if(LB_VIEWS.indexOf(h)>-1)return h;
   try{var s=sessionStorage.getItem('lb-view');if(s&&LB_VIEWS.indexOf(s)>-1)return s;}catch(e){}
   return 'overview';
 }
 function lbShow(v,keep){
   if(LB_VIEWS.indexOf(v)<0)v='overview';
   document.querySelectorAll('.view').forEach(function(s){s.classList.toggle('on',s.id==='v-'+v);});
   document.querySelectorAll('.navi a').forEach(function(a){a.classList.toggle('on',a.getAttribute('data-v')===v);});
   try{history.replaceState(null,'','#'+v);}catch(e){if(location.hash!=='#'+v)location.hash=v;}
   try{sessionStorage.setItem('lb-view',v);}catch(e){}
   if(!keep)window.scrollTo(0,0);
 }

 /* فیلترِ رویدادها | events filters */
 var LB_CAT='',LB_SEV='';
 function lbApplyEv(){
   var inp=document.getElementById('lbsearch');var q=(inp&&inp.value?inp.value:'').trim().toLowerCase();
   var anyVis=false;
   document.querySelectorAll('#v-events .panel').forEach(function(p){
     var catOk=!LB_CAT||p.getAttribute('data-cat')===LB_CAT;var any=false;
     p.querySelectorAll('.erow').forEach(function(r){
       var hit=catOk&&(!LB_SEV||r.getAttribute('data-sev')===LB_SEV)&&(!q||r.textContent.toLowerCase().indexOf(q)>-1);
       r.classList.toggle('hide',!hit);if(hit)any=true;
     });
     p.style.display=any?'':'none';if(any)anyVis=true;
   });
   document.querySelectorAll('.fchip[data-cat]').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-cat')===LB_CAT);});
   document.querySelectorAll('.fchip[data-sev]').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-sev')===LB_SEV);});
   var e=document.getElementById('evnone');if(e)e.style.display=anyVis?'none':'';
   try{sessionStorage.setItem('lb-ev',JSON.stringify({c:LB_CAT,s:LB_SEV,q:q}));}catch(x){}
 }
 function lbCat(k){LB_CAT=k||'';lbShow('events');lbApplyEv();}
 function lbSev(s){LB_SEV=s||'';lbApplyEv();}

 var LB_FPH='$(L 'فیلتر…' 'Filter…')';
 var LB_WEB='$(if($webOn){"http://localhost:$webPort/"})', LB_OPEN='$(L 'باز کردن در کنسولِ وب: جزئیات، لاگ‌های مرتبط و اقدام' 'Open in the web console: details, related logs and actions')';
 function lbCellVal(tr,i){ var c=tr.cells[i]; return c?c.innerText.trim():''; }
 function lbSort(tb,idx,th){
   var dir = (th.getAttribute('data-dir')==='asc')?'desc':'asc';
   Array.prototype.forEach.call(tb.tHead.rows[0].cells,function(h){ h.setAttribute('data-dir',''); var a=h.querySelector('.arw'); if(a){a.remove();} });
   th.setAttribute('data-dir',dir);
   var arw=document.createElement('span'); arw.className='arw'; arw.textContent=(dir==='asc')?'\u25B2':'\u25BC'; th.appendChild(arw);
   var tbody=tb.tBodies[0]; if(!tbody){return;}
   var rows=Array.prototype.slice.call(tbody.rows);
   rows.sort(function(a,b){
     var x=lbCellVal(a,idx), y=lbCellVal(b,idx);
     var nx=parseFloat(x.replace(/[^0-9.\-]/g,'')), ny=parseFloat(y.replace(/[^0-9.\-]/g,''));
     var numish=/^[\s0-9.,:\-\/]+$/;
     var isNum=(x!==''&&y!==''&&!isNaN(nx)&&!isNaN(ny)&&numish.test(x)&&numish.test(y));
     var r = isNum ? (nx-ny) : x.localeCompare(y);
     return (dir==='asc')? r : -r;
   });
   rows.forEach(function(r){ tbody.appendChild(r); });
 }
 function lbInitTables(){
   document.querySelectorAll('table').forEach(function(tb){
     if(tb.tHead && tb.tHead.rows.length){
       Array.prototype.forEach.call(tb.tHead.rows[0].cells,function(th,idx){
         th.classList.add('sortable');
         th.addEventListener('click',function(){ lbSort(tb,idx,th); });
       });
     }
     if(tb.tBodies.length){
       Array.prototype.forEach.call(tb.tBodies[0].rows,function(tr){
         tr.classList.add('clk');
         var fid = tr.getAttribute('data-id');
         if (fid && LB_WEB) { tr.title = LB_OPEN; tr.addEventListener('click',function(){ window.location.href = LB_WEB + '#/event/' + fid; }); return; }
         tr.addEventListener('click',function(){ tr.classList.toggle('exp'); tr.classList.toggle('sel'); });
       });
     }
   });
 }
 function lbInitFilters(){
   document.querySelectorAll('.panel, .card').forEach(function(p){
     var head=p.querySelector('h2') || p.querySelector('h3');
     if(!head || !p.querySelector('tbody') || p.querySelectorAll('tbody tr').length<6) { return; }
     var inp=document.createElement('input'); inp.type='search'; inp.className='pfilter'; inp.placeholder=LB_FPH;
     inp.addEventListener('click',function(e){ e.stopPropagation(); });
     inp.addEventListener('input',function(){
       var q=inp.value.trim().toLowerCase();
       p.querySelectorAll('tbody tr').forEach(function(tr){
         tr.style.display = (!q || tr.innerText.toLowerCase().indexOf(q)>-1) ? '' : 'none';
       });
     });
     head.appendChild(inp);
   });
 }

 /* به‌روزرسانیِ خودکار هر ۲ دقیقه — تب، فیلتر و اسکرول حفظ می‌شود؛ وقتی چیزی تایپ می‌کنید صبر می‌کند */
 function lbTick(){
   var a=document.activeElement;
   if(a&&a.tagName==='INPUT'&&a.value){setTimeout(lbTick,30000);return;}
   try{sessionStorage.setItem('lb-y',String(window.scrollY||0));}catch(e){}
   location.reload();
 }
 function lbInit(){
   lbInitTables();lbInitFilters();
   try{var o=JSON.parse(sessionStorage.getItem('lb-ev')||'null');if(o){LB_CAT=o.c||'';LB_SEV=o.s||'';var i=document.getElementById('lbsearch');if(i&&o.q)i.value=o.q;}}catch(e){}
   lbShow(lbView(),true);lbApplyEv();
   try{var y=parseInt(sessionStorage.getItem('lb-y')||'0',10);sessionStorage.removeItem('lb-y');if(y>0)window.scrollTo(0,y);}catch(e){}
   window.addEventListener('hashchange',function(){lbShow(lbView(),true);});
   setTimeout(lbTick,120000);
 }
 if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',lbInit);}else{lbInit();}
</script>
</body></html>
"@


if (-not (Test-Path $cfg.Paths.Reports)) { New-Item -ItemType Directory -Path $cfg.Paths.Reports -Force | Out-Null }
$out = Join-Path $cfg.Paths.Reports 'dashboard.html'
$html | Set-Content -Path $out -Encoding UTF8
Write-Host "داشبورد ساخته شد | Dashboard: $out"
