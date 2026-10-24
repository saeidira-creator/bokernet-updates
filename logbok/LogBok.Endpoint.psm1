# ==========================================================================
#  LogBok.Endpoint.psm1 — مدیریتِ سیستم‌ها از کنسول (الگو: Endpoint Central / Log360 Agent)
#  Endpoint management over the agent's secure push channel (no inbound port on clients):
#   • سیاست‌ها | policies : «محدودیتِ اینترنتِ برنامه‌ها» و «پروفایلِ سپرِ ورود» برای هر سیستم/گروهی
#   • فرمان‌ها | actions  : موجودی‌گیری، اسکنِ Defender، ایزوله/رفعِ ایزوله، بستنِ برنامه، بلاکِ IP،
#                          ری‌استارت، به‌روزرسانیِ ایجنت — در صف تا ضربانِ بعدیِ ایجنت (حداکثر ۲ دقیقه)
#   • موجودی | inventory  : سخت‌افزار، نرم‌افزار، به‌روزرسانی‌ها، مدیرانِ محلی، سلامت
#   • به‌روزرسانیِ خودکار : کدِ ایجنت با امضا و SHA-256 از همین کانال به‌روز می‌شود
#  دستورها هرگز «متنِ اسکریپتِ دلخواه» نیستند؛ فقط انواعِ ازپیش‌تعریف‌شده با پارامترِ اعتبارسنجی‌شده.
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:ActionTypes = @('inventory','defender-scan','defender-update','isolate','unisolate','kill-process','block-ip','unblock-ip','reboot','update-agent','sync-policy','posture-scan','fix-posture','patch-scan','install-updates','set-server','logoff-session','disconnect-session','message-session','uninstall')
$script:PostureFixable = @('fw-on','av-rt','av-sig','smb1','rdp-nla','uac','guest','autorun','wdigest','lsa-ppl','ntlm','llmnr','anon','ps2','screenlock','pwlen','lockout','wuauserv','audit-logon')
$script:WeekDays = @('Saturday','Sunday','Monday','Tuesday','Wednesday','Thursday','Friday')

$script:PostureCatalog = @(
    @('fw-on', 'high', 'فایروالِ ویندوز در همهٔ پروفایل‌ها روشن باشد', 'Windows Firewall on for all profiles'),
    @('av-rt', 'high', 'محافظتِ آنیِ Defender روشن باشد', 'Defender real-time protection on'),
    @('av-sig', 'medium', 'امضای آنتی‌ویروس به‌روز باشد (حداکثر ۳ روز)', 'Antivirus signatures up to date (max 3 days)'),
    @('smb1', 'high', 'پروتکلِ قدیمیِ SMBv1 خاموش باشد', 'Legacy SMBv1 disabled'),
    @('rdp-nla', 'high', 'اگر ریموت‌دسکتاپ باز است، NLA اجباری باشد', 'If Remote Desktop is on, NLA is required'),
    @('uac', 'high', 'UAC روشن باشد', 'UAC enabled'),
    @('guest', 'medium', 'حسابِ Guest غیرفعال باشد', 'Guest account disabled'),
    @('autorun', 'medium', 'اجرای خودکارِ فلش و CD خاموش باشد', 'AutoRun disabled for all drives'),
    @('wdigest', 'high', 'WDigest رمزِ متنی را در حافظه نگه ندارد', 'WDigest does not keep clear-text passwords'),
    @('lsa-ppl', 'medium', 'محافظتِ LSA روشن باشد (ضدِ سرقتِ رمز از حافظه)', 'LSA protection on (credential theft defence)'),
    @('ntlm', 'medium', 'فقط NTLMv2 فرستاده شود', 'Send NTLMv2 only'),
    @('llmnr', 'low', 'LLMNR خاموش باشد (ضدِ جعلِ نام در شبکه)', 'LLMNR disabled (name-spoofing defence)'),
    @('anon', 'low', 'فهرست‌کردنِ ناشناسِ حساب‌ها ممنوع باشد', 'No anonymous enumeration of accounts'),
    @('ps2', 'medium', 'موتورِ قدیمیِ PowerShell 2 حذف باشد', 'Legacy PowerShell 2.0 engine removed'),
    @('screenlock', 'low', 'قفلِ خودکارِ صفحه پس از حداکثر ۱۵ دقیقه', 'Automatic screen lock after at most 15 minutes'),
    @('pwlen', 'medium', 'حداقلِ طولِ رمز ۸ کاراکتر (سیستم‌های خارج از دامنه)', 'Minimum password length 8 (non-domain computers)'),
    @('lockout', 'medium', 'قفل‌شدنِ حساب پس از تلاش‌های ناموفق (سیستم‌های خارج از دامنه)', 'Account lockout after failed attempts (non-domain computers)'),
    @('wuauserv', 'high', 'سرویسِ Windows Update غیرفعال نباشد', 'Windows Update service not disabled'),
    @('audit-logon', 'medium', 'ممیزیِ ورودِ موفق و ناموفق روشن باشد', 'Logon success/failure auditing on'),
    @('bitlocker', 'medium', 'درایوِ ویندوز با BitLocker رمزگذاری شده باشد', 'System drive encrypted with BitLocker'),
    @('admins', 'low', 'تعدادِ مدیرانِ محلی کم باشد (حداکثر ۳)', 'Few local administrators (max 3)')
)
function Get-LBPostureCatalog { param([string]$Lang = 'fa') return @($script:PostureCatalog | ForEach-Object { [ordered]@{ id = $_[0]; sev = $_[1]; title = $(if ($Lang -eq 'en') { $_[3] } else { $_[2] }); fix = ($script:PostureFixable -contains $_[0]) } }) }
function Read-LBJsonList { param([string]$File) if (-not (Test-Path $File)) { return @() }; try { $h = ConvertTo-LBHashtable ((Get-Content $File -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return @($h) }; return @($h | Where-Object { $_ -is [hashtable] }) } catch { return @() } }
function Write-LBJsonFile { param([string]$File, $Obj) $tmp = "$File.tmp"; [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $Obj -Depth 8), (New-Object Text.UTF8Encoding($false))); Move-Item -Path $tmp -Destination $File -Force }
function Get-LBShaHex { param([string]$Text) $h = [Security.Cryptography.SHA256]::Create(); try { return (-join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })) } finally { $h.Dispose() } }

# --- سیاست‌ها | policies (state\endpoint-policies.json) ---------------------------------------
function Get-LBEndpointPolicies { param([Parameter(Mandatory)][string]$StateDir) return @(Read-LBJsonList (Join-Path $StateDir 'endpoint-policies.json')) }
function Save-LBEndpointPolicies { param([string]$StateDir, [object[]]$Policies) Write-LBJsonFile -File (Join-Path $StateDir 'endpoint-policies.json') -Obj @($Policies) }
function Test-LBProgramSpec {
    param([string]$p)
    $p = $p.Trim()
    if (-not $p -or $p.Length -gt 260) { return $false }
    if ($p -match '[<>"|?*]') { return $false }
    # نامِ فایلِ اجرایی (chrome.exe) یا مسیرِ کامل (C:\…\x.exe یا %ProgramFiles%\…\x.exe)
    return ($p -match '^[^\\/:]+\.exe$' -or $p -match '^([A-Za-z]:|%[A-Za-z_]+%)\\.+\.exe$')
}
function Set-LBEndpointPolicy {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][hashtable]$Policy, [string]$By)
    if (-not $Policy.Id) { $Policy.Id = 'ep' + [guid]::NewGuid().ToString('N').Substring(0, 8) }
    if ([string]$Policy.Id -notmatch '^[A-Za-z0-9_\-]{1,40}$') { throw 'invalid id' }
    if (-not ([string]$Policy.Name).Trim()) { throw 'نام لازم است | name required' }
    if ([string]$Policy.Type -notin 'appblock','guard','hardening','patch','applaunch','appremove','services') { throw 'type must be appblock, guard, hardening, patch, applaunch, appremove or services' }
    $t = if ($Policy.Targets) { $Policy.Targets } else { @{} }
    $hosts = @(@($t.Hosts) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-Z0-9_.\-]{1,63}$' } | Select-Object -Unique)
    $pats = @(@($t.Patterns) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-Z0-9_.\-*?]{1,63}$' } | Select-Object -Unique)
    $exHosts = @(@($t.ExceptHosts) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-Z0-9_.\-]{1,63}$' } | Select-Object -Unique)
    $exPats = @(@($t.ExceptPatterns) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-Z0-9_.\-*?]{1,63}$' } | Select-Object -Unique)
    $dnOk = { param($v) ([string]$v).Trim() -match '^(OU|CN|DC)=[^\r\n]{1,400}$' }
    $ous = @(@($t.OUs) | Where-Object { $_ -and (& $dnOk $_) } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
    $exOus = @(@($t.ExceptOUs) | Where-Object { $_ -and (& $dnOk $_) } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
    $grps = @(@($t.Groups) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[^\r\n]{1,200}$' } | Select-Object -Unique)
    $exGrps = @(@($t.ExceptGroups) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[^\r\n]{1,200}$' } | Select-Object -Unique)
    $Policy.Targets = @{ All = ($t.All -eq $true); Hosts = $hosts; Patterns = $pats; IncludeServer = ($t.IncludeServer -eq $true); ExceptHosts = $exHosts; ExceptPatterns = $exPats
                         OUs = $ous; ExceptOUs = $exOus; Groups = $grps; ExceptGroups = $exGrps }
    $st = if ($Policy.Settings) { $Policy.Settings } else { @{} }
    if ($Policy.Type -eq 'appblock') {
        $progs = @(@($st.Programs) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        foreach ($p in $progs) { if (-not (Test-LBProgramSpec $p)) { throw "برنامهٔ نامعتبر | invalid program: $p (use name.exe or a full path)" } }
        if (-not $progs.Count) { throw 'حداقل یک برنامه لازم است | at least one program' }
        $sch = if ($st.Schedule) { $st.Schedule } else { @{} }
        if ($sch.Enabled -eq $true -and ([string]$sch.Start -notmatch '^\d{2}:\d{2}$' -or [string]$sch.End -notmatch '^\d{2}:\d{2}$')) { throw 'ساعت باید HH:mm باشد | time must be HH:mm' }
        $uChk = { param($x) $v = ([string]$x).Trim(); ($v -and $v.Length -le 256 -and $v -notmatch '[<>:"/|?*]' -and $v -match '^(S-1-[0-9-]+|[^\\]+\\[^\\]+|[^\\]+)$') }
        $users = @(@($st.Users) | Where-Object { & $uChk $_ } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
        $exUsers = @(@($st.ExceptUsers) | Where-Object { & $uChk $_ } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
        $Policy.Settings = @{ Programs = $progs; Scope = $(if ([string]$st.Scope -eq 'all') { 'all' } else { 'internet' })
                              Schedule = @{ Enabled = ($sch.Enabled -eq $true); Days = @(@($sch.Days) | Where-Object { $_ -in 'Saturday','Sunday','Monday','Tuesday','Wednesday','Thursday','Friday' }); Start = [string]$sch.Start; End = [string]$sch.End }
                              Users = $users; ExceptUsers = $exUsers; Note = [string]$st.Note }
    } elseif ($Policy.Type -eq 'hardening') {
        $ck = @(@($st.Checks) | ForEach-Object { [string]$_ } | Where-Object { $script:PostureFixable -contains $_ } | Select-Object -Unique)
        if (-not $ck.Count) { throw 'حداقل یک مورد را انتخاب کنید | choose at least one setting' }
        $Policy.Settings = @{ Checks = $ck }
    } elseif ($Policy.Type -eq 'applaunch') {
        $progs = @(@($st.Programs) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        foreach ($pg in $progs) { if (-not (Test-LBProgramSpec $pg)) { throw "برنامهٔ نامعتبر | invalid program: $pg (use name.exe or a full path)" } }
        if (-not $progs.Count) { throw 'حداقل یک برنامه لازم است | at least one program' }
        $Policy.Settings = @{ Programs = $progs; Mode = $(if ([string]$st.Mode -in 'block','warn','audit') { [string]$st.Mode } else { 'block' }); List = $(if ([string]$st.List -eq 'allowlist') { 'allowlist' } else { 'blocklist' }); WarnText = ([string]$st.WarnText).Trim() }
        $Policy.Priority = [int]$Policy.Priority
    } elseif ($Policy.Type -eq 'appremove') {
        # programs here are app names/tokens (OneDrive, Copilot, a Store app name, or a classic display name), not exe paths
        $progs = @(@($st.Programs) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -and $_.Length -le 128 -and $_ -notmatch '[\r\n<>|]' } | Select-Object -Unique)
        if (-not $progs.Count) { throw 'حداقل یک برنامه لازم است | at least one app' }
        $Policy.Settings = @{ Programs = $progs; Note = [string]$st.Note }
    } elseif ($Policy.Type -eq 'services') {
        $svc = @(@($st.Services) | Where-Object { $_ -and ([string]$_.Name).Trim() } | ForEach-Object {
                @{ Name = ([string]$_.Name).Trim(); Startup = $(if ([string]$_.Startup -in 'auto', 'delayed', 'manual', 'disabled') { [string]$_.Startup } else { 'leave' }); State = $(if ([string]$_.State -in 'running', 'stopped') { [string]$_.State } else { 'leave' }) }
            } | Where-Object { $_.Name.Length -le 128 -and $_.Name -match '^[^\r\n<>|]+$' })
        if (-not $svc.Count) { throw 'حداقل یک سرویس لازم است | at least one service' }
        $Policy.Settings = @{ Services = $svc }
    } elseif ($Policy.Type -eq 'patch') {
        $Policy.Settings = @{ Scope = $(if ([string]$st.Scope -eq 'all') { 'all' } else { 'security' }); Days = @(@($st.Days) | Where-Object { $script:WeekDays -contains $_ }); Hour = [math]::Max(0, [math]::Min(23, [int]$st.Hour)); Reboot = $(if ([string]$st.Reboot -eq 'if-needed') { 'if-needed' } else { 'never' }) }
        $Policy.Priority = [int]$Policy.Priority
    } else {
        $g = @{}
        foreach ($k in 'MaxFailedAttempts','AttemptWindowMinutes','BlockMinutes','PermanentAfterBlocks','WebMaxFailures') { if ($null -ne $st[$k] -and "$($st[$k])" -ne '') { $g[$k] = [math]::Max(0, [int]$st[$k]) } }
        if ($null -ne $st.EscalationFactor -and "$($st.EscalationFactor)" -ne '') { $g.EscalationFactor = [math]::Max(1, [double]$st.EscalationFactor) }
        $pr = if ($st.Protect) { $st.Protect } else { @{} }
        $g.Protect = @{}; foreach ($k in 'RDP','WindowsLogon','SQL','FTP','Web','SSH') { $g.Protect[$k] = ($pr[$k] -ne $false) }
        $g.AutoWhitelistLan = ($st.AutoWhitelistLan -ne $false)
        foreach ($k in 'Whitelist','Blacklist') { $g[$k] = @(@($st[$k]) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[0-9./\-]{7,40}$' }) }
        $g.GeoMode = $(if ([string]$st.GeoMode -in 'Off','AllowOnly','BlockListed') { [string]$st.GeoMode } else { 'Off' })
        foreach ($k in 'AllowedCountries','BlockedCountries') { $g[$k] = @(@($st[$k]) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-Z]{2}$' }) }
        $wh = if ($st.WorkHours) { $st.WorkHours } else { @{} }
        $g.WorkHours = @{ Enabled = ($wh.Enabled -eq $true); Days = @(@($wh.Days) | Where-Object { $_ }); Start = $(if ([string]$wh.Start -match '^\d{2}:\d{2}$') { [string]$wh.Start } else { '08:00' }); End = $(if ([string]$wh.End -match '^\d{2}:\d{2}$') { [string]$wh.End } else { '17:00' }) }
        $g.Enabled = ($st.Enabled -ne $false)
        $Policy.Settings = $g
        $Policy.Priority = [int]$Policy.Priority
    }
    $Policy.Enabled = ($Policy.Enabled -ne $false)
    $all = @(Get-LBEndpointPolicies -StateDir $StateDir)
    $old = $all | Where-Object { [string]$_.Id -eq [string]$Policy.Id } | Select-Object -First 1
    $Policy.Created = $(if ($old -and $old.Created) { $old.Created } else { (Get-Date).ToString('o', $script:Inv) })
    $Policy.Updated = (Get-Date).ToString('o', $script:Inv); $Policy.By = $By
    Save-LBEndpointPolicies -StateDir $StateDir -Policies @(@($all | Where-Object { [string]$_.Id -ne [string]$Policy.Id }) + $Policy)
    return $Policy
}
function Remove-LBEndpointPolicy { param([string]$StateDir, [string]$Id) Save-LBEndpointPolicies -StateDir $StateDir -Policies @(Get-LBEndpointPolicies -StateDir $StateDir | Where-Object { [string]$_.Id -ne $Id }) }
# آیا OUِ سیستم زیرِ OUِ هدف است؟ | is the host's OU inside the target OU (subtree)?
function Test-LBOuMatch { param([string]$HostOu, [string]$TargetOu) if (-not $HostOu -or -not $TargetOu) { return $false }; $a = $HostOu.ToLowerInvariant() -replace '\s*,\s*', ','; $b = $TargetOu.ToLowerInvariant() -replace '\s*,\s*', ','; return ($a -eq $b -or $a.EndsWith(',' + $b)) }
function Test-LBGroupMatch { param($Info, [string]$Group) if (-not $Info -or -not $Group) { return $false }; $g = $Group.Trim(); $gl = ($g -replace '^.*\\', '').ToLowerInvariant(); foreach ($x in @($Info.groups)) { if (([string]$x).ToLowerInvariant() -eq $gl) { return $true } }; foreach ($x in @($Info.groupDns)) { if (([string]$x).ToLowerInvariant() -eq $g.ToLowerInvariant()) { return $true } }; return $false }
function Test-LBPolicyTarget {
    param($Policy, [string]$HostName, [switch]$IsServer, $Info)
    $t = $Policy.Targets; $h = $HostName.ToUpperInvariant()
    # استثناها همیشه برنده‌اند | exclusions always win
    if (@($t.ExceptHosts) -contains $h) { return $false }
    foreach ($p in @($t.ExceptPatterns)) { if ($h -like $p) { return $false } }
    if ($Info) {
        foreach ($o in @($t.ExceptOUs)) { if (Test-LBOuMatch -HostOu ([string]$Info.ou) -TargetOu $o) { return $false } }
        foreach ($g in @($t.ExceptGroups)) { if (Test-LBGroupMatch -Info $Info -Group $g) { return $false } }
    }
    if (@($t.Hosts) -contains $h) { return $true }
    foreach ($p in @($t.Patterns)) { if ($h -like $p) { return $true } }
    if ($Info) {
        foreach ($o in @($t.OUs)) { if (Test-LBOuMatch -HostOu ([string]$Info.ou) -TargetOu $o) { return $true } }
        foreach ($g in @($t.Groups)) { if (Test-LBGroupMatch -Info $Info -Group $g) { return $true } }
    }
    if ($t.All -eq $true) { if ($IsServer) { return ($t.IncludeServer -eq $true) } else { return $true } }
    return $false
}
# نقشهٔ AD (کش ۶۰ ثانیه) | AD computer map (state\ad-computers.json), 60s cache
$script:AdMapCache = @{ At = [datetime]::MinValue; Map = @{}; Dir = '' }
function Get-LBHostAdInfoMap {
    param([string]$StateDir)
    if ($script:AdMapCache.Dir -eq $StateDir -and (Get-Date) -lt $script:AdMapCache.At.AddSeconds(60)) { return $script:AdMapCache.Map }
    $m = @{}; $f = Join-Path $StateDir 'ad-computers.json'
    if (Test-Path $f) { try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { $m = $h } } catch { } }
    $script:AdMapCache = @{ At = (Get-Date); Map = $m; Dir = $StateDir }
    return $m
}
# نسخهٔ مرتب‌شده برای هشِ پایدار | canonical (sorted keys) copy for a stable revision hash
function ConvertTo-LBCanonical {
    param($o)
    if ($null -eq $o) { return $null }
    if ($o -is [string] -or $o -is [ValueType]) { return $o }
    if ($o -is [Collections.IDictionary]) { $r = [ordered]@{}; foreach ($k in @(@($o.Keys) | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) { $r[$k] = ConvertTo-LBCanonical $o[$k] }; return $r }
    if ($o -is [Collections.IEnumerable]) { return ,@(@($o) | ForEach-Object { ConvertTo-LBCanonical $_ }) }
    return $o
}
# سیاستِ مؤثرِ یک سیستم | effective policy for one host
function Get-LBEffectivePolicy {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$HostName, [switch]$IsServer, [object[]]$Policies)
    $src = if ($PSBoundParameters.ContainsKey('Policies')) { @($Policies) } else { @(Get-LBEndpointPolicies -StateDir $StateDir) }
    $info = $null; try { $cm = Get-LBHostAdInfoMap -StateDir $StateDir; $info = $cm[$HostName.ToUpperInvariant()] } catch { }
    $ps = @($src | Where-Object { $_.Enabled -ne $false -and (Test-LBPolicyTarget -Policy $_ -HostName $HostName -IsServer:$IsServer -Info $info) })
    $ab = @($ps | Where-Object { $_.Type -eq 'appblock' } | Sort-Object { [string]$_.Id } | ForEach-Object { [ordered]@{ id = [string]$_.Id; name = [string]$_.Name; programs = @($_.Settings.Programs); scope = [string]$_.Settings.Scope; schedule = $_.Settings.Schedule; users = @($_.Settings.Users); except = @($_.Settings.ExceptUsers) } })
    $ar = @($ps | Where-Object { $_.Type -eq 'appremove' } | Sort-Object { [string]$_.Id } | ForEach-Object { [ordered]@{ id = [string]$_.Id; name = [string]$_.Name; programs = @($_.Settings.Programs) } })
    $sv = @($ps | Where-Object { $_.Type -eq 'services' } | Sort-Object { [string]$_.Id } | ForEach-Object { @($_.Settings.Services) } | Where-Object { $_ -and $_.Name })
    $gp = $ps | Where-Object { $_.Type -eq 'guard' } | Sort-Object @{ Expression = { [int]$_.Priority }; Descending = $true }, @{ Expression = { [string]$_.Updated }; Descending = $true } | Select-Object -First 1
    $hd = @($ps | Where-Object { $_.Type -eq 'hardening' } | ForEach-Object { @($_.Settings.Checks) } | Where-Object { $_ } | Sort-Object -Unique)
    $pp = $ps | Where-Object { $_.Type -eq 'patch' } | Sort-Object @{ Expression = { [int]$_.Priority }; Descending = $true }, @{ Expression = { [string]$_.Updated }; Descending = $true } | Select-Object -First 1
    $alp = $ps | Where-Object { $_.Type -eq 'applaunch' } | Sort-Object @{ Expression = { [int]$_.Priority }; Descending = $true }, @{ Expression = { [string]$_.Updated }; Descending = $true } | Select-Object -First 1
    $o = [ordered]@{ appBlocks = $ab; appRemoves = $ar; services = $sv; guard = $(if ($gp) { [ordered]@{ id = [string]$gp.Id; name = [string]$gp.Name; settings = $gp.Settings } } else { $null })
                     harden = $hd; patch = $(if ($pp) { [ordered]@{ id = [string]$pp.Id; name = [string]$pp.Name; scope = [string]$pp.Settings.Scope; days = @($pp.Settings.Days); hour = [int]$pp.Settings.Hour; reboot = [string]$pp.Settings.Reboot } } else { $null })
                     appLaunch = $(if ($alp) { [ordered]@{ id = [string]$alp.Id; name = [string]$alp.Name; mode = [string]$alp.Settings.Mode; list = [string]$alp.Settings.List; programs = @($alp.Settings.Programs); warnText = [string]$alp.Settings.WarnText } } else { $null }) }
    $o.rev = (Get-LBShaHex (ConvertTo-Json -InputObject (ConvertTo-LBCanonical $o) -Depth 10 -Compress)).Substring(0, 16)
    return $o
}

# --- فرمان‌ها | action queue (state\agent-actions.json) -----------------------------------------
function Get-LBAgentActions { param([string]$StateDir, [string]$HostName) $a = @(Read-LBJsonList (Join-Path $StateDir 'agent-actions.json')); if ($HostName) { $a = @($a | Where-Object { [string]$_.Host -eq $HostName.ToUpperInvariant() }) }; return $a }
function Save-LBAgentActions { param([string]$StateDir, [object[]]$Actions) $keep = @($Actions | Sort-Object { [string]$_.Created } | Select-Object -Last 2000); Write-LBJsonFile -File (Join-Path $StateDir 'agent-actions.json') -Obj $keep }
function Add-LBAgentAction {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string[]]$Hosts, [Parameter(Mandatory)][string]$Type, [hashtable]$Arguments = @{}, [string]$By)
    if ($script:ActionTypes -notcontains $Type) { throw "unknown action: $Type" }
    $a = @{}
    switch ($Type) {
        'kill-process' { $n = ([string]$Arguments.name).Trim(); if ($n -notmatch '^[A-Za-z0-9_.\- ]{1,80}(\.exe)?$') { throw 'invalid process name' }; $a.name = ($n -replace '\.exe$', '') }
        'block-ip'     { if ([string]$Arguments.ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw 'invalid IP' }; $a.ip = [string]$Arguments.ip; $a.minutes = [math]::Max(0, [int]$Arguments.minutes) }
        'unblock-ip'   { if ([string]$Arguments.ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw 'invalid IP' }; $a.ip = [string]$Arguments.ip }
        'fix-posture'  { $a.checks = @(@($Arguments.checks) | ForEach-Object { [string]$_ } | Where-Object { $script:PostureFixable -contains $_ } | Select-Object -Unique); if (-not $a.checks.Count) { throw 'no fixable setting selected' } }
        'install-updates' { $a.scope = $(if ([string]$Arguments.scope -eq 'all') { 'all' } else { 'security' }); $a.reboot = $(if ([string]$Arguments.reboot -eq 'if-needed') { 'if-needed' } else { 'never' }) }
        'logoff-session'     { $a.id = [int]$Arguments.id; if ($a.id -le 0) { throw 'invalid session id' } }
        'disconnect-session' { $a.id = [int]$Arguments.id; if ($a.id -le 0) { throw 'invalid session id' } }
        'message-session'    { $a.id = [int]$Arguments.id; if ($a.id -le 0) { throw 'invalid session id' }; $tx = ([string]$Arguments.text -replace '[\x00-\x08\x0b\x0c\x0e-\x1f]', '').Trim(); if (-not $tx) { throw 'message text required' }; if ($tx.Length -gt 500) { $tx = $tx.Substring(0, 500) }; $a.text = $tx }
        'set-server'   { $a.names = @(@($Arguments.names) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[A-Za-z0-9_.\-]{1,255}$' -and $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique)
                         $a.ips = @(@($Arguments.ips) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique)
                         $a.port = [math]::Max(0, [math]::Min(65535, [int]$Arguments.port)); if (-not $a.names.Count -and -not $a.ips.Count) { throw 'new server name or IP required' } }
        'reboot'       { $a.minutes = [math]::Max(1, [math]::Min(1440, [int]$(if ($Arguments.minutes) { $Arguments.minutes } else { 5 }))); $a.message = ([string]$Arguments.message -replace '[^\p{L}\p{N} .,:!?()\-]', '').Substring(0, [math]::Min(200, ([string]$Arguments.message -replace '[^\p{L}\p{N} .,:!?()\-]', '').Length)) }
    }
    $all = @(Get-LBAgentActions -StateDir $StateDir)
    $new = @()
    foreach ($h in $Hosts) {
        $hn = ([string]$h).Trim().ToUpperInvariant(); if ($hn -notmatch '^[A-Z0-9_.\-]{1,63}$') { continue }
        $new += @{ Id = 'a' + [guid]::NewGuid().ToString('N').Substring(0, 10); Host = $hn; Type = $Type; Args = $a; Created = (Get-Date).ToString('o', $script:Inv); By = $By; Status = 'queued' }
    }
    Save-LBAgentActions -StateDir $StateDir -Actions @($all + $new)
    return $new
}
function Set-LBAgentActionResults {
    param([string]$StateDir, [string]$HostName, [object[]]$Results)
    if (-not @($Results).Count) { return }
    $all = @(Get-LBAgentActions -StateDir $StateDir)
    foreach ($r in $Results) {
        foreach ($a in $all) { if ([string]$a.Id -eq [string]$r.id -and [string]$a.Host -eq $HostName) { $a.Status = $(if ($r.ok) { 'done' } else { 'failed' }); $a.Ok = [bool]$r.ok; $a.Output = ([string]$r.out).Substring(0, [math]::Min(2000, ([string]$r.out).Length)); $a.DoneAt = (Get-Date).ToString('o', $script:Inv) } }
    }
    Save-LBAgentActions -StateDir $StateDir -Actions $all
}

# --- نسخهٔ کدِ ایجنت (هشِ فایل‌های payload) | agent code version ---------------------------------
function Get-LBPayloadHashFromManifest { param($Manifest) $lines = [string[]]@($Manifest.files.PSObject.Properties | Where-Object { $_.Name -like 'files/*' } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }); [Array]::Sort($lines, [StringComparer]::Ordinal); return (Get-LBShaHex ($lines -join "`n")).Substring(0, 16) }
function Get-LBServerPayloadHash {
    param([string]$InstallDir)
    $mf = Join-Path $InstallDir '_Agents\Windows\LogBok-Agent\manifest.json'
    if (-not (Test-Path $mf)) { return '' }
    try { return (Get-LBPayloadHashFromManifest (Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json)) } catch { return '' }
}

# --- گزارشِ ایجنت و دستورهای پاسخ | agent report in, directives out ------------------------------
function Save-LBAgentReport {
    param([string]$StateDir, [string]$HostName, $Body)
    $hd = Get-LBPushDir -StateDir $StateDir -HostName $HostName
    if (-not (Test-Path $hd)) { New-Item -ItemType Directory -Path $hd -Force | Out-Null }
    if ($Body.inv) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Data = $Body.inv }; [IO.File]::WriteAllText((Join-Path $hd 'inventory.json'), (ConvertTo-Json -InputObject $o -Depth 6), (New-Object Text.UTF8Encoding($false))) }
    if ($Body.health) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Data = $Body.health }; [IO.File]::WriteAllText((Join-Path $hd 'health.json'), (ConvertTo-Json -InputObject $o -Depth 5), (New-Object Text.UTF8Encoding($false))) }
    if ($Body.ps) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Rev = [string]$Body.pr; Data = $Body.ps }; [IO.File]::WriteAllText((Join-Path $hd 'policy-status.json'), (ConvertTo-Json -InputObject $o -Depth 6), (New-Object Text.UTF8Encoding($false))) }
    if ($Body.post) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Data = $Body.post }; [IO.File]::WriteAllText((Join-Path $hd 'posture.json'), (ConvertTo-Json -InputObject $o -Depth 6), (New-Object Text.UTF8Encoding($false))) }
    if ($Body.pat) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Data = $Body.pat }; [IO.File]::WriteAllText((Join-Path $hd 'patches.json'), (ConvertTo-Json -InputObject $o -Depth 6), (New-Object Text.UTF8Encoding($false))) }
    if ($Body.ar) { Set-LBAgentActionResults -StateDir $StateDir -HostName $HostName -Results @($Body.ar) }
    if ($Body.PSObject.Properties['sess']) { $o = [ordered]@{ At = (Get-Date).ToString('o', $script:Inv); Data = @($Body.sess | Where-Object { $_ }) }; [IO.File]::WriteAllText((Join-Path $hd 'sessions.json'), (ConvertTo-Json -InputObject $o -Depth 5), (New-Object Text.UTF8Encoding($false))) }
}
function Get-LBAgentDirectives {
    param([string]$StateDir, [string]$InstallDir, [string]$HostName, $Body)
    $d = [ordered]@{}
    $pol = Get-LBEffectivePolicy -StateDir $StateDir -HostName $HostName
    if ([string]$Body.pr -ne [string]$pol.rev) { $d.pol = $pol }
    $all = @(Get-LBAgentActions -StateDir $StateDir); $send = @(); $changed = $false
    foreach ($a in $all) {
        if ([string]$a.Host -ne $HostName) { continue }
        $resend = ([string]$a.Status -eq 'sent' -and (ConvertTo-LBDate ([string]$a.SentAt)) -lt (Get-Date).AddMinutes(-15))
        if ([string]$a.Status -eq 'queued' -or $resend) { $send += [ordered]@{ id = [string]$a.Id; type = [string]$a.Type; args = $a.Args }; $a.Status = 'sent'; $a.SentAt = (Get-Date).ToString('o', $script:Inv); $changed = $true }
    }
    if ($changed) { Save-LBAgentActions -StateDir $StateDir -Actions $all }
    if ($send.Count) { $d.acts = $send }
    $cfg = $null; try { $cfg = Get-LogBokConfig } catch { }
    $auto = -not ($cfg -and $cfg.Agent -and $cfg.Agent.AutoUpdate -eq $false)
    $sp = Get-LBServerPayloadHash -InstallDir $InstallDir
    $forced = @($send | Where-Object { $_.type -eq 'update-agent' }).Count -gt 0
    if ($sp -and ($forced -or ($auto -and $Body.ph -and [string]$Body.ph -ne $sp))) { $d.update = @{ hash = $sp } }
    return $d
}

# موجودیِ نرم‌افزار در همهٔ سیستم‌ها (جست‌وجو) | software search across all agents
function Find-LBSoftware {
    param([string]$StateDir, [string]$Query, [int]$Max = 2000)
    $root = Get-LBPushDir -StateDir $StateDir
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path $root)) { return @() }
    $q = ([string]$Query).Trim()
    foreach ($d in @(Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue)) {
        $f = Join-Path $d.FullName 'inventory.json'; if (-not (Test-Path $f)) { continue }
        $inv = $null; try { $inv = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        foreach ($s in @($inv.Data.software)) {
            if (-not $q -or ([string]$s.n -like "*$q*") -or ([string]$s.p -like "*$q*")) { [void]$out.Add([ordered]@{ host = $d.Name; name = [string]$s.n; version = [string]$s.v; publisher = [string]$s.p; installed = [string]$s.d }); if ($out.Count -ge $Max) { return $out.ToArray() } }
        }
    }
    return $out.ToArray()
}

Export-ModuleMember -Function Get-LBPostureCatalog, Get-LBEndpointPolicies, Save-LBEndpointPolicies, Set-LBEndpointPolicy, Remove-LBEndpointPolicy, Test-LBPolicyTarget, Get-LBEffectivePolicy, Get-LBHostAdInfoMap, Test-LBProgramSpec, `
    Get-LBAgentActions, Add-LBAgentAction, Set-LBAgentActionResults, Get-LBPayloadHashFromManifest, Get-LBServerPayloadHash, Save-LBAgentReport, Get-LBAgentDirectives, Find-LBSoftware, Get-LBShaHex
