# ==========================================================================
#  LogBok.AgentIn.psm1 — دریافتِ امنِ رویداد از ایجنت‌ها (push) | secure agent intake
#  ایجنت‌ها هر ۲ دقیقه رویدادهای تازه را خودشان به این سرور می‌فرستند (TCP 8687)؛ سرور به
#  هیچ رمز/دسترسیِ راه‌دور روی کلاینت‌ها نیاز ندارد.
#
#  امنیت (الگو: Endpoint Central، سخت‌گیرانه‌تر):
#   • ثبت‌نام (enroll): بسته فقط «توکنِ ثبت‌نام» دارد (انقضا، سقفِ تعداد، قابلِ ابطال) — نه کلیدِ دائمی.
#     ایجنت هنگامِ نصب یک «رازِ اختصاصی» تصادفی می‌سازد و رمزگذاری‌شده ثبتش می‌کند؛ از آن به بعد
#     هر سیستم کلیدِ خودش را دارد (DPAPI روی هر دو طرف). لو رفتنِ بسته بعد از انقضا بی‌اثر است.
#   • نامِ سیستم قابلِ تصاحب نیست: ثبت‌نامِ دوباره با رازِ دیگر «در انتظارِ تأیید» می‌ماند.
#   • گزینهٔ «ایجنتِ تازه فقط با تأییدِ مدیر».
#   • هر بسته: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)، زمانِ یکنوا (ضدِ تکرار)، ±۱۵ دقیقه.
#   • امضای نادرستِ پیاپی از یک IP → آن IP نیم ساعت نادیده گرفته می‌شود.
#   • حذفِ ایجنت فقط با «کدِ حذف»ِ همان سیستم (در کنسول).
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:Known = @{}
$script:BadIp = @{}
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }

function Get-LBHmacHex {
    param([string]$Key, [byte[]]$Data)
    $h = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($Key))
    try { return (-join ($h.ComputeHash($Data) | ForEach-Object { $_.ToString('x2') })) } finally { $h.Dispose() }
}
function Test-LBEqualHex { param([string]$a, [string]$b) if ($a.Length -ne $b.Length) { return $false }; $d = 0; for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }; return ($d -eq 0) }
function Get-LBAesKey { param([string]$Secret, [string]$Purpose) $sha = [Security.Cryptography.SHA256]::Create(); try { return $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Secret|$Purpose")) } finally { $sha.Dispose() } }
function Unprotect-LBAesBytes {
    param([byte[]]$Key, [byte[]]$Data)
    if ($Data.Length -lt 32) { throw 'short payload' }
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $Key
    $iv = New-Object byte[] 16; [Array]::Copy($Data, 0, $iv, 0, 16); $aes.IV = $iv
    try { $d = $aes.CreateDecryptor(); return $d.TransformFinalBlock($Data, 16, $Data.Length - 16) } finally { $aes.Dispose() }
}
function Protect-LBAesBytes {
    param([byte[]]$Key, [byte[]]$Plain)
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $Key; $aes.GenerateIV()
    try { $ct = $aes.CreateEncryptor().TransformFinalBlock($Plain, 0, $Plain.Length); $o = New-Object byte[] (16 + $ct.Length); [Array]::Copy($aes.IV, 0, $o, 0, 16); [Array]::Copy($ct, 0, $o, 16, $ct.Length); return $o } finally { $aes.Dispose() }
}
function Compress-LBGzip { param([string]$Text) $ms = New-Object IO.MemoryStream; $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress); $b = [Text.Encoding]::UTF8.GetBytes($Text); $gz.Write($b, 0, $b.Length); $gz.Close(); return $ms.ToArray() }
function Expand-LBGzip { param([byte[]]$Data) $gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(, $Data)), [IO.Compression.CompressionMode]::Decompress); $sr = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8); try { return $sr.ReadToEnd() } finally { $sr.Dispose() } }
function Protect-LBMachine { param([string]$Plain) return [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Plain), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) }
function Unprotect-LBMachine { param([string]$B64) return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($B64), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) }

# --- توکنِ ثبت‌نام | enrollment token (state\agent-enroll.json) ---------------------------------
function Get-LBEnrollInfo {
    param([Parameter(Mandatory)][string]$StateDir, [switch]$Rotate)
    $f = Join-Path $StateDir 'agent-enroll.json'
    $o = $null
    if (-not $Rotate -and (Test-Path $f)) { try { $o = ConvertTo-LBHashtable (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $o = $null } }
    if (-not $o -or -not $o.Token) {
        $prev = $null; if (Test-Path $f) { try { $prev = ConvertTo-LBHashtable (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
        $b = New-Object byte[] 24; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
        $o = @{ Token = (-join ($b | ForEach-Object { $_.ToString('x2') })); Created = (Get-Date).ToString('o', $script:Inv)
                Expires = (Get-Date).AddDays($(if ($prev -and $prev.Days) { [int]$prev.Days } else { 30 })).ToString('o', $script:Inv)
                Days = $(if ($prev -and $prev.Days) { [int]$prev.Days } else { 30 }); MaxUses = $(if ($prev -and $prev.MaxUses) { [int]$prev.MaxUses } else { 1000 }); Uses = 0
                RequireApproval = $(if ($prev) { [bool]$prev.RequireApproval } else { $false }) }
        Save-LBEnrollInfo -StateDir $StateDir -Info $o
    }
    return $o
}
function Save-LBEnrollInfo {
    param([string]$StateDir, $Info)
    $f = Join-Path $StateDir 'agent-enroll.json'
    [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $Info), (New-Object Text.UTF8Encoding($false)))
    try { & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } catch { }
}
function Test-LBEnrollValid { param($Info) if (-not $Info -or $Info.Revoked) { return $false }; $e = ConvertTo-LBDate ([string]$Info.Expires); if ($e -and (Get-Date) -gt $e) { return $false }; return ([int]$Info.Uses -lt [int]$Info.MaxUses) }

# --- کلیدِ اختصاصیِ هر ایجنت | per-agent keys (state\agent-keys.json, DPAPI) --------------------
function Get-LBAgentKeys {
    param([string]$StateDir)
    $f = Join-Path $StateDir 'agent-keys.json'
    if (-not (Test-Path $f)) { return @{} }
    try { $h = ConvertTo-LBHashtable (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json); if ($h -is [hashtable]) { return $h } } catch { }
    return @{}
}
function Save-LBAgentKeys {
    param([string]$StateDir, $Keys)
    $f = Join-Path $StateDir 'agent-keys.json'; $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $Keys -Depth 5), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
    try { & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } catch { }
}
function Get-LBAgentSecret { param($Rec) if (-not $Rec -or -not $Rec.Secret) { return $null }; try { return (Unprotect-LBMachine ([string]$Rec.Secret)) } catch { return $null } }
# کدِ حذفِ ایجنت (فقط کسی که به کنسول دسترسی دارد می‌بیند) | uninstall code shown in the console
function Get-LBAgentUninstallCode {
    param([string]$StateDir, [string]$HostName)
    $k = (Get-LBAgentKeys -StateDir $StateDir)[$HostName.ToUpperInvariant()]
    $sec = Get-LBAgentSecret $k; if (-not $sec) { return $null }
    $h = Get-LBHmacHex -Key $sec -Data ([Text.Encoding]::UTF8.GetBytes('uninstall:' + $HostName.ToUpperInvariant()))
    return ($h.Substring(0, 12).ToUpperInvariant() -replace '(.{4})(?!$)', '$1-')
}
# is this host a known domain-managed computer? (used for AD-aware auto-approval) | عضوِ دامنهٔ شناخته‌شده؟
function Test-LBKnownDomainComputer {
    param([string]$StateDir, [string]$HostName)
    if (-not $HostName) { return $false }
    $f = Join-Path $StateDir 'ad-computers.json'
    if (-not (Test-Path $f)) { return $false }
    try {
        $m = (Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json
        $short = (($HostName.ToUpperInvariant()) -split '\.')[0]
        foreach ($p in $m.PSObject.Properties) { $ns = ((([string]$p.Name).ToUpperInvariant()) -split '\.')[0]; if ($ns -eq $short) { return $true } }
    } catch { }
    return $false
}
function Set-LBAgentKeyStatus {
    param([string]$StateDir, [string]$HostName, [ValidateSet('approve','revoke','approve-reenroll')][string]$Action)
    $keys = Get-LBAgentKeys -StateDir $StateDir; $hn = $HostName.ToUpperInvariant(); $r = $keys[$hn]
    if (-not $r) { throw "agent not found: $HostName" }
    switch ($Action) {
        'approve'          { $r.Status = 'active'; [void]$r.Remove('Removed') }
        'revoke'           { $r.Status = 'revoked' }
        'approve-reenroll' { if ($r.PendingSecret) { $r.Secret = $r.PendingSecret; $r.Remove('PendingSecret'); $r.LastTs = '' }; $r.Status = 'active'; $r.Reenroll = $false; [void]$r.Remove('Removed') }
    }
    $keys[$hn] = $r; Save-LBAgentKeys -StateDir $StateDir -Keys $keys
    # با تأیید، وضعیتِ کنسول هم از approval به «وصل» می‌رود (قبلاً جا می‌ماند) | approving also flips the console status from approval to connected
    if ($Action -ne 'revoke') {
        try { $st0 = @(Get-LBAgentStatus -StateDir $StateDir) | Where-Object { [string]$_.Name -eq $hn } | Select-Object -First 1
              $m0 = if ($st0 -and $st0.Method) { [string]$st0.Method } else { 'package' }
              $a0 = if ($st0 -and $st0.Address) { [string]$st0.Address } else { '' }
              Set-LBAgentStatus -StateDir $StateDir -Name $hn -Fields @{ Method = $m0; Kind = 'Windows'; Address = $a0; Step = 'enrolled'; Ok = $true; Message = 'تأیید شد | approved' } } catch { }
    }
}

# ذخیرهٔ یک بسته | store one batch (one line per event, hourly files per log)
function Save-LBPushBatch {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$HostName, [object[]]$Events, [string]$Ip, [string]$Version, $Perf)
    $byFile = @{}
    $n = 0
    foreach ($e in @($Events)) {
        if (-not $e -or -not $e.l) { continue }
        $t = $null; try { $t = [datetime]::Parse([string]$e.t, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } catch { continue }
        $dir = Get-LBPushLogDir -StateDir $StateDir -HostName $HostName -LogName ([string]$e.l)
        $f = Join-Path $dir ($t.ToLocalTime().ToString('yyyyMMddHH', $script:Inv) + '.ndjson')
        $o = [ordered]@{ l = [string]$e.l; i = [int]$e.i; t = [string]$e.t; r = [long]$e.r; p = [string]$e.p; v = [string]$e.v; m = [string]$e.m
                         s = ([string]$e.s).Substring(0, [math]::Min(4000, ([string]$e.s).Length)); x = ([string]$e.x).Substring(0, [math]::Min(20000, ([string]$e.x).Length)) }
        if (-not $byFile.ContainsKey($f)) { $byFile[$f] = New-Object System.Collections.Generic.List[string] }
        $byFile[$f].Add((ConvertTo-Json -InputObject $o -Compress -Depth 3))
        $n++
    }
    foreach ($f in $byFile.Keys) {
        $d = Split-Path -Parent $f; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        [IO.File]::AppendAllLines($f, [string[]]$byFile[$f].ToArray(), (New-Object Text.UTF8Encoding($false)))
    }
    $hd = Get-LBPushDir -StateDir $StateDir -HostName $HostName
    if (-not (Test-Path $hd)) { New-Item -ItemType Directory -Path $hd -Force | Out-Null }
    $prev = Get-LBPushLast -StateDir $StateDir -HostName $HostName
    $total = [long]$n; if ($prev -and $prev.Total) { $total += [long]$prev.Total }
    $last = [ordered]@{ Host = $HostName; At = (Get-Date).ToString('o', $script:Inv); Ip = $Ip; Version = $Version; Count = $n; Total = $total; Perf = $Perf; First = $(if ($prev -and $prev.First) { [string]$prev.First } else { (Get-Date).ToString('o', $script:Inv) }) }
    [IO.File]::WriteAllText((Join-Path $hd 'last.json'), (ConvertTo-Json -InputObject $last), (New-Object Text.UTF8Encoding($false)))
    return $n
}

# اولین تماسِ ایجنت: ثبت در منابع (Monitor=agent) و وضعیتِ ایجنت | register on first contact
function Register-LBPushAgent {
    param([string]$StateDir, [string]$InstallDir, [string]$HostName, [string]$Ip, [string]$Version)
    if (-not $script:Known[$HostName]) {
        $all = @(Get-LBTargets -InstallDir $InstallDir)
        $t = $all | Where-Object { [string]$_.Name -eq $HostName -or ([string]$_.Address -split '\.')[0] -eq $HostName -or ($Ip -and [string]$_.Address -eq $Ip) } | Select-Object -First 1
        if ($t) {
            if ([string]$t.Monitor -ne 'agent') { $t.Monitor = 'agent'; $t.Updated = (Get-Date).ToString('o', $script:Inv); Save-LBTargets -Targets $all -InstallDir $InstallDir }
        } else {
            $addr = if ($Ip) { $Ip } else { '' }
            [void](Add-LBTarget -Name $HostName -Address $addr -Kind 'Windows' -Monitor 'agent' -Source 'agent' -InstallDir $InstallDir -By 'agent-push')
        }
        $script:Known[$HostName] = $true
    }
    # هر ایجنتی که رویداد می‌فرستد باید «وصل» نشان داده شود؛ اگر enroll وضعیت را روی approval/pending جا گذاشته بود، همین‌جا اصلاح می‌شود
    # a forwarding agent must always show as connected: if enroll left the status at approval/pending, correct it here (self-heals stuck agents)
    $st = @(Get-LBAgentStatus -StateDir $StateDir) | Where-Object { [string]$_.Name -eq $HostName } | Select-Object -First 1
    if (-not $st -or [string]$st.Step -ne 'done' -or $st.Ok -ne $true) {
        $m = if ($st -and $st.Method) { [string]$st.Method } else { 'package' }
        Set-LBAgentStatus -StateDir $StateDir -Name $HostName -Fields @{ Method = $m; Kind = 'Windows'; Address = $Ip; Step = 'done'; Ok = $true; Message = ("وصل است و رویداد می‌فرستد | connected, sending events (v{0})" -f $Version) }
    }
}

# پاک‌سازیِ فایل‌های قدیمی (انبارِ اصلیِ لاگ جداست) | prune the push buffer
function Clear-LBPushOld {
    param([string]$StateDir, [int]$Days = 7)
    $root = Get-LBPushDir -StateDir $StateDir
    if (-not (Test-Path $root)) { return }
    $cut = (Get-Date).AddDays(-$Days)
    Get-ChildItem -Path $root -Recurse -Filter '*.ndjson' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut } | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Send-LBInReply {
    param($Ctx, [int]$Status, $Obj)
    try {
        $b = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Obj -Compress))
        $Ctx.Response.StatusCode = $Status; $Ctx.Response.ContentType = 'application/json'
        $Ctx.Response.ContentLength64 = $b.Length; $Ctx.Response.OutputStream.Write($b, 0, $b.Length)
    } catch { } finally { try { $Ctx.Response.OutputStream.Close() } catch { } }
}

function Test-LBBadIp { param([string]$Ip) $x = $script:BadIp[$Ip]; return ($x -and $x.Until -and (Get-Date) -lt $x.Until) }
function Add-LBBadIp {
    param([string]$Ip, [string]$Why = '', [string]$HostName = '')
    if (-not $Ip) { return }
    # record every rejection once per host/reason per hour, so a silent agent shows up in the log
    try { $k = $Ip + '|' + $HostName + '|' + $Why; if (-not $script:RejLog) { $script:RejLog = @{} }; if (-not $script:RejLog[$k] -or (Get-Date) -gt $script:RejLog[$k].AddHours(1)) { $script:RejLog[$k] = Get-Date; Write-LogBokLog -Message ("درخواستِ ایجنت رد شد | agent request rejected: {0} ({1}) - {2}" -f $HostName, $Ip, $Why) -Level WARN } } catch { }
    $x = $script:BadIp[$Ip]; if (-not $x -or (Get-Date) -gt $x.Since.AddMinutes(10)) { $x = @{ N = 0; Since = Get-Date; Until = $null } }
    $x.N++; if ($x.N -ge 20) { $x.Until = (Get-Date).AddMinutes(30) }
    $script:BadIp[$Ip] = $x
}

# پردازشِ یک درخواست | handle one request
function Invoke-LBInRequest {
    param($Ctx, [string]$StateDir, [string]$InstallDir)
    $req = $Ctx.Request
    $path = $req.Url.AbsolutePath
    $ip = ''; try { $ip = $req.RemoteEndPoint.Address.ToString() } catch { }
    if ($req.HttpMethod -eq 'GET' -and $path -eq '/ping') { Send-LBInReply -Ctx $Ctx -Status 200 -Obj @{ ok = $true; t = (Get-Date).ToUniversalTime().ToString('o', $script:Inv) }; return }
    # نصبِ تک‌پورتی: ایجنت را فقط از همین پورت (۸۶۸۷) می‌کشد؛ هیچ پورتی روی سیستمِ مقصد باز نمی‌شود
    # single-port install: the target pulls the agent over THIS port (8687) only — no inbound port on the client
    if ($req.HttpMethod -eq 'GET' -and ($path -eq '/install.ps1' -or $path -eq '/pkg')) {
        if (Test-LBBadIp $ip) { Send-LBInReply -Ctx $Ctx -Status 429 -Obj @{ error = 'too many bad requests' }; return }
        $tok = ''; try { $tok = ([string]$req.QueryString['t']).Trim().ToLowerInvariant() } catch { }
        $enr = Get-LBEnrollInfo -StateDir $StateDir
        if ($tok -notmatch '^[0-9a-f]{16,96}$' -or $tok -ne ([string]$enr.Token).ToLowerInvariant() -or -not (Test-LBEnrollValid $enr)) {
            Add-LBBadIp $ip
            $m = 'LogBok: invalid or expired install link. Download a fresh command from the console (Add computers).'
            try { $mb = [Text.Encoding]::UTF8.GetBytes($m); $Ctx.Response.StatusCode = 403; $Ctx.Response.ContentType = 'text/plain; charset=utf-8'; $Ctx.Response.ContentLength64 = $mb.Length; $Ctx.Response.OutputStream.Write($mb, 0, $mb.Length) } catch { } finally { try { $Ctx.Response.OutputStream.Close() } catch { } }
            return
        }
        try {
            if ($path -eq '/pkg') {
                $zf = Join-Path $InstallDir '_Agents\Windows\LogBok-Agent.zip'
                if (-not (Test-Path $zf)) { Send-LBInReply -Ctx $Ctx -Status 404 -Obj @{ error = 'package not built yet' }; return }
                $bytes = [IO.File]::ReadAllBytes($zf)
                $Ctx.Response.StatusCode = 200; $Ctx.Response.ContentType = 'application/zip'; $Ctx.Response.AddHeader('Content-Disposition', 'attachment; filename="LogBok-Agent.zip"')
                $Ctx.Response.ContentLength64 = $bytes.Length; $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                try { $Ctx.Response.OutputStream.Close() } catch { }
            } else {
                $self = ''; try { $self = [string]$req.Url.Host } catch { }
                if (-not $self -or $self -eq '+') { $self = $env:COMPUTERNAME }
                $port = 8687; try { $port = [int]$req.Url.Port } catch { }
                $script = New-LBBootstrapScript -Server $self -Port $port -Token $tok -PkgHash (Get-LBPkgHash -InstallDir $InstallDir)
                $sb = [Text.Encoding]::UTF8.GetBytes($script)
                $Ctx.Response.StatusCode = 200; $Ctx.Response.ContentType = 'text/plain; charset=utf-8'
                $Ctx.Response.ContentLength64 = $sb.Length; $Ctx.Response.OutputStream.Write($sb, 0, $sb.Length)
                try { $Ctx.Response.OutputStream.Close() } catch { }
            }
        } catch { try { $Ctx.Response.OutputStream.Close() } catch { } }
        return
    }
    if ($req.HttpMethod -ne 'POST' -or $path -notin '/enroll', '/ingest', '/bye', '/update') { Send-LBInReply -Ctx $Ctx -Status 404 -Obj @{ error = 'not found' }; return }
    if (Test-LBBadIp $ip) { Send-LBInReply -Ctx $Ctx -Status 429 -Obj @{ error = 'too many bad requests' }; return }
    if ($req.ContentLength64 -gt 16MB) { Send-LBInReply -Ctx $Ctx -Status 413 -Obj @{ error = 'too large' }; return }
    $hn = ([string]$req.Headers['X-LogBok-Host']).Trim().ToUpperInvariant()
    $ts = [string]$req.Headers['X-LogBok-Ts']; $sig = ([string]$req.Headers['X-LogBok-Sig']).ToLowerInvariant()
    $aid = ([string]$req.Headers['X-LogBok-Id']).Trim().ToLowerInvariant(); if ($aid -notmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$') { $aid = '' }
    if ($hn -notmatch '^[A-Z0-9_.\-]{1,63}$' -or -not $ts -or $sig -notmatch '^[0-9a-f]{64}$') { Add-LBBadIp $ip; Send-LBInReply -Ctx $Ctx -Status 400 -Obj @{ error = 'bad headers' }; return }
    $tsd = $null; try { $tsd = [datetime]::Parse($ts, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } catch { }
    if (-not $tsd -or [math]::Abs(([datetime]::UtcNow - $tsd.ToUniversalTime()).TotalMinutes) -gt 15) { Send-LBInReply -Ctx $Ctx -Status 401 -Obj @{ error = 'clock skew'; server = [datetime]::UtcNow.ToString('o', $script:Inv) }; return }
    $ms = New-Object IO.MemoryStream; try { $req.InputStream.CopyTo($ms) } catch { }
    $raw = $ms.ToArray()
    $pre = [Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n$path`n")
    $buf = New-Object byte[] ($pre.Length + $raw.Length); [Array]::Copy($pre, 0, $buf, 0, $pre.Length); [Array]::Copy($raw, 0, $buf, $pre.Length, $raw.Length)
    $keys = Get-LBAgentKeys -StateDir $StateDir
    # تغییرِ نامِ سیستم (مثلاً پس از عضویت در دامنه): رکورد با شناسهٔ پایدار پیدا و به نامِ تازه منتقل می‌شود
    # computer renamed (e.g. after a domain join): find its record by the stable agent id and move it to the new name
    if ($aid -and -not ($keys[$hn] -and $keys[$hn].Secret)) {
        $oldName = $null
        foreach ($k in @($keys.Keys)) { if ($k -ne $hn -and [string]$keys[$k].AgentId -eq $aid -and [string]$keys[$k].Status -ne 'revoked') { $oldName = $k; break } }
        if ($oldName) {
            $rec = $keys[$oldName]; $rec.RenamedFrom = $oldName; $rec.RenamedAt = (Get-Date).ToString('o', $script:Inv)
            $keys[$hn] = $rec; $keys.Remove($oldName); Save-LBAgentKeys -StateDir $StateDir -Keys $keys
            try { Set-LBAgentStatus -StateDir $StateDir -Name $oldName -Fields @{ Step = 'renamed'; Ok = $null; Message = ("نامِ سیستم به {0} تغییر کرد | computer renamed to {0}" -f $hn) } } catch { }
            try { Set-LBAgentStatus -StateDir $StateDir -Name $hn -Fields @{ Kind = 'Windows'; Address = $ip; Step = 'enrolled'; Ok = $true; Message = ("قبلاً {0} بود؛ هویت حفظ شد | was {0}; identity kept" -f $oldName) } } catch { }
            try { Write-LogBokLog -Message ("ایجنت {0} به {1} تغییرِ نام داد | agent {0} renamed to {1} (identity kept)" -f $oldName, $hn) } catch { }
        }
    }

    if ($path -eq '/enroll') {
        $enr = Get-LBEnrollInfo -StateDir $StateDir
        if (-not (Test-LBEnrollValid $enr)) { Send-LBInReply -Ctx $Ctx -Status 403 -Obj @{ error = 'enrollment token expired, used up or revoked — download a new agent package from the console' }; return }
        if (-not (Test-LBEqualHex (Get-LBHmacHex -Key ([string]$enr.Token) -Data $buf) $sig)) { Add-LBBadIp $ip 'bad enrollment signature' $hn; Send-LBInReply -Ctx $Ctx -Status 401 -Obj @{ error = 'bad enrollment signature (package from another server or modified)' }; return }
        $plain = $null; try { $plain = [Text.Encoding]::UTF8.GetString((Unprotect-LBAesBytes -Key (Get-LBAesKey ([string]$enr.Token) 'enroll') -Data $raw)) | ConvertFrom-Json } catch { }
        if (-not $plain -or [string]$plain.secret -notmatch '^[0-9a-f]{64}$') { Send-LBInReply -Ctx $Ctx -Status 400 -Obj @{ error = 'bad enrollment body' }; return }
        $secEnc = Protect-LBMachine ([string]$plain.secret)
        $r = $keys[$hn]; $status = 'active'
        # AD-aware auto-approval: a computer in the admin's own AD domain is trusted and approved automatically;
        # unknown / workgroup machines still wait for manual approval. Controlled by enroll flag AutoApproveDomain (default on).
        $autoDom = ($enr.AutoApproveDomain -ne $false) -and (Test-LBKnownDomainComputer -StateDir $StateDir -HostName $hn)
        if ($r -and $r.Secret -and (Get-LBAgentSecret $r) -ne [string]$plain.secret -and [string]$r.Status -ne 'revoked') {
            # سیستمی با همین نام از قبل ثبت است؛ جایگزینی فقط با تأییدِ مدیر | existing identity: never silently taken over
            if ($autoDom) {
                $r.Secret = $secEnc; [void]$r.Remove('PendingSecret'); [void]$r.Remove('PendingIp'); [void]$r.Remove('PendingAt'); $r.Reenroll = $false; $r.Status = 'active'; $r.LastTs = ''; $status = 'active'
            } else {
                $r.PendingSecret = $secEnc; $r.Reenroll = $true; $r.PendingIp = $ip; $r.PendingAt = (Get-Date).ToString('o', $script:Inv); $status = 'pending-reenroll'
            }
        } else {
            $needApproval = ($enr.RequireApproval -eq $true) -and -not ($r -and [string]$r.Status -eq 'active')
            if ($needApproval -and $autoDom) { $needApproval = $false }
            $status = $(if ($needApproval) { 'pending' } else { 'active' })
            $r = @{ Secret = $secEnc; Status = $status; Enrolled = (Get-Date).ToString('o', $script:Inv); Ip = $ip; Os = [string]$plain.os; Version = [string]$plain.version; LastTs = '' }
        }
        if ($aid) { $r.AgentId = $aid }
        $keys[$hn] = $r; Save-LBAgentKeys -StateDir $StateDir -Keys $keys
        $enr.Uses = [int]$enr.Uses + 1; Save-LBEnrollInfo -StateDir $StateDir -Info $enr
        try {
            $msg = switch ($status) { 'active' { 'ثبت شد | enrolled' } 'pending' { 'منتظرِ تأییدِ مدیر | waiting for admin approval' } default { 'ثبت‌نامِ دوباره منتظرِ تأیید | re-enrollment waiting for approval' } }
            Set-LBAgentStatus -StateDir $StateDir -Name $hn -Fields @{ Kind = 'Windows'; Address = $ip; Step = $(if ($status -eq 'active') { 'enrolled' } else { 'approval' }); Ok = $(if ($status -eq 'active') { $true } else { $null }); Message = $msg; Approval = $status }
        } catch { }
        Send-LBInReply -Ctx $Ctx -Status 200 -Obj @{ ok = $true; status = $status }
        return
    }

    # /ingest و /bye: کلیدِ اختصاصیِ همان سیستم | per-agent key
    $r = $keys[$hn]; $sec = Get-LBAgentSecret $r
    if (-not $sec) { Add-LBBadIp $ip 'unknown agent (no key on server)' $hn; Send-LBInReply -Ctx $Ctx -Status 401 -Obj @{ error = 'unknown agent — re-enroll'; reenroll = $true }; return }
    if (-not (Test-LBEqualHex (Get-LBHmacHex -Key $sec -Data $buf) $sig)) { Add-LBBadIp $ip $(if ($r.PendingSecret) { 'bad signature - agent was reinstalled, re-enrollment waits for approval' } else { 'bad signature (agent key differs from the server)' }) $hn; Send-LBInReply -Ctx $Ctx -Status 401 -Obj @{ error = 'bad signature' }; return }
    if ([string]$r.Status -eq 'revoked') { Send-LBInReply -Ctx $Ctx -Status 403 -Obj @{ error = 'agent revoked' }; return }
    if ([string]$r.Status -eq 'pending') { Send-LBInReply -Ctx $Ctx -Status 202 -Obj @{ ok = $false; status = 'pending' }; return }
    $lastTs = ConvertTo-LBDate ([string]$r.LastTs)
    if ($lastTs -and $tsd.ToUniversalTime() -le $lastTs.ToUniversalTime()) { Send-LBInReply -Ctx $Ctx -Status 409 -Obj @{ error = 'replay' }; return }
    $r.LastTs = $tsd.ToUniversalTime().ToString('o', $script:Inv); $keys[$hn] = $r; Save-LBAgentKeys -StateDir $StateDir -Keys $keys
    if ($path -eq '/update') {
        # کدِ تازهٔ ایجنت، رمزگذاری‌شده با کلیدِ همان سیستم و امضاشده | new agent code, encrypted + signed for this agent
        $zf = Join-Path $InstallDir '_Agents\Windows\LogBok-Agent.zip'
        if (-not (Test-Path $zf)) { Send-LBInReply -Ctx $Ctx -Status 404 -Obj @{ error = 'no package' }; return }
        $out = Protect-LBAesBytes -Key (Get-LBAesKey $sec 'upd') -Plain ([IO.File]::ReadAllBytes($zf))
        $rp = [Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n/update-resp`n"); $rb = New-Object byte[] ($rp.Length + $out.Length); [Array]::Copy($rp, 0, $rb, 0, $rp.Length); [Array]::Copy($out, 0, $rb, $rp.Length, $out.Length)
        $rsig = Get-LBHmacHex -Key $sec -Data $rb
        try { $Ctx.Response.StatusCode = 200; $Ctx.Response.ContentType = 'application/octet-stream'; $Ctx.Response.Headers['X-LogBok-Sig'] = $rsig; $Ctx.Response.ContentLength64 = $out.Length; $Ctx.Response.OutputStream.Write($out, 0, $out.Length) } catch { } finally { try { $Ctx.Response.OutputStream.Close() } catch { } }
        return
    }
    $json = ''
    try { $json = Expand-LBGzip (Unprotect-LBAesBytes -Key (Get-LBAesKey $sec 'enc') -Data $raw) } catch { Send-LBInReply -Ctx $Ctx -Status 400 -Obj @{ error = 'bad body' }; return }
    $b = $null; try { $b = $json | ConvertFrom-Json } catch { Send-LBInReply -Ctx $Ctx -Status 400 -Obj @{ error = 'bad json' }; return }
    if ($path -eq '/bye') {
        Set-LBAgentStatus -StateDir $StateDir -Name $hn -Fields @{ Step = 'uninstalled'; Ok = $null; Message = ("ایجنت با کدِ حذف برداشته شد | agent uninstalled with the uninstall code ({0})" -f [string]$b.by) }
        $r.Status = 'revoked'; $keys[$hn] = $r; Save-LBAgentKeys -StateDir $StateDir -Keys $keys
        try { $all = @(Get-LBTargets -InstallDir $InstallDir); $t = $all | Where-Object { [string]$_.Name -eq $hn } | Select-Object -First 1; if ($t) { $t.Enabled = $false; Save-LBTargets -Targets $all -InstallDir $InstallDir } } catch { }
        Send-LBInReply -Ctx $Ctx -Status 200 -Obj @{ ok = $true }; return
    }
    $ver = [string]$b.v
    $n = Save-LBPushBatch -StateDir $StateDir -HostName $hn -Events @($b.e) -Ip $ip -Version $ver -Perf $b.perf
    try { Register-LBPushAgent -StateDir $StateDir -InstallDir $InstallDir -HostName $hn -Ip $ip -Version $ver } catch { }
    $reply = @{ ok = $true; stored = $n }
    if ($b.ctl -and (Get-Command Get-LBAgentDirectives -ErrorAction SilentlyContinue)) {
        # گزارشِ موجودی/سلامت/نتیجه‌ها + دستورهای تازه (رمزگذاری‌شده و امضاشده) | report in, signed+encrypted directives out
        try { Save-LBAgentReport -StateDir $StateDir -HostName $hn -Body $b } catch { }
        $dir = $null; try { $dir = Get-LBAgentDirectives -StateDir $StateDir -InstallDir $InstallDir -HostName $hn -Body $b } catch { }
        if ($dir -and $dir.Count) {
            $x = [Convert]::ToBase64String((Protect-LBAesBytes -Key (Get-LBAesKey $sec 'resp') -Plain (Compress-LBGzip (ConvertTo-Json -InputObject $dir -Depth 8 -Compress))))
            $reply.x = $x; $reply.xs = Get-LBHmacHex -Key $sec -Data ([Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n$x"))
        }
    }
    Send-LBInReply -Ctx $Ctx -Status 200 -Obj $reply
}

function Start-LBAgentInServer {
    param([int]$Port = 8687, [string]$StateDir, [string]$InstallDir, [int]$MaxRequests = 0)
    [void](Get-LBEnrollInfo -StateDir $StateDir)
    $l = New-Object Net.HttpListener
    $l.Prefixes.Add("http://+:$Port/")
    $l.AuthenticationSchemes = [Net.AuthenticationSchemes]::Anonymous
    # a client that connects and then stalls must never freeze the (single-threaded) intake
    try { $tm = $l.TimeoutManager; $tm.EntityBody = [TimeSpan]::FromSeconds(30); $tm.DrainEntityBody = [TimeSpan]::FromSeconds(30); $tm.HeaderWait = [TimeSpan]::FromSeconds(30); $tm.IdleConnection = [TimeSpan]::FromSeconds(60) } catch { }
    $l.Start()
    $n = 0; $lastPrune = Get-Date
    try {
        while ($l.IsListening) {
            $ctx = $null
            try { $ctx = $l.GetContext() } catch { break }
            try { Invoke-LBInRequest -Ctx $ctx -StateDir $StateDir -InstallDir $InstallDir } catch { try { Send-LBInReply -Ctx $ctx -Status 500 -Obj @{ error = 'server error' } } catch { } }
            if ((Get-Date) -gt $lastPrune.AddHours(6)) { Clear-LBPushOld -StateDir $StateDir; $lastPrune = Get-Date }
            $n++; if ($MaxRequests -gt 0 -and $n -ge $MaxRequests) { break }
        }
    } finally { try { $l.Stop(); $l.Close() } catch { } }
}

Export-ModuleMember -Function Protect-LBAesBytes, Compress-LBGzip, Get-LBHmacHex, Get-LBAesKey, Unprotect-LBAesBytes, Protect-LBMachine, Unprotect-LBMachine, Get-LBEnrollInfo, Save-LBEnrollInfo, Test-LBEnrollValid, `
    Get-LBAgentKeys, Save-LBAgentKeys, Get-LBAgentSecret, Get-LBAgentUninstallCode, Set-LBAgentKeyStatus, Save-LBPushBatch, Register-LBPushAgent, Clear-LBPushOld, Invoke-LBInRequest, Start-LBAgentInServer
