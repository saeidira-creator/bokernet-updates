# ==========================================================================
#  LogBok.Diag.psm1 - client diagnostics for the development period
#  Every LogBok server (not the vendor) sends a small ENCRYPTED health report
#  every 15 minutes: version, job results, recent errors from its own log and
#  LogBok's own Windows events. No passwords, no config secrets, no customer
#  event data. Only BokerNet's private key (owner\LBDiagPriv.xml on the vendor
#  computer) can open it. Inbox: a private, randomly named ntfy.sh topic that
#  keeps files for a few hours. Turn off per server: config Update.Diagnostics = $false
# ==========================================================================
$script:LBDiagTopic = 'lbdiag-5998ce47a25c4f2a990d2a532e520a4507b7'
$script:LBDiagPub = '<RSAKeyValue><Modulus>v9mNvaAoRl7LN/enHVkfCLQuflyLxMXztpp5PTaqUAom6vZ0OphZoYDP/MKj0lDzxx1CTPBO/BONp12+T06321qVeqaaIfmRo8RdWcnzxegC++4LdU/r+tF5VqZDDg5FlBwiHw2lpndV8q5cEdKO9X/yd5tPeWQAKUVP5TXZhzt5T8+jnMMrJ1M2ihJSqaQWKAMuMJ5zfc6TmXPKH4LrVgyhquf5YhPwg/Nyi852h9+WhgJCNeNx7foK/w+QuLvO3SZrQAF/M4qy6iuDnlcSLbn2wtp2Z4feDNZMBQBT9GuQaw5TlFTHbTSbJQBwKW2HUV94gheK9zsXrL9JZCNRiWQPD0oMFZL9aI6J4y8oBBEDgPdZFeGa94eMkDeaAo+onhLnebektJg+S2fKa3KhOg5O/neKQjdfrDsOhTma50gFjXsi/oY+t5PmKdVzHyuq5MU5WbpsdYyBOql3Ia9hdMnhdlHk4a0nrOr/E3JZFTtyoGFAa1J8nVUTrd+xsJsn</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'

function Get-LBDiagClientId {
    $g = ''
    try { $g = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch { $g = $env:COMPUTERNAME }
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('LogBokDiag|' + $g))
    return (($h[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-LBDiagReport {
    param([string]$Root, $Config, [string]$StateDir)
    $sb = New-Object Text.StringBuilder
    function Add([string]$s) { [void]$sb.AppendLine($s) }
    $sd = Join-Path $Root 'state'
    if ($StateDir) { $sd = $StateDir } else { try { $sd = Get-LBStateDir -Config $Config -Root $Root } catch { } }
    $ver = ''; foreach ($vn in 'server-version.txt', 'version.txt') { if (-not $ver) { try { $ver = (Get-Content (Join-Path $sd $vn) -Raw -ErrorAction Stop).Trim() } catch { } } }
    $cust = ''; $exp = ''
    try { $lk = Get-Content (Join-Path $Root 'license.key') -Raw -ErrorAction Stop
          $m = [regex]::Match($lk, '(?m)^Company\s*[:=]\s*(.+)$'); if ($m.Success) { $cust = $m.Groups[1].Value.Trim() }
          $m = [regex]::Match($lk, '(?m)^Expires\s*[:=]\s*(.+)$'); if ($m.Success) { $exp = $m.Groups[1].Value.Trim() } } catch { }
    $os = ''; try { $os = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
    Add ('LogBok diagnostics report')
    Add ('client: ' + (Get-LBDiagClientId))
    Add ('computer: ' + $env:COMPUTERNAME)
    $dom = ''; try { $dom = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { }
    Add ('domain: ' + $dom)
    Add ('customer: ' + $cust + '  expires: ' + $exp)
    Add ('version: ' + $ver)
    Add ('time: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
    Add ('os: ' + $os + '  ps: ' + $PSVersionTable.PSVersion + '  root: ' + $Root)
    try { Add ('mode: ' + $Config.CollectionMode + '  feed: ' + $Config.Update.ServerFeed + '  fastpull: ' + $Config.Update.DevFastPull) } catch { }
    try { $en = @(); foreach ($k in $Config.Enabled.Keys) { if ($Config.Enabled[$k] -eq $false) { $en += $k } }; Add ('disabled features: ' + ($en -join ', ')) } catch { }
    Add ''
    Add '== scheduled tasks (\LogBok\) =='
    try {
        foreach ($t in @(Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction Stop)) {
            $i = $null; try { $i = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }
            $res = ''; $last = ''; if ($i) { $res = '0x{0:X}' -f [int64]$i.LastTaskResult; $last = [string]$i.LastRunTime }
            Add ('{0,-22} {1,-9} last={2} result={3}' -f $t.TaskName, $t.State, $last, $res)
        }
    } catch { Add ('(could not list: ' + $_.Exception.Message + ')') }
    Add ''
    Add '== update / state files =='
    foreach ($n in 'version.txt', 'update-status.txt', 'update-last.txt') {
        $p = Join-Path $sd $n
        if (Test-Path $p) { try { $c = (Get-Content $p -Raw -ErrorAction Stop) -replace '\s+', ' '; if ($c.Length -gt 1500) { $c = $c.Substring(0, 1500) + ' ...' }; Add ($n + ': ' + $c.Trim()) } catch { } }
    }
    Add ''
    Add '== connectivity (per computer and channel) =='
    try {
        $cj = Get-Content (Join-Path $sd 'connectivity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Add ('generated: ' + [string]$cj.Generated + '  mode: ' + [string]$cj.Mode)
        foreach ($tg in @($cj.Targets)) {
            Add ('- {0} ({1}) kind={2} status={3}' -f $tg.Name, $tg.Target, $tg.Kind, $tg.Status)
            foreach ($ch in @($tg.Channels)) {
                $dt = (([string]$ch.Detail) + ' ' + ([string]$ch.Reason)).Trim() -replace '\s+', ' '; if ($dt.Length -gt 220) { $dt = $dt.Substring(0, 220) + '...' }
                Add ('    {0,-14} ok={1,-5} {2,-5} {3}' -f $ch.Channel, $ch.Ok, $ch.State, $dt)
            }
        }
    } catch { Add '(none)' }
    Add ''
    Add '== agents (no secrets) =='
    try {
        $ak = Get-Content (Join-Path $sd 'agent-keys.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($pp in $ak.PSObject.Properties) { $a = $pp.Value; $st2 = ''; try { $sf = Join-Path $sd ('agents\' + $pp.Name + '.json'); if (Test-Path $sf) { $sj = Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json; $st2 = ('step={0} ok={1} msg={2} at={3}' -f $sj.Step, $sj.Ok, (([string]$sj.Message) -replace '\s+', ' '), $sj.Updated) } } catch { }; Add ('- {0} ip={1} version={2} status={3} enrolled={4} last={5} reenroll={6} pendingAt={7} pendingIp={8} {9}' -f $pp.Name, $a.Ip, $a.Version, $a.Status, $a.Enrolled, $a.LastTs, $a.Reenroll, $a.PendingAt, $a.PendingIp, $st2) }
    } catch { Add '(none)' }
    try { $tj = Get-Content (Join-Path $sd 'targets.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json; Add ('targets: ' + ((@($tj) | ForEach-Object { '{0}[{1}]' -f $_.Name, (@($_.Methods) + @($_.Method) | Where-Object { $_ }) -join '/' }) -join ', ')) } catch { }
    Add ''
    Add '== LogBok log: WARN/ERROR lines, last 2 days (deduplicated) =='
    $logDir = Join-Path $Root 'logs'; try { if ($Config.Paths.Logs) { $logDir = $Config.Paths.Logs } } catch { }
    try {
        $files = @(Get-ChildItem $logDir -Filter 'logbok-*.log' -ErrorAction Stop | Sort-Object Name -Descending | Select-Object -First 2)
        $seen = @{}; $rows = New-Object Collections.ArrayList
        foreach ($f in $files) {
            foreach ($l in (Get-Content $f.FullName -Encoding UTF8 -ErrorAction SilentlyContinue)) {
                if ($l -notmatch '\[(WARN|ERROR)\]' -and $l -notmatch '(?i)exception|failed|cannot|could not|error') { continue }
                $key = ($l -replace '^\S+ \S+ ', '') -replace '\d+', '#'
                if ($seen.ContainsKey($key)) { $seen[$key]++; continue }
                $seen[$key] = 1; [void]$rows.Add(@($key, $l))
            }
        }
        foreach ($r in ($rows | Select-Object -Last 150)) { $n = $seen[$r[0]]; Add ($(if ($n -gt 1) { "[x$n] " } else { '' }) + $r[1]) }
    } catch { Add ('(log not readable: ' + $_.Exception.Message + ')') }
    Add ''
    Add '== LogBok log: last 60 lines (today) =='
    try { $f = Get-ChildItem $logDir -Filter 'logbok-*.log' -ErrorAction Stop | Sort-Object Name -Descending | Select-Object -First 1; foreach ($l in (Get-Content $f.FullName -Tail 60 -Encoding UTF8)) { Add $l } } catch { }
    Add ''
    Add '== Windows Application log: LogBok source, warnings/errors, last 24 h =='
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'LogBok'; Level = 2, 3; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 60 -ErrorAction Stop)
        foreach ($e in $ev) { $msg = ($e.Message -replace '\s+', ' '); if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }; Add ('{0:yyyy-MM-dd HH:mm} id={1} {2}' -f $e.TimeCreated, $e.Id, $msg) }
    } catch { Add '(none)' }
    Add ''
    Add '== PowerShell errors: LogBok scripts, last 24 h =='
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Windows PowerShell'; Level = 2, 3; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 200 -ErrorAction Stop | Where-Object { $_.Message -match 'LogBok' } | Select-Object -First 30)
        foreach ($e in $ev) { $msg = ($e.Message -replace '\s+', ' '); if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' }; Add ('{0:yyyy-MM-dd HH:mm} id={1} {2}' -f $e.TimeCreated, $e.Id, $msg) }
    } catch { Add '(none)' }
    Add ''
    Add '== console (browser) errors =='
    try { $p = Join-Path $sd 'ui-errors.txt'; if (Test-Path $p) { foreach ($l in (Get-Content $p -Tail 40 -Encoding UTF8)) { Add $l } } else { Add '(none)' } } catch { }
    return $sb.ToString()
}

function Send-LBDiagnostics {
    param([string]$Root, $Config, [string]$StateDir, [switch]$Force)
    try { if ($Config.Update.Diagnostics -eq $false) { return } } catch { }
    if (Test-Path (Join-Path $Root 'Tools\privatekey.xml')) { return }   # the vendor computer does not report to itself
    $sd = Join-Path $Root 'state'; if ($StateDir) { $sd = $StateDir } else { try { $sd = Get-LBStateDir -Config $Config -Root $Root } catch { } }
    $stamp = Join-Path $sd 'diag-last.txt'
    if (-not $Force -and (Test-Path $stamp) -and (((Get-Date) - (Get-Item $stamp).LastWriteTime).TotalMinutes -lt 15)) { return }
    try { Set-Content -Path $stamp -Value (Get-Date -Format s) -Encoding ASCII } catch { }
    $text = New-LBDiagReport -Root $Root -Config $Config -StateDir $sd
    # gzip -> AES-256-CBC (random key/iv) -> key wrapped with RSA-OAEP (BokerNet public key)
    $ms = New-Object IO.MemoryStream
    $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
    $raw = [Text.Encoding]::UTF8.GetBytes($text); $gz.Write($raw, 0, $raw.Length); $gz.Close()
    $plain = $ms.ToArray()
    $aes = New-Object Security.Cryptography.RijndaelManaged
    $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.GenerateKey(); $aes.GenerateIV()
    $ct = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
    $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider; $rsa.PersistKeyInCsp = $false; $rsa.FromXmlString($script:LBDiagPub)
    $ek = $rsa.Encrypt($aes.Key, $true)
    $out = New-Object IO.MemoryStream
    $hdr = [Text.Encoding]::ASCII.GetBytes('LBD1'); $out.Write($hdr, 0, 4)
    $kl = [BitConverter]::GetBytes([int]$ek.Length); $out.Write($kl, 0, 4)
    $out.Write($ek, 0, $ek.Length); $out.Write($aes.IV, 0, 16); $out.Write($ct, 0, $ct.Length)
    $body = $out.ToArray()
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $id = Get-LBDiagClientId
    $rq = [Net.HttpWebRequest]::Create('https://ntfy.sh/' + $script:LBDiagTopic)
    $rq.Method = 'PUT'; $rq.ContentType = 'application/octet-stream'; $rq.Timeout = 60000; $rq.ReadWriteTimeout = 60000; $rq.KeepAlive = $false
    $rq.Headers['Filename'] = $id + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss') + '.lbd'
    $rq.Headers['Title'] = 'LogBok ' + $id
    $rq.ContentLength = $body.Length
    $s = $rq.GetRequestStream(); $s.Write($body, 0, $body.Length); $s.Close()
    $rs = $rq.GetResponse(); $rs.Close()
}

# VENDOR side: fetch new bundles, open them with owner\LBDiagPriv.xml, save to Diagnostics\<client>\
function Receive-LBDiagnostics {
    param([string]$Root)
    $privFile = Join-Path $Root 'owner\LBDiagPriv.xml'
    if (-not (Test-Path $privFile)) { return 0 }
    $out = Join-Path $Root 'Diagnostics'; New-Item -ItemType Directory -Force -Path $out | Out-Null
    $sinceFile = Join-Path $out '.since'
    $since = '12h'; if (Test-Path $sinceFile) { $s0 = (Get-Content $sinceFile -Raw).Trim(); if ($s0) { $since = $s0 } }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $wc = New-Object Net.WebClient; $wc.Encoding = [Text.Encoding]::UTF8
    $json = $wc.DownloadString('https://ntfy.sh/' + $script:LBDiagTopic + '/json?poll=1&since=' + $since)
    $privXml = [IO.File]::ReadAllText($privFile)
    $got = 0
    foreach ($l in ($json -split "`n")) {
        if (-not $l.Trim()) { continue }
        $o = $null; try { $o = $l | ConvertFrom-Json } catch { continue }
        if ($o.event -ne 'message') { continue }
        try {
            if ($o.attachment -and ('' + $o.attachment.name) -match '^([a-f0-9]{16})-(\d{14})\.lbd$') {
                $id = $Matches[1]; $st = $Matches[2]
                $b = $wc.DownloadData($o.attachment.url)
                if ([Text.Encoding]::ASCII.GetString($b, 0, 4) -ne 'LBD1') { throw 'not a LogBok bundle' }
                $kl = [BitConverter]::ToInt32($b, 4)
                $ek = New-Object byte[] $kl; [Array]::Copy($b, 8, $ek, 0, $kl)
                $iv = New-Object byte[] 16; [Array]::Copy($b, 8 + $kl, $iv, 0, 16)
                $off = 8 + $kl + 16; $ct = New-Object byte[] ($b.Length - $off); [Array]::Copy($b, $off, $ct, 0, $ct.Length)
                $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider; $rsa.PersistKeyInCsp = $false; $rsa.FromXmlString($privXml)
                $key = $rsa.Decrypt($ek, $true)
                $aes = New-Object Security.Cryptography.RijndaelManaged
                $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $key; $aes.IV = $iv
                $gzb = $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
                $zs = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(, $gzb)), [IO.Compression.CompressionMode]::Decompress)
                $rd = New-Object IO.StreamReader($zs, [Text.Encoding]::UTF8); $text = $rd.ReadToEnd(); $rd.Close()
                $pc = ''; $m = [regex]::Match($text, '(?m)^computer: (.+)$'); if ($m.Success) { $pc = $m.Groups[1].Value.Trim() }
                $cust = ''; $m = [regex]::Match($text, '(?m)^customer: (.*?)  expires:'); if ($m.Success) { $cust = $m.Groups[1].Value.Trim() }
                $ver = ''; $m = [regex]::Match($text, '(?m)^version: (\S*)'); if ($m.Success) { $ver = $m.Groups[1].Value }
                $label = ($id + ' ' + $cust + ' ' + $pc).Trim() -replace '[\\/:*?"<>|]', '_'
                $cd = Get-ChildItem $out -Directory -Filter ($id + '*') -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($cd -and $cd.Name -ne $label) { Rename-Item $cd.FullName $label -ErrorAction SilentlyContinue }
                $cdir = Join-Path $out $label; New-Item -ItemType Directory -Force -Path $cdir | Out-Null
                $enc = New-Object Text.UTF8Encoding($true)
                [IO.File]::WriteAllText((Join-Path $cdir ($st + '.txt')), $text, $enc)
                [IO.File]::WriteAllText((Join-Path $cdir 'latest.txt'), $text, $enc)
                Get-ChildItem $cdir -Filter '2*.txt' | Sort-Object Name -Descending | Select-Object -Skip 40 | Remove-Item -Force -ErrorAction SilentlyContinue
                $sum = Join-Path $out 'clients.txt'
                $lines = @(); if (Test-Path $sum) { $lines = @(Get-Content $sum -Encoding UTF8 | Where-Object { $_ -and -not $_.StartsWith($id) }) }
                $lines += ($id + '  last: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + '  version: ' + $ver + '  customer: ' + $cust + '  computer: ' + $pc)
                Set-Content -Path $sum -Value ($lines | Sort-Object) -Encoding UTF8
                $got++
            }
        } catch { }
        Set-Content -Path $sinceFile -Value ('' + $o.id) -Encoding ASCII
    }
    return $got
}

Export-ModuleMember -Function Get-LBDiagClientId, New-LBDiagReport, Send-LBDiagnostics, Receive-LBDiagnostics
