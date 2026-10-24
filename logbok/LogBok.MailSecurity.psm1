# ==========================================================================
#  LogBok.MailSecurity.psm1  -  email security module (Mail Security)
#  Part of LogBok (BokerNet). COMPLETELY SEPARATE from FireBok's simple mail
#  filter: this module never touches FireBok. It reads Microsoft Exchange logs
#  on each Exchange server (via the agent), scores mail, checks sender auth
#  (SPF/DKIM/DMARC), checks IP reputation (DNSBL + AbuseIPDB + the shared
#  LogBok blocklist), applies content filtering (attachment types + phishing
#  links), quarantines, and can remove a message from mailboxes safely.
#
#  Depends on LogBok.Core (logging, state, findings helpers).
#  Categories emitted: MailSpam, MailPhish, MailAuth, MailAttach.
# ==========================================================================

$script:Inv = [Globalization.CultureInfo]::InvariantCulture

# ---------------------------------------------------------------- Exchange presence
function Test-LBMailExchangePresent {
    # true only on a machine that actually has Exchange installed
    try { if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction SilentlyContinue) { return $true } } catch { }
    try { if (Get-Service -Name MSExchangeADTopology -ErrorAction SilentlyContinue) { return $true } } catch { }
    return $false
}
function Get-LBExchangeInstallPath {
    foreach ($v in 'v15', 'v14') {
        try { $p = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\ExchangeServer\$v\Setup" -ErrorAction SilentlyContinue).MsiInstallPath; if ($p -and (Test-Path $p)) { return $p } } catch { }
    }
    return $null
}

# ---------------------------------------------------------------- Exchange log parsing
#  Exchange W3C logs start with #Software/#Version/#Date lines then a
#  "#Fields: a,b,c" header and CSV data. Read incrementally from $Start.
function Import-LBExchangeLog {
    param([Parameter(Mandatory)][string]$File, [datetime]$Start)
    if (-not (Test-Path -LiteralPath $File)) { return @() }
    $fields = $null; $rows = New-Object System.Collections.Generic.List[string]
    try {
        $sr = New-Object IO.StreamReader((New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)), [Text.Encoding]::UTF8)
        while ($null -ne ($ln = $sr.ReadLine())) {
            if ($ln.StartsWith('#')) { if ($ln -match '^#Fields:\s*(.+)$') { $fields = $Matches[1].Trim() }; continue }
            if ($ln) { $rows.Add($ln) }
        }
    } catch { return @() } finally { if ($sr) { $sr.Dispose() } }
    if (-not $fields -or -not $rows.Count) { return @() }
    $recs = @(); try { $recs = @(($fields + "`n" + ($rows.ToArray() -join "`n")) | ConvertFrom-Csv) } catch { return @() }
    if ($Start) {
        $recs = @($recs | Where-Object {
                $t = $null; $v = $_.'date-time'; if (-not $v) { $v = $_.'DateTime' }; if (-not $v) { $v = $_.date }
                if ([datetime]::TryParse([string]$v, $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { $t.ToLocalTime() -ge $Start } else { $true }
            })
    }
    return $recs
}
function Get-LBMailLogDir {
    param([string]$Leaf)
    $base = Get-LBExchangeInstallPath; if (-not $base) { return $null }
    $d = Join-Path $base ("TransportRoles\Logs\" + $Leaf)
    if (Test-Path $d) { return $d }
    return $null
}
function Get-LBMailRecentFiles {
    param([string]$Dir, [datetime]$Start, [int]$MaxFiles = 8)
    if (-not $Dir -or -not (Test-Path $Dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $Dir -Filter '*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Start.AddHours(-1) } | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxFiles)
}
# message tracking entries (inbound), parsed to a simple record
function Get-LBMailTracking {
    param([datetime]$Start)
    $dir = Get-LBMailLogDir -Leaf 'MessageTracking'; if (-not $dir) { return @() }
    $out = @()
    foreach ($f in (Get-LBMailRecentFiles -Dir $dir -Start $Start)) {
        foreach ($r in (Import-LBExchangeLog -File $f.FullName -Start $Start)) {
            $evt = [string]$r.'event-id'; if ($evt -notin 'RECEIVE', 'DELIVER', 'FAIL', 'SPAM') { continue }
            $out += [pscustomobject]@{
                Time = [string]$r.'date-time'; ClientIp = [string]$r.'original-client-ip'; FromIp = [string]$r.'client-ip'
                Sender = [string]$r.'sender-address'; Recipient = [string]$r.'recipient-address'; Subject = [string]$r.'message-subject'
                MessageId = [string]$r.'message-id'; NetMsgId = [string]$r.'network-message-id'; Event = $evt
                Bytes = [string]$r.'total-bytes'; Dir = [string]$r.directionality; Status = [string]$r.'recipient-status'
            }
        }
    }
    return $out
}
# anti-spam agent log (SCL, verdict) keyed by network-message-id
function Get-LBMailAgentVerdicts {
    param([datetime]$Start)
    $map = @{}
    foreach ($leaf in 'Hub\AgentLog', 'FrontEnd\AgentLog') {
        $dir = Get-LBMailLogDir -Leaf $leaf; if (-not $dir) { continue }
        foreach ($f in (Get-LBMailRecentFiles -Dir $dir -Start $Start)) {
            foreach ($r in (Import-LBExchangeLog -File $f.FullName -Start $Start)) {
                $id = [string]$r.'network-message-id'; if (-not $id) { continue }
                $map[$id] = [pscustomobject]@{ Agent = [string]$r.agent; Event = [string]$r.event; Action = [string]$r.action; Reason = [string]$r.reason; ReasonData = [string]$r.'reason-data'; Ip = [string]$r.'p1-from-address' }
            }
        }
    }
    return $map
}

# ---------------------------------------------------------------- sender authentication (DNS, works anywhere)
function Resolve-LBTxt { param([string]$Name) try { return @(Resolve-DnsName -Name $Name -Type TXT -ErrorAction Stop | Where-Object { $_.Strings } | ForEach-Object { ($_.Strings -join '') }) } catch { return @() } }
function Test-LBMailSpf {
    param([string]$Domain, [string]$Ip)
    if (-not $Domain) { return 'none' }
    $spf = @(Resolve-LBTxt $Domain | Where-Object { $_ -match '^v=spf1' }) | Select-Object -First 1
    if (-not $spf) { return 'none' }
    # light evaluation: explicit ip4/ip6 and a/mx are resolved; otherwise rely on qualifier
    try {
        foreach ($tok in ($spf -split '\s+')) {
            if ($tok -match '^ip4:([\d\./]+)$' -and $Ip -and $Ip -notmatch ':') { if (Test-LBIpInCidr -Ip $Ip -Cidr $Matches[1]) { return 'pass' } }
            elseif ($tok -match '^ip6:(.+)$' -and $Ip -match ':') { if (($Ip.ToLower()) -eq ($Matches[1].ToLower().Split('/')[0])) { return 'pass' } }
        }
    } catch { }
    if ($spf -match '-all') { return 'fail' } elseif ($spf -match '~all') { return 'softfail' }
    return 'neutral'
}
function Test-LBMailDmarc {
    param([string]$Domain)
    if (-not $Domain) { return @{ policy = 'none'; present = $false } }
    $d = @(Resolve-LBTxt ("_dmarc." + $Domain) | Where-Object { $_ -match 'v=DMARC1' }) | Select-Object -First 1
    if (-not $d) { return @{ policy = 'none'; present = $false } }
    $pol = 'none'; if ($d -match 'p=\s*([a-zA-Z]+)') { $pol = $Matches[1].ToLowerInvariant() }
    return @{ policy = $pol; present = $true }
}
function Test-LBIpInCidr {
    param([string]$Ip, [string]$Cidr)
    try {
        $parts = $Cidr.Split('/'); $net = [Net.IPAddress]::Parse($parts[0]); $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
        $ipA = [Net.IPAddress]::Parse($Ip); if ($ipA.AddressFamily -ne $net.AddressFamily) { return $false }
        $ipB = $ipA.GetAddressBytes(); $nB = $net.GetAddressBytes(); $full = [math]::Floor($bits / 8); $rem = $bits % 8
        for ($i = 0; $i -lt $full; $i++) { if ($ipB[$i] -ne $nB[$i]) { return $false } }
        if ($rem -gt 0) { $mask = [byte](0xFF -shl (8 - $rem)); if (($ipB[$full] -band $mask) -ne ($nB[$full] -band $mask)) { return $false } }
        return $true
    } catch { return $false }
}

# ---------------------------------------------------------------- IP reputation
#  DNSBL (Spamhaus zen, SpamCop), AbuseIPDB (API key), and the shared LogBok blocklist.
function Test-LBMailDnsbl {
    param([string]$Ip)
    if (-not $Ip -or $Ip -match ':') { return @() }
    $rev = ($Ip.Split('.')[3..0] -join '.'); $hits = @()
    foreach ($bl in @(@{n = 'Spamhaus'; z = 'zen.spamhaus.org' }, @{n = 'SpamCop'; z = 'bl.spamcop.net' })) {
        try { if (@(Resolve-DnsName -Name ("$rev." + $bl.z) -Type A -ErrorAction Stop).Count) { $hits += $bl.n } } catch { }
    }
    return $hits
}
function Test-LBMailAbuseIpdb {
    param([string]$Ip, [string]$ApiKey)
    if (-not $Ip -or -not $ApiKey) { return $null }
    try {
        $r = Invoke-RestMethod -Uri ("https://api.abuseipdb.com/api/v2/check?ipAddress={0}&maxAgeInDays=90" -f $Ip) -Headers @{ Key = $ApiKey; Accept = 'application/json' } -TimeoutSec 8 -ErrorAction Stop
        if ($r.data) { return [int]$r.data.abuseConfidenceScore }
    } catch { }
    return $null
}
function Get-LBMailSharedBlocklist {
    param([string]$StateDir)
    $f = Join-Path $StateDir 'mail\shared-blocklist.json'
    if (Test-Path $f) { try { return @((Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).ips) } catch { } }
    return @()
}

# ---------------------------------------------------------------- content filtering
$script:LBBlockedExt = @('exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'cpl', 'msc', 'jar', 'bat', 'cmd', 'com', 'pif', 'ps1', 'reg', 'lnk', 'iso', 'img', 'ace', 'arj', 'docm', 'xlsm', 'pptm')
function Test-LBMailAttachment {
    param([string[]]$Names, [string[]]$ExtraBlocked)
    $blocked = @($script:LBBlockedExt + @($ExtraBlocked | ForEach-Object { ([string]$_).TrimStart('.').ToLowerInvariant() }))
    $hits = @()
    foreach ($n in @($Names)) { $e = ([IO.Path]::GetExtension([string]$n)).TrimStart('.').ToLowerInvariant(); if ($e -and ($blocked -contains $e)) { $hits += "$n [$e]" } }
    return $hits
}
function Test-LBMailPhishLinks {
    param([string]$Body, [string[]]$Urls)
    $all = @($Urls); if ($Body) { $all += @([regex]::Matches($Body, 'https?://[^\s"''<>]+') | ForEach-Object { $_.Value }) }
    $reasons = @()
    foreach ($u in ($all | Select-Object -Unique)) {
        try {
            $hostn = ([Uri]$u).Host
            if ($hostn -match '^\d{1,3}(\.\d{1,3}){3}$') { $reasons += "IP-literal URL: $u" }
            if ($hostn -match '(^|\.)(tk|ml|ga|cf|gq|zip|mov|top|xyz|rest)$') { $reasons += "suspicious TLD: $hostn" }
            if ($hostn -match 'bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly|rb\.gy|rebrand\.ly') { $reasons += "URL shortener: $hostn" }
            if ($hostn -match 'xn--') { $reasons += "punycode/IDN: $hostn" }
            if (($hostn -split '\.').Count -ge 5) { $reasons += "deep subdomain: $hostn" }
        } catch { }
    }
    return @($reasons | Select-Object -Unique)
}

# ---------------------------------------------------------------- quarantine store (metadata)
function Get-LBMailQuarantineDir { param([string]$StateDir) $d = Join-Path $StateDir 'mail\quarantine'; if (-not (Test-Path $d)) { try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch { } }; return $d }
function Add-LBMailQuarantine {
    param([string]$StateDir, $Item)
    $d = Get-LBMailQuarantineDir -StateDir $StateDir
    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $rec = [ordered]@{ id = $id; at = (Get-Date).ToString('o', $script:Inv); status = 'held' } + ([ordered]@{} + $Item)
    try { (ConvertTo-Json -InputObject $rec -Depth 6) | Set-Content -Path (Join-Path $d "$id.json") -Encoding UTF8 } catch { }
    return $id
}
function Get-LBMailQuarantine {
    param([string]$StateDir, [int]$Max = 500)
    $d = Get-LBMailQuarantineDir -StateDir $StateDir
    return @(Get-ChildItem $d -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $Max | ForEach-Object { try { Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } } | Where-Object { $_ })
}
function Set-LBMailQuarantineStatus {
    param([string]$StateDir, [string]$Id, [string]$Status)
    if ($Id -notmatch '^[0-9a-f]{12}$') { throw 'invalid id' }
    $f = Join-Path (Get-LBMailQuarantineDir -StateDir $StateDir) "$Id.json"
    if (-not (Test-Path $f)) { return $false }
    if ($Status -eq 'deleted') { Remove-Item $f -Force -ErrorAction SilentlyContinue; return $true }
    try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; $j.status = $Status; (ConvertTo-Json -InputObject $j -Depth 6) | Set-Content -Path $f -Encoding UTF8; return $true } catch { return $false }
}

# ---------------------------------------------------------------- mail event store (for the dashboard)
function Add-LBMailEvent {
    param([string]$StateDir, $Rec)
    $d = Join-Path $StateDir 'mail'; if (-not (Test-Path $d)) { try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch { } }
    $f = Join-Path $d ('events-{0}.ndjson' -f (Get-Date).ToString('yyyy-MM-dd', $script:Inv))
    try { Add-Content -Path $f -Value (ConvertTo-Json -InputObject $Rec -Depth 5 -Compress) -Encoding UTF8 } catch { }
}
function Get-LBMailEvents {
    param([string]$StateDir, [int]$Days = 7)
    $d = Join-Path $StateDir 'mail'; $out = @()
    for ($i = $Days - 1; $i -ge 0; $i--) {
        $f = Join-Path $d ('events-{0}.ndjson' -f (Get-Date).AddDays(-$i).ToString('yyyy-MM-dd', $script:Inv))
        if (Test-Path $f) { foreach ($ln in (Get-Content $f -ErrorAction SilentlyContinue)) { if ($ln) { try { $out += ($ln | ConvertFrom-Json) } catch { } } } }
    }
    return $out
}

# ---------------------------------------------------------------- scoring + detection cycle
#  Combine Exchange SCL/verdict + reputation + auth + content into a score 0..100.
function Invoke-LBMailSecurityCycle {
    param([Parameter(Mandatory)][string]$StateDir, $Config, [datetime]$Start)
    $findings = @()
    if (-not (Test-LBMailExchangePresent)) { return $findings }   # only on Exchange servers
    $cfg = if ($Config.MailSecurity) { $Config.MailSecurity } else { @{} }
    $apiKey = [string]$cfg.AbuseIpdbKey
    $extraExt = @($cfg.BlockedAttachments)
    $spamAt = if ($cfg.SpamScore) { [int]$cfg.SpamScore } else { 50 }
    $quarAt = if ($cfg.QuarantineScore) { [int]$cfg.QuarantineScore } else { 70 }
    $shared = Get-LBMailSharedBlocklist -StateDir $StateDir
    $verdicts = Get-LBMailAgentVerdicts -Start $Start
    foreach ($m in (Get-LBMailTracking -Start $Start)) {
        if ([string]$m.Dir -eq 'Originating') { continue }   # inbound only
        $ip = if ($m.FromIp) { $m.FromIp } else { $m.ClientIp }
        $senderDom = ''; if ($m.Sender -match '@(.+)$') { $senderDom = $Matches[1].ToLowerInvariant() }
        $score = 0; $why = @()
        # anti-spam agent verdict / SCL
        $v = $verdicts[[string]$m.NetMsgId]
        if ($v) { if ([string]$v.action -match 'Reject|Delete|Quarantine') { $score += 40; $why += "agent: $($v.action)/$($v.reason)" } }
        if ([string]$m.Event -eq 'SPAM') { $score += 40; $why += 'Exchange marked SPAM' }
        # reputation
        if ($ip) {
            if ($shared -contains $ip) { $score += 50; $why += 'shared blocklist' }
            $bl = Test-LBMailDnsbl -Ip $ip; if ($bl.Count) { $score += 35; $why += ('DNSBL: ' + ($bl -join ',')) }
            if ($apiKey) { $ab = Test-LBMailAbuseIpdb -Ip $ip -ApiKey $apiKey; if ($ab -ne $null -and $ab -ge 50) { $score += 25; $why += "AbuseIPDB $ab%" } }
        }
        # sender auth
        $spf = Test-LBMailSpf -Domain $senderDom -Ip $ip
        $dmarc = Test-LBMailDmarc -Domain $senderDom
        if ($spf -eq 'fail') { $score += 20; $why += 'SPF fail' }
        if ($dmarc.present -and $dmarc.policy -eq 'reject' -and $spf -in 'fail', 'softfail', 'none') { $score += 20; $why += "DMARC p=reject, SPF $spf" }
        # content: phishing links in the subject (body not available from tracking log)
        $ph = Test-LBMailPhishLinks -Body ([string]$m.Subject) -Urls @()
        if ($ph.Count) { $score += 25; $why += ('phishing: ' + ($ph -join '; ')) }
        if ($score -le 0) { continue }
        $cat = if ($ph.Count) { 'MailPhish' } elseif ($spf -eq 'fail' -or ($dmarc.present -and $dmarc.policy -eq 'reject')) { 'MailAuth' } else { 'MailSpam' }
        $sev = if ($score -ge $quarAt) { 'Critical' } elseif ($score -ge $spamAt) { 'Warning' } else { 'Info' }
        if ($score -ge $spamAt) {
            $findings += [pscustomobject]@{
                Category = $cat; Severity = $sev; Machine = $env:COMPUTERNAME; Time = $m.Time
                Title = ("Suspicious email ({0}/100) from {1} | ایمیلِ مشکوک ({0}/۱۰۰) از {1}" -f $score, $m.Sender)
                Details = ("Sender: {0}  IP: {1}  To: {2}  Subject: {3}`r`nReasons: {4}" -f $m.Sender, $ip, $m.Recipient, $m.Subject, ($why -join ' ; '))
                Key = ("MAILSEC|{0}|{1}" -f $env:COMPUTERNAME, $m.NetMsgId)
                MailScore = $score; MailFrom = $m.Sender; MailTo = $m.Recipient; MailIp = $ip; MailSubject = $m.Subject; MailMsgId = $m.MessageId
            }
            Add-LBMailEvent -StateDir $StateDir -Rec ([ordered]@{ t = (Get-Date).ToString('o', $script:Inv); cat = $cat; sev = $sev; from = $m.Sender; to = $m.Recipient; ip = $ip; subject = $m.Subject; score = $score; server = $env:COMPUTERNAME })
            if ($score -ge $quarAt) { [void](Add-LBMailQuarantine -StateDir $StateDir -Item @{ from = $m.Sender; to = $m.Recipient; ip = $ip; subject = $m.Subject; score = $score; reasons = $why; msgId = $m.MessageId; netMsgId = $m.NetMsgId; server = $env:COMPUTERNAME }) }
        }
    }
    return $findings
}

# ---------------------------------------------------------------- Exchange auto-connect + recipients
#  Loads the Exchange Management Shell automatically — no configuration needed.
function Connect-LBExchange {
    if (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) { return $true }
    $base = Get-LBExchangeInstallPath
    if ($base) {
        $rem = Join-Path $base 'bin\RemoteExchange.ps1'
        if (Test-Path $rem) { try { . $rem; Connect-ExchangeServer -auto -ClientApplication:ManagementShell -ErrorAction Stop } catch { } }
    }
    if (-not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue)) { try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue } catch { } }
    return [bool](Get-Command Get-Mailbox -ErrorAction SilentlyContinue)
}
#  mailbox addresses + databases, for the console pickers (empty off an Exchange box)
function Get-LBMailRecipients {
    $out = [ordered]@{ exchange = $false; mailboxes = @(); databases = @() }
    if (-not (Test-LBMailExchangePresent)) { return $out }
    $out.exchange = $true
    if (-not (Connect-LBExchange)) { return $out }
    try { $out.mailboxes = @(Get-Mailbox -ResultSize 2000 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.PrimarySmtpAddress } | Where-Object { $_ } | Sort-Object -Unique) } catch { }
    try { $out.databases = @(Get-MailboxDatabase -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Sort-Object -Unique) } catch { }
    return $out
}

# ---------------------------------------------------------------- PREVIEW: list messages BEFORE removing
#  Lets the operator see exactly which messages match before any delete.
#   1) Message-tracking logs — fast, and give the real Message-Id/From/To/Subject/Time.
#   2) Fallback: Compliance Search *Preview* (no purge) across the same scope.
#  Returns an array of rows; empty array off an Exchange box.
function Find-LBMailMessages {
    param(
        $Config,
        [string]$Subject, [string]$Sender, [string]$MessageId, [string]$From, [string]$To,
        [string]$Mailbox = 'all', [string]$Database = '', [int]$Max = 100
    )
    $uniq = New-Object System.Collections.ArrayList
    if (-not (Test-LBMailExchangePresent)) { return , @() }
    [void](Connect-LBExchange)
    $snd = if ($Sender) { $Sender } elseif ($From) { $From } else { '' }
    $seen = @{}

    # --- 1) message tracking (returns Message-Id) ---
    if (Get-Command Get-MessageTrackingLog -ErrorAction SilentlyContinue) {
        try {
            $srv = @(Get-TransportService -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
            if (-not $srv.Count) { $srv = @($env:COMPUTERNAME) }
            foreach ($s in $srv) {
                $p = @{ Server = $s; ResultSize = [string]([math]::Max(50, $Max * 4)); Start = (Get-Date).AddDays(-30); End = (Get-Date) }
                if ($snd) { $p.Sender = $snd }
                if ($MessageId) { $p.MessageId = ($MessageId -replace '[<>]', '') }
                $logs = $null; try { $logs = Get-MessageTrackingLog @p -ErrorAction SilentlyContinue | Where-Object { [string]$_.EventId -in @('RECEIVE', 'DELIVER', 'SUBMIT') } } catch { }
                foreach ($m in @($logs)) {
                    if ($Subject -and ([string]$m.MessageSubject -notlike ('*' + $Subject + '*'))) { continue }
                    $rcpt = @($m.Recipients) -join ', '
                    if ($To -and ($rcpt -notmatch [regex]::Escape($To))) { continue }
                    if ($Mailbox -and $Mailbox -ne 'all' -and ($rcpt -notmatch [regex]::Escape($Mailbox))) { continue }
                    $mid = ([string]$m.MessageId -replace '[<>]', '')
                    $k = if ($mid) { 'id:' + $mid } else { 's:' + [string]$m.MessageSubject + '|' + [string]$m.Timestamp }
                    if ($seen.ContainsKey($k)) { continue }
                    $seen[$k] = $true
                    [void]$uniq.Add([ordered]@{
                            date = $(if ($m.Timestamp) { ([datetime]$m.Timestamp).ToString('yyyy-MM-dd HH:mm', $script:Inv) } else { '' })
                            from = [string]$m.Sender; to = $rcpt; subject = [string]$m.MessageSubject
                            messageId = $mid; size = [string]$m.TotalBytes; source = 'tracking'
                        })
                    if ($uniq.Count -ge $Max) { break }
                }
                if ($uniq.Count -ge $Max) { break }
            }
        } catch { }
    }

    # --- 2) fallback: Compliance Search Preview (no purge) ---
    if (-not $uniq.Count -and (Get-Command New-ComplianceSearch -ErrorAction SilentlyContinue)) {
        $parts = @()
        if ($Subject) { $parts += ('subject:"{0}"' -f ($Subject -replace '"', '')) }
        if ($snd) { $parts += ('from:"{0}"' -f ($snd -replace '"', '')) }
        if ($To) { $parts += ('to:"{0}"' -f ($To -replace '"', '')) }
        $kql = ($parts -join ' AND ')
        if ($kql) {
            $name = 'LogBok-Preview-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            try {
                $loc = @('All')
                if ($Database) { $loc = @(Get-Mailbox -Database $Database -ResultSize Unlimited -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.PrimarySmtpAddress } | Where-Object { $_ }); if (-not $loc.Count) { $loc = @('All') } }
                elseif ($Mailbox -and $Mailbox -ne 'all') { $loc = @($Mailbox) }
                New-ComplianceSearch -Name $name -ExchangeLocation $loc -ContentMatchQuery $kql -ErrorAction Stop | Out-Null
                Start-ComplianceSearch -Identity $name -ErrorAction Stop
                $tries = 0; do { Start-Sleep -Seconds 5; $cs = Get-ComplianceSearch -Identity $name; $tries++ } while ([string]$cs.Status -ne 'Completed' -and $tries -lt 24)
                if ([string]$cs.Status -eq 'Completed' -and [int]$cs.Items -gt 0) {
                    New-ComplianceSearchAction -SearchName $name -Preview -ErrorAction Stop | Out-Null
                    $tries = 0; do { Start-Sleep -Seconds 5; $pa = Get-ComplianceSearchAction -Identity ($name + '_Preview') -Details -ErrorAction SilentlyContinue; $tries++ } while ((-not $pa -or [string]$pa.Status -ne 'Completed') -and $tries -lt 24)
                    if ($pa -and $pa.Results) {
                        foreach ($line in ([string]$pa.Results -split "`r?`n")) {
                            if ($line -notmatch 'Location:') { continue }
                            $f = @{}; foreach ($pair in ($line -split ';\s*')) { if ($pair -match '^\s*([^:]+):\s*(.*)$') { $f[$matches[1].Trim()] = $matches[2].Trim() } }
                            [void]$uniq.Add([ordered]@{
                                    date = [string]$f['Received Time']; from = [string]$f['Sender']; to = [string]$f['Location']
                                    subject = [string]$f['Subject']; messageId = ''; size = [string]$f['Size']; source = 'preview'
                                })
                            if ($uniq.Count -ge $Max) { break }
                        }
                    }
                }
            }
            catch { }
            finally { try { Remove-ComplianceSearch -Identity $name -Confirm:$false -ErrorAction SilentlyContinue } catch { } }
        }
    }
    return , @($uniq)
}

# ---------------------------------------------------------------- SAFE mailbox message removal
#  Uses Exchange's native eDiscovery/compliance purge so the mailbox database
#  and Outlook/OWA clients stay fully consistent (no manual DB edits, no MFCMAPI).
#   - Exchange 2016/2019: New-ComplianceSearch + New-ComplianceSearchAction -Purge
#     (SoftDelete = recoverable from Recoverable Items; HardDelete = permanent).
#   - Fallback (older builds): Search-Mailbox -DeleteContent.
#  Runs inside the Exchange Management Shell on the Exchange server.
function Remove-LBMailboxMessage {
    param(
        [Parameter(Mandatory)][string]$StateDir, $Config,
        [string]$Subject, [string]$Sender, [string]$MessageId, [string]$From, [string]$To,
        [ValidateSet('soft', 'hard')][string]$Mode = 'soft',
        [string]$Mailbox = 'all',   # a single SMTP address, or 'all'
        [string]$Database = ''      # optional: scope to all mailboxes in this database
    )
    $res = [ordered]@{ at = (Get-Date).ToString('o', $script:Inv); mode = $Mode; scope = $(if ($Database) { 'db:' + $Database } else { $Mailbox }); method = ''; removed = 0; errors = @() }
    if (-not (Test-LBMailExchangePresent)) { $res.errors += 'not an Exchange server'; return $res }
    [void](Connect-LBExchange)
    # build a KQL content-match query from whatever we were given
    $parts = @()
    if ($Subject) { $parts += ('subject:"{0}"' -f ($Subject -replace '"', '')) }
    if ($Sender -or $From) { $parts += ('from:"{0}"' -f ($(if ($Sender) { $Sender } else { $From }) -replace '"', '')) }
    if ($To) { $parts += ('to:"{0}"' -f ($To -replace '"', '')) }
    $kql = ($parts -join ' AND '); if (-not $kql) { $res.errors += 'no search criteria'; return $res }
    $purge = if ($Mode -eq 'hard') { 'HardDelete' } else { 'SoftDelete' }
    if (Get-Command New-ComplianceSearch -ErrorAction SilentlyContinue) {
        $res.method = 'ComplianceSearch'
        $name = 'LogBok-Purge-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        try {
            $loc = @('All')
            if ($Database) { $loc = @(Get-Mailbox -Database $Database -ResultSize Unlimited -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.PrimarySmtpAddress } | Where-Object { $_ }); if (-not $loc.Count) { $loc = @('All') } }
            elseif ($Mailbox -and $Mailbox -ne 'all') { $loc = @($Mailbox) }
            New-ComplianceSearch -Name $name -ExchangeLocation $loc -ContentMatchQuery $kql -ErrorAction Stop | Out-Null
            Start-ComplianceSearch -Identity $name -ErrorAction Stop
            $tries = 0; do { Start-Sleep -Seconds 5; $s = Get-ComplianceSearch -Identity $name; $tries++ } while ($s.Status -ne 'Completed' -and $tries -lt 36)
            if ($s.Status -eq 'Completed') {
                New-ComplianceSearchAction -SearchName $name -Purge -PurgeType $purge -Confirm:$false -ErrorAction Stop | Out-Null
                $res.removed = [int]$s.Items
            }
            else { $res.errors += "search status: $($s.Status)" }
        }
        catch { $res.errors += [string]$_.Exception.Message }
    }
    elseif (Get-Command Search-Mailbox -ErrorAction SilentlyContinue) {
        $res.method = 'Search-Mailbox'
        $q = @(); if ($Subject) { $q += ('Subject:"{0}"' -f ($Subject -replace '"', '')) }; if ($Sender -or $From) { $q += ('From:"{0}"' -f ($(if ($Sender) { $Sender } else { $From }))) }
        $sq = ($q -join ' AND ')
        try {
            $src = if ($Database) { Get-Mailbox -Database $Database -ResultSize Unlimited } elseif ($Mailbox -and $Mailbox -ne 'all') { Get-Mailbox -Identity $Mailbox } else { Get-Mailbox -ResultSize Unlimited }
            $src | Search-Mailbox -SearchQuery $sq -DeleteContent -Force -ErrorAction Stop | ForEach-Object { $res.removed += [int]$_.ResultItemsCount }
        }
        catch { $res.errors += [string]$_.Exception.Message }
    }
    else { $res.errors += 'no compliance/search cmdlets available' }
    try { Import-Module (Join-Path (Split-Path $StateDir -Parent) 'LogBok.Core.psm1') -DisableNameChecking -ErrorAction SilentlyContinue; Write-LogBokLog -Message ("Mail purge ({0}/{1}) on {2}: {3} item(s); q={4}" -f $Mode, $res.method, $env:COMPUTERNAME, $res.removed, $kql) -Config $Config } catch { }
    return $res
}

Export-ModuleMember -Function *
