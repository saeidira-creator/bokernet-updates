# ==========================================================================
#  LogBok.Guard.psm1 - Login Guard: automatic blocking of attacker IPs
#
#  a native LogBok capability (no dependency on another product): any IP with
#  several failed logins in a given window is blocked in the Windows firewall.
#   - sources: RDP, Windows/SMB logon (4625/4771), RDP-NLA (RdpCoreTS 140), SQL Server
#     (18456), OpenSSH, IIS FTP (530) and web (IIS 401).
#   - escalating block: longer each time (x factor); permanent after N times.
#   - white/black list (IP, CIDR, a-b range); the internal network is auto-whitelisted.
#   - country restriction (AllowOnly/BlockListed) with an offline IP->country database.
#   - business hours: outside work hours/days, any non-whitelisted IP that attempts a login is blocked.
#   - malicious-IP feed from a URL (optional) and "shared block": an IP blocked on one server
#     is blocked on all LogBok machines too.
#   - event-driven: the LogBok-Guard task runs immediately on a failed-login event;
#     if someone deletes the guard firewall rule, it is rebuilt and alerted at once.
#  output: events 9015 (block) and 9016 (unblock) in Application -> engine/dashboard.
#
#  honest boundary: only the standard Windows firewall is used; the rules, named
#  "LogBok-Guard-...", are visible to and removable by the administrator.
# ==========================================================================

$script:Inv        = [Globalization.CultureInfo]::InvariantCulture
$script:RulePrefix = 'LogBok-Guard-Block-'
$script:ChunkSize  = 300
$script:Geo        = $null
$script:FwMock     = $null      # tests only
# internal/reserved networks: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 0/8, 224/3
$script:LocalRanges = @(@(167772160, 184549375), @(2886729728, 2887778303), @(3232235520, 3232301055), @(2130706432, 2147483647),
                        @(2851995648, 2852061183), @(1681915904, 1686110207), @(0, 16777215), @(3758096384, 4294967295))

# ---------------------------------------------------------------------------
#  settings with defaults
# ---------------------------------------------------------------------------
function Get-LBGuardSettings {
    param($Config)
    $g = if ($Config -and $Config.Guard) { $Config.Guard } else { @{} }
    $p = if ($g.Protect) { $g.Protect } else { @{} }
    $w = if ($g.WorkHours) { $g.WorkHours } else { @{} }
    function _v($v, $d) { if ($null -eq $v -or "$v" -eq '') { return $d } else { return $v } }
    [pscustomobject]@{
        MaxFailedAttempts    = [int](_v $g.MaxFailedAttempts 5)
        AttemptWindowMinutes = [int](_v $g.AttemptWindowMinutes 10)
        WebMaxFailures       = [int](_v $g.WebMaxFailures 20)
        BlockMinutes         = [int](_v $g.BlockMinutes 20)
        EscalationFactor     = [double](_v $g.EscalationFactor 3)
        MaxBlockMinutes      = [int](_v $g.MaxBlockMinutes 43200)   # cap on a temporary block (30 days)
        PermanentAfterBlocks = [int](_v $g.PermanentAfterBlocks 3)
        ProtectRDP           = ($p.RDP -ne $false)
        ProtectWindowsLogon  = ($p.WindowsLogon -ne $false)
        ProtectSQL           = ($p.SQL -ne $false)
        ProtectFTP           = ($p.FTP -ne $false)
        ProtectWeb           = ($p.Web -ne $false)
        ProtectSSH           = ($p.SSH -ne $false)
        WebStatusCodes       = @(_v $g.WebStatusCodes @(401))
        AutoWhitelistLan     = ($g.AutoWhitelistLan -ne $false)
        Whitelist            = @($g.Whitelist | Where-Object { $_ })
        Blacklist            = @($g.Blacklist | Where-Object { $_ })
        GeoMode              = [string](_v $g.GeoMode 'Off')
        AllowedCountries     = @(@(_v $g.AllowedCountries @('IR')) | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ })
        BlockedCountries     = @(@($g.BlockedCountries) | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ })
        GeoDbUrl             = [string](_v $g.GeoDbUrl 'https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv')
        GeoUpdateHours       = [int](_v $g.GeoUpdateHours 72)
        FeedUrls             = @($g.FeedUrls | Where-Object { $_ })
        FeedUpdateHours      = [int](_v $g.FeedUpdateHours 12)
        ShareBlocks          = ($g.ShareBlocks -ne $false)
        AlertEveryBlock      = ($g.AlertEveryBlock -eq $true)
        WorkHoursEnabled     = ($w.Enabled -eq $true)
        WorkDays             = @(@(_v $w.Days @('Saturday','Sunday','Monday','Tuesday','Wednesday')) | ForEach-Object { [string]$_ })
        WorkStart            = [string](_v $w.Start '08:00')
        WorkEnd              = [string](_v $w.End '17:00')
        IISLogPath           = [string](_v $Config.IISLogPath 'C:\inetpub\logs\LogFiles')
        FtpLogPath           = [string](_v $Config.FtpLogPath 'C:\inetpub\logs\LogFiles')
        Collector            = [string]$Config.CollectorFqdn
        MgmtWhitelist        = @($(try { if ($Config.Management -and $Config.Management.ProtectSelf -ne $false) { @($Config.Management.AdminIPs | Where-Object { $_ }) } } catch { @() }))
    }
}

# ---------------------------------------------------------------------------
#  IP helpers
# ---------------------------------------------------------------------------
# normalize an IP (strip ::ffff:, brackets, zone) -> canonical text or $null
function ConvertTo-LBCleanIp {
    param([string]$Ip)
    if (-not $Ip) { return $null }
    $s = $Ip.Trim().Trim('[', ']')
    if ($s -eq '-' -or $s -eq '') { return $null }
    $s = $s -replace '^::ffff:', ''
    $pct = $s.IndexOf('%'); if ($pct -gt 0) { $s = $s.Substring(0, $pct) }
    $a = $null
    if (-not [Net.IPAddress]::TryParse($s, [ref]$a)) { return $null }
    if ($a.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($s -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }   # do not treat "10" or "1.2" as an IP
        return $a.ToString()
    }
    return $a.ToString().ToLowerInvariant()
}
function ConvertTo-LBIpNumber {
    param([string]$Ip)
    if ($Ip -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $null }
    $o = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    foreach ($x in $o) { if ($x -gt 255) { return $null } }
    return ([uint64]$o[0] * 16777216 + [uint64]$o[1] * 65536 + [uint64]$o[2] * 256 + [uint64]$o[3])
}
# one list entry: IP | CIDR | a-b range  ->  @{ Lo; Hi; V6; Text }
function ConvertTo-LBIpEntry {
    param([string]$Entry)
    $e = ([string]$Entry).Trim()
    if (-not $e) { return $null }
    if ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $v = ConvertTo-LBIpNumber $Matches[1]; $p = [int]$Matches[2]
        if ($null -eq $v -or $p -gt 32) { return $null }
        $size = [uint64][math]::Pow(2, 32 - $p)
        $lo = [uint64]([math]::Floor([double]$v / $size) * $size)
        $hi = $lo + $size - 1
        $txt = if ($p -eq 32) { $Matches[1] } else { '{0}/{1}' -f (ConvertFrom-LBIpNumber $lo), $p }
        return @{ Lo = $lo; Hi = $hi; V6 = $null; Text = $txt }
    }
    if ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
        $a = ConvertTo-LBIpNumber $Matches[1]; $b = ConvertTo-LBIpNumber $Matches[2]
        if ($null -eq $a -or $null -eq $b) { return $null }
        if ($b -lt $a) { $t = $a; $a = $b; $b = $t }
        return @{ Lo = $a; Hi = $b; V6 = $null; Text = ('{0}-{1}' -f (ConvertFrom-LBIpNumber $a), (ConvertFrom-LBIpNumber $b)) }
    }
    $c = ConvertTo-LBCleanIp $e
    if (-not $c) { return $null }
    if ($c.Contains(':')) { return @{ Lo = $null; Hi = $null; V6 = $c; Text = $c } }
    $v = ConvertTo-LBIpNumber $c
    return @{ Lo = $v; Hi = $v; V6 = $null; Text = $c }
}
function ConvertFrom-LBIpNumber {
    param([uint64]$N)
    $a = [math]::Floor($N / 16777216) % 256; $b = [math]::Floor($N / 65536) % 256; $c = [math]::Floor($N / 256) % 256; $d = $N % 256
    return ('{0}.{1}.{2}.{3}' -f $a, $b, $c, $d)
}
function ConvertTo-LBIpEntries {
    param($List)
    $out = New-Object System.Collections.ArrayList
    foreach ($x in @($List)) { $e = ConvertTo-LBIpEntry ([string]$x); if ($e) { [void]$out.Add($e) } }
    return $out.ToArray()
}
function Test-LBIpInEntries {
    param([string]$Ip, $Entries)
    $c = ConvertTo-LBCleanIp $Ip
    if (-not $c) { return $false }
    if ($c.Contains(':')) { foreach ($e in @($Entries)) { if ($e.V6 -and $e.V6 -eq $c) { return $true } }; return $false }
    $v = ConvertTo-LBIpNumber $c
    foreach ($e in @($Entries)) { if ($null -ne $e.Lo -and $v -ge $e.Lo -and $v -le $e.Hi) { return $true } }
    return $false
}
# private/local/reserved (never blocked when AutoWhitelistLan is on)
function Test-LBLocalIp {
    param([string]$Ip)
    $c = ConvertTo-LBCleanIp $Ip
    if (-not $c) { return $true }
    if ($c.Contains(':')) {
        return ($c -eq '::1' -or $c -eq '::' -or $c -match '^fe[89ab][0-9a-f]:' -or $c -match '^f[cd][0-9a-f]{2}:')
    }
    $v = ConvertTo-LBIpNumber $c
    foreach ($r in $script:LocalRanges) { if ($v -ge $r[0] -and $v -le $r[1]) { return $true } }
    return $false
}
# does the range [Lo,Hi] overlap an internal/reserved network or one of the entries?
function Test-LBRangeOverlap {
    param($Entry, $Entries, [switch]$Local)
    if ($null -eq $Entry.Lo) { return $false }
    if ($Local) { foreach ($r in $script:LocalRanges) { if ($Entry.Lo -le $r[1] -and $Entry.Hi -ge $r[0]) { return $true } } }
    foreach ($w in @($Entries)) { if ($null -ne $w.Lo -and $Entry.Lo -le $w.Hi -and $Entry.Hi -ge $w.Lo) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
#  state (state\guard.json)
# ---------------------------------------------------------------------------
function Get-LBGuardStatePath { param([string]$StateDir) Join-Path $StateDir 'guard.json' }
# one state dir for the task and the console
function Get-LBGuardStateDir {
    param($Config, [string]$InstallDir)
    if ($Config -and $Config.Paths -and $Config.Paths.State) {
        $p = [string]$Config.Paths.State
        if (Test-Path $p) { return $p }
        $parent = Split-Path $p -Parent
        if ($parent -and (Test-Path $parent)) { return $p }
    }
    return (Join-Path $InstallDir 'state')
}
# global lock so the task and console do not overwrite guard.json at the same time
function Enter-LBGuardLock {
    param([int]$TimeoutMs = 60000)
    $m = $null
    try { $m = New-Object System.Threading.Mutex($false, 'Global\LogBokGuard') } catch { return $null }
    try { if ($m.WaitOne($TimeoutMs)) { return $m } }
    catch [System.Threading.AbandonedMutexException] { return $m }
    catch { }
    try { $m.Dispose() } catch { }
    return $null
}
function Exit-LBGuardLock {
    param($Mutex)
    if ($Mutex) { try { $Mutex.ReleaseMutex() } catch { }; try { $Mutex.Dispose() } catch { } }
}
function ConvertTo-LBHash {
    param($Obj)
    $h = @{}
    if ($null -eq $Obj) { return $h }
    if ($Obj -is [hashtable]) { return $Obj }
    foreach ($p in $Obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}
function Get-LBGuardState {
    param([string]$StateDir)
    $f = Get-LBGuardStatePath $StateDir
    $o = $null
    if (Test-Path $f) { try { $o = [IO.File]::ReadAllText($f) | ConvertFrom-Json } catch { $o = $null } }
    $st = @{ attempts = @{}; blocks = @{}; history = @{}; lastRec = @{}; lastTime = @{}; files = @{}; ruleHashes = @{}
             whitelist = @(); blacklist = @(); feed = @(); shared = @{}; unshared = @{}; meta = @{} }
    if ($o) {
        foreach ($k in 'attempts','history','lastRec','lastTime','files','ruleHashes','unshared','meta') { $st[$k] = ConvertTo-LBHash $o.$k }
        foreach ($k in 'blocks','shared') {
            $t = ConvertTo-LBHash $o.$k
            foreach ($ip in @($t.Keys)) { $t[$ip] = ConvertTo-LBHash $t[$ip] }
            $st[$k] = $t
        }
        foreach ($k in @($st.history.Keys)) { $st.history[$k] = ConvertTo-LBHash $st.history[$k] }
        foreach ($k in @($st.attempts.Keys)) { $st.attempts[$k] = ConvertTo-LBHash $st.attempts[$k] }
        foreach ($k in @($st.files.Keys)) { $st.files[$k] = ConvertTo-LBHash $st.files[$k] }
        foreach ($k in 'whitelist','blacklist','feed') { $st[$k] = @(@($o.$k) | Where-Object { $_ }) }
    }
    return $st
}
function Save-LBGuardState {
    param([string]$StateDir, $State)
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $f = Get-LBGuardStatePath $StateDir
    $tmp = "$f.$PID.tmp"
    $json = $State | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
function Get-LBUtcNow { return (Get-Date).ToUniversalTime() }
function ConvertTo-LBUtc {
    param($v)
    if ($v -is [datetime]) { return $v.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$v, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}
function Get-LBIso { param([datetime]$Utc) return $Utc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $script:Inv) }

# ---------------------------------------------------------------------------
#  decisions
# ---------------------------------------------------------------------------
# are we currently "inside" business hours? (off = always inside); an overnight window (22:00->06:00) is supported
function Test-LBWorkHours {
    param($Settings, [datetime]$Now = (Get-Date))
    if (-not $Settings.WorkHoursEnabled) { return $true }
    $s = [TimeSpan]::Zero; $e = [TimeSpan]::Zero
    if (-not [TimeSpan]::TryParse($Settings.WorkStart, [ref]$s)) { $s = New-TimeSpan -Hours 8 }
    if (-not [TimeSpan]::TryParse($Settings.WorkEnd, [ref]$e)) { $e = New-TimeSpan -Hours 17 }
    $t = $Now.TimeOfDay
    $day = $Now.DayOfWeek.ToString()
    $days = @($Settings.WorkDays)
    if ($s -le $e) { return (($days -contains $day) -and $t -ge $s -and $t -lt $e) }
    # overnight window: starts on a work day until midnight, or continues from the previous work day
    $prev = $Now.AddDays(-1).DayOfWeek.ToString()
    return ((($days -contains $day) -and $t -ge $s) -or (($days -contains $prev) -and $t -lt $e))
}
# minutes until the next work-hours start (for the out-of-hours block)
function Get-LBMinutesToWorkStart {
    param($Settings, [datetime]$Now = (Get-Date))
    $s = [TimeSpan]::Zero
    if (-not [TimeSpan]::TryParse($Settings.WorkStart, [ref]$s)) { $s = New-TimeSpan -Hours 8 }
    for ($i = 0; $i -le 8; $i++) {
        $d = $Now.Date.AddDays($i).Add($s)
        if ($d -gt $Now -and (@($Settings.WorkDays) -contains $d.DayOfWeek.ToString())) { return [int][math]::Ceiling(($d - $Now).TotalMinutes) }
    }
    return 720
}
# block duration for the n-th time (minutes); -1 = permanent
function Get-LBBlockMinutes {
    param($Settings, [int]$Count)
    if ($Settings.PermanentAfterBlocks -gt 0 -and $Count -ge $Settings.PermanentAfterBlocks) { return -1 }
    $m = [double]$Settings.BlockMinutes * [math]::Pow([math]::Max(1, $Settings.EscalationFactor), [math]::Max(0, $Count - 1))
    return [int][math]::Min($m, [double]$Settings.MaxBlockMinutes)
}
# the effective whitelist (config + local + Collector + the machine's own IPs)
function Get-LBGuardWhitelist {
    param($Settings, $State)
    $list = @($Settings.Whitelist) + @($State.whitelist) + @('127.0.0.1', '::1')
    # management IPs (AdminIPs/Collector) are never blocked so LogBok's own path stays stable
    if ($Settings.MgmtWhitelist) { $list += @($Settings.MgmtWhitelist) }
    if ($Settings.Collector) {
        # the management server address is never blocked (6-hour cache to avoid resolving DNS every time)
        $at = $null; if ($State.meta) { $at = ConvertTo-LBUtc $State.meta.colAt }
        if ($at -and $at -gt (Get-LBUtcNow).AddHours(-6) -and $State.meta.colIps) { $list += @($State.meta.colIps -split ',') }
        else {
            $ips = @(); try { foreach ($a in [Net.Dns]::GetHostAddresses($Settings.Collector)) { $ips += $a.ToString() } } catch { }
            if ($State.meta) { $State.meta.colIps = ($ips -join ','); $State.meta.colAt = Get-LBIso (Get-LBUtcNow) }
            $list += $ips
        }
    }
    try {
        foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { $list += $ua.Address.ToString() }
        }
    } catch { }
    return @(ConvertTo-LBIpEntries $list)
}
function Test-LBGuardWhitelisted {
    param([string]$Ip, $Settings, $WhiteEntries)
    if ($Settings.AutoWhitelistLan -and (Test-LBLocalIp $Ip)) { return $true }
    return (Test-LBIpInEntries -Ip $Ip -Entries $WhiteEntries)
}
# should it be blocked based on country?
function Test-LBGeoBlock {
    param($Settings, [string]$Country)
    if (-not $Country) { return $false }            # an unknown country is not blocked
    switch ($Settings.GeoMode) {
        'AllowOnly'   { return ($Settings.AllowedCountries -notcontains $Country.ToUpperInvariant()) }
        'BlockListed' { return ($Settings.BlockedCountries -contains $Country.ToUpperInvariant()) }
        default       { return $false }
    }
}

# record a block in state (returns the block record)
function Set-LBGuardBlock {
    param($State, $Settings, [string]$Ip, [string]$Reason, [string]$Source, [int]$Attempts, [string]$Users, [string]$Country,
          [int]$Minutes = 0, [switch]$Permanent, [switch]$Manual, [switch]$NoEscalate, [datetime]$NowUtc = (Get-LBUtcNow))
    $hist = if ($State.history.ContainsKey($Ip)) { $State.history[$Ip] } else { @{ count = 0; last = $null } }
    $count = if ($NoEscalate) { [int]$hist.count } else { [int]$hist.count + 1 }
    $mins = if ($Permanent) { -1 } elseif ($Minutes -gt 0) { $Minutes } else { Get-LBBlockMinutes -Settings $Settings -Count $count }
    $until = if ($mins -lt 0) { 'permanent' } else { Get-LBIso $NowUtc.AddMinutes($mins) }
    $b = @{ since = (Get-LBIso $NowUtc); until = $until; count = $count; reason = $Reason; source = $Source
            attempts = $Attempts; users = $Users; country = $Country; manual = [bool]$Manual }
    $State.blocks[$Ip] = $b
    if (-not $NoEscalate) { $State.history[$Ip] = @{ count = $count; last = (Get-LBIso $NowUtc) } }
    if ($State.attempts.ContainsKey($Ip)) { $State.attempts.Remove($Ip) }
    return $b
}

# register one failed attempt; returns a block if the threshold is reached
#  $Attempt = @{ Ip; Source; User; TimeUtc; Kind='fail'|'success' }
function Add-LBGuardAttempt {
    param($State, $Settings, $Attempt, $WhiteEntries, [scriptblock]$CountryOf, [datetime]$NowUtc = (Get-LBUtcNow), $InWorkHours = $null)
    $ip = ConvertTo-LBCleanIp $Attempt.Ip
    if (-not $ip) { return $null }
    if (Test-LBGuardWhitelisted -Ip $ip -Settings $Settings -WhiteEntries $WhiteEntries) { return $null }
    if ($State.blocks.ContainsKey($ip)) { return $null }                       # already blocked
    # the event's own time (not processing time); attempts older than the window are not counted
    $win = $NowUtc.AddMinutes(-$Settings.AttemptWindowMinutes)
    $at = if ($Attempt.TimeUtc) { ConvertTo-LBUtc $Attempt.TimeUtc } else { $NowUtc }
    if (-not $at) { $at = $NowUtc }
    if ($at -lt $win) { return $null }
    if ($at -gt $NowUtc) { $at = $NowUtc }
    if ($null -eq $InWorkHours) { $InWorkHours = Test-LBWorkHours -Settings $Settings -Now $at.ToLocalTime() }
    $cc = ''
    if ($CountryOf) { try { $cc = [string](& $CountryOf $ip) } catch { $cc = '' } }
    # 1) outside business hours: any login attempt (success or failure) -> immediate block
    if (-not $InWorkHours) {
        $m = Get-LBMinutesToWorkStart -Settings $Settings -Now $NowUtc.ToLocalTime()
        return (Set-LBGuardBlock -State $State -Settings $Settings -Ip $ip -Reason 'off-hours' -Source $Attempt.Source -Attempts 1 -Users $Attempt.User -Country $cc -Minutes $m -NoEscalate -NowUtc $NowUtc)
    }
    if ($Attempt.Kind -eq 'success') { return $null }
    # 2) disallowed country -> immediate block
    if (Test-LBGeoBlock -Settings $Settings -Country $cc) {
        return (Set-LBGuardBlock -State $State -Settings $Settings -Ip $ip -Reason ("geo:$cc") -Source $Attempt.Source -Attempts 1 -Users $Attempt.User -Country $cc -NowUtc $NowUtc)
    }
    # 3) count attempts within the window
    $a = if ($State.attempts.ContainsKey($ip)) { $State.attempts[$ip] } else { @{ t = @(); users = @(); src = '' } }
    $times = New-Object System.Collections.ArrayList
    foreach ($x in @($a.t)) { $d = ConvertTo-LBUtc $x; if ($d -and $d -ge $win) { [void]$times.Add((Get-LBIso $d)) } }
    [void]$times.Add((Get-LBIso $at))
    $users = @(@($a.users) + @($Attempt.User) | Where-Object { $_ } | Select-Object -Unique | Select-Object -Last 5)
    $State.attempts[$ip] = @{ t = @($times.ToArray()); users = $users; src = [string]$Attempt.Source }
    $limit = if ($Attempt.Source -eq 'Web') { $Settings.WebMaxFailures } else { $Settings.MaxFailedAttempts }
    if ($times.Count -ge $limit) {
        return (Set-LBGuardBlock -State $State -Settings $Settings -Ip $ip -Reason 'attempts' -Source $Attempt.Source -Attempts $times.Count -Users ($users -join ',') -Country $cc -NowUtc $NowUtc)
    }
    return $null
}

# expire blocks, prune history/attempts
function Invoke-LBGuardExpire {
    param($State, $Settings, [datetime]$NowUtc = (Get-LBUtcNow))
    $expired = New-Object System.Collections.ArrayList
    foreach ($ip in @($State.blocks.Keys)) {
        $u = $State.blocks[$ip].until
        if ($u -eq 'permanent') { continue }
        $d = ConvertTo-LBUtc $u
        if (-not $d -or $d -le $NowUtc) { [void]$expired.Add(@{ Ip = $ip; Block = $State.blocks[$ip] }); $State.blocks.Remove($ip) }
    }
    foreach ($ip in @($State.history.Keys)) {
        $d = ConvertTo-LBUtc $State.history[$ip].last
        if (-not $d -or $d -lt $NowUtc.AddDays(-30)) { if (-not $State.blocks.ContainsKey($ip)) { $State.history.Remove($ip) } }
    }
    $win = $NowUtc.AddMinutes(-$Settings.AttemptWindowMinutes)
    foreach ($ip in @($State.attempts.Keys)) {
        $keep = @(@($State.attempts[$ip].t) | Where-Object { $d = ConvertTo-LBUtc $_; $d -and $d -ge $win })
        if ($keep.Count -eq 0) { $State.attempts.Remove($ip) } else { $State.attempts[$ip].t = $keep }
    }
    foreach ($ip in @($State.shared.Keys)) {
        $d = ConvertTo-LBUtc $State.shared[$ip].until
        if ($State.shared[$ip].until -ne 'permanent' -and (-not $d -or $d -le $NowUtc)) { $State.shared.Remove($ip) }
    }
    return $expired.ToArray()
}

# ---------------------------------------------------------------------------
#  event sources
# ---------------------------------------------------------------------------
$script:Sources = @(
    @{ Name='Security'; Log='Security'; Ids=@(4625, 4771) }
    @{ Name='RdpLogon'; Log='Security'; Ids=@(4624); Extra="*[EventData[Data[@Name='LogonType']='10']]"; WorkHoursOnly=$true }
    @{ Name='SQL';      Log='Application'; Ids=@(18456) }
    @{ Name='RdpCore';  Log='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Ids=@(140) }
    @{ Name='SSH';      Log='OpenSSH/Operational'; Ids=@(4) }
)
# all EventData fields, parsed in one pass
function Get-LBGuardEventFields {
    param($Event)
    $h = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $h[[string]$d.Name] = [string]$d.'#text' } }
    } catch { }
    return $h
}
$script:IpRx = '((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})'
# parse one event into a login attempt (or $null)
function ConvertFrom-LBGuardEvent {
    param($Event, $Settings)
    $id = [int]$Event.Id
    $t = $null; try { $t = $Event.TimeCreated.ToUniversalTime() } catch { }
    switch ($id) {
        4625 {
            $F = Get-LBGuardEventFields $Event
            $isRdp = ($F['LogonType'] -eq '10')
            # RDP with NLA is logged as LogonType=3; RdpCoreTS/140 covers that
            if ($isRdp) { if (-not $Settings.ProtectRDP) { return $null } }
            elseif (-not $Settings.ProtectWindowsLogon) { return $null }
            return @{ Ip = $F['IpAddress']; User = $F['TargetUserName']; Source = $(if ($isRdp) { 'RDP' } else { 'Logon' }); TimeUtc = $t; Kind = 'fail' }
        }
        4771 {
            if (-not $Settings.ProtectWindowsLogon) { return $null }
            $F = Get-LBGuardEventFields $Event
            return @{ Ip = $F['IpAddress']; User = $F['TargetUserName']; Source = 'Kerberos'; TimeUtc = $t; Kind = 'fail' }
        }
        4624 {
            # only for the business-hours restriction: a successful RDP logon
            $F = Get-LBGuardEventFields $Event
            if ($F['LogonType'] -ne '10') { return $null }
            return @{ Ip = $F['IpAddress']; User = $F['TargetUserName']; Source = 'RDP'; TimeUtc = $t; Kind = 'success' }
        }
        18456 {
            if (-not $Settings.ProtectSQL) { return $null }
            $m = ''; try { $m = [string]$Event.Message } catch { }
            if ($m -notmatch 'CLIENT:\s*([^\]\s]+)') { return $null }
            $ip = $Matches[1]
            $u = if ($m -match "user '([^']*)'") { $Matches[1] } else { '' }
            return @{ Ip = $ip; User = $u; Source = 'SQL'; TimeUtc = $t; Kind = 'fail' }
        }
        140 {
            if (-not $Settings.ProtectRDP) { return $null }
            $F = Get-LBGuardEventFields $Event
            $ip = $F['IPString']
            $m = ''
            if (-not $ip) { try { $m = [string]$Event.Message } catch { } }
            if (-not $ip -and $m -match ('address of ' + $script:IpRx)) { $ip = $Matches[1] }
            if (-not $ip -and $m -match $script:IpRx) { $ip = $Matches[1] }
            return @{ Ip = $ip; User = ''; Source = 'RDP'; TimeUtc = $t; Kind = 'fail' }
        }
        4 {
            if (-not $Settings.ProtectSSH) { return $null }
            $m = ''; try { $m = [string]$Event.Message } catch { }
            if ($m -match 'Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+)') {
                return @{ Ip = $Matches[2]; User = $Matches[1]; Source = 'SSH'; TimeUtc = $t; Kind = 'fail' }
            }
            if ($m -match 'Invalid user (\S+) from (\S+)') { return @{ Ip = $Matches[2]; User = $Matches[1]; Source = 'SSH'; TimeUtc = $t; Kind = 'fail' } }
            return $null
        }
    }
    return $null
}

# XPath query: only records after the last RecordId and within the counting window
function Get-LBGuardXPath {
    param([int[]]$Ids, [long]$AfterRecord, [long]$WithinMs, [string]$Extra)
    $idx = (@($Ids) | ForEach-Object { "EventID=$_" }) -join ' or '
    $x = "*[System[($idx)"
    if ($AfterRecord -gt 0) { $x += " and (EventRecordID > $AfterRecord)" }
    if ($WithinMs -gt 0) { $x += " and TimeCreated[timediff(@SystemTime) <= $WithinMs]" }
    $x += ']]'
    if ($Extra) { $x += " and $Extra" }
    return $x
}
# new events since each source's last RecordId
#  (EventRecordID in the filter; if the log was cleared and numbering restarts, start over)
function Get-LBGuardAttempts {
    param($State, $Settings, [int]$MaxEvents = 5000)
    $out = New-Object System.Collections.ArrayList
    $winMs = [long]([math]::Max(2, $Settings.AttemptWindowMinutes)) * 60000
    foreach ($src in $script:Sources) {
        if ($src.WorkHoursOnly -and -not $Settings.WorkHoursEnabled) { continue }
        $ids = @($src.Ids)
        $key = [string]$src.Name                                           # several sources can share one log
        $last = 0L; if ($State.lastRec.ContainsKey($key)) { $last = [long]$State.lastRec[$key] }
        $evts = @()
        try { $evts = @(Get-WinEvent -LogName $src.Log -FilterXPath (Get-LBGuardXPath -Ids $ids -AfterRecord $last -WithinMs $winMs -Extra $src.Extra) -MaxEvents $MaxEvents -ErrorAction Stop) } catch { $evts = @() }
        if ($evts.Count -eq 0 -and $last -gt 0) {
            # log cleared? the newest record is smaller than the last seen number
            $newest = $null
            try { $newest = Get-WinEvent -LogName $src.Log -MaxEvents 1 -ErrorAction Stop } catch { }
            if ($newest -and [long]$newest.RecordId -lt $last) {
                $last = 0L; $State.lastRec[$key] = 0
                try { $evts = @(Get-WinEvent -LogName $src.Log -FilterXPath (Get-LBGuardXPath -Ids $ids -AfterRecord 0 -WithinMs $winMs -Extra $src.Extra) -MaxEvents $MaxEvents -ErrorAction Stop) } catch { $evts = @() }
            }
        }
        $max = $last
        foreach ($e in ($evts | Sort-Object RecordId)) {
            $rid = [long]$e.RecordId
            if ($rid -le $last) { continue }
            if ($rid -gt $max) { $max = $rid }
            $a = ConvertFrom-LBGuardEvent -Event $e -Settings $Settings
            if ($a) { [void]$out.Add($a) }
        }
        if ($max -gt 0) { $State.lastRec[$key] = $max }
    }
    return $out.ToArray()
}

# tail IIS (web 401) and IIS-FTP (530) W3C logs
function Read-LBGuardW3C {
    param($State, [string]$File, [string]$Source, $Settings, $SinceUtc)
    $out = New-Object System.Collections.ArrayList
    $fi = Get-Item -LiteralPath $File -ErrorAction SilentlyContinue
    if (-not $fi) { return $out.ToArray() }
    $st = if ($State.files.ContainsKey($File)) { $State.files[$File] } else { $null }
    $off = 0L; $fields = $null
    if ($st) { $off = [long]$st.off; $fields = [string]$st.fields }
    elseif ($SinceUtc -and $fi.CreationTimeUtc -gt $SinceUtc) { $off = 0L }   # a freshly created daily file: from the start
    else { $off = [long]$fi.Length }                                    # an old file seen for the first time: only from here on
    if ($fi.Length -lt $off) { $off = 0L; $fields = $null }              # file rotated/rewritten
    if (-not $fields) {
        # IIS keeps the current file open for writing; reading is only possible with a ReadWrite share
        $hs = $null; $sr = $null
        try {
            $hs = New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            $sr = New-Object IO.StreamReader($hs, [Text.Encoding]::UTF8)
            for ($k = 0; $k -lt 50; $k++) {
                $l = $sr.ReadLine(); if ($null -eq $l) { break }
                if ($l.StartsWith('#Fields:')) { $fields = $l.Substring(8).Trim() } elseif (-not $l.StartsWith('#')) { break }
            }
        } catch { } finally { if ($sr) { $sr.Dispose() } elseif ($hs) { $hs.Dispose() } }
    }
    if ($fi.Length -gt $off) {
        $fs = $null
        try {
            $fs = New-Object IO.FileStream($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            [void]$fs.Seek($off, [IO.SeekOrigin]::Begin)
            $len = [int][math]::Min($fi.Length - $off, 8MB)
            $buf = New-Object byte[] $len
            $n = $fs.Read($buf, 0, $len)
            $lastNl = if ($n -gt 0) { [Array]::LastIndexOf($buf, [byte]10, $n - 1) } else { -1 }
            if ($lastNl -ge 0) {
                $text = [Text.Encoding]::UTF8.GetString($buf, 0, $lastNl + 1)
                $off += ($lastNl + 1)
                $cols = if ($fields) { $fields -split '\s+' } else { @() }
                foreach ($ln in ($text -split "`r?`n")) {
                    if (-not $ln) { continue }
                    if ($ln.StartsWith('#Fields:')) { $fields = $ln.Substring(8).Trim(); $cols = $fields -split '\s+'; continue }
                    if ($ln.StartsWith('#') -or $cols.Count -eq 0) { continue }
                    $v = $ln -split '\s+'
                    if ($v.Count -lt $cols.Count) { continue }
                    $row = @{}; for ($i = 0; $i -lt $cols.Count; $i++) { $row[$cols[$i]] = $v[$i] }
                    $code = [string]$row['sc-status']; $sub = [string]$row['sc-substatus']
                    $hit = $false
                    if ($Source -eq 'FTP') { $hit = ($code -eq '530') }
                    else {
                        $hit = (@($Settings.WebStatusCodes | ForEach-Object { [string]$_ }) -contains $code)
                        # 401.2 and 401.1 with win32=2148074254 are part of the normal NTLM/Negotiate handshake, not a failed login
                        if ($hit -and $code -eq '401' -and ($sub -eq '2' -or [string]$row['sc-win32-status'] -eq '2148074254')) { $hit = $false }
                    }
                    if (-not $hit) { continue }
                    $tu = $null; $d = [datetime]::MinValue
                    if ([datetime]::TryParseExact(("{0} {1}" -f $row['date'], $row['time']), 'yyyy-MM-dd HH:mm:ss', $script:Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { $tu = $d }
                    $user = [string]$row['cs-username']; if ($user -eq '-') { $user = '' }
                    [void]$out.Add(@{ Ip = $row['c-ip']; User = $user; Source = $Source; TimeUtc = $tu; Kind = 'fail' })
                }
            }
        } catch { } finally { if ($fs) { $fs.Dispose() } }
    }
    $State.files[$File] = @{ off = $off; fields = $fields; seen = (Get-LBIso (Get-LBUtcNow)) }
    return $out.ToArray()
}
function Get-LBGuardLogAttempts {
    param($State, $Settings)
    $out = New-Object System.Collections.ArrayList
    $jobs = @()
    if ($Settings.ProtectWeb) { $jobs += @{ Base = $Settings.IISLogPath; Rx = '\\W3SVC\d+\\|/W3SVC\d+/'; Src = 'Web' } }
    if ($Settings.ProtectFTP) { $jobs += @{ Base = $Settings.FtpLogPath; Rx = '\\FTPSVC\d+\\|/FTPSVC\d+/'; Src = 'FTP' } }
    $cut = (Get-Date).AddDays(-1)
    $since = ConvertTo-LBUtc $State.meta.lastHk
    foreach ($j in $jobs) {
        if (-not $j.Base -or -not (Test-Path $j.Base)) { continue }
        foreach ($f in @(Get-ChildItem -Path $j.Base -Recurse -Filter '*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match $j.Rx -and $_.LastWriteTime -ge $cut })) {
            foreach ($a in (Read-LBGuardW3C -State $State -File $f.FullName -Source $j.Src -Settings $Settings -SinceUtc $since)) { [void]$out.Add($a) }
        }
    }
    # drop files from state that no longer exist / are stale
    foreach ($k in @($State.files.Keys)) {
        $d = ConvertTo-LBUtc $State.files[$k].seen
        if (-not $d -or $d -lt (Get-LBUtcNow).AddDays(-3)) { $State.files.Remove($k) }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
#  IP -> country (offline, binary) geo database
# ---------------------------------------------------------------------------
function ConvertTo-LBGeoBin {
    param([string]$CsvPath, [string]$BinPath)
    $starts = New-Object 'System.Collections.Generic.List[uint32]'
    $ends   = New-Object 'System.Collections.Generic.List[uint32]'
    $cc     = New-Object System.Text.StringBuilder
    foreach ($line in [IO.File]::ReadLines($CsvPath)) {
        if (-not $line -or $line.IndexOf(':') -ge 0) { continue }
        $p = $line.Split(',')
        if ($p.Length -lt 3) { continue }
        $a = $p[0].Trim('"').Split('.'); $b = $p[1].Trim('"').Split('.')
        if ($a.Length -ne 4 -or $b.Length -ne 4) { continue }
        $c = $p[2].Trim('"').Trim()
        if ($c.Length -ne 2) { continue }
        try {
            $s = [uint64]$a[0] * 16777216 + [uint64]$a[1] * 65536 + [uint64]$a[2] * 256 + [uint64]$a[3]
            $e = [uint64]$b[0] * 16777216 + [uint64]$b[1] * 65536 + [uint64]$b[2] * 256 + [uint64]$b[3]
        } catch { continue }
        $starts.Add([uint32]$s); $ends.Add([uint32]$e); [void]$cc.Append($c.ToUpperInvariant())
    }
    $n = $starts.Count
    if ($n -lt 1000) { throw "geo csv too small ($n rows)" }
    $ms = New-Object IO.MemoryStream
    $hdr = [Text.Encoding]::ASCII.GetBytes('LBGEO1'); $ms.Write($hdr, 0, 6)
    $nb = [BitConverter]::GetBytes([int]$n); $ms.Write($nb, 0, 4)
    $sa = $starts.ToArray(); $ea = $ends.ToArray()
    $bs = New-Object byte[] ($n * 4); [Buffer]::BlockCopy($sa, 0, $bs, 0, $n * 4); $ms.Write($bs, 0, $bs.Length)
    $be = New-Object byte[] ($n * 4); [Buffer]::BlockCopy($ea, 0, $be, 0, $n * 4); $ms.Write($be, 0, $be.Length)
    $bc = [Text.Encoding]::ASCII.GetBytes($cc.ToString()); $ms.Write($bc, 0, $bc.Length)
    $tmp = "$BinPath.tmp"
    [IO.File]::WriteAllBytes($tmp, $ms.ToArray())
    Move-Item $tmp $BinPath -Force
    return $n
}
function Import-LBGuardGeo {
    param([string]$BinPath)
    $script:Geo = $null
    if (-not (Test-Path $BinPath)) { return $false }
    try {
        $bytes = [IO.File]::ReadAllBytes($BinPath)
        if ([Text.Encoding]::ASCII.GetString($bytes, 0, 6) -ne 'LBGEO1') { return $false }
        $n = [BitConverter]::ToInt32($bytes, 6)
        $s = New-Object 'uint32[]' $n; [Buffer]::BlockCopy($bytes, 10, $s, 0, $n * 4)
        $e = New-Object 'uint32[]' $n; [Buffer]::BlockCopy($bytes, 10 + $n * 4, $e, 0, $n * 4)
        $c = [Text.Encoding]::ASCII.GetString($bytes, 10 + $n * 8, $n * 2)
        $script:Geo = @{ S = $s; E = $e; C = $c; N = $n }
        return $true
    } catch { $script:Geo = $null; return $false }
}
function Get-LBGuardCountry {
    param([string]$Ip)
    if (-not $script:Geo) { return '' }
    $v = ConvertTo-LBIpNumber (ConvertTo-LBCleanIp $Ip)
    if ($null -eq $v) { return '' }
    $lo = 0; $hi = $script:Geo.N - 1
    while ($lo -le $hi) {
        $mid = [int][math]::Floor(($lo + $hi) / 2)
        if ($v -lt $script:Geo.S[$mid]) { $hi = $mid - 1 }
        elseif ($v -gt $script:Geo.E[$mid]) { $lo = $mid + 1 }
        else { return $script:Geo.C.Substring($mid * 2, 2) }
    }
    return ''
}
function Get-LBGuardDistDir {
    param([string]$InstallDir, $Config)
    $local = Join-Path $InstallDir 'dist'
    if (Test-Path (Join-Path $InstallDir 'engine.flag')) { return $local }
    return $null
}
function Get-LBGuardShareSource {
    param($Config)
    if ($Config.Update -and $Config.Update.Source) { return [string]$Config.Update.Source }
    if ($Config.CollectorFqdn) { return "\\$($Config.CollectorFqdn)\LogBokDist`$" }
    return $null
}
# update the country database: first from the central server (LAN), then from the internet
function Update-LBGuardGeo {
    param($Settings, [string]$StateDir, [string]$InstallDir, $Config, [switch]$Force)
    $ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads very slow in PS 5.1
    $bin = Join-Path $StateDir 'guard-geo.bin'
    $fresh = (Test-Path $bin) -and ((Get-Item $bin).LastWriteTime -gt (Get-Date).AddHours(-$Settings.GeoUpdateHours))
    if ($fresh -and -not $Force) { return $false }
    $tryF = Join-Path $StateDir 'guard-geo.try'
    if (-not $Force -and (Test-Path $tryF) -and (Get-Item $tryF).LastWriteTime -gt (Get-Date).AddHours(-1)) { return $false }   # failed attempt: once per hour
    try { [IO.File]::WriteAllText($tryF, (Get-LBIso (Get-LBUtcNow))) } catch { }
    $ok = $false
    $share = Get-LBGuardShareSource -Config $Config
    if ($share) {
        try {
            $remote = Join-Path $share 'guard-geo.bin'
            if ((Test-Path $remote) -and ((-not (Test-Path $bin)) -or (Get-Item $remote).LastWriteTime -gt (Get-Item $bin).LastWriteTime)) {
                Copy-Item $remote "$bin.tmp" -Force; Move-Item "$bin.tmp" $bin -Force; $ok = $true
            }
        } catch { }
    }
    if (-not $ok -and $Settings.GeoDbUrl) {
        $csv = Join-Path $StateDir 'guard-geo.csv'
        try {
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
            Invoke-WebRequest -Uri $Settings.GeoDbUrl -OutFile $csv -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop
            [void](ConvertTo-LBGeoBin -CsvPath $csv -BinPath $bin)
            $ok = $true
        } catch { } finally { Remove-Item $csv -Force -ErrorAction SilentlyContinue }
    }
    if ($ok) {
        $dist = Get-LBGuardDistDir -InstallDir $InstallDir -Config $Config
        if ($dist -and (Test-Path $dist)) { try { Copy-Item $bin (Join-Path $dist 'guard-geo.bin') -Force } catch { } }
    }
    return $ok
}

# malicious-IP feed from a URL (one IP/CIDR per line; # and ; are comments)
function ConvertFrom-LBFeedText {
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($ln in ($Text -split "`r?`n")) {
        $l = $ln.Trim()
        if (-not $l -or $l.StartsWith('#') -or $l.StartsWith(';') -or $l.StartsWith('//')) { continue }
        $tok = ($l -split '[\s,;]+')[0]
        $e = ConvertTo-LBIpEntry $tok
        if (-not $e) { continue }
        if ($e.V6) { if (-not (Test-LBLocalIp $e.V6)) { $out.Add($e.Text) }; continue }
        # a range that is too large or overlaps the internal network is rejected (prevents locking out the LAN)
        if (($e.Hi - $e.Lo) -ge 16777216 -or (Test-LBRangeOverlap -Entry $e -Local)) { continue }
        $out.Add($e.Text)
    }
    return $out.ToArray()
}
# download the feed to state\guard-feed.txt (outside the lock; may take a while)
function Update-LBGuardFeed {
    param($Settings, [string]$StateDir, [switch]$Force)
    $ProgressPreference = 'SilentlyContinue'
    $f = Join-Path $StateDir 'guard-feed.txt'
    if (@($Settings.FeedUrls).Count -eq 0) { if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue; return $true }; return $false }
    $tryF = Join-Path $StateDir 'guard-feed.try'
    if (-not $Force -and (Test-Path $tryF) -and (Get-Item $tryF).LastWriteTime -gt (Get-Date).AddHours(-$Settings.FeedUpdateHours)) { return $false }
    try { [IO.File]::WriteAllText($tryF, (Get-LBIso (Get-LBUtcNow))) } catch { }
    $all = New-Object System.Collections.Generic.HashSet[string]
    $okAny = $false
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    foreach ($u in $Settings.FeedUrls) {
        try {
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            foreach ($x in (ConvertFrom-LBFeedText -Text ([string]$r.Content))) { [void]$all.Add($x) }
            $okAny = $true
        } catch { }
    }
    if ($okAny) {
        [IO.File]::WriteAllText("$f.tmp", ((@($all) | Select-Object -First 20000) -join "`r`n"), (New-Object Text.UTF8Encoding($false)))
        Move-Item "$f.tmp" $f -Force
        return $true
    }
    return $false
}
function Get-LBGuardFeedList {
    param($Settings, [string]$StateDir)
    if (@($Settings.FeedUrls).Count -eq 0) { return @() }
    $f = Join-Path $StateDir 'guard-feed.txt'
    if (-not (Test-Path $f)) { return @() }
    try { return @([IO.File]::ReadAllLines($f) | Where-Object { $_ }) } catch { return @() }
}

# ---------------------------------------------------------------------------
#  shared blocks across all LogBok machines
# ---------------------------------------------------------------------------
# was this IP's attack seen in the Security log (which a normal user cannot forge)?
#  any interactive user can write Application events (including 9015), so only
#  IPs whose failed login is recorded in Security/ForwardedEvents go to the "shared block".
function Test-LBGuardCorroboration {
    param($Config, [string]$Ip, [string]$Machine, [int]$Hours = 2)
    $c = ConvertTo-LBCleanIp $Ip
    if (-not $c) { return $false }
    if (-not $Machine -or $Machine -notmatch '^[A-Za-z0-9._-]+$') { return $false }   # only a valid name goes into the XPath
    $ms = [long]$Hours * 3600000
    $base = "*[System[(EventID=4625 or EventID=4771) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='IpAddress']='$c' or Data[@Name='IpAddress']='::ffff:$c']]"
    $isSelf = ($Machine -eq $env:COMPUTERNAME -or $Machine -like "$($env:COMPUTERNAME).*" -or $Machine -eq 'localhost')
    $queries = @()
    if ($isSelf) { $queries += @{ LogName = 'Security'; FilterXPath = $base } }            # the engine's own blocks
    if ($Config.CollectionMode -eq 'Collector') {
        $fl = if ($Config.ForwardedLog) { [string]$Config.ForwardedLog } else { 'ForwardedEvents' }
        $queries += @{ LogName = $fl; FilterXPath = ($base + " and *[System[Computer='$Machine']]") }
    } elseif (-not $isSelf) {
        $queries += @{ LogName = 'Security'; FilterXPath = $base; ComputerName = $Machine }
    }
    foreach ($q in $queries) {
        $p = @{ LogName = $q.LogName; FilterXPath = $q.FilterXPath; MaxEvents = 1; ErrorAction = 'Stop' }
        if ($q.ComputerName) { $p.ComputerName = $q.ComputerName }
        try { if (@(Get-WinEvent @p).Count -gt 0) { return $true } } catch { }
    }
    return $false
}
# on the engine: public IPs blocked on any machine -> dist\guard-shared.json
#  - at most KeepHours hours and no longer than the original block duration (never permanent)
#  - a manual unblock (9016 reason=manual) also removes it from the shared list
function Publish-LBGuardShared {
    param([string]$InstallDir, $Findings, $Config, [int]$KeepHours = 24, [scriptblock]$Verify)
    $dist = Join-Path $InstallDir 'dist'
    if (-not (Test-Path $dist)) { return 0 }
    $f = Join-Path $dist 'guard-shared.json'
    $cur = @{}
    if (Test-Path $f) { try { (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cur[$_.Name] = ConvertTo-LBHash $_.Value } } catch { } }
    $now = Get-LBUtcNow
    $cap = $now.AddHours($KeepHours)
    if (-not $Verify) { $Verify = { param($ip, $machine) Test-LBGuardCorroboration -Config $Config -Ip $ip -Machine $machine } }
    $guard = @($Findings | Where-Object { $_.Category -eq 'Guard' -and $_.PSObject.Properties.Name -contains 'GuardIp' -and $_.GuardIp })
    foreach ($x in @($guard | Where-Object { $_.GuardAction -eq 'block' })) {
        $ip = ConvertTo-LBCleanIp $x.GuardIp
        if (-not $ip -or (Test-LBLocalIp $ip)) { continue }
        if ($x.GuardSource -notin 'RDP','Logon','Kerberos') { continue }       # only sources verifiable in Security
        if ($cur.ContainsKey($ip)) { continue }
        if (-not (& $Verify $ip ([string]$x.Machine))) { continue }
        $u = if ($x.GuardUntil -eq 'permanent') { $cap } else { ConvertTo-LBUtc $x.GuardUntil }
        if (-not $u -or $u -gt $cap) { $u = $cap }
        if ($u -le $now) { continue }
        $cur[$ip] = @{ until = (Get-LBIso $u); from = [string]$x.Machine; reason = [string]$x.GuardReason }
    }
    foreach ($x in @($guard | Where-Object { $_.GuardAction -eq 'unblock' -and $_.GuardReason -eq 'manual' })) {
        # only the machine that reported the block can remove it from the shared list
        $ip = ConvertTo-LBCleanIp $x.GuardIp
        if ($ip -and $cur.ContainsKey($ip) -and [string]$cur[$ip].from -eq [string]$x.Machine) { $cur.Remove($ip) }
    }
    foreach ($k in @($cur.Keys)) {
        $d = ConvertTo-LBUtc $cur[$k].until
        if (-not $d -or $d -le $now -or $d -gt $cap.AddHours(1)) { $cur.Remove($k) }
    }
    $o = [ordered]@{}; foreach ($k in ($cur.Keys | Sort-Object)) { $o[$k] = $cur[$k] }
    $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, ($o | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    Move-Item $tmp $f -Force
    return $o.Count
}
# on each machine: agents pull the shared list
function Update-LBGuardShared {
    param($Settings, $State, $Config, [string]$InstallDir)
    if (-not $Settings.ShareBlocks) { $State.shared = @{}; return }
    $src = $null
    $dist = Get-LBGuardDistDir -InstallDir $InstallDir -Config $Config
    if ($dist) { $src = Join-Path $dist 'guard-shared.json' }
    else { $sh = Get-LBGuardShareSource -Config $Config; if ($sh) { $src = Join-Path $sh 'guard-shared.json' } }
    if (-not $src -or -not (Test-Path $src)) { return }
    $now = Get-LBUtcNow
    foreach ($k in @($State.unshared.Keys)) { $d = ConvertTo-LBUtc $State.unshared[$k]; if (-not $d -or $d -le $now) { $State.unshared.Remove($k) } }
    try {
        $o = Get-Content $src -Raw -Encoding UTF8 | ConvertFrom-Json
        $new = @{}
        foreach ($p in $o.PSObject.Properties) {
            $ip = ConvertTo-LBCleanIp $p.Name
            if (-not $ip -or (Test-LBLocalIp $ip)) { continue }
            if ($State.unshared.ContainsKey($ip)) { continue }                   # released manually here
            $u = ConvertTo-LBUtc $p.Value.until
            if (-not $u -or $u -le $now -or $u -gt $now.AddHours(25)) { continue }   # never permanent/unbounded
            $new[$ip] = @{ until = (Get-LBIso $u); from = [string]$p.Value.from; reason = [string]$p.Value.reason }
        }
        $State.shared = $new
    } catch { }
}

# ---------------------------------------------------------------------------
#  firewall
# ---------------------------------------------------------------------------
# the desired set of addresses (blocks + blacklist + feed + shared), minus the whitelist
function Get-LBGuardDesired {
    param($State, $Settings, $WhiteEntries)
    $set = New-Object System.Collections.Generic.HashSet[string]
    $cands = @(@($State.blocks.Keys) + @($Settings.Blacklist) + @($State.blacklist) + @($State.feed))
    if ($Settings.ShareBlocks) { $cands += @($State.shared.Keys) }
    foreach ($x in $cands) {
        $e = ConvertTo-LBIpEntry ([string]$x)
        if (-not $e) { continue }
        # a whitelisted address is never blocked; a range/CIDR overlapping the internal network or the whitelist,
        # or larger than /8, is skipped (otherwise the management server/LAN would be locked out)
        if ($e.V6 -or $e.Lo -eq $e.Hi) {
            $ipTxt = if ($e.V6) { $e.V6 } else { $e.Text }
            if (Test-LBGuardWhitelisted -Ip $ipTxt -Settings $Settings -WhiteEntries $WhiteEntries) { continue }
        } elseif (($e.Hi - $e.Lo) -ge 16777216 -or (Test-LBRangeOverlap -Entry $e -Entries $WhiteEntries -Local:$Settings.AutoWhitelistLan)) { continue }
        [void]$set.Add($e.Text)
    }
    return (@($set) | Sort-Object)
}
function Get-LBChunkHash {
    param([string[]]$Items)
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Items -join ','))) } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($h) -replace '-', '').Substring(0, 16)
}
# firewall layer (NetSecurity; netsh as a fallback)
function Invoke-LBGuardFw {
    param([ValidateSet('List','ListAll','Set','Remove','Count')][string]$Op, [string]$Name, [string[]]$Addresses)
    if ($script:FwMock) { return (& $script:FwMock $Op $Name $Addresses) }
    $hasNs = [bool](Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)
    switch ($Op) {
        'List' {
            # a disabled or Allow rule counts as "missing" so it gets repaired
            if ($hasNs) { return @(Get-NetFirewallRule -Name "$($script:RulePrefix)*" -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Block' } | ForEach-Object { $_.Name }) }
            $out = @(); foreach ($l in (& netsh advfirewall firewall show rule name=all 2>$null)) { if ($l -match ('^\S.*?:\s+(' + [regex]::Escape($script:RulePrefix) + '\d+)\s*$')) { $out += $Matches[1] } }
            return $out
        }
        'Set' {
            if ($hasNs) {
                $r = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
                if ($r) { Set-NetFirewallRule -Name $Name -RemoteAddress $Addresses -Enabled True -Action Block -ErrorAction Stop }
                else {
                    New-NetFirewallRule -Name $Name -DisplayName $Name -Group 'LogBok Guard' -Description 'LogBok Login Guard — blocked attacker IPs (auto-managed)' `
                        -Direction Inbound -Action Block -Profile Any -RemoteAddress $Addresses -Enabled True -ErrorAction Stop | Out-Null
                }
                return $true
            }
            $list = $Addresses -join ','
            & netsh advfirewall firewall delete rule name="$Name" 2>$null | Out-Null
            & netsh advfirewall firewall add rule name="$Name" dir=in action=block remoteip="$list" enable=yes profile=any | Out-Null
            return ($LASTEXITCODE -eq 0)
        }
        'ListAll' {
            if ($hasNs) { return @(Get-NetFirewallRule -Name "$($script:RulePrefix)*" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
            return @(Invoke-LBGuardFw -Op List)
        }
        'Count' {
            # the rule's address count (to detect RemoteAddress tampering)
            if (-not $hasNs) { return -1 }
            try { $r = Get-NetFirewallRule -Name $Name -ErrorAction Stop; return @(($r | Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress).Count } catch { return -1 }
        }
        'Remove' {
            if ($hasNs) { Remove-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue; return $true }
            & netsh advfirewall firewall delete rule name="$Name" 2>$null | Out-Null; return $true
        }
    }
}
# reconcile the rules with the desired set; returns a summary
function Sync-LBGuardRules {
    param($State, $Settings, $WhiteEntries, [switch]$Force, [switch]$Deep)
    $desired = @(Get-LBGuardDesired -State $State -Settings $Settings -WhiteEntries $WhiteEntries)
    $chunks = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $desired.Count; $i += $script:ChunkSize) {
        [void]$chunks.Add(@($desired[$i..([math]::Min($i + $script:ChunkSize, $desired.Count) - 1)]))
    }
    $existing = @(Invoke-LBGuardFw -Op List)
    $missing = 0; $updated = 0; $removed = 0
    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $name = $script:RulePrefix + ($i + 1)
        $h = Get-LBChunkHash -Items $chunks[$i]
        $exists = $existing -contains $name
        if (-not $exists -and $State.ruleHashes.ContainsKey($name)) { $missing++ }
        $tampered = $false
        if ($Deep -and $exists -and $State.ruleHashes[$name] -eq $h) {
            $cnt = Invoke-LBGuardFw -Op Count -Name $name
            if ($cnt -ge 0 -and $cnt -ne @($chunks[$i]).Count) { $tampered = $true; $missing++ }
        }
        if ($Force -or $tampered -or -not $exists -or $State.ruleHashes[$name] -ne $h) {
            $ok = $false
            try { $ok = [bool](Invoke-LBGuardFw -Op Set -Name $name -Addresses $chunks[$i]) } catch { $ok = $false }
            if ($ok) { $State.ruleHashes[$name] = $h; $updated++ }
        }
    }
    $all = @(Invoke-LBGuardFw -Op ListAll)
    foreach ($n in @(@($existing) + @($all) + @($State.ruleHashes.Keys) | Select-Object -Unique)) {
        if ($n -notlike "$($script:RulePrefix)*") { continue }
        $idx = 0; [void][int]::TryParse($n.Substring($script:RulePrefix.Length), [ref]$idx)
        if ($idx -gt $chunks.Count -or $idx -lt 1) {
            [void](Invoke-LBGuardFw -Op Remove -Name $n); if ($State.ruleHashes.ContainsKey($n)) { $State.ruleHashes.Remove($n) }; $removed++
        }
    }
    $State.meta.lastSync = Get-LBIso (Get-LBUtcNow)
    return [pscustomobject]@{ Addresses = $desired.Count; Rules = $chunks.Count; Updated = $updated; Removed = $removed; Missing = $missing }
}
# remove all guard rules (agent uninstall)
function Remove-LBGuardRules {
    foreach ($n in @(Invoke-LBGuardFw -Op ListAll)) { [void](Invoke-LBGuardFw -Op Remove -Name $n) }
}

# ---------------------------------------------------------------------------
#  events (9015 block, 9016 unblock, 9001 tamper)
# ---------------------------------------------------------------------------
$script:EventSink = $null   # tests only
function Write-LBGuardEvent {
    param([int]$Id, [string]$Type, [string]$Message)
    if ($script:EventSink) { & $script:EventSink $Id $Type $Message; return }
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch { }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId $Id -EntryType $Type -Message $Message } catch { }
}
function Format-LBGuardBlockMessage {
    param([string]$Ip, $Block)
    return ("GUARD BLOCK on {0}: ip={1} country={2} reason={3} source={4} attempts={5} users={6} until={7} count={8}" -f `
        $env:COMPUTERNAME, $Ip, $(if ($Block.country) { $Block.country } else { '-' }), $Block.reason, $(if ($Block.source) { $Block.source } else { '-' }),
        [int]$Block.attempts, $(if ($Block.users) { ($Block.users -replace '\s', '') } else { '-' }), $Block.until, [int]$Block.count)
}

# ---------------------------------------------------------------------------
#  main entry (Run-Guard.ps1)
# ---------------------------------------------------------------------------
function Invoke-LBGuard {
    param($Config, [string]$InstallDir, [switch]$Housekeeping, [int]$MaxLoops = 3)
    $S = Get-LBGuardSettings -Config $Config
    $stateDir = Get-LBGuardStateDir -Config $Config -InstallDir $InstallDir
    # downloads (geo/feed) outside the lock so the console does not wait
    $pre = Get-LBGuardState -StateDir $stateDir
    $preHk = ConvertTo-LBUtc $pre.meta.lastHk
    if ($Housekeeping -or -not $preHk -or $preHk -lt (Get-LBUtcNow).AddMinutes(-4)) {
        if ($S.GeoMode -ne 'Off') { try { [void](Update-LBGuardGeo -Settings $S -StateDir $stateDir -InstallDir $InstallDir -Config $Config) } catch { } }
        try { [void](Update-LBGuardFeed -Settings $S -StateDir $stateDir) } catch { }
    }
    $lock = Enter-LBGuardLock
    if (-not $lock) { return [pscustomobject]@{ Blocked = 0; Unblocked = 0; Housekeeping = $false; Rules = $null; Skipped = $true } }
    try {
    $st = Get-LBGuardState -StateDir $stateDir
    $now = Get-LBUtcNow
    $white = Get-LBGuardWhitelist -Settings $S -State $st
    $hk = $Housekeeping -or -not (ConvertTo-LBUtc $st.meta.lastHk) -or ((ConvertTo-LBUtc $st.meta.lastHk) -lt $now.AddMinutes(-4))
    $blocked = New-Object System.Collections.ArrayList
    $unblocked = @()

    # the country database is loaded only when needed
    $geoBin = Join-Path $stateDir 'guard-geo.bin'
    if ($S.GeoMode -ne 'Off' -or (Test-Path $geoBin)) { [void](Import-LBGuardGeo -BinPath $geoBin) }
    $countryOf = { param($ip) Get-LBGuardCountry $ip }

    # 1) new events (up to 3 rounds, if fresh events arrive while running)
    for ($loop = 0; $loop -lt $MaxLoops; $loop++) {
        $atts = @(Get-LBGuardAttempts -State $st -Settings $S)
        if ($hk -and $loop -eq 0) { $atts += @(Get-LBGuardLogAttempts -State $st -Settings $S) }
        if ($atts.Count -eq 0) { break }
        foreach ($a in $atts) {
            $b = Add-LBGuardAttempt -State $st -Settings $S -Attempt $a -WhiteEntries $white -CountryOf $countryOf -NowUtc (Get-LBUtcNow)
            if ($b) { [void]$blocked.Add(@{ Ip = (ConvertTo-LBCleanIp $a.Ip); Block = $b }) }
        }
        if ($blocked.Count -gt 0) {
            # apply the block immediately (before the next round)
            try { [void](Sync-LBGuardRules -State $st -Settings $S -WhiteEntries $white) } catch { }
        }
    }

    # 2) periodic housekeeping
    $summary = $null
    if ($hk) {
        $unblocked = @(Invoke-LBGuardExpire -State $st -Settings $S -NowUtc (Get-LBUtcNow))
        $st.feed = @(Get-LBGuardFeedList -Settings $S -StateDir $stateDir)
        try { Update-LBGuardShared -Settings $S -State $st -Config $Config -InstallDir $InstallDir } catch { }
        $st.meta.lastHk = Get-LBIso (Get-LBUtcNow)
    }
    # 3) reconcile/check rules (a deleted rule -> rebuild + tamper alert)
    try {
        $summary = Sync-LBGuardRules -State $st -Settings $S -WhiteEntries $white -Deep:$hk
        if ($summary.Missing -gt 0) {
            Write-LBGuardEvent -Id 9001 -Type Warning -Message ("Tamper/repair on {0}: LogBok Guard firewall rule(s) were deleted, disabled or edited — {1} rule(s) restored" -f $env:COMPUTERNAME, $summary.Missing)
        }
    } catch { }

    foreach ($x in $blocked) {
        $type = if ($x.Block.until -eq 'permanent') { 'Error' } else { 'Warning' }
        Write-LBGuardEvent -Id 9015 -Type $type -Message (Format-LBGuardBlockMessage -Ip $x.Ip -Block $x.Block)
    }
    foreach ($u in $unblocked) {
        Write-LBGuardEvent -Id 9016 -Type Information -Message ("GUARD UNBLOCK on {0}: ip={1} reason=expired" -f $env:COMPUTERNAME, $u.Ip)
    }
    $st.meta.lastRun = Get-LBIso (Get-LBUtcNow)
    Save-LBGuardState -StateDir $stateDir -State $st
    return [pscustomobject]@{ Blocked = $blocked.Count; Unblocked = $unblocked.Count; Housekeeping = [bool]$hk; Rules = $summary }
    } finally { Exit-LBGuardLock $lock }
}

# ---------------------------------------------------------------------------
#  admin operations (console)
# ---------------------------------------------------------------------------
function Get-LBGuardContext {
    param([string]$InstallDir)
    $cfg = @{}
    try { $cfg = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1') } catch { }
    $stateDir = Get-LBGuardStateDir -Config $cfg -InstallDir $InstallDir
    $S = Get-LBGuardSettings -Config $cfg
    $st = Get-LBGuardState -StateDir $stateDir
    return @{ Config = $cfg; Settings = $S; State = $st; StateDir = $stateDir; White = (Get-LBGuardWhitelist -Settings $S -State $st) }
}
function Get-LBGuardBlocks {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    $c = Get-LBGuardContext -InstallDir $InstallDir
    foreach ($ip in ($c.State.blocks.Keys | Sort-Object)) {
        $b = $c.State.blocks[$ip]
        [pscustomobject]@{ Ip = $ip; Country = $b.country; Reason = $b.reason; Source = $b.source; Since = $b.since; Until = $b.until; Count = $b.count; Users = $b.users }
    }
}
function Add-LBGuardManualBlock {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [Parameter(Mandatory)][string]$Ip, [int]$Minutes = 0)
    $clean = ConvertTo-LBCleanIp $Ip
    if (-not $clean) { throw "Invalid IP: $Ip" }
    $lock = Enter-LBGuardLock
    if (-not $lock) { throw 'Guard is busy (another run holds the lock) — retry in a minute | سپر مشغول است؛ یک دقیقهٔ دیگر دوباره امتحان کنید' }
    try {
        $c = Get-LBGuardContext -InstallDir $InstallDir
        if (Test-LBGuardWhitelisted -Ip $clean -Settings $c.Settings -WhiteEntries $c.White) { throw "IP is whitelisted (LAN/whitelist): $clean" }
        $b = if ($Minutes -gt 0) { Set-LBGuardBlock -State $c.State -Settings $c.Settings -Ip $clean -Reason 'manual' -Source 'Console' -Minutes $Minutes -Manual }
             else { Set-LBGuardBlock -State $c.State -Settings $c.Settings -Ip $clean -Reason 'manual' -Source 'Console' -Permanent -Manual }
        if ($c.State.unshared.ContainsKey($clean)) { $c.State.unshared.Remove($clean) }
        $r = Sync-LBGuardRules -State $c.State -Settings $c.Settings -WhiteEntries $c.White
        Save-LBGuardState -StateDir $c.StateDir -State $c.State
    } finally { Exit-LBGuardLock $lock }
    Write-LBGuardEvent -Id 9015 -Type Warning -Message (Format-LBGuardBlockMessage -Ip $clean -Block $b)
    return $r
}
function Remove-LBGuardBlocks {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [Parameter(Mandatory)][string[]]$Ip, [switch]$ResetHistory)
    $n = 0
    $lock = Enter-LBGuardLock
    if (-not $lock) { throw 'Guard is busy (another run holds the lock) — retry in a minute | سپر مشغول است؛ یک دقیقهٔ دیگر دوباره امتحان کنید' }
    try {
        $c = Get-LBGuardContext -InstallDir $InstallDir
        $until = Get-LBIso ((Get-LBUtcNow).AddHours(25))
        foreach ($x in $Ip) {
            $clean = ConvertTo-LBCleanIp $x; if (-not $clean) { continue }
            $was = $false
            if ($c.State.blocks.ContainsKey($clean)) { $c.State.blocks.Remove($clean); $was = $true }
            if ($c.State.shared.ContainsKey($clean)) { $c.State.shared.Remove($clean); $was = $true }
            $c.State.unshared[$clean] = $until                   # so the server's shared list does not re-block it
            if ($c.State.attempts.ContainsKey($clean)) { $c.State.attempts.Remove($clean) }
            if ($ResetHistory -and $c.State.history.ContainsKey($clean)) { $c.State.history.Remove($clean) }
            $c.State.blacklist = @($c.State.blacklist | Where-Object { $_ -ne $clean })
            if ($was) { $n++; Write-LBGuardEvent -Id 9016 -Type Information -Message ("GUARD UNBLOCK on {0}: ip={1} reason=manual" -f $env:COMPUTERNAME, $clean) }
        }
        [void](Sync-LBGuardRules -State $c.State -Settings $c.Settings -WhiteEntries $c.White)
        Save-LBGuardState -StateDir $c.StateDir -State $c.State
    } finally { Exit-LBGuardLock $lock }
    return $n
}
function Add-LBGuardListEntry {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [ValidateSet('whitelist','blacklist')][string]$List, [Parameter(Mandatory)][string]$Entry)
    $e = ConvertTo-LBIpEntry $Entry
    if (-not $e) { throw "Invalid IP / CIDR / range: $Entry" }
    if ($List -eq 'blacklist' -and $null -ne $e.Lo -and (($e.Hi - $e.Lo) -ge 16777216 -or (Test-LBRangeOverlap -Entry $e -Local))) {
        throw "Range too large or overlaps the internal network: $($e.Text)"
    }
    $lock = Enter-LBGuardLock
    if (-not $lock) { throw 'Guard is busy (another run holds the lock) — retry in a minute | سپر مشغول است؛ یک دقیقهٔ دیگر دوباره امتحان کنید' }
    try {
        $c = Get-LBGuardContext -InstallDir $InstallDir
        $c.State[$List] = @(@($c.State[$List]) + $e.Text | Select-Object -Unique)
        if ($List -eq 'whitelist') {
            # blocked IPs that are now whitelisted get released
            foreach ($ip in @($c.State.blocks.Keys)) { if (Test-LBIpInEntries -Ip $ip -Entries @($e)) { $c.State.blocks.Remove($ip) } }
        }
        $c.White = Get-LBGuardWhitelist -Settings $c.Settings -State $c.State
        [void](Sync-LBGuardRules -State $c.State -Settings $c.Settings -WhiteEntries $c.White)
        Save-LBGuardState -StateDir $c.StateDir -State $c.State
    } finally { Exit-LBGuardLock $lock }
    return $e.Text
}
function Remove-LBGuardListEntry {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [ValidateSet('whitelist','blacklist')][string]$List, [Parameter(Mandatory)][string]$Entry)
    $e = ConvertTo-LBIpEntry $Entry
    $txt = if ($e) { $e.Text } else { $Entry.Trim() }
    $lock = Enter-LBGuardLock
    if (-not $lock) { throw 'Guard is busy (another run holds the lock) — retry in a minute | سپر مشغول است؛ یک دقیقهٔ دیگر دوباره امتحان کنید' }
    try {
        $c = Get-LBGuardContext -InstallDir $InstallDir
        $c.State[$List] = @(@($c.State[$List]) | Where-Object { $_ -ne $txt })
        $c.White = Get-LBGuardWhitelist -Settings $c.Settings -State $c.State
        [void](Sync-LBGuardRules -State $c.State -Settings $c.Settings -WhiteEntries $c.White)
        Save-LBGuardState -StateDir $c.StateDir -State $c.State
    } finally { Exit-LBGuardLock $lock }
}
function Get-LBGuardStatus {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    $c = Get-LBGuardContext -InstallDir $InstallDir
    $perm = @($c.State.blocks.Values | Where-Object { $_.until -eq 'permanent' }).Count
    [pscustomobject]@{
        Host = $env:COMPUTERNAME
        Blocked = $c.State.blocks.Count; Permanent = $perm
        Watching = $c.State.attempts.Count
        LocalWhitelist = (@($c.State.whitelist) -join ', '); LocalBlacklist = (@($c.State.blacklist) -join ', ')
        FeedIps = @($c.State.feed).Count; SharedIps = @($c.State.shared.Keys).Count
        Rules = @(Invoke-LBGuardFw -Op List).Count
        GeoMode = $c.Settings.GeoMode; GeoDb = (Test-Path (Join-Path $c.StateDir 'guard-geo.bin'))
        WorkHours = $(if ($c.Settings.WorkHoursEnabled) { "$($c.Settings.WorkStart)-$($c.Settings.WorkEnd)" } else { 'off' })
        LastRun = $c.State.meta.lastRun; LastSync = $c.State.meta.lastSync
    }
}

# ---------------------------------------------------------------------------
#  event-trigger subscriptions for the scheduled task
# ---------------------------------------------------------------------------
function Test-LBEventChannel {
    param([string]$Name)
    try { return [bool](Get-WinEvent -ListLog $Name -ErrorAction Stop) } catch { return $false }
}
function Get-LBGuardSubscriptions {
    param($Config, [switch]$SkipChannelCheck)
    $S = Get-LBGuardSettings -Config $Config
    $subs = New-Object System.Collections.ArrayList
    function _q($path, $xpath) { "<QueryList><Query Id=`"0`" Path=`"$path`"><Select Path=`"$path`">$xpath</Select></Query></QueryList>" }
    if ($S.ProtectRDP -or $S.ProtectWindowsLogon) { [void]$subs.Add((_q 'Security' '*[System[(EventID=4625 or EventID=4771)]]')) }
    if ($S.WorkHoursEnabled) { [void]$subs.Add((_q 'Security' "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]")) }
    if ($S.ProtectSQL) { [void]$subs.Add((_q 'Application' '*[System[(EventID=18456)]]')) }
    $opt = @()
    if ($S.ProtectRDP) { $opt += @{ P = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; X = '*[System[(EventID=140)]]' } }
    if ($S.ProtectSSH) { $opt += @{ P = 'OpenSSH/Operational'; X = '*[System[(EventID=4)]]' } }
    # firewall rule deletion (2006/2033 old, 2052 new) -> immediate rebuild
    $opt += @{ P = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; X = '*[System[(EventID=2006 or EventID=2033 or EventID=2052)]]' }
    foreach ($o in $opt) { if ($SkipChannelCheck -or (Test-LBEventChannel $o.P)) { [void]$subs.Add((_q $o.P $o.X)) } }
    return $subs.ToArray()
}

Export-ModuleMember -Function Get-LBGuardStateDir, Enter-LBGuardLock, Exit-LBGuardLock, Test-LBRangeOverlap, Test-LBGuardCorroboration, Get-LBGuardXPath, Get-LBGuardSettings, ConvertTo-LBCleanIp, ConvertTo-LBIpEntry, ConvertTo-LBIpEntries, Test-LBIpInEntries, Test-LBLocalIp, `
    Get-LBGuardState, Save-LBGuardState, Test-LBWorkHours, Get-LBMinutesToWorkStart, Get-LBBlockMinutes, Get-LBGuardWhitelist, Test-LBGuardWhitelisted, Test-LBGeoBlock, `
    Set-LBGuardBlock, Add-LBGuardAttempt, Invoke-LBGuardExpire, ConvertFrom-LBGuardEvent, Get-LBGuardAttempts, Read-LBGuardW3C, Get-LBGuardLogAttempts, `
    ConvertTo-LBGeoBin, Import-LBGuardGeo, Get-LBGuardCountry, Update-LBGuardGeo, ConvertFrom-LBFeedText, Update-LBGuardFeed, Get-LBGuardFeedList, `
    Publish-LBGuardShared, Update-LBGuardShared, Get-LBGuardDesired, Sync-LBGuardRules, Remove-LBGuardRules, Invoke-LBGuardFw, `
    Format-LBGuardBlockMessage, Invoke-LBGuard, Get-LBGuardBlocks, Add-LBGuardManualBlock, Remove-LBGuardBlocks, Add-LBGuardListEntry, `
    Remove-LBGuardListEntry, Get-LBGuardStatus, Get-LBGuardSubscriptions, ConvertFrom-LBIpNumber
