# ==========================================================================
#  LogBok.Connect.psm1 - connectivity to target hosts + fault diagnostics + protecting LogBok's own management path
#  Connectivity to target machines/services, failure diagnosis, and
#  self-protection so LogBok never cuts its own management/collection path
#  when it enables, resets or isolates the firewall.
#
#  two jobs:
#   1) Test-LBConnectivity : for each target and channel (DNS, port, WinRM, remote
#      event read, WEF) runs a probe and, on failure, reports where it broke with
#      a reason and a remedy, and writes the status to state\connectivity.json.
#   2) Assert-LBMgmtAllow : "always-open" rules for the management/collection path
#      (WinRM, admin RDP, WEF); called before the firewall is enabled/reset
#      and the login guard (Guard) never blocks these IPs.
# ==========================================================================

$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:MgmtPrefix = 'LogBok-Mgmt-Allow-'

# ---------------------------------------------------------------------------
#  settings
# ---------------------------------------------------------------------------
function Get-LBMgmtSettings {
    param($Config)
    $m = if ($Config -and $Config.Management) { $Config.Management } else { @{} }
    function _v($v,$d){ if ($null -eq $v -or "$v" -eq '') { return $d } else { return $v } }
    [pscustomobject]@{
        ProtectSelf  = ($m.ProtectSelf -ne $false)
        AdminIPs     = @($m.AdminIPs | Where-Object { $_ })
        AllowRDP     = ($m.AllowRDP   -ne $false)
        AllowWinRM   = ($m.AllowWinRM -ne $false)
        AllowWEF     = ($m.AllowWEF   -ne $false)
        AllowSMB     = ($m.AllowSMB   -eq $true)
        ExtraPorts   = @($m.ExtraPorts | Where-Object { $_ })
        AllowFromLan = ($m.AllowFromLan -ne $false)
        Collector    = [string](_v $Config.CollectorFqdn '')
        WebLan       = ($Config.Web -and [string]$Config.Web.Listen -eq 'lan' -and $Config.Web.Enabled -ne $false)
        WebPort      = [int]$(if ($Config.Web -and $Config.Web.Port) { $Config.Web.Port } else { 8686 })
        AgentIn      = ((Test-Path (Join-Path (Split-Path -Parent $PSCommandPath) 'engine.flag')) -and -not ($Config.Jobs -and $Config.Jobs.AgentIn -eq $false))
        AgentInPort  = [int]$(if ($Config.Agent -and $Config.Agent.IngestPort) { $Config.Agent.IngestPort } else { 8687 })
    }
}
function Get-LBConnSettings {
    param($Config)
    $c = if ($Config -and $Config.Connectivity) { $Config.Connectivity } else { @{} }
    [pscustomobject]@{
        Enabled   = ($c.Enabled -ne $false)
        Targets   = @($c.Targets | Where-Object { $_ })
        TimeoutMs = [int]$(if ($c.TimeoutMs) { $c.TimeoutMs } else { 2500 })
    }
}

# RemoteAddress for the management rules: admin IPs, else LocalSubnet (conservative to avoid lockout)
function Get-LBMgmtRemote {
    param($S)
    if (@($S.AdminIPs).Count -gt 0) { return @($S.AdminIPs) }
    if ($S.AllowFromLan) { return @('LocalSubnet') }
    return @('Any')
}

# the "always-open" rules that must exist | desired management allow-rules
function Get-LBMgmtAllowRules {
    param($S)
    $remote = Get-LBMgmtRemote -S $S
    $rules = New-Object System.Collections.ArrayList
    if ($S.AllowWinRM) { [void]$rules.Add(@{ Name='WinRM';  Port='5985,5986'; Remote=$remote }) }   # management + WEF
    if ($S.AllowRDP)   { [void]$rules.Add(@{ Name='RDP';    Port='3389';      Remote=$remote }) }
    if ($S.AllowWEF)   { [void]$rules.Add(@{ Name='WEF';    Port='5985';      Remote=@('LocalSubnet') }) }  # event push from clients
    if ($S.AllowSMB)   { [void]$rules.Add(@{ Name='SMB';    Port='445';       Remote=$remote }) }
    if (@($S.ExtraPorts).Count) { [void]$rules.Add(@{ Name='Extra'; Port=(@($S.ExtraPorts) -join ','); Remote=$remote }) }
    if ($S.WebLan) { [void]$rules.Add(@{ Name='Web'; Port=[string]$S.WebPort; Remote=$remote }) }
    # agent event push (HMAC-signed; from any network)
    if ($S.AgentIn) { [void]$rules.Add(@{ Name='AgentIn'; Port=[string]$S.AgentInPort; Remote=@('Any') }) }
    return $rules.ToArray()
}

# IPs the login guard must never block
function Get-LBMgmtWhitelistIps {
    param($S)
    $ips = @($S.AdminIPs)
    if ($S.Collector) { try { foreach ($a in [Net.Dns]::GetHostAddresses($S.Collector)) { $ips += $a.ToString() } } catch { } }
    return @($ips | Where-Object { $_ } | Select-Object -Unique)
}

# ---------------------------------------------------------------------------
#  assert management allow-rules
#  idempotent: left alone if present, created if missing.
#  called before the firewall is enabled/reset so the management path stays up.
# ---------------------------------------------------------------------------
function Assert-LBMgmtAllow {
    param($Config, [string]$InstallDir = 'C:\Scripts\LogBok')
    if (-not $Config) { try { $Config = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1') } catch { $Config = @{} } }
    $S = Get-LBMgmtSettings -Config $Config
    if (-not $S.ProtectSelf) { return 0 }
    $hasNs = [bool](Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)
    $n = 0
    foreach ($r in (Get-LBMgmtAllowRules -S $S)) {
        $name = $script:MgmtPrefix + $r.Name
        $ports = $r.Port
        $remote = @($r.Remote)
        try {
            if ($hasNs) {
                $ex = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
                if ($ex) {
                    Set-NetFirewallRule -Name $name -Enabled True -Action Allow -ErrorAction SilentlyContinue
                    Set-NetFirewallRule -Name $name -RemoteAddress $remote -ErrorAction SilentlyContinue
                } else {
                    New-NetFirewallRule -Name $name -DisplayName $name -Group 'LogBok Management' `
                        -Description 'LogBok keeps its own management/collection path open (auto-managed; do not delete)' `
                        -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort ($ports -split ',') `
                        -RemoteAddress $remote -Enabled True -ErrorAction Stop | Out-Null
                    $n++
                }
            } else {
                $list = ($remote -join ',')
                & netsh advfirewall firewall delete rule name="$name" 2>$null | Out-Null
                & netsh advfirewall firewall add rule name="$name" dir=in action=allow protocol=TCP localport="$ports" remoteip="$list" enable=yes profile=any | Out-Null
                if ($LASTEXITCODE -eq 0) { $n++ }
            }
        } catch { }
    }
    return $n
}

# report which management allow-rules are present (for diagnostics and the dashboard)
function Test-LBMgmtAllow {
    param($Config, [string]$InstallDir = 'C:\Scripts\LogBok')
    if (-not $Config) { try { $Config = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1') } catch { $Config = @{} } }
    $S = Get-LBMgmtSettings -Config $Config
    $hasNs = [bool](Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)
    $out = @()
    foreach ($r in (Get-LBMgmtAllowRules -S $S)) {
        $name = $script:MgmtPrefix + $r.Name
        $present = $false; $enabled = $false
        if ($hasNs) {
            $ex = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            if ($ex) { $present = $true; $enabled = ([string]$ex.Enabled -eq 'True' -and [string]$ex.Action -eq 'Allow') }
        } else {
            $present = [bool]((& netsh advfirewall firewall show rule name="$name" 2>$null) -match 'Rule Name|نام قاعده'); $enabled = $present
        }
        $out += [pscustomobject]@{ Name=$r.Name; Rule=$name; Ports=$r.Port; Remote=(@($r.Remote) -join ','); Present=$present; Enabled=$enabled }
    }
    return $out
}

# ---------------------------------------------------------------------------
#  connectivity diagnostics
# ---------------------------------------------------------------------------
# one channel result
function New-LBConn {
    param([string]$Target,[string]$Channel,[bool]$Ok,[int]$Ms,[string]$Detail,[string]$Reason,[string]$Remedy,[string]$State='')
    if (-not $State) { $State = if ($Ok) { 'OK' } else { 'Fail' } }
    [pscustomobject]@{ Target=$Target; Channel=$Channel; Ok=$Ok; State=$State; Ms=$Ms; Detail=$Detail; Reason=$Reason; Remedy=$Remedy }
}

# TCP port probe with timeout -> @{Ok;Ms}
function Test-LBTcpPort {
    param([string]$HostName,[int]$Port,[int]$TimeoutMs=2500)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return @{ Ok=$false; Ms=[int]$sw.ElapsedMilliseconds; Err='timeout' } }
        $client.EndConnect($iar)
        return @{ Ok=$true; Ms=[int]$sw.ElapsedMilliseconds; Err='' }
    } catch {
        return @{ Ok=$false; Ms=[int]$sw.ElapsedMilliseconds; Err=$_.Exception.InnerException.Message }
    } finally { try { $client.Close() } catch { } }
}

# is the target the local machine?
function Test-LBIsSelf {
    param([string]$Target)
    $t = ([string]$Target).Trim()
    if (-not $t) { return $true }
    if ($t -in 'localhost','127.0.0.1','::1',$env:COMPUTERNAME) { return $true }
    try { if ($t -eq [Net.Dns]::GetHostName()) { return $true } } catch { }
    return $false
}

# --- learned on/off pattern per agent computer (state\agent-presence.json) ---------------------
#  For every hour of the week we count how often the computer was seen online at that hour.
function Update-LBPresence {
    param([string]$StateDir, [string]$HostName, [bool]$Online, $LastSeen)
    $f = Join-Path $StateDir 'agent-presence.json'
    $all = @{}
    try { if (Test-Path $f) { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($p in $j.PSObject.Properties) { $all[$p.Name] = $p.Value } } } catch { }
    $now = Get-Date
    $slot = [int]$now.DayOfWeek * 24 + $now.Hour
    $h = $all[$HostName]
    if (-not $h) { $h = [pscustomobject]@{ On = @(0) * 168; Obs = @(0) * 168; Since = $now.ToString('o', $script:Inv); LastSlotAt = '' } }
    $on = @($h.On); $obs = @($h.Obs); if ($on.Count -ne 168) { $on = @(0) * 168 }; if ($obs.Count -ne 168) { $obs = @(0) * 168 }
    # one observation per computer per clock hour
    $stamp = $now.ToString('yyyy-MM-dd HH')
    if ([string]$h.LastSlotAt -ne $stamp) {
        $obs[$slot] = [int]$obs[$slot] + 1
        $wasOn = $Online
        if (-not $wasOn -and $LastSeen) { try { $wasOn = ($LastSeen.ToLocalTime().ToString('yyyy-MM-dd HH') -eq $stamp) } catch { } }
        if ($wasOn) { $on[$slot] = [int]$on[$slot] + 1 }
        $h = [pscustomobject]@{ On = $on; Obs = $obs; Since = [string]$h.Since; LastSlotAt = $stamp }
        $all[$HostName] = $h
        try { $o = [ordered]@{}; foreach ($k in ($all.Keys | Sort-Object)) { $o[$k] = $all[$k] }; [IO.File]::WriteAllText($f, ($o | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding($false))) } catch { }
    }
    # learned once this hour-of-week was observed at least twice (two weeks), or the computer was watched for 7+ days
    $days = 0; try { $days = ($now - [datetime]::Parse([string]$h.Since, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind)).TotalDays } catch { }
    $n = [int]$obs[$slot]; $ratio = if ($n -gt 0) { [double]$on[$slot] / $n } else { 1.0 }
    $learned = ($n -ge 2) -or ($days -ge 7 -and $n -ge 1)
    # a short human summary: the hours of a weekday it is usually on
    $pattern = ''
    if ($days -ge 2) {
        $hrs = @(); for ($hh = 0; $hh -lt 24; $hh++) { $t = 0; $c = 0; for ($d = 0; $d -lt 7; $d++) { $t += [int]$on[$d * 24 + $hh]; $c += [int]$obs[$d * 24 + $hh] }; if ($c -gt 0 -and ($t / $c) -ge 0.5) { $hrs += $hh } }
        if ($hrs.Count -and $hrs.Count -lt 24) { $pattern = ('معمولاً روشن | usually on {0:00}:00-{1:00}:59' -f $hrs[0], $hrs[-1]) }
    }
    return [pscustomobject]@{ Learned = $learned; OnRatio = $ratio; OffNormalNow = ($learned -and $ratio -lt 0.25); Pattern = $pattern }
}

# which channels to probe per target (based on its role in config)
function Get-LBConnTargets {
    param($Config)
    $S = Get-LBConnSettings -Config $Config
    $mode = [string]$Config.CollectionMode
    $map = [ordered]@{}
    $remoteOk = $false; try { $remoteOk = Test-LBRemoteAccessAllowed -Config $Config } catch { }
    function _add($name,$ch){ $k=[string]$name; if (-not $k) { return }; if (-not $map.Contains($k)) { $map[$k]=New-Object System.Collections.Generic.HashSet[string] }; [void]$map[$k].Add($ch) }
    # always: the engine host itself
    _add $env:COMPUTERNAME 'self'
    # remote channels (RPC 135 / WinRM 5985) only when remote access was explicitly switched on;
    # otherwise every Windows computer is reached through the LogBok agent channel only
    if ($remoteOk) {
        if ($S.Targets.Count) { foreach ($t in $S.Targets) { _add $t 'eventlog'; _add $t 'winrm' } }
        if ($mode -eq 'Remote') { foreach ($t in @($Config.Machines)) { _add $t 'eventlog'; _add $t 'winrm' } }
        if ($mode -eq 'Collector' -and $Config.CollectorFqdn) { _add $Config.CollectorFqdn 'winrm' }
    } else {
        if ($S.Targets.Count) { foreach ($t in $S.Targets) { _add $t 'agent-push' } }
        if ($mode -eq 'Remote') { foreach ($t in @($Config.Machines)) { _add $t 'agent-push' } }
    }
    foreach ($t in @($Config.SqlServers)) { if (-not (Test-LBIsSelf $t)) { _add $t 'sql' } }
    foreach ($t in @($Config.IISServers)) { if (-not (Test-LBIsSelf $t)) { _add $t 'http' } }
    foreach ($t in @($Config.FtpServers)) { if (-not (Test-LBIsSelf $t)) { _add $t 'ftp' } }
    # sources registered from the console/web (with type, role and port)
    $meta = @{}
    $reg = @()
    try { if (Get-Command Get-LBTargetList -ErrorAction SilentlyContinue) { $reg = @(Get-LBTargetList -StateDir (Get-LBStateDir -Config $Config)) } } catch { }
    foreach ($r in @($reg | Where-Object { $_.Enabled -ne $false })) {
        $addr = if ($r.Address) { [string]$r.Address } else { [string]$r.Name }
        $roles = @($r.Roles | Where-Object { $_ })
        if ((Test-LBIsSelf $addr) -and [string]$r.Kind -eq 'Windows') { continue }   # the engine host is probed separately
        switch ([string]$r.Kind) {
            'Windows' {
                if ($r.Monitor -eq 'agent' -or ($r.Monitor -ne 'none' -and -not $remoteOk)) { _add $addr 'agent-push' }
                elseif ($r.Monitor -ne 'none') { _add $addr 'eventlog'; _add $addr 'winrm' }
                if ($roles -contains 'DC')   { _add $addr 'ldap'; _add $addr 'kerberos'; _add $addr 'dnsport' }
                if ($roles -contains 'SQL')  { _add $addr 'sql' }
                if ($roles -contains 'IIS')  { _add $addr 'http'; if ($remoteOk) { _add $addr 'smb' } }
                if ($roles -contains 'FTP')  { _add $addr 'ftp'; if ($remoteOk) { _add $addr 'smb' } }
                if ($remoteOk -and ($roles -contains 'DHCP' -or $roles -contains 'Apache')) { _add $addr 'smb' }
                if ($remoteOk -and @($r.Custom | Where-Object { $_ -and $_.Type -eq 'File' }).Count) { _add $addr 'smb' }
            }
            'NetworkDevice' { _add $addr 'syslog-in' }
            'Linux'         { _add $addr 'ssh' }
            default         { _add $addr 'ping-only' }
        }
        foreach ($pt in @($r.Ports | Where-Object { $_ })) { _add $addr ("tcp:{0}" -f [int]$pt) }
        $meta[$addr] = @{ Name=[string]$r.Name; Kind=[string]$r.Kind; Roles=$roles; DeviceType=[string]$r.DeviceType }
    }
    if (@($reg | Where-Object { $_.Kind -eq 'NetworkDevice' -and $_.Enabled -ne $false }).Count) { _add $env:COMPUTERNAME 'syslog-listener' }
    $out = @()
    foreach ($k in $map.Keys) {
        $m = $meta[$k]
        $out += [pscustomobject]@{ Target=$k; Channels=@($map[$k]); Name=$(if ($m) { $m.Name } else { $k }); Kind=$(if ($m) { $m.Kind } elseif (Test-LBIsSelf $k) { 'Server' } else { 'Windows' }); Roles=$(if ($m) { @($m.Roles) } else { @() }); DeviceType=$(if ($m) { $m.DeviceType } else { '' }) }
    }
    return $out
}

# full diagnosis of one target -> list of channel results
function Test-LBConnTarget {
    param([string]$Target,[string[]]$Channels,[int]$TimeoutMs=2500,$Config)
    $res = New-Object System.Collections.ArrayList
    $isSelf = Test-LBIsSelf $Target

    if ($isSelf -and -not ($Channels -contains 'self')) {
        # a service/device on this machine: probe its ports only
        foreach ($ch in $Channels) {
            if ($ch -notlike 'tcp:*') { continue }
            $port = [int]($ch.Substring(4)); $r = Test-LBTcpPort -HostName '127.0.0.1' -Port $port -TimeoutMs $TimeoutMs
            [void]$res.Add((New-LBConn -Target $Target -Channel ("port-$port") -Ok $r.Ok -Ms $r.Ms -Detail "TCP $port (localhost)" `
                -Reason $(if($r.Ok){''}else{("سرویس روی پورتِ $port گوش نمی‌دهد | nothing is listening on TCP $port")}) `
                -Remedy "سرویس/برنامه را روشن کنید | start the service or application"))
        }
        return $res.ToArray()
    }
    if ($isSelf) {
        # --- the engine host: local capability checks ---
        try { $src=[Diagnostics.EventLog]::SourceExists('LogBok') } catch { $src=$false }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'event-source' -Ok $src -Ms 0 `
            -Detail "LogBok (Application)" `
            -Reason $(if($src){''}else{'منبعِ رویدادِ LogBok ثبت نشده | LogBok event source not registered'}) `
            -Remedy 'نصّاب را اجرا کنید | re-run the installer'))
        $auOk=$true; try { $csv=@((& auditpol.exe /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r) 2>$null | Where-Object { $_ }); if ($csv.Count -ge 2 -and ($csv -join ' ') -match 'No Auditing|بدون') { $auOk=$false } } catch { $auOk=$false }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'audit-policy' -Ok $auOk -Ms 0 `
            -Detail 'Logon auditing' -Reason $(if($auOk){''}else{'حسابرسیِ ورود خاموش است | logon auditing disabled'}) -Remedy 'نصّاب → Audit Policy | installer → Audit Policy'))
        $local=$false; try { [void]@(Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop); $local=$true } catch { }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'local-security-log' -Ok $local -Ms 0 `
            -Detail 'Security log readable' -Reason $(if($local){''}else{'لاگِ Security خوانده نشد | cannot read local Security log'}) -Remedy 'موتور باید با SYSTEM/Admin اجرا شود | run the engine as SYSTEM/Admin'))
        # firewall state (informational)
        $fwOn=$true; try { $fwOn = -not ((& netsh advfirewall show allprofiles state) -match 'OFF|خاموش') } catch { }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'firewall' -Ok $true -Ms 0 -State $(if($fwOn){'OK'}else{'Warn'}) `
            -Detail $(if($fwOn){'روشن | on'}else{'خاموش | off'}) -Reason '' -Remedy ''))
        # management allow-rules present?
        $mg=@(Test-LBMgmtAllow -Config $Config); $mgMiss=@($mg | Where-Object { -not $_.Enabled })
        if ($mg.Count) {
            [void]$res.Add((New-LBConn -Target $Target -Channel 'mgmt-allow' -Ok ($mgMiss.Count -eq 0) -Ms 0 `
                -Detail ("{0}/{1} rules" -f ($mg.Count-$mgMiss.Count), $mg.Count) `
                -Reason $(if($mgMiss.Count){('رولِ همیشه‌بازِ مدیریت ناقص است: ' + (@($mgMiss.Name) -join ',') + ' | management allow-rules missing')}else{''}) `
                -Remedy 'خودکار در اجرای بعدی ساخته می‌شود | auto-created next run'))
        }
        # syslog listener up?
        if ($Channels -contains 'syslog-listener') {
            $udp = $false; try { $udp = [bool](Get-NetUDPEndpoint -LocalPort 514 -ErrorAction Stop) } catch { try { $udp = [bool]((& netstat -an -p UDP) -match ':514\s') } catch { } }
            [void]$res.Add((New-LBConn -Target $Target -Channel 'syslog-listener' -Ok $udp -Ms 0 -Detail 'UDP 514' `
                -Reason $(if($udp){''}else{'گیرندهٔ syslog روی UDP 514 گوش نمی‌دهد | syslog listener not running on UDP 514'}) `
                -Remedy 'جابِ Syslog را در config روشن کنید یا از کنسول «جاب‌ها» اجرا کنید | enable/run the Syslog job'))
        }
        # WEF subscription on collector
        if ([string]$Config.CollectionMode -eq 'Collector') {
            $wef=$false; $wefDetail=''
            try { $sub=(& wecutil gs LogBok-Collect /f:xml 2>$null) -join "`n"; if ($sub) { $wef=$true; if ($sub -notmatch '9020') { $wefDetail='اشتراکِ قدیمی (بدونِ 9020) | old subscription (no 9020)' } } } catch { }
            [void]$res.Add((New-LBConn -Target $Target -Channel 'wef-subscription' -Ok $wef -Ms 0 `
                -Detail $(if($wefDetail){$wefDetail}else{'LogBok-Collect'})  `
                -Reason $(if($wef){''}else{'اشتراکِ WEF ساخته نشده | WEF subscription missing'}) -Remedy 'LogBok-Deploy-Clients.ps1 -SetupCollector'))
        }
        return $res.ToArray()
    }

    # --- push agent: freshness of received events ---
    #  Office computers are switched off after work and on weekends. LogBok learns, per computer and per
    #  hour of the week, when it is normally on, so "off at its usual off-time" is normal (OK), not a problem.
    if ($Channels -contains 'agent-push') {
        $nm = $Target; if ($Config.AgentHosts -and $Config.AgentHosts[$Target]) { $nm = [string]$Config.AgentHosts[$Target] }
        $sdir = Get-LBStateDir -Config $Config
        $last = $null; try { $last = Get-LBPushLast -StateDir $sdir -HostName $nm } catch { }
        $at = $null; if ($last) { try { $at = [datetime]::Parse([string]$last.At, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } catch { } }
        $age = if ($at) { [int]((Get-Date) - $at).TotalMinutes } else { -1 }
        $online = ($age -ge 0 -and $age -le 10)
        $pr = Update-LBPresence -StateDir $sdir -HostName $nm -Online $online -LastSeen $at
        $usuallyOff = ($pr -and $pr.Learned -and $pr.OnRatio -lt 0.25)
        # off at its usual time = OK; off up to 3 days (night, weekend, holiday) = Warn without alarm; longer = Fail
        $st = if ($online) { 'OK' } elseif ($at -and $usuallyOff) { 'OK' } elseif ($age -ge 0 -and $age -le 4320) { 'Warn' } else { 'Fail' }
        $pat = if ($pr -and $pr.Pattern) { ' · ' + $pr.Pattern } else { '' }
        $reason = if ($online) { '' } elseif ($at -and $usuallyOff) { 'خاموش است؛ در این ساعت معمولاً خاموش است (رفتارِ یادگرفته‌شده) | switched off - normal for this computer at this time (learned)' } elseif ($at) { 'ایجنت مدتی است رویدادی نفرستاده (شاید سیستم خاموش است) | the agent has not sent events recently (the computer may be off)' } else { 'ایجنت روی این سیستم نصب نیست یا هنوز وصل نشده؛ لاگ‌بوک بدونِ ایجنت به سیستم‌ها وصل نمی‌شود (پورت‌های 135/445/5985 استفاده نمی‌شود) | no agent on this computer yet: LogBok reaches computers only through its agent (ports 135/445/5985 are not used)' }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'agent-push' -Ok ($st -ne 'Fail') -State $st -Ms 0 `
            -Detail $(if ($at) { ("آخرین دریافت | last received: {0} ({1} min) · {2}{3}" -f $at.ToString('yyyy-MM-dd HH:mm'), $age, [string]$last.Ip, $pat) } else { 'هنوز رویدادی نرسیده | nothing received yet' }) `
            -Reason $reason `
            -Remedy $(if ($at) { 'اگر سیستم روشن است: TCP 8687 به این سرور برسد؛ لاگ: C:\Windows\Temp\logbok-agent-gpo.log | if the computer is on: TCP 8687 to this server must be reachable' } else { 'ایجنت را نصب کنید: Computers → Add Computers → نصبِ امن با Group Policy (بدونِ باز کردنِ پورت) | install the agent: Computers → Add Computers → secure install via Group Policy (no open port)' })))
        $Channels = @($Channels | Where-Object { $_ -ne 'agent-push' })
        if (-not $Channels.Count) { return $res.ToArray() }
    }

    # --- remote target ---
    # 1) DNS
    $ips=@(); $sw=[Diagnostics.Stopwatch]::StartNew()
    try { $ips=@([Net.Dns]::GetHostAddresses($Target) | ForEach-Object { $_.IPAddressToString }) } catch { }
    $dnsOk=($ips.Count -gt 0)
    [void]$res.Add((New-LBConn -Target $Target -Channel 'dns' -Ok $dnsOk -Ms ([int]$sw.ElapsedMilliseconds) `
        -Detail (@($ips) -join ', ') `
        -Reason $(if($dnsOk){''}else{'نامِ سیستم قابلِ‌ترجمه نیست (DNS) | host name does not resolve'}) `
        -Remedy 'نام را درست کنید یا IP بگذارید؛ DNS/هاست را بررسی کنید | fix the name or use an IP; check DNS/hosts'))
    if (-not $dnsOk) { return $res.ToArray() }   # without DNS the rest is meaningless

    # 2) ping (informational; the target may block ICMP)
    $pOk=$false; $pMs=0
    try { $pr=(New-Object Net.NetworkInformation.Ping).Send(($ips[0]), $TimeoutMs); if ($pr.Status -eq 'Success') { $pOk=$true; $pMs=[int]$pr.RoundtripTime } } catch { }
    [void]$res.Add((New-LBConn -Target $Target -Channel 'ping' -Ok $true -Ms $pMs -State $(if($pOk){'OK'}else{'Warn'}) `
        -Detail $(if($pOk){"$pMs ms"}else{'بی‌پاسخ (شاید ICMP بسته است) | no reply (ICMP may be blocked)'}) -Reason '' -Remedy ''))

    # 3) required TCP ports per channel
    $portMap = @{ winrm=@(5985); eventlog=@(135); sql=@(1433); http=@(80,443); ftp=@(21); rdp=@(3389)
                  ldap=@(389); kerberos=@(88); dnsport=@(53); smb=@(445); ssh=@(22) }
    $needRemoting = ($Channels -contains 'eventlog' -or $Channels -contains 'winrm')
    $portOk = @{}
    foreach ($ch in $Channels) {
        $ports = @($portMap[$ch])
        if ($ch -like 'tcp:*') { $ports = @([int]($ch.Substring(4))) }
        foreach ($port in $ports) {
            if (-not $port) { continue }
            if ($portOk.ContainsKey($port)) { continue }
            $r=Test-LBTcpPort -HostName $ips[0] -Port $port -TimeoutMs $TimeoutMs
            $portOk[$port] = [bool]$r.Ok
            [void]$res.Add((New-LBConn -Target $Target -Channel ("port-$port") -Ok $r.Ok -Ms $r.Ms `
                -Detail "TCP $port ($ch)" `
                -Reason $(if($r.Ok){''}else{("پورت $port بسته/فیلترشده است | TCP $port closed or filtered")}) `
                -Remedy "روی مقصد: سرویس و رولِ فایروالِ پورت $port را بررسی کنید | on the target: check the service and the firewall rule for port $port"))
        }
    }

    # 3.5) syslog received from a network device?
    if ($Channels -contains 'syslog-in') {
        $seen = $null
        try {
            Import-Module (Join-Path (Split-Path -Parent $PSCommandPath) 'LogBok.Archive.psm1') -DisableNameChecking -ErrorAction Stop
            foreach ($ip in @($ips) + $Target) {
                $hit = @(Search-LBArchive -Config $Config -From (Get-Date).AddDays(-7) -To (Get-Date) -Source syslog -Text $ip -Max 2000 | Where-Object { [string]$_.host -eq $ip })
                if ($hit.Count) { $last = $hit[-1]; $seen = [string]$last.t; break }
            }
        } catch { }
        $srvIp = ''
        try { foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) { foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { if ($ua.Address.AddressFamily -eq 'InterNetwork' -and -not $ua.Address.ToString().StartsWith('127.')) { $srvIp = $ua.Address.ToString(); break } }; if ($srvIp) { break } } } catch { }
        $recent = $false
        if ($seen) { try { $recent = ([datetime]::Parse($seen, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) -gt (Get-Date).AddHours(-24)) } catch { $recent = $true } }
        [void]$res.Add((New-LBConn -Target $Target -Channel 'syslog-in' -Ok ([bool]$seen) -Ms 0 -State $(if ($recent) { 'OK' } elseif ($seen) { 'Warn' } else { 'Fail' }) `
            -Detail $(if ($seen) { "آخرین دریافت | last received: $seen" } else { 'هیچ syslogی دریافت نشده | nothing received' }) `
            -Reason $(if ($seen) { '' } else { 'از این دستگاه هیچ syslogی به لاگ‌بوک نرسیده | no syslog received from this device' }) `
            -Remedy ("روی دستگاه syslog را به {0} پورتِ UDP 514 بفرستید؛ جابِ Syslog روی این سرور روشن باشد | on the device send syslog to {0} UDP 514; keep the Syslog job on" -f $srvIp)))
    }

    # 4) WinRM / WS-Man remoting handshake
    if ($needRemoting) {
        $cred = $null
        try { if (Get-Command Get-LBTargetCredential -ErrorAction SilentlyContinue) { $cred = Get-LBTargetCredential -Computer $Target -StateDir (Get-LBStateDir -Config $Config) } } catch { }
        $wsOk=$false; $wsMs=0; $wsErr=''
        $sw=[Diagnostics.Stopwatch]::StartNew()
        # closed port -> fail fast (otherwise each probe would take tens of seconds)
        if ($portOk.ContainsKey(5985) -and -not $portOk[5985]) { $wsErr = 'port 5985 closed' }
        else { try { if ($cred) { [void](Test-WSMan -ComputerName $Target -Credential $cred -Authentication Negotiate -ErrorAction Stop) } else { [void](Test-WSMan -ComputerName $Target -ErrorAction Stop) }; $wsOk=$true } catch { $wsErr=$_.Exception.Message } }
        $wsMs=[int]$sw.ElapsedMilliseconds
        [void]$res.Add((New-LBConn -Target $Target -Channel 'winrm' -Ok $wsOk -Ms $wsMs `
            -Detail 'WS-Man ident' `
            -Reason $(if($wsOk){''}else{'سرویسِ WinRM پاسخ نداد | WinRM not responding'}) `
            -Remedy 'روی مقصد: winrm quickconfig و رولِ فایروالِ 5985 | on the target: winrm quickconfig and allow port 5985'))

        # 5) the real remote event read - exactly what the engine does
        $elOk=$false; $elMs=0; $reason=''; $remedy=''
        $sw=[Diagnostics.Stopwatch]::StartNew()
        try {
            if ($portOk.ContainsKey(135) -and -not $portOk[135]) { throw 'The RPC server is unavailable (TCP 135 closed)' }
            $gp=@{ ComputerName=$Target; LogName='Security'; MaxEvents=1; ErrorAction='Stop' }; if ($cred) { $gp.Credential = $cred }; [void]@(Get-WinEvent @gp); $elOk=$true }
        catch {
            $m=$_.Exception.Message
            if ($m -match 'Access is denied|دسترسی|0x5') { $reason='دسترسی رد شد (احراز هویت/مجوز) | access denied'; $remedy='حسابِ اجرای موتور باید عضوِ Event Log Readers یا Administrators مقصد باشد | the engine account must be in the target''s Event Log Readers or Administrators' }
            elseif ($m -match 'RPC server is unavailable|0x6ba|RPC') { $reason='RPC در دسترس نیست | RPC server unavailable'; $remedy='پورت 135 + پویا باز؛ سرویسِ Remote Registry/Event Log روشن | open port 135 + dynamic; start Remote Registry / Event Log service' }
            elseif ($m -match 'No events were found|هیچ رویدادی') { $elOk=$true }
            else { $reason=("خطا در خواندنِ رویداد | event read failed: {0}" -f $m); $remedy='اتصال و مجوز را بررسی کنید | check the connection and permissions' }
        }
        $elMs=[int]$sw.ElapsedMilliseconds
        [void]$res.Add((New-LBConn -Target $Target -Channel 'eventlog' -Ok $elOk -Ms $elMs `
            -Detail $(if ($cred) { ("Security log (remote read) · {0}" -f $cred.UserName) } else { 'Security log (remote read) · computer account' }) -Reason $reason -Remedy $(if ($reason -and -not $cred) { $remedy + ' — یا در «منابع» برای این سیستم نام‌کاربری/گذرواژه بگذارید | or set a credential for this source' } else { $remedy })))
    }
    return $res.ToArray()
}

# run all targets; optionally save to state\connectivity.json
function Test-LBConnectivity {
    param($Config, [string]$InstallDir='C:\Scripts\LogBok', [switch]$Save, [string[]]$Only)
    if (-not $Config) { try { $Config = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1') } catch { $Config = @{} } }
    $S = Get-LBConnSettings -Config $Config
    $targets = @(Get-LBConnTargets -Config $Config)
    if ($Only) { $targets = @($targets | Where-Object { $Only -contains $_.Target -or $Only -contains $_.Name }) }
    $tmeta = @{}; foreach ($t in $targets) { $tmeta[[string]$t.Target] = $t }
    $all = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        foreach ($r in (Test-LBConnTarget -Target $t.Target -Channels $t.Channels -TimeoutMs $S.TimeoutMs -Config $Config)) { [void]$all.Add($r) }
    }
    $results = $all.ToArray()
    if ($Save) {
        $byT = @{}
        foreach ($r in $results) {
            if (-not $byT.ContainsKey($r.Target)) { $byT[$r.Target] = New-Object System.Collections.ArrayList }
            [void]$byT[$r.Target].Add($r)
        }
        $targetsOut = @()
        foreach ($k in $byT.Keys) {
            $ch=@($byT[$k]); $fail=@($ch | Where-Object { -not $_.Ok }); $warn=@($ch | Where-Object { $_.Ok -and $_.State -eq 'Warn' })
            $status = if ($fail.Count) { 'Fail' } elseif ($warn.Count) { 'Warn' } else { 'OK' }
            $tm = $tmeta[[string]$k]
            $targetsOut += [pscustomobject]@{ Target=$k; Name=$(if ($tm) { $tm.Name } else { $k }); Kind=$(if ($tm) { $tm.Kind } else { '' }); Roles=$(if ($tm) { @($tm.Roles) } else { @() }); DeviceType=$(if ($tm) { $tm.DeviceType } else { '' }); Self=((Test-LBIsSelf $k) -and $tm -and (@($tm.Channels) -contains 'self')); Status=$status; Channels=$ch }
        }
        # partial test: keep the other previously saved results
        if ($Only) {
            try {
                $prev = Get-LBConnectStatus -InstallDir $InstallDir
                $done = @($targetsOut | ForEach-Object { [string]$_.Target })
                $live = @($(Get-LBConnTargets -Config $Config) | ForEach-Object { [string]$_.Target })
                foreach ($pt in @($prev.Targets)) { if ($done -notcontains [string]$pt.Target -and $live -contains [string]$pt.Target) { $targetsOut += $pt } }
            } catch { }
        }
        $doc = [pscustomobject]@{
            Generated = (Get-Date).ToString('o', $script:Inv)
            Host      = $env:COMPUTERNAME
            Mode      = [string]$Config.CollectionMode
            Targets   = $targetsOut
        }
        $dir = Join-Path $InstallDir 'state'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        try { $doc | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $dir 'connectivity.json') -Encoding UTF8 } catch { }
        $script:UnreachCache = $null
    }
    return $results
}

# read saved status for the dashboard
function Get-LBConnectStatus {
    param([string]$InstallDir='C:\Scripts\LogBok')
    $f = Join-Path $InstallDir 'state\connectivity.json'
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

Export-ModuleMember -Function Get-LBMgmtSettings, Get-LBConnSettings, Get-LBMgmtAllowRules, Get-LBMgmtWhitelistIps, `
    Assert-LBMgmtAllow, Test-LBMgmtAllow, Test-LBTcpPort, Test-LBIsSelf, Get-LBConnTargets, `
    Test-LBConnTarget, Test-LBConnectivity, Get-LBConnectStatus, New-LBConn
