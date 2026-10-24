# ==========================================================================
#  LogBok.Core.psm1 - shared core of the LogBok engine
#  Includes: config loading, logging, state, email anti-flood, email sending,
#         event query helpers (local/remote/Collector) and the threshold engine.
# ==========================================================================

$script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# --- invariant culture ---------------------------------------------------
# on Windows with a Persian (fa-IR) calendar, Get-Date -Format and ToString write dates
# in the Persian calendar (e.g. 1405-07-16), breaking file names, licensing and time
# comparisons. The whole engine uses the invariant culture.
try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
} catch { }
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

# invariant date formatting
function Get-LBDate {
    param([string]$Format = 'yyyy-MM-dd', [datetime]$Date = (Get-Date))
    return $Date.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}
# invariant date parse; $null on failure
function ConvertTo-LBDate {
    param([string]$Text, [string[]]$Format = @('yyyy-MM-dd','yyyy-MM-dd HH:mm:ss','o','yyyy-MM-ddTHH:mm:ss'))
    if (-not $Text) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParseExact($Text, $Format, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$d)) { return $d }
    if ([datetime]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $d }
    return $null
}
# safe HTML encode (always available, no System.Web)
function ConvertTo-LBHtml {
    param($Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# --- config loading --------------------------------------------------------
function Get-LogBokConfig {
    param([string]$Path = (Join-Path $script:Root 'config.psd1'), [switch]$Raw)
    if (-not (Test-Path $Path)) { throw "فایل پیکربندی یافت نشد: $Path" }
    $cfg = Import-PowerShellDataFile -Path $Path
    if ($Raw) { return $cfg }
    # settings saved from the web/console (state\settings.json) overlay the config,
    # and registered log sources (state\targets.json) are added to the config lists.
    $sd = Get-LBStateDir -Config $cfg -Root (Split-Path -Parent $Path)
    try { $cfg = Merge-LBSettingsOverlay -Config $cfg -StateDir $sd } catch { }
    try { $cfg = Merge-LBTargetsIntoConfig -Config $cfg -StateDir $sd } catch { }
    return $cfg
}

# robust local time from an ISO string or DateTime (PS 5.1 gives a string, PS 7 a date)
function ConvertTo-LBLocal {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Utc) { return $Value.ToLocalTime() } else { return $Value } }
    $t = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$t)) {
        if ($t.Kind -eq [DateTimeKind]::Utc) { return $t.ToLocalTime() } else { return $t }
    }
    return $null
}

# state directory (config path if it exists, else <root>\state)
function Get-LBStateDir {
    param($Config, [string]$Root = $script:Root)
    if ($Config -and $Config.Paths -and $Config.Paths.State) {
        $p = [string]$Config.Paths.State
        if (Test-Path $p) { return $p }
    }
    $d = Join-Path $Root 'state'
    if (-not (Test-Path $d)) { try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch { } }
    return $d
}

# --- JSON -> Hashtable (PS 5.1 compatible), recursive conversion -------------
function ConvertTo-LBHashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = @{}; foreach ($k in @($InputObject.Keys)) { $h[[string]$k] = ConvertTo-LBHashtable $InputObject[$k] }; return $h
    }
    if ($InputObject -is [string]) { return $InputObject }
    # order matters: in PS 5.1 "-is [pscustomobject]" is also true for arrays (accelerator = PSObject)
    # order matters: in PS 5.1 '-is [pscustomobject]' is also true for wrapped arrays, so test arrays first
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $arr = @(); foreach ($x in $InputObject) { $arr += ,(ConvertTo-LBHashtable $x) }; return ,$arr
    }
    if ($InputObject.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $h = @{}; foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-LBHashtable $p.Value }; return $h
    }
    return $InputObject
}

# --- settings overlay from the UI (state\settings.json) ---------------------
function Get-LBSettingsOverlay {
    param([string]$StateDir)
    $f = Join-Path $StateDir 'settings.json'
    if (-not (Test-Path $f)) { return @{} }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return $h } } catch { }
    return @{}
}
function Merge-LBHash {
    param([hashtable]$Base, [hashtable]$Over)
    foreach ($k in @($Over.Keys)) {
        if ($Base.ContainsKey($k) -and $Base[$k] -is [hashtable] -and $Over[$k] -is [hashtable]) { Merge-LBHash -Base $Base[$k] -Over $Over[$k] | Out-Null }
        else { $Base[$k] = $Over[$k] }
    }
    return $Base
}
function Merge-LBSettingsOverlay {
    param($Config, [string]$StateDir)
    $o = Get-LBSettingsOverlay -StateDir $StateDir
    if ($o.Count) { [void](Merge-LBHash -Base $Config -Over $o) }
    return $Config
}
# write a value into the saved settings; dotted path, e.g. 'Mail.To'
function Set-LBSetting {
    param([Parameter(Mandatory)][string]$Path, $Value, [string]$StateDir, [switch]$Remove)
    if (-not $StateDir) { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) }
    $o = Get-LBSettingsOverlay -StateDir $StateDir
    $parts = $Path -split '\.'
    $cur = $o
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if (-not ($cur[$parts[$i]] -is [hashtable])) { $cur[$parts[$i]] = @{} }
        $cur = $cur[$parts[$i]]
    }
    $leaf = $parts[-1]
    if ($Remove) { $cur.Remove($leaf) } else { $cur[$leaf] = $Value }
    $f = Join-Path $StateDir 'settings.json'
    $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $o -Depth 12), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
    return $o
}

# --- registered log sources (state\targets.json) ----------------------------
function Get-LBTargetsFile { param([string]$StateDir) Join-Path $StateDir 'targets.json' }
function Get-LBTargetList {
    param([string]$StateDir)
    $f = Get-LBTargetsFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @() }
    try {
        $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json)
        if ($h -is [hashtable]) { return @($h) }
        return @($h | Where-Object { $_ -is [hashtable] })
    } catch { return @() }
}
# --- store of events pushed by agents ----------------------------------------
#  state\push\<HOST>\<log>\yyyyMMddHH.ndjson; each line: l,i,t,r,p,v,m,s,x (log, id, time, record, provider, level, machine, message, XML)
function Get-LBPushDir { param([string]$StateDir, [string]$HostName) $d = Join-Path $StateDir 'push'; if ($HostName) { $d = Join-Path $d ((Get-LBSafeName $HostName).ToUpperInvariant()) }; return $d }
function Get-LBPushLogDir { param([string]$StateDir, [string]$HostName, [string]$LogName) return (Join-Path (Get-LBPushDir -StateDir $StateDir -HostName $HostName) ($LogName -replace '[^A-Za-z0-9]', '_')) }
function Get-LBPushLast {
    param([string]$StateDir, [string]$HostName)
    $f = Join-Path (Get-LBPushDir -StateDir $StateDir -HostName $HostName) 'last.json'
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}
function New-LBPushEvent {
    param($o, [string]$HostName)
    $t = $null; try { $t = [datetime]::Parse([string]$o.t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime() } catch { $t = Get-Date }
    $e = [pscustomobject]@{ Id = [int]$o.i; TimeCreated = $t; MachineName = $(if ($o.m) { [string]$o.m } else { $HostName }); RecordId = [long]$o.r; LogName = [string]$o.l
                            ProviderName = [string]$o.p; LevelDisplayName = [string]$o.v; Message = [string]$o.s; _xml = [string]$o.x }
    $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this._xml }
    return $e
}
function Get-LBPushEvents {
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][string]$LogName, [int[]]$Id, [datetime]$StartTime, [int]$MaxEvents = 5000, [string]$StateDir)
    if (-not $StateDir) { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) }
    $dir = Get-LBPushLogDir -StateDir $StateDir -HostName $HostName -LogName $LogName
    if (-not (Test-Path $dir)) { return @() }
    $from = if ($PSBoundParameters.ContainsKey('StartTime') -and $StartTime) { $StartTime } else { (Get-Date).AddHours(-24) }
    $fromKey = $from.AddHours(-1).ToString('yyyyMMddHH', [Globalization.CultureInfo]::InvariantCulture)
    $ids = @{}; foreach ($x in @($Id | Where-Object { $null -ne $_ })) { $ids[[int]$x] = $true }
    $out = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-ChildItem -Path $dir -Filter '*.ndjson' -File -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -ge $fromKey } | Sort-Object Name -Descending)) {
        $lines = @(); try { $lines = [IO.File]::ReadAllLines($f.FullName, [Text.Encoding]::UTF8) } catch { continue }
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            $ln = $lines[$i]; if (-not $ln) { continue }
            if ($ids.Count) { if ($ln -notmatch '"i":(\d+)') { continue }; if (-not $ids[[int]$Matches[1]]) { continue } }
            $o = $null; try { $o = $ln | ConvertFrom-Json } catch { continue }
            $e = New-LBPushEvent -o $o -HostName $HostName
            if ($e.TimeCreated -lt $from) { continue }
            [void]$out.Add($e)
            if ($out.Count -ge $MaxEvents) { break }
        }
        if ($out.Count -ge $MaxEvents) { break }
    }
    return @($out | Sort-Object TimeCreated -Descending)
}

function Merge-LBTargetsIntoConfig {
    param($Config, [string]$StateDir)
    $list = @(Get-LBTargetList -StateDir $StateDir | Where-Object { $_.Enabled -ne $false })
    if (-not $list.Count) { return $Config }
    function _addTo($key, $val) {
        if (-not $val) { return }
        $cur = @($Config[$key] | Where-Object { $_ })
        if ($cur -notcontains $val) { $Config[$key] = @($cur + $val) }
    }
    $remote = @(); $names = @{}; $custom = @(); $agents = @{}; $agentSrc = @()
    foreach ($t in $list) {
        $addr = if ($t.Address) { [string]$t.Address } else { [string]$t.Name }
        $roles = @($t.Roles | Where-Object { $_ })
        switch ([string]$t.Kind) {
            'Windows' {
                if ($t.Monitor -eq 'agent') { $agents[$addr] = [string]$t.Name; $agents[[string]$t.Name] = [string]$t.Name; $agentSrc += $addr }
                elseif ($t.Monitor -ne 'none') { $remote += $addr }
                if ($roles -contains 'SQL')    { _addTo 'SqlServers'    $addr }
                if ($roles -contains 'IIS')    { _addTo 'IISServers'    $addr }
                if ($roles -contains 'FTP')    { _addTo 'FtpServers'    $addr }
                if ($roles -contains 'DHCP')   { _addTo 'DhcpServers'   $addr }
                if ($roles -contains 'Apache') { _addTo 'ApacheServers' $addr }
            }
            'NetworkDevice' { $names[$addr] = [string]$t.Name }
            default { }
        }
        foreach ($c in @($t.Custom | Where-Object { $_ })) {
            $c2 = @{}; foreach ($k in $c.Keys) { $c2[$k] = $c[$k] }
            $c2.Host = $addr; $c2.Target = [string]$t.Name
            $custom += $c2
        }
    }
    if ($remote.Count) {
        $Config['RemoteHosts'] = @($remote | Select-Object -Unique)
        if ([string]$Config.CollectionMode -eq 'Remote') { foreach ($r in $remote) { _addTo 'Machines' $r } }
    }
    if ($agents.Count) { $Config['AgentHosts'] = $agents; $Config['AgentSources'] = @($agentSrc | Select-Object -Unique) }
    if ($names.Count) { $Config['SyslogNames'] = $names }
    if ($custom.Count) { $Config['CustomSources'] = $custom }
    return $Config
}

# --- per-source credentials (machine DPAPI) ---------------------------------
#  only SYSTEM and Administrators can read; "_default" applies to all sources.
function Get-LBCredDir { param([string]$StateDir) $d = Join-Path $StateDir 'creds'; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null; try { & icacls.exe $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null } catch { } }; return $d }
function Get-LBSafeName { param([string]$Name) return (([string]$Name).Trim() -replace '[^A-Za-z0-9_.\-]', '_') }
function Set-LBTargetCredential {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][pscredential]$Credential, [string]$StateDir)
    if (-not $StateDir) { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) }
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $plain = $Credential.UserName + "`n" + $Credential.GetNetworkCredential().Password
    $enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($plain), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $plain = $null
    $f = Join-Path (Get-LBCredDir -StateDir $StateDir) ((Get-LBSafeName $Name) + '.sec')
    [IO.File]::WriteAllText($f, [Convert]::ToBase64String($enc))
    try { & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } catch { }
    return $f
}
function Remove-LBTargetCredential {
    param([Parameter(Mandatory)][string]$Name, [string]$StateDir)
    if (-not $StateDir) { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) }
    $f = Join-Path (Get-LBCredDir -StateDir $StateDir) ((Get-LBSafeName $Name) + '.sec')
    if (Test-Path $f) { Remove-Item $f -Force }
}
function Test-LBTargetCredential {
    param([string]$Name, [string]$StateDir)
    if (-not $StateDir) { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) }
    return (Test-Path (Join-Path (Join-Path $StateDir 'creds') ((Get-LBSafeName $Name) + '.sec')))
}
function Read-LBCredFile {
    param([string]$File)
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $enc = [Convert]::FromBase64String((Get-Content $File -Raw).Trim())
        $plain = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
        $i = $plain.IndexOf("`n"); if ($i -lt 1) { return $null }
        $u = $plain.Substring(0, $i); $pw = $plain.Substring($i + 1); $plain = $null
        $sec = New-Object Security.SecureString; foreach ($ch in $pw.ToCharArray()) { $sec.AppendChar($ch) }; $pw = $null
        return New-Object System.Management.Automation.PSCredential($u, $sec)
    } catch { return $null }
}
# resolve a host credential: by its name or address in the source list, else "_default"
function Get-LBTargetCredential {
    param([string]$Computer, [string]$StateDir)
    if (-not $Computer) { return $null }
    if (-not $StateDir) { try { $StateDir = Get-LBStateDir -Config (Get-LogBokConfig -Raw) } catch { return $null } }
    $dir = Join-Path $StateDir 'creds'
    if (-not (Test-Path $dir)) { return $null }
    $cands = @($Computer)
    foreach ($t in (Get-LBTargetList -StateDir $StateDir)) { if ($t.Name -eq $Computer -or $t.Address -eq $Computer) { $cands += [string]$t.Name } }
    foreach ($n in ($cands + '_default' | Select-Object -Unique)) {
        $f = Join-Path $dir ((Get-LBSafeName $n) + '.sec')
        if (Test-Path $f) { $c = Read-LBCredFile -File $f; if ($c) { return $c } }
    }
    return $null
}

# hosts whose last connectivity test for reading events failed (the engine does not wait on them)
function Get-LBUnreachableHosts {
    param($Config)
    if ($script:UnreachCache -and $script:UnreachAt -gt (Get-Date).AddMinutes(-1)) { return $script:UnreachCache }
    $out = @()
    try {
        $f = Join-Path (Get-LBStateDir -Config $Config) 'connectivity.json'
        if (Test-Path $f) {
            $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($t in @($j.Targets)) {
                if ($t.Self) { continue }
                $bad = @($t.Channels | Where-Object { ($_.Channel -eq 'eventlog' -or $_.Channel -eq 'dns') -and -not $_.Ok })
                if ($bad.Count) { $out += [string]$t.Target; if ($t.Address) { $out += [string]$t.Address } }
            }
        }
    } catch { }
    $script:UnreachCache = $out; $script:UnreachAt = Get-Date
    return $out
}

# --- internal engine log ---------------------------------------------------
function Write-LogBokLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
        $Config
    )
    try {
        if (-not $Config) { $Config = Get-LogBokConfig }
        $dir = $Config.Paths.Logs
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $file = Join-Path $dir ("logbok-{0}.log" -f (Get-LBDate))
        $line = '{0} [{1}] {2}' -f (Get-LBDate 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        Add-Content -Path $file -Value $line -Encoding UTF8
    } catch { }
    if ($Level -eq 'ERROR') { Write-Host $Message -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $Message -ForegroundColor Yellow }
    else { Write-Host $Message }
}

# --- read/write state (JSON) -----------------------------------------------
# state keeps: the last processed RecordId and the last alert time per key.
function Get-LogBokState {
    param($Config)
    if (-not $Config) { $Config = Get-LogBokConfig }
    $dir = $Config.Paths.State
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file = Join-Path $dir 'state.json'
    if (Test-Path $file) {
        try {
            $raw = Get-Content -Path $file -Raw -Encoding UTF8
            if ($raw.Trim()) {
                $obj = $raw | ConvertFrom-Json
                # convert to a Hashtable for easy editing
                $ht = @{}
                foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = $p.Value }
                return $ht
            }
        } catch { }
    }
    return @{}
}

function Save-LogBokState {
    param($State, $Config)
    if (-not $Config) { $Config = Get-LogBokConfig }
    $dir = $Config.Paths.State
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $file = Join-Path $dir 'state.json'
    # prune expired anti-flood keys so state.json does not grow forever
    $keep = [Math]::Max(1500, [int]$Config.AlertThrottleMinutes * 4)   # >= 25 hours (for daily throttles)
    foreach ($k in @($State.Keys)) {
        if ($k -like 'throttle::*') {
            $v = $State[$k]
            $d = if ($v -is [datetime]) { $v } else { ConvertTo-LBDate ([string]$v) }
            if (-not $d -or $d -lt (Get-Date).AddMinutes(-$keep)) { $State.Remove($k) }
        }
    }
    $tmp = "$file.tmp"
    $State | ConvertTo-Json -Depth 6 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $file -Force
}

# --- email anti-flood: has this key already alerted within the throttle window? ---
function Test-LogBokThrottle {
    param([string]$Key, $State, $Config, [int]$Minutes = 0)
    $minutes = if ($Minutes -gt 0) { $Minutes } else { [int]$Config.AlertThrottleMinutes }
    $stKey = "throttle::$Key"
    if ($State.ContainsKey($stKey)) {
        $v = $State[$stKey]
        $last = if ($v -is [datetime]) { $v } else { ConvertTo-LBDate ([string]$v) }
        if ($last -and (Get-Date) -lt $last.AddMinutes($minutes)) { return $false } # still within the window -> do not send
    }
    return $true
}
function Set-LogBokThrottle {
    param([string]$Key, $State)
    $State["throttle::$Key"] = (Get-Date).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

# --- SMTP password: machine-level DPAPI encryption -------------------------
# it used to be stored with user DPAPI (cred.xml), which SYSTEM tasks could not
# read, so email failed silently. Now smtp.sec is readable only by SYSTEM and
# Administrators.
function Set-LogBokMailSecret {
    param([Parameter(Mandatory)][securestring]$Password, [string]$Root = $script:Root)
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
        $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $f = Join-Path $Root 'smtp.sec'
    [IO.File]::WriteAllText($f, [Convert]::ToBase64String($enc))
    try { & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } catch {}
    return $f
}
function Get-LogBokMailCredential {
    param([string]$User, [string]$Root = $script:Root)
    $f = Join-Path $Root 'smtp.sec'
    if (Test-Path $f) {
        try {
            Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
            $enc = [Convert]::FromBase64String((Get-Content $f -Raw).Trim())
            $plain = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
            $sec = New-Object Security.SecureString
            foreach ($ch in $plain.ToCharArray()) { $sec.AppendChar($ch) }
            $plain = $null
            return New-Object System.Management.Automation.PSCredential($User, $sec)
        } catch { Write-LogBokLog -Message "خواندن smtp.sec ناموفق: $($_.Exception.Message)" -Level WARN }
    }
    $old = Join-Path $Root 'cred.xml'   # compatibility with old installs
    if (Test-Path $old) { try { return Import-Clixml -Path $old } catch {} }
    return $null
}

# --- send email ------------------------------------------------------------
# --- SMTP over implicit TLS (port 465) -------------------------------------
#  Send-MailMessage/SmtpClient only does STARTTLS. .NET builds the message (with attachments) as MIME
#  (pickup directory) and the same bytes are sent over a TLS connection from the start. The server certificate is validated.
#  Send-MailMessage/SmtpClient only do STARTTLS. .NET builds the MIME message (with attachments) via a pickup
#  directory and the exact bytes are sent over a connection that is TLS from the first byte. The server certificate is validated.
function Send-LBSmtpImplicitTls {
    param([Parameter(Mandatory)][string]$Server, [int]$Port = 465, [Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string[]]$To,
          [string]$Subject, [string]$Body, [switch]$Html, [string[]]$Attachments, [pscredential]$Credential, [int]$TimeoutMs = 30000)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('lbmail-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $bytes = $null
    try {
        $msg = New-Object Net.Mail.MailMessage
        try {
            $msg.From = New-Object Net.Mail.MailAddress($From)
            foreach ($a in @($To | Where-Object { $_ })) { $msg.To.Add([string]$a) }
            $msg.Subject = $Subject; $msg.SubjectEncoding = [Text.Encoding]::UTF8
            $msg.Body = $Body; $msg.BodyEncoding = [Text.Encoding]::UTF8; $msg.IsBodyHtml = [bool]$Html
            foreach ($f in @($Attachments | Where-Object { $_ })) { $msg.Attachments.Add((New-Object Net.Mail.Attachment([string]$f))) }
            $pc = New-Object Net.Mail.SmtpClient('localhost')
            $pc.DeliveryMethod = [Net.Mail.SmtpDeliveryMethod]::SpecifiedPickupDirectory
            $pc.PickupDirectoryLocation = $tmp
            $pc.Send($msg)
        } finally { $msg.Dispose() }
        $eml = Get-ChildItem -Path $tmp -Filter '*.eml' -File | Select-Object -First 1
        if (-not $eml) { throw 'MIME message could not be built' }
        $bytes = [IO.File]::ReadAllBytes($eml.FullName)
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    # Latin-1 keeps every byte as-is
    $l1 = [Text.Encoding]::GetEncoding(28591)
    $lines = New-Object System.Collections.Generic.List[string]
    $hdr = $true
    foreach ($ln in ($l1.GetString($bytes) -split "`r`n")) {
        if ($hdr -and $ln -match '^X-(Sender|Receiver):') { continue }   # pickup-only headers
        if ($hdr -and $ln -eq '') { $hdr = $false }
        $lines.Add($(if ($ln.StartsWith('.')) { '.' + $ln } else { $ln }))   # dot-stuffing
    }
    if (-not ($lines | Where-Object { $_ -match '^Date:' } | Select-Object -First 1)) { $lines.Insert(0, 'Date: ' + [datetime]::UtcNow.ToString('r', [Globalization.CultureInfo]::InvariantCulture)) }
    while ($lines.Count -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    $data = $l1.GetBytes((($lines.ToArray()) -join "`r`n") + "`r`n.`r`n")

    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($Server, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw ("could not connect to {0}:{1} (timeout)" -f $Server, $Port) }
        try { $tcp.EndConnect($ar) } catch { $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }; throw ("could not connect to {0}:{1} ({2})" -f $Server, $Port, $ie.Message) }
        $tcp.ReceiveTimeout = $TimeoutMs; $tcp.SendTimeout = $TimeoutMs
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($Server, $null, [Security.Authentication.SslProtocols]::Tls12, $true)   # certificate validated
        $rd = New-Object IO.StreamReader($ssl, [Text.Encoding]::ASCII)
        $read = {
            $code = 0; $txt = New-Object Text.StringBuilder
            while ($true) {
                $l = $rd.ReadLine(); if ($null -eq $l) { throw 'SMTP server closed the connection' }
                [void]$txt.Append($l + ' ')
                if ($l.Length -ge 4 -and $l[3] -ne '-') { $code = [int]$l.Substring(0, 3); break }
                if ($l.Length -eq 3) { $code = [int]$l; break }
            }
            return @{ Code = $code; Text = $txt.ToString().Trim() }
        }
        $send = { param([string]$c) $b = [Text.Encoding]::ASCII.GetBytes($c + "`r`n"); $ssl.Write($b, 0, $b.Length); $ssl.Flush() }
        $expect = { param($r, [int[]]$ok, [string]$step) if ($ok -notcontains $r.Code) { throw ("SMTP {0}: {1}" -f $step, $r.Text) } }
        & $expect (& $read) @(220) 'greeting'
        & $send ('EHLO ' + $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'logbok' }))
        $eh = & $read; & $expect $eh @(250) 'EHLO'
        if ($Credential) {
            $u = $Credential.UserName; $p = $Credential.GetNetworkCredential().Password
            if ($eh.Text -match 'AUTH[ =][^\r\n]*LOGIN') {
                & $send 'AUTH LOGIN'; & $expect (& $read) @(334) 'AUTH'
                & $send ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($u))); & $expect (& $read) @(334) 'AUTH user'
                & $send ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($p))); & $expect (& $read) @(235) 'AUTH (user name or password rejected)'
            } else {
                & $send ('AUTH PLAIN ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("`0$u`0$p"))); & $expect (& $read) @(235) 'AUTH (user name or password rejected)'
            }
        }
        & $send ('MAIL FROM:<' + ([Net.Mail.MailAddress]$From).Address + '>'); & $expect (& $read) @(250) 'MAIL FROM'
        foreach ($a in @($To | Where-Object { $_ })) { & $send ('RCPT TO:<' + ([Net.Mail.MailAddress]([string]$a)).Address + '>'); & $expect (& $read) @(250, 251) ("RCPT TO " + $a) }
        & $send 'DATA'; & $expect (& $read) @(354) 'DATA'
        $ssl.Write($data, 0, $data.Length); $ssl.Flush()
        & $expect (& $read) @(250) 'message'
        try { & $send 'QUIT' } catch { }
        try { $ssl.Dispose() } catch { }
    } finally { try { $tcp.Close() } catch { } }
    return $true
}

function Get-LBLastMailError { return [string]$script:LBLastMailError }
function Send-LogBokMail {
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [string[]]$Attachments,
        [switch]$Html,
        [string[]]$To,
        $Config
    )
    if (-not $Config) { $Config = Get-LogBokConfig }
    $m = $Config.Mail
    $subj = ('{0} {1}' -f $m.SubjectTag, $Subject).Trim()

    $params = @{
        SmtpServer = $m.SmtpServer
        Port       = $m.Port
        From       = $m.From
        To         = $(if ($To) { $To } else { @($m.To) })
        Subject     = $subj
        Body        = $Body
        Encoding    = [System.Text.Encoding]::UTF8
    }
    if ($m.UseSsl) { $params.UseSsl = $true }
    if ($Html)     { $params.BodyAsHtml = $true }
    if ($Attachments) { $params.Attachments = $Attachments }

    # SMTP password (machine-level encryption; readable by SYSTEM tasks)
    if ($m.User) {
        $cr = Get-LogBokMailCredential -User $m.User
        if ($cr) { $params.Credential = $cr }
        else { Write-LogBokLog -Message "گذرواژهٔ SMTP یافت نشد؛ ارسال بدون احراز هویت (Console → تنظیم گذرواژهٔ ایمیل)" -Level WARN -Config $Config }
    }
    if ($m.UseSsl) { try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {} }
    $script:LBLastMailError = ''
    try {
        if ([int]$m.Port -eq 465) {
            # port 465: implicit TLS
            [void](Send-LBSmtpImplicitTls -Server ([string]$m.SmtpServer) -Port 465 -From ([string]$m.From) -To @($params.To) -Subject $subj -Body $Body -Html:$Html -Attachments $Attachments -Credential $params.Credential)
        } else {
            Send-MailMessage @params -ErrorAction Stop
        }
        Write-LogBokLog -Message "ایمیل ارسال شد: $subj" -Config $Config
        return $true
    } catch {
        $em = $_.Exception.Message
        if ($_.Exception.InnerException -and $em -notlike ('*' + $_.Exception.InnerException.Message + '*')) { $em += ' — ' + $_.Exception.InnerException.Message }
        $script:LBLastMailError = $em
        Write-LogBokLog -Message "خطا در ارسال ایمیل '$subj' : $em" -Level ERROR -Config $Config
        return $false
    }
}

# --- alert email template (bilingual per config.Language) ------------------
function New-LogBokAlertHtml {
    param($Finding, $Config)
    # a readable plain-language email: what happened / where / why it matters / what to do / if it is normal
    # a readable alert: what happened / where / why it matters / what to do / if this is normal
    $lang = if ($Config.Language -eq 'en') { 'en' } else { 'fa' }
    $isEn = ($lang -eq 'en')
    $E = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $one = { param($t) $pp = ([string]$t) -split '\s\|\s', 2; if ($pp.Count -eq 2) { if ($isEn) { $pp[1] } else { $pp[0] } } else { [string]$t } }
    $dir = if ($isEn) { 'ltr' } else { 'rtl' }; $al = if ($isEn) { 'left' } else { 'right' }
    $b = if ($Config.Brand) { $Config.Brand } else { @{} }
    $ink = if ($b.InkTeal) { $b.InkTeal } else { '#0E2529' }
    $brass = if ($b.Brass) { $b.Brass } else { '#C9A24B' }
    $name = if ($b.NameEn) { $b.NameEn } else { 'LogBok' }
    $sevColor = switch ([string]$Finding.Severity) { 'Critical' { '#C53030' } 'Warning' { '#B7791F' } default { '#2B6CB0' } }
    $sevTxt = switch ([string]$Finding.Severity) { 'Critical' { $(if ($isEn) { 'Critical' } else { 'بحرانی' }) } 'Warning' { $(if ($isEn) { 'Warning' } else { 'هشدار' }) } default { $(if ($isEn) { 'Info' } else { 'اطلاع' }) } }
    $t = if ($Finding.Time -is [datetime]) { $Finding.Time.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } else { [string]$Finding.Time }
    $pb = $null
    try { if (-not (Get-Command Get-LBPlaybook -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $PSScriptRoot 'LogBok.Playbook.psm1') -DisableNameChecking -ErrorAction Stop }; $pb = Get-LBPlaybook -Category ([string]$Finding.Category) -Title ([string]$Finding.Title) -Lang $lang } catch { }
    $L = @{
        what = $(if ($isEn) { 'What happened' } else { 'چه اتفاقی افتاده؟' }); where = $(if ($isEn) { 'Where and when' } else { 'کجا و کِی؟' }); why = $(if ($isEn) { 'Why it matters' } else { 'چرا مهم است؟' })
        do = $(if ($isEn) { 'What to do' } else { 'چه کار کنیم؟' }); normal = $(if ($isEn) { 'When this is normal' } else { 'اگر عادی است' }); det = $(if ($isEn) { 'Technical details' } else { 'جزئیاتِ فنی' })
        host = $(if ($isEn) { 'Computer' } else { 'سیستم' }); time = $(if ($isEn) { 'Time' } else { 'زمان' }); cat = $(if ($isEn) { 'Type' } else { 'نوع' })
        urg = @{ now = $(if ($isEn) { 'Act now' } else { 'همین حالا اقدام کنید' }); today = $(if ($isEn) { 'Check today' } else { 'امروز بررسی کنید' }); week = $(if ($isEn) { 'Fix this week' } else { 'این هفته درست کنید' }) }
        mute = $(if ($isEn) { 'Too many of these? Open the incident in the console and press Mute, or change the alert profile under Alerts.' } else { 'این هشدار زیاد می‌آید؟ در کنسول رخداد را باز کنید و «بی‌صدا» را بزنید، یا در بخشِ هشدارها پروفایلش را تغییر دهید.' })
        foot = $(if ($isEn) { 'Automated alert' } else { 'هشدارِ خودکار' })
    }
    $urgKey = $(if ($pb -and $pb.Urgency) { [string]$pb.Urgency } elseif ([string]$Finding.Severity -eq 'Critical') { 'now' } else { 'today' })
    $urgColor = switch ($urgKey) { 'now' { '#C53030' } 'today' { '#B7791F' } default { '#2B6CB0' } }
    $sec = { param($h, $body, $color) "<div style='margin:14px 0 0'><div style='font-size:12px;font-weight:700;color:$color;letter-spacing:.2px;margin-bottom:4px'>$h</div><div style='font-size:14px;line-height:1.7;color:#22343a'>$body</div></div>" }
    $kv = { param($k, $v) "<tr><td style='padding:5px 10px;color:#6b7c80;white-space:nowrap'>$k</td><td style='padding:5px 10px;font-weight:600'>$v</td></tr>" }
    $title = & $one $Finding.Title
    $catTitle = & $one ([string]$Finding.Category)
    $steps = ''
    if ($pb -and @($pb.Do).Count) { $steps = '<ol style="margin:4px 0 0;padding-' + $(if ($isEn) { 'left' } else { 'right' }) + ':22px">' + ((@($pb.Do) | ForEach-Object { "<li style='margin:3px 0'>$(& $E $_)</li>" }) -join '') + '</ol>' }
    $details = [string]$Finding.Details
    if ($details.Length -gt 1500) { $details = $details.Substring(0, 1500) + '…' }
    $html = @"
<!DOCTYPE html><html dir="$dir"><head><meta charset="utf-8"></head>
<body style="margin:0;padding:18px;background:#f2f5f6;font-family:Vazirmatn,'Segoe UI',Tahoma,sans-serif;direction:$dir;text-align:$al">
<div style="max-width:680px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e1e7e9">
 <div style="background:$ink;padding:14px 20px;color:#fff;font-weight:700;font-size:15px">
   <span style="color:$brass">&#9679;</span> $name
   <span style="float:$(if($isEn){'right'}else{'left'});background:$sevColor;color:#fff;border-radius:20px;padding:2px 12px;font-size:12px">$sevTxt</span>
 </div>
 <div style="padding:18px 20px 14px">
  <div style="font-size:18px;font-weight:700;color:#13272B;border-$(if($isEn){'left'}else{'right'}):4px solid $sevColor;padding-$(if($isEn){'left'}else{'right'}):10px">$(& $E $title)</div>
  <div style="margin:8px 0 0;display:inline-block;background:$urgColor;color:#fff;border-radius:6px;padding:3px 10px;font-size:12px;font-weight:700">$($L.urg[$urgKey])</div>
  $(if ($pb) { & $sec $L.what (& $E $pb.What) '#13272B' })
  $(& $sec $L.where ("<table style='border-collapse:collapse;font-size:13px'>" + (& $kv $L.host (& $E $Finding.Machine)) + (& $kv $L.time (& $E $t)) + (& $kv $L.cat (& $E $catTitle)) + "</table>") '#13272B')
  $(if ($pb) { & $sec $L.why (& $E $pb.Why) '#13272B' })
  $(if ($steps) { & $sec $L.do $steps '#1f7a3a' })
  $(if ($pb -and $pb.Normal -and $pb.Normal -ne '—') { & $sec $L.normal (& $E $pb.Normal) '#6b7c80' })
  <details style="margin-top:14px"><summary style="cursor:pointer;color:#6b7c80;font-size:12px">$($L.det) · MITRE $(& $E $Finding.Mitre)</summary>
   <pre style="background:#f6f8f9;border-radius:8px;padding:12px;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;color:#22343a;margin:8px 0 0;text-align:left;direction:ltr">$(& $E $details)</pre></details>
  <div style="margin-top:12px;font-size:12px;color:#8a999c">$($L.mute)</div>
 </div>
 <div style="padding:10px 20px;background:#fafbfb;color:#8a999c;font-size:11px;border-top:1px solid #eef1f2">$($L.foot) · $name · $(& $E $env:COMPUTERNAME)</div>
</div></body></html>
"@
    return $html
}

# --- event query (with error handling and local/remote/Collector support) --
# returns: an array of events (may be empty).
function Get-LogBokEvents {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Id,
        [datetime]$StartTime,
        [string]$ComputerName,
        [int]$MaxEvents = 5000,
        $Config
    )
    # push-agent hosts read from the received store
    if ($ComputerName -and $Config -and $Config.AgentHosts -and $Config.AgentHosts.ContainsKey($ComputerName)) {
        $pp = @{ HostName = [string]$Config.AgentHosts[$ComputerName]; LogName = $LogName; MaxEvents = $MaxEvents; StateDir = (Get-LBStateDir -Config $Config) }
        if ($Id) { $pp.Id = $Id }
        if ($PSBoundParameters.ContainsKey('StartTime')) { $pp.StartTime = $StartTime }
        return @(Get-LBPushEvents @pp)
    }
    # Get-WinEvent rejects more than ~23 IDs per filter; we query in chunks
    if ($Id -and $Id.Count -gt 20) {
        $all = @()
        for ($i = 0; $i -lt $Id.Count; $i += 20) {
            $chunk = @($Id[$i..([math]::Min($i + 19, $Id.Count - 1))])
            $cp = @{ LogName = $LogName; Id = $chunk; MaxEvents = $MaxEvents; Config = $Config }
            if ($PSBoundParameters.ContainsKey('StartTime')) { $cp.StartTime = $StartTime }
            if ($ComputerName) { $cp.ComputerName = $ComputerName }
            $all += @(Get-LogBokEvents @cp)
        }
        return @($all | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents)
    }
    $filter = @{ LogName = $LogName }
    if ($Id)        { $filter.Id = $Id }
    if ($StartTime) { $filter.StartTime = $StartTime }

    $p = @{ FilterHashtable = $filter; MaxEvents = $MaxEvents; ErrorAction = 'Stop' }
    if ($ComputerName -and $ComputerName -ne 'localhost' -and $ComputerName -ne $env:COMPUTERNAME) {
        $p.ComputerName = $ComputerName
        # stored credential for this host (or the default)
        try { $cr = Get-LBTargetCredential -Computer $ComputerName -StateDir (Get-LBStateDir -Config $Config); if ($cr) { $p.Credential = $cr } } catch { }
    }
    try {
        return @(Get-WinEvent @p)
    } catch {
        # "No events were found" is a normal error -> empty array
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found|هیچ رویدادی') { return @() }
        # a harmless Windows error rendering the event text (message template not installed); it repeated every cycle and filled the log
        if ($_.Exception.Message -match 'message text for message number|message file for|find message text') { return @() }
        Write-LogBokLog -Message "خطای خواندن لاگ '$LogName' روی '$ComputerName' : $($_.Exception.Message)" -Level WARN -Config $Config
        return @()
    }
}

# returns which sources the Security log should be read from in the current mode.
# returns: an array of @{ Log=...; Computer=... }
function Get-LogBokSecuritySources {
    param($Config)
    $skip = @(Get-LBUnreachableHosts -Config $Config)
    $extra = @()
    foreach ($h in @($Config.RemoteHosts | Where-Object { $_ })) { if ($skip -notcontains $h) { $extra += @{ Log = 'Security'; Computer = $h } } }
    # push agents that send events themselves - no remote access needed
    foreach ($h in @($Config.AgentSources | Where-Object { $_ })) { $extra += @{ Log = 'Security'; Computer = $h } }
    switch ($Config.CollectionMode) {
        'Collector' { return @( @{ Log = $Config.ForwardedLog; Computer = 'localhost' } ) + $extra }
        'Remote'    {
            $out = @()
            foreach ($mch in @($Config.Machines | Select-Object -Unique)) { if ($mch -and $skip -notcontains $mch) { $out += @{ Log = 'Security'; Computer = $mch } } }
            if (-not $out) { $out = @( @{ Log = 'Security'; Computer = 'localhost' } ) }
            return $out
        }
        default     { return @( @{ Log = 'Security'; Computer = 'localhost' } ) + $extra }  # Local + registered sources
    }
}

# extract one value from the event XML (EventData) by name
function Get-LogBokEventField {
    param($Event, [string]$Name)
    try {
        $xml = [xml]$Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        if ($node) { return [string]$node.'#text' }
    } catch { }
    return $null
}

# all EventData/UserData fields, parsing the XML once
function Get-LBEventDataMap {
    param($Event)
    $m = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($n in @($xml.Event.EventData.Data)) { if ($n -and $n.Name) { $m[[string]$n.Name] = [string]$n.'#text' } }
        if ($xml.Event.UserData) { foreach ($c in @($xml.Event.UserData.ChildNodes)) { foreach ($n in @($c.ChildNodes)) { if ($n.LocalName -and -not $m.ContainsKey($n.LocalName)) { $m[[string]$n.LocalName] = [string]$n.InnerText } } } }
    } catch { }
    return $m
}

# build a unique key to avoid processing an event twice
function Get-LogBokRecordKey {
    param($Event, [string]$Computer)
    return ('{0}|{1}|{2}' -f $Computer, $Event.LogName, $Event.RecordId)
}

Export-ModuleMember -Function *
