# ==========================================================================
#  LogBok.Targets.psm1 — مدیریتِ منابعِ لاگ (سیستم، اکتیودایرکتوری، دستگاهِ شبکه، سرویس، لاگِ سفارشی)
#  Log-source management: Windows hosts, Active Directory discovery/import,
#  network (syslog) devices, services, custom event-channel / file logs,
#  per-source credentials. Registry: state\targets.json (merged into config
#  by Get-LogBokConfig, so every detector/archive/connectivity test uses it).
#  هم کنسول و هم کنسولِ وب از همین توابع استفاده می‌کنند.
# ==========================================================================

$script:Here = Split-Path -Parent $PSCommandPath
if (-not (Get-Command Get-LBTargetList -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $script:Here 'LogBok.Core.psm1') -DisableNameChecking -ErrorAction SilentlyContinue
}
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:Kinds = @('Windows','NetworkDevice','Linux','Service')
$script:Roles = @('DC','SQL','IIS','FTP','DHCP','Apache','File')
$script:DeviceTypes = @('Switch','Router','Firewall','AccessPoint','NVR','Printer','UPS','Storage','Other')

function Get-LBTargetStateDir { param([string]$InstallDir) if (-not $InstallDir) { $InstallDir = Split-Path $script:Here -Parent; if (-not (Test-Path (Join-Path $InstallDir 'config.psd1'))) { $InstallDir = $script:Here } }; $c = $null; try { $c = Import-PowerShellDataFile (Join-Path $InstallDir 'config.psd1') } catch { }; return (Get-LBStateDir -Config $c -Root $InstallDir) }

function Get-LBTargets {
    param([string]$InstallDir)
    return @(Get-LBTargetList -StateDir (Get-LBTargetStateDir -InstallDir $InstallDir))
}
function Save-LBTargets {
    param([object[]]$Targets, [string]$InstallDir)
    $sd = Get-LBTargetStateDir -InstallDir $InstallDir
    $f = Get-LBTargetsFile -StateDir $sd
    $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Targets) -Depth 10), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
function Get-LBTarget {
    param([Parameter(Mandatory)][string]$Name, [string]$InstallDir)
    return (Get-LBTargets -InstallDir $InstallDir | Where-Object { $_.Name -eq $Name -or $_.Address -eq $Name } | Select-Object -First 1)
}

function Write-LBTargetAudit {
    param([string]$Message)
    try { if (-not [Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch { }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9002 -EntryType Information -Message $Message } catch { }
}

# افزودن/به‌روزرسانیِ یک منبع | add or update a source (upsert by Name)
function Add-LBTarget {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Address,
        [ValidateSet('Windows','NetworkDevice','Linux','Service')][string]$Kind = 'Windows',
        [string[]]$Roles = @(),
        [int[]]$Ports = @(),
        [ValidateSet('remote','agent','syslog','probe','none')][string]$Monitor,
        [string]$DeviceType,
        [string]$Source = 'manual',
        [string]$Notes,
        [string]$Os,
        [string]$InstallDir,
        [string]$By
    )
    $Name = $Name.Trim()
    if (-not $Name) { throw 'نام خالی است | name is empty' }
    if ($Name -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { throw "نامِ نامعتبر | invalid name: $Name" }
    if ($Address) { $Address = $Address.Trim(); if ($Address -notmatch '^[A-Za-z0-9_.\-:]{1,255}$') { throw "آدرسِ نامعتبر | invalid address: $Address" } }
    if (-not $Monitor) { $Monitor = switch ($Kind) { 'Windows' { 'remote' } 'NetworkDevice' { 'syslog' } default { 'probe' } } }
    $Roles = @($Roles | Where-Object { $_ } | ForEach-Object { [string]$_ } | Where-Object { $script:Roles -contains $_ } | Select-Object -Unique)
    $Ports = @($Ports | Where-Object { $_ -gt 0 -and $_ -lt 65536 } | Select-Object -Unique)
    $all = @(Get-LBTargets -InstallDir $InstallDir)
    $ex = $all | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    $now = (Get-Date).ToString('o', $script:Inv)
    if ($ex) {
        $ex.Address = $Address; $ex.Kind = $Kind; $ex.Roles = $Roles; $ex.Ports = $Ports; $ex.Monitor = $Monitor
        if ($PSBoundParameters.ContainsKey('DeviceType')) { $ex.DeviceType = $DeviceType }
        if ($PSBoundParameters.ContainsKey('Notes')) { $ex.Notes = $Notes }
        if ($Os) { $ex.Os = $Os }
        $ex.Updated = $now
        $t = $ex
    } else {
        $t = @{ Name=$Name; Address=$Address; Kind=$Kind; Roles=$Roles; Ports=$Ports; Monitor=$Monitor; DeviceType=$DeviceType
                Source=$Source; Notes=$Notes; Os=$Os; Enabled=$true; Added=$now; Updated=$now; Custom=@() }
        $all += $t
    }
    Save-LBTargets -Targets $all -InstallDir $InstallDir
    Write-LBTargetAudit ("LogBok source added/updated: {0} ({1} {2}) by {3}" -f $Name, $Kind, $Address, $(if ($By) { $By } else { $env:USERNAME }))
    return $t
}
function Remove-LBTarget {
    param([Parameter(Mandatory)][string]$Name, [string]$InstallDir, [string]$By)
    $all = @(Get-LBTargets -InstallDir $InstallDir)
    $left = @($all | Where-Object { $_.Name -ne $Name })
    if ($left.Count -eq $all.Count) { return $false }
    Save-LBTargets -Targets $left -InstallDir $InstallDir
    try { Remove-LBTargetCredential -Name $Name -StateDir (Get-LBTargetStateDir -InstallDir $InstallDir) } catch { }
    Write-LBTargetAudit ("LogBok source removed: {0} by {1}" -f $Name, $(if ($By) { $By } else { $env:USERNAME }))
    return $true
}
function Set-LBTargetEnabled {
    param([Parameter(Mandatory)][string]$Name, [bool]$Enabled, [string]$InstallDir)
    $all = @(Get-LBTargets -InstallDir $InstallDir)
    foreach ($t in $all) { if ($t.Name -eq $Name) { $t.Enabled = $Enabled } }
    Save-LBTargets -Targets $all -InstallDir $InstallDir
}

# --- لاگِ سفارشی روی یک منبع | custom log source on a target ------------------
#  Type EventLog: هر کانالِ رویدادِ ویندوز (مثلاً Microsoft-Windows-TerminalServices-...)، با Ids و/یا Keywords
#  Type File    : فایلِ متنیِ لاگ (محلی یا روی سیستمِ راه‌دور از طریقِ اشتراکِ مدیریتی)، با Keywords
function Add-LBCustomSource {
    param(
        [Parameter(Mandatory)][string]$Target,
        [ValidateSet('EventLog','File')][string]$Type = 'EventLog',
        [Parameter(Mandatory)][string]$Name,
        [string]$Log, [int[]]$Ids = @(), [string]$Path,
        [string[]]$Keywords = @(),
        [ValidateSet('Critical','Warning','Info')][string]$Severity = 'Warning',
        [bool]$Alert = $true,
        [string]$InstallDir
    )
    if ($Type -eq 'EventLog' -and -not $Log) { throw 'نامِ کانالِ رویداد لازم است | event channel name required' }
    if ($Type -eq 'File' -and -not $Path) { throw 'مسیرِ فایل لازم است | file path required' }
    if ($Type -eq 'File' -and $Path -notmatch '^[A-Za-z]:\\') { throw 'مسیر باید کامل باشد، مثل D:\App\logs\app.log | absolute path required' }
    $all = @(Get-LBTargets -InstallDir $InstallDir)
    $t = $all | Where-Object { $_.Name -eq $Target } | Select-Object -First 1
    if (-not $t) { throw "منبع پیدا نشد | source not found: $Target" }
    $id = 'c' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $c = @{ Id=$id; Type=$Type; Name=$Name; Log=$Log; Ids=@($Ids | Where-Object { $_ -gt 0 }); Path=$Path
            Keywords=@($Keywords | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }); Severity=$Severity; Alert=$Alert }
    $t.Custom = @(@($t.Custom | Where-Object { $_ }) + $c)
    Save-LBTargets -Targets $all -InstallDir $InstallDir
    Write-LBTargetAudit ("LogBok custom log added on {0}: {1} {2}{3}" -f $Target, $Type, $Log, $Path)
    return $c
}
function Remove-LBCustomSource {
    param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$Id, [string]$InstallDir)
    $all = @(Get-LBTargets -InstallDir $InstallDir)
    foreach ($t in $all) { if ($t.Name -eq $Target) { $t.Custom = @($t.Custom | Where-Object { $_ -and $_.Id -ne $Id }) } }
    Save-LBTargets -Targets $all -InstallDir $InstallDir
}

# --- خودِ این سرور (برای تنظیمِ syslog روی دستگاه‌ها) | this server's IPv4s ----
function Get-LBServerIPs {
    $ips = @()
    try {
        foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up' -or $ni.NetworkInterfaceType -eq 'Loopback') { continue }
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq 'InterNetwork' -and -not $ua.Address.ToString().StartsWith('169.254.')) { $ips += $ua.Address.ToString() }
            }
        }
    } catch { }
    return @($ips | Select-Object -Unique)
}

# راهنمای ارسالِ syslog برای هر نوع دستگاه | per-device syslog setup hint
function Get-LBSyslogHint {
    param([string]$DeviceType, [string]$ServerIp, [int]$Port = 514)
    if (-not $ServerIp) { $ServerIp = (Get-LBServerIPs | Select-Object -First 1) }
    $lines = switch -Regex ([string]$DeviceType) {
        'Switch|Router' { @("Cisco IOS:  logging host $ServerIp", "            logging trap informational", "MikroTik:   /system logging action set remote remote=$ServerIp remote-port=$Port", "            /system logging add topics=info,warning,error,critical action=remote") }
        'Firewall'      { @("FortiGate:  config log syslogd setting / set status enable / set server $ServerIp / end", "pfSense:    Status > System Logs > Settings > Remote log servers: ${ServerIp}:$Port", "Sophos/others: Syslog server = $ServerIp, UDP $Port") }
        'NVR'           { @("NVR/Camera: Configuration > Network > Advanced > Syslog server = $ServerIp, port $Port (UDP)") }
        default         { @("Syslog server = $ServerIp, UDP port $Port") }
    }
    return @($lines)
}

# --- تشخیصِ نقشِ سرور با آزمونِ پورت | role detection by TCP probes -----------
function Find-LBTargetRoles {
    param([Parameter(Mandatory)][string]$Address, [int]$TimeoutMs = 600)
    if (-not (Get-Command Test-LBTcpPort -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $script:Here 'LogBok.Connect.psm1') -DisableNameChecking -ErrorAction SilentlyContinue }
    $roles = @()
    $probe = { param($p) (Test-LBTcpPort -HostName $Address -Port $p -TimeoutMs $TimeoutMs).Ok }
    if ((& $probe 1433)) { $roles += 'SQL' }
    if ((& $probe 80) -or (& $probe 443)) { $roles += 'IIS' }
    if ((& $probe 21)) { $roles += 'FTP' }
    if ((& $probe 389) -and (& $probe 88)) { $roles += 'DC' }
    return @($roles)
}

# ---------------------------------------------------------------------------
#  اکتیودایرکتوری | Active Directory (ADSI — بدونِ نیاز به RSAT)
# ---------------------------------------------------------------------------
function Get-LBADRoot {
    param([string]$Server, [pscredential]$Credential, [string]$SearchBase)
    $path = 'LDAP://'
    if ($Server) { $path += "$Server/" }
    if ($SearchBase) { $path += $SearchBase }
    else {
        $rp = 'LDAP://' + $(if ($Server) { "$Server/" } else { '' }) + 'RootDSE'
        $rd = if ($Credential) { New-Object DirectoryServices.DirectoryEntry($rp, $Credential.UserName, $Credential.GetNetworkCredential().Password) } else { New-Object DirectoryServices.DirectoryEntry($rp) }
        $dn = [string]$rd.Properties['defaultNamingContext'].Value
        if (-not $dn) { throw 'به اکتیودایرکتوری وصل نشد (RootDSE) | cannot reach AD (RootDSE)' }
        $path += $dn
    }
    if ($Credential) { return New-Object DirectoryServices.DirectoryEntry($path, $Credential.UserName, $Credential.GetNetworkCredential().Password) }
    return New-Object DirectoryServices.DirectoryEntry($path)
}

# وضعیتِ اتصال به دامنه با جزئیات و دلیلِ شکست | domain connection diagnosis
function Test-LBADConnection {
    param([string]$Server, [pscredential]$Credential, [int]$TimeoutMs = 1500)
    if (-not (Get-Command New-LBConn -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $script:Here 'LogBok.Connect.psm1') -DisableNameChecking -ErrorAction SilentlyContinue }
    $res = New-Object System.Collections.ArrayList
    $self = $env:COMPUTERNAME
    # ۱) عضوِ دامنه؟ | domain-joined?
    $joined = $false; $domain = ''
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $joined = [bool]$cs.PartOfDomain; $domain = [string]$cs.Domain } catch { }
    [void]$res.Add((New-LBConn -Target 'AD' -Channel 'domain-joined' -Ok ($joined -or [bool]$Server) -Ms 0 -State $(if ($joined) { 'OK' } elseif ($Server) { 'Warn' } else { 'Fail' }) `
        -Detail $(if ($joined) { $domain } else { 'workgroup' }) `
        -Reason $(if ($joined -or $Server) { '' } else { 'این سرور عضوِ دامنه نیست | this server is not domain-joined' }) `
        -Remedy 'سرور را عضوِ دامنه کنید، یا آدرسِ DC و اعتبارنامهٔ دامنه را وارد کنید | join the domain, or enter a DC address and domain credentials'))
    # ۲) پیدا کردنِ DCها | locate domain controllers
    $dcs = @()
    if ($Server) { $dcs = @($Server) }
    elseif ($joined) {
        try { $d = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); foreach ($dc in $d.DomainControllers) { $dcs += [string]$dc.Name } } catch { }
        if (-not $dcs.Count) { try { $dcs = @(([Net.Dns]::GetHostAddresses($domain) | Select-Object -First 3 | ForEach-Object { $_.IPAddressToString })) } catch { } }
    }
    [void]$res.Add((New-LBConn -Target 'AD' -Channel 'domain-controllers' -Ok ($dcs.Count -gt 0) -Ms 0 `
        -Detail ($dcs -join ', ') `
        -Reason $(if ($dcs.Count) { '' } else { 'هیچ کنترل‌کنندهٔ دامنه‌ای پیدا نشد (DNS) | no domain controller found (DNS)' }) `
        -Remedy 'DNSِ این سرور باید به DNSِ دامنه اشاره کند | point this server''s DNS to the domain DNS'))
    # ۳) پورت‌های لازم روی هر DC | required ports on each DC
    $ports = [ordered]@{ 389='LDAP'; 88='Kerberos'; 53='DNS'; 445='SMB'; 135='RPC'; 3268='GC' }
    foreach ($dc in ($dcs | Select-Object -First 3)) {
        foreach ($p in $ports.Keys) {
            $r = Test-LBTcpPort -HostName $dc -Port $p -TimeoutMs $TimeoutMs
            $isGc = ($p -eq 3268)
            [void]$res.Add((New-LBConn -Target $dc -Channel ("{0}-{1}" -f $ports[$p].ToLowerInvariant(), $p) -Ok ($r.Ok -or $isGc) -Ms $r.Ms -State $(if ($r.Ok) { 'OK' } elseif ($isGc) { 'Warn' } else { 'Fail' }) `
                -Detail ("TCP {0} ({1})" -f $p, $ports[$p]) `
                -Reason $(if ($r.Ok -or $isGc) { '' } else { ("پورتِ {0} روی DC بسته است | TCP {0} on the DC is closed or filtered" -f $p) }) `
                -Remedy ("فایروالِ بینِ این سرور و DC را برای پورتِ {0} باز کنید | allow TCP {0} between this server and the DC" -f $p)))
        }
    }
    # ۴) اتصالِ واقعیِ LDAP و شمارشِ کامپیوترها | real LDAP bind
    $ldapOk = $false; $detail = ''; $reason = ''; $remedy = ''
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $root = Get-LBADRoot -Server $Server -Credential $Credential
        $ds = New-Object DirectoryServices.DirectorySearcher($root, '(objectCategory=computer)')
        $ds.PageSize = 200; $ds.SizeLimit = 1; [void]$ds.PropertiesToLoad.Add('name')
        $one = $ds.FindOne()
        $ldapOk = $true; $detail = [string]$root.Path
    } catch {
        $m = $_.Exception.Message
        if ($m -match 'password|credentials|logon failure|نام کاربری|0x8007052e') { $reason = 'نام کاربری یا گذرواژهٔ دامنه نادرست است | invalid domain credentials'; $remedy = 'اعتبارنامهٔ دامنه را درست وارد کنید | enter valid domain credentials' }
        elseif ($m -match 'server is not operational|0x8007203a') { $reason = 'سرورِ LDAP در دسترس نیست | LDAP server not reachable'; $remedy = 'آدرسِ DC و پورتِ 389 را بررسی کنید | check the DC address and TCP 389' }
        else { $reason = ("اتصال به LDAP ناموفق | LDAP bind failed: {0}" -f $m); $remedy = 'آدرسِ DC، DNS و اعتبارنامه را بررسی کنید | check DC address, DNS and credentials' }
    }
    [void]$res.Add((New-LBConn -Target 'AD' -Channel 'ldap-bind' -Ok $ldapOk -Ms ([int]$sw.ElapsedMilliseconds) -Detail $detail -Reason $reason -Remedy $remedy))
    # ۵) RSAT (اطلاعی) | AD PowerShell module (informational)
    $rsat = [bool](Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    [void]$res.Add((New-LBConn -Target 'AD' -Channel 'rsat-ad-module' -Ok $true -Ms 0 -State $(if ($rsat) { 'OK' } else { 'Warn' }) `
        -Detail $(if ($rsat) { 'installed | نصب است' } else { 'نصب نیست؛ کشف با ADSI کار می‌کند | not installed; ADSI discovery still works' }) -Reason '' -Remedy ''))
    return $res.ToArray()
}

# فهرستِ کامپیوترهای دامنه | list domain computers
function Find-LBADComputers {
    param(
        [ValidateSet('All','Servers','Workstations','DCs')][string]$Type = 'All',
        [string]$SearchBase, [string]$NameLike, [switch]$IncludeDisabled,
        [string]$Server, [pscredential]$Credential, [int]$Max = 5000,
        [string[]]$MemberOf = @(), [string[]]$NotMemberOf = @()   # DNهای گروه (عضویتِ تودرتو) | group DNs, nested membership
    )
    $root = Get-LBADRoot -Server $Server -Credential $Credential -SearchBase $SearchBase
    $esc = { param($v) (([string]$v) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00') }
    $f = '(&(objectCategory=computer)'
    $inc = @($MemberOf | Where-Object { $_ })
    if ($inc.Count) { $f += '(|' + (($inc | ForEach-Object { '(memberOf:1.2.840.113556.1.4.1941:=' + (& $esc $_) + ')' }) -join '') + ')' }
    foreach ($x in @($NotMemberOf | Where-Object { $_ })) { $f += '(!(memberOf:1.2.840.113556.1.4.1941:=' + (& $esc $x) + '))' }
    if (-not $IncludeDisabled) { $f += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' }
    switch ($Type) {
        'DCs'          { $f += '(userAccountControl:1.2.840.113556.1.4.803:=8192)' }
        'Servers'      { $f += '(operatingSystem=*Server*)' }
        'Workstations' { $f += '(!(operatingSystem=*Server*))' }
    }
    if ($NameLike) { $safe = ($NameLike -replace '[()\\]', ''); $f += "(name=$safe)" }
    $f += ')'
    $ds = New-Object DirectoryServices.DirectorySearcher($root, $f)
    $ds.PageSize = 500; $ds.SizeLimit = $Max
    foreach ($p in 'name','dnshostname','operatingsystem','operatingsystemversion','useraccountcontrol','lastlogontimestamp','distinguishedname','description') { [void]$ds.PropertiesToLoad.Add($p) }
    $known = @{}; foreach ($t in (Get-LBTargets)) { $known[[string]$t.Name] = $true }
    $out = New-Object System.Collections.ArrayList
    foreach ($r in $ds.FindAll()) {
        $pp = $r.Properties
        $name = [string]($pp['name'] | Select-Object -First 1)
        $uac = [int]($pp['useraccountcontrol'] | Select-Object -First 1)
        $ll = $null; try { $v = $pp['lastlogontimestamp'] | Select-Object -First 1; if ($v) { $ll = [datetime]::FromFileTime([long]$v).ToString('yyyy-MM-dd', $script:Inv) } } catch { }
        $dn = [string]($pp['distinguishedname'] | Select-Object -First 1)
        [void]$out.Add([pscustomobject]@{
            Name = $name
            Address = [string]($pp['dnshostname'] | Select-Object -First 1)
            Os = [string]($pp['operatingsystem'] | Select-Object -First 1)
            IsDC = (($uac -band 8192) -ne 0)
            Enabled = (($uac -band 2) -eq 0)
            LastLogon = $ll
            OU = $(if ($dn -match '^CN=[^,]+,(.+)$') { $Matches[1] } else { '' })
            Added = [bool]$known[$name]
        })
    }
    return @($out | Sort-Object Name)
}

# واحدهای سازمانی (برای انتخابِ محدوده) | list OUs
function Get-LBADOUs {
    param([string]$Server, [pscredential]$Credential)
    $root = Get-LBADRoot -Server $Server -Credential $Credential
    $ds = New-Object DirectoryServices.DirectorySearcher($root, '(objectCategory=organizationalUnit)')
    $ds.PageSize = 500; [void]$ds.PropertiesToLoad.Add('distinguishedname')
    return @($ds.FindAll() | ForEach-Object { [string]($_.Properties['distinguishedname'] | Select-Object -First 1) } | Sort-Object)
}

# افزودنِ کامپیوترهای انتخاب‌شده به منابع | import selected computers as sources
function Import-LBADComputers {
    param([object[]]$Computers, [switch]$DetectRoles, [string]$InstallDir, [string]$By)
    $n = 0
    foreach ($c in $Computers) {
        $name = [string]$c.Name; if (-not $name) { continue }
        $addr = if ($c.Address) { [string]$c.Address } else { $name }
        $roles = @(); if ($c.IsDC -eq $true -or [string]$c.IsDC -eq 'True') { $roles += 'DC' }
        if ($DetectRoles -and @($Computers).Count -le 50) { try { $roles += @(Find-LBTargetRoles -Address $addr -TimeoutMs 400) } catch { } }
        [void](Add-LBTarget -Name $name -Address $addr -Kind 'Windows' -Roles @($roles | Select-Object -Unique) -Source 'ad' -Os ([string]$c.Os) -InstallDir $InstallDir -By $By)
        $n++
    }
    return $n
}

Export-ModuleMember -Function Get-LBTargets, Save-LBTargets, Get-LBTarget, Add-LBTarget, Remove-LBTarget, Set-LBTargetEnabled, `
    Add-LBCustomSource, Remove-LBCustomSource, Get-LBServerIPs, Get-LBSyslogHint, Find-LBTargetRoles, `
    Test-LBADConnection, Find-LBADComputers, Get-LBADOUs, Import-LBADComputers, Get-LBTargetStateDir
