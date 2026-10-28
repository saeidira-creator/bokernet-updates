# ==========================================================================
#  LogBok.AgentDeploy.psm1 — استقرارِ ایجنت در کلِ سازمان (الگو: ManageEngine Endpoint/Log360)
#  Organization-wide agent rollout, driven by "deployment policies":
#
#   محدوده | scope    : OUهای انتخابی (یا کلِ دامنه) + نوع (سرور/ایستگاه/DC) + فیلترِ نام
#                       + فقط اعضای گروه‌های X (تودرتو) + به‌جز اعضای گروه‌های Y
#   روش   | method    : push  — کشف و نصبِ فوری روی سیستم‌های روشن (WinRM + C$)، موازی
#                       gpo   — GPOِ «Startup Script» که روی OUها لینک می‌شود؛ هر سیستمی که
#                               روشن شود (حتی سیستمِ تازه) خودش ایجنت را نصب/به‌روز می‌کند
#                       both  — هر دو: فوری برای روشن‌ها + GPO برای خاموش‌ها و سیستم‌های آینده
#   خودکار | auto     : هر ۱۵ دقیقه سیستم‌های تازهٔ محدوده پیدا و نصب می‌شوند (جابِ Connect)
#
#  GPO مستقیم با LDAP + SYSVOL ساخته می‌شود (بدونِ نیاز به RSAT/GPMC و حتی از سرورِ workgroup
#  با حسابِ Domain Admin). همهٔ تغییرات قابلِ حذفِ کامل‌اند (Remove-LBAgentGpo).
# ==========================================================================
$script:Inv = [Globalization.CultureInfo]::InvariantCulture
$script:ScriptsCse = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
# اسکریپتِ startup + «تسکِ فوری» (Group Policy Preferences) تا بدونِ ری‌استارت هم نصب شود
# startup script + GPP Immediate Task, so computers install at the next background refresh (no restart needed)
$script:GpoCses = '[{00000000-0000-0000-0000-000000000000}{40B6664F-4972-11D1-A7CA-0000F87571E3}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'
function New-LBGpoImmediateTaskXml {
    param([string]$ScriptUnc)
    $args0 = [Security.SecurityElement]::Escape(('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $ScriptUnc))
    $uid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
    # «یک‌بار اجرا کن و دوباره اجرا نکن» (برای هر انتشار یک شناسهٔ تازه)؛ وگرنه با هر بازخوانیِ GPO (روی DC هر ۵ دقیقه) اجرا می‌شود
    # "apply once and do not reapply" (a new id per publish); otherwise it runs at every policy refresh (every 5 minutes on a DC)
    $once = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
    $chg = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    return @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="LogBok Agent Deployment" image="0" changed="$chg" uid="$uid" userContext="0" removePolicy="0"><Properties action="C" name="LogBok Agent Deployment" runAs="NT AUTHORITY\System" logonType="S4U"><Task version="1.3"><RegistrationInfo><Author>LogBok</Author><Description>Installs or updates the LogBok agent (managed by LogBok)</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>$args0</Arguments></Exec></Actions></Task></Properties><Filters><FilterRunOnce hidden="1" not="0" bool="AND" id="$once"/></Filters></ImmediateTaskV2></ScheduledTasks>
"@
}
$script:ApplyGpRight = [guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
$script:Here = Split-Path -Parent $PSCommandPath

# --- AD: اتصال و کمک‌ها | AD connection helpers -------------------------------------------
function New-LBDE {
    param([Parameter(Mandatory)][string]$Path, [pscredential]$Credential)
    if ($Credential) { return New-Object DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password) }
    return New-Object DirectoryServices.DirectoryEntry($Path)
}
function ConvertTo-LBDomainCred {
    param([pscredential]$Credential, [string]$Domain)
    if (-not $Credential -or -not $Domain) { return $Credential }
    $u = [string]$Credential.UserName
    if ($u -match '[\\@]') { return $Credential }
    return New-Object Management.Automation.PSCredential(("{0}@{1}" -f $u, $Domain), $Credential.Password)
}
function Get-LBADContext {
    param([string]$Server, [pscredential]$Credential)
    $rp = 'LDAP://' + $(if ($Server) { "$Server/" } else { '' }) + 'RootDSE'
    $rd = New-LBDE -Path $rp -Credential $Credential
    $dn = ''; $why = ''
    try { $rd.RefreshCache(); $dn = [string]$rd.Properties['defaultNamingContext'].Value } catch { $why = $_.Exception.InnerException.Message; if (-not $why) { $why = $_.Exception.Message } }
    if (-not $dn) {
        $joined = $false; try { $joined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
        if (-not $Server -and -not $joined) { throw 'این سرور عضوِ دامنه نیست؛ آدرسِ DC و یک حسابِ دامنه وارد کنید | this server is not domain-joined: enter a DC address and a domain account' }
        throw ("به اکتیودایرکتوری وصل نشد | cannot reach Active Directory{0}: {1}" -f $(if ($Server) { " ($Server)" } else { '' }), $(if ($why) { $why.Trim() } else { 'RootDSE' }))
    }
    $dc = [string]$rd.Properties['dnsHostName'].Value
    if (-not $dc) { $dc = $Server }
    $fqdn = (($dn -split ',') | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.'
    # نامِ کاربرِ بدونِ دامنه از سرورِ workgroup برای SMB حسابِ محلی حساب می‌شود؛ به UPN تبدیل شود
    # a bare user name from a workgroup server is treated as a LOCAL account by SMB: qualify it as user@domain
    $Credential = ConvertTo-LBDomainCred -Credential $Credential -Domain $fqdn
    return [pscustomobject]@{ DomainDN = $dn; Fqdn = $fqdn; DC = $dc; Server = $(if ($Server) { $Server } else { $dc }); Credential = $Credential }
}
function Get-LBADObject {
    param($Ctx, [string]$Dn)
    return New-LBDE -Path ("LDAP://{0}/{1}" -f $Ctx.Server, $Dn) -Credential $Ctx.Credential
}

# گروه‌ها برای انتخاب | groups for the include/exclude pickers
function Get-LBADGroups {
    param([string]$Like = '*', [string]$Server, [pscredential]$Credential, [int]$Max = 500)
    $ctx = Get-LBADContext -Server $Server -Credential $Credential
    $root = Get-LBADObject -Ctx $ctx -Dn $ctx.DomainDN
    $l = ([string]$Like -replace '[()\\]', ''); if (-not $l) { $l = '*' }; if ($l -notmatch '\*') { $l = "*$l*" }
    $ds = New-Object DirectoryServices.DirectorySearcher($root, "(&(objectCategory=group)(|(name=$l)(sAMAccountName=$l)))")
    $ds.PageSize = 500; $ds.SizeLimit = $Max
    foreach ($p in 'name','samaccountname','distinguishedname','description','grouptype') { [void]$ds.PropertiesToLoad.Add($p) }
    return @($ds.FindAll() | ForEach-Object {
        $pp = $_.Properties
        [pscustomobject]@{ Name = [string]($pp['name'] | Select-Object -First 1); Sam = [string]($pp['samaccountname'] | Select-Object -First 1)
                           Dn = [string]($pp['distinguishedname'] | Select-Object -First 1); Description = [string]($pp['description'] | Select-Object -First 1) }
    } | Sort-Object Name)
}
# نام/DN گروه → DN و SID | resolve a group (name, sAMAccountName or DN) to DN + SID
function Resolve-LBADGroup {
    param($Ctx, [Parameter(Mandatory)][string]$Group)
    $root = Get-LBADObject -Ctx $Ctx -Dn $Ctx.DomainDN
    $g = $Group.Trim()
    $f = if ($g -match '^CN=') { "(&(objectCategory=group)(distinguishedName=$($g -replace '[()*]', ''))" + ')' } else { $v = ($g -replace '^.*\\', '' -replace '[()*\\]', ''); "(&(objectCategory=group)(|(sAMAccountName=$v)(name=$v)))" }
    $ds = New-Object DirectoryServices.DirectorySearcher($root, $f)
    [void]$ds.PropertiesToLoad.Add('distinguishedname'); [void]$ds.PropertiesToLoad.Add('objectsid'); [void]$ds.PropertiesToLoad.Add('samaccountname')
    $r = $ds.FindOne()
    if (-not $r) { throw "گروه پیدا نشد | group not found: $Group" }
    $sid = New-Object Security.Principal.SecurityIdentifier(([byte[]]($r.Properties['objectsid'] | Select-Object -First 1)), 0)
    return [pscustomobject]@{ Dn = [string]($r.Properties['distinguishedname'] | Select-Object -First 1); Sid = $sid; Sam = [string]($r.Properties['samaccountname'] | Select-Object -First 1) }
}

# a computer account (NAME, NAME$ or name.domain) -> DN + SID, for per-computer GPO filtering
function Resolve-LBADComputer {
    param($Ctx, [Parameter(Mandatory)][string]$Name)
    $root = Get-LBADObject -Ctx $Ctx -Dn $Ctx.DomainDN
    $v = (($Name.Trim() -replace '^.*\\', '') -split '\.')[0] -replace '\$$', '' -replace '[()*\\]', ''
    $ds = New-Object DirectoryServices.DirectorySearcher($root, "(&(objectCategory=computer)(|(sAMAccountName=$v`$)(name=$v)))")
    [void]$ds.PropertiesToLoad.Add('distinguishedname'); [void]$ds.PropertiesToLoad.Add('objectsid'); [void]$ds.PropertiesToLoad.Add('samaccountname')
    $r = $ds.FindOne()
    if (-not $r) { throw "کامپیوتر در اکتیودایرکتوری پیدا نشد | computer not found in AD: $Name" }
    $sid = New-Object Security.Principal.SecurityIdentifier(([byte[]]($r.Properties['objectsid'] | Select-Object -First 1)), 0)
    return [pscustomobject]@{ Dn = [string]($r.Properties['distinguishedname'] | Select-Object -First 1); Sid = $sid; Sam = [string]($r.Properties['samaccountname'] | Select-Object -First 1) }
}

# --- سیاست‌های استقرار | deployment policies (state\agent-policies.json) -------------------
function Get-LBAgentPolicyFile { param([string]$StateDir) Join-Path $StateDir 'agent-policies.json' }
function Get-LBAgentPolicies {
    param([Parameter(Mandatory)][string]$StateDir)
    $f = Get-LBAgentPolicyFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @() }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return @($h) }; return @($h | Where-Object { $_ -is [hashtable] }) } catch { return @() }
}
function Save-LBAgentPolicies {
    param([Parameter(Mandatory)][string]$StateDir, [object[]]$Policies)
    $f = Get-LBAgentPolicyFile -StateDir $StateDir
    $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Policies) -Depth 10), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
function Get-LBAgentPolicy { param([string]$StateDir, [string]$Id) return (Get-LBAgentPolicies -StateDir $StateDir | Where-Object { [string]$_.Id -eq $Id } | Select-Object -First 1) }
function Set-LBAgentPolicy {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][hashtable]$Policy)
    if (-not $Policy.Id) { $Policy.Id = 'ap' + [guid]::NewGuid().ToString('N').Substring(0, 8) }
    if ([string]$Policy.Id -notmatch '^[A-Za-z0-9_\-]{1,40}$') { throw 'invalid policy id' }
    if (-not ([string]$Policy.Name).Trim()) { throw 'نامِ سیاست لازم است | policy name required' }
    if ([string]$Policy.Method -notin 'push','gpo','both') { $Policy.Method = 'gpo' }
    if ([string]$Policy.Type -notin 'All','Servers','Workstations','DCs') { $Policy.Type = 'All' }
    foreach ($k in 'OUs','IncludeGroups','ExcludeGroups','Computers') { $Policy[$k] = @(@($Policy[$k]) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) }
    if ($Policy.DomainId) {
        $dc0 = Get-LBADDomainConn -StateDir $StateDir -Id ([string]$Policy.DomainId)
        $Policy.Server = $dc0.Server; $Policy.CredName = $dc0.CredName; $Policy.Domain = [string]$dc0.Domain.Fqdn
    }
    if ($Policy.Collector -and [string]$Policy.Collector -notmatch '^[A-Za-z0-9_.\-:]{1,255}$') { throw 'invalid collector address' }
    if ($Policy.Server -and [string]$Policy.Server -notmatch '^[A-Za-z0-9_.\-:]{1,255}$') { throw 'invalid DC address' }
    $all = @(Get-LBAgentPolicies -StateDir $StateDir)
    $old = $all | Where-Object { [string]$_.Id -eq [string]$Policy.Id } | Select-Object -First 1
    if ($old) { foreach ($k in 'Gpo','LastRun','LastResult','LastAutoRun','Created') { if ($old.ContainsKey($k) -and -not $Policy.ContainsKey($k)) { $Policy[$k] = $old[$k] } } }
    if (-not $Policy.Created) { $Policy.Created = (Get-Date).ToString('o', $script:Inv) }
    $Policy.Updated = (Get-Date).ToString('o', $script:Inv)
    Save-LBAgentPolicies -StateDir $StateDir -Policies @(@($all | Where-Object { [string]$_.Id -ne [string]$Policy.Id }) + $Policy)
    return $Policy
}
function Update-LBAgentPolicyField {
    param([string]$StateDir, [string]$Id, [hashtable]$Fields)
    $all = @(Get-LBAgentPolicies -StateDir $StateDir)
    foreach ($p in $all) { if ([string]$p.Id -eq $Id) { foreach ($k in $Fields.Keys) { $p[$k] = $Fields[$k] } } }
    Save-LBAgentPolicies -StateDir $StateDir -Policies $all
}
function Remove-LBAgentPolicy {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Id)
    Save-LBAgentPolicies -StateDir $StateDir -Policies @(Get-LBAgentPolicies -StateDir $StateDir | Where-Object { [string]$_.Id -ne $Id })
}

# اعتبارنامهٔ دامنهٔ یک سیاست | the domain credential a policy uses
function Get-LBAgentPolicyCred {
    param($Policy, [string]$StateDir)
    if ($Policy.DomainId) { try { return (Get-LBADDomainConn -StateDir $StateDir -Id ([string]$Policy.DomainId)).Credential } catch { } }
    $n = if ($Policy.CredName) { [string]$Policy.CredName } else { 'ad-deploy' }
    $c = Get-LBTargetCredential -Computer $n -StateDir $StateDir
    return $c
}

# --- محدوده → فهرستِ سیستم‌ها | resolve a policy's scope to computers ------------------------
function Get-LBAgentPolicyTargets {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string]$StateDir, [pscredential]$Credential)
    if (-not $Credential) { $Credential = Get-LBAgentPolicyCred -Policy $Policy -StateDir $StateDir }
    $srv = [string]$Policy.Server
    $ctx = Get-LBADContext -Server $srv -Credential $Credential
    $inc = @(); foreach ($g in @($Policy.IncludeGroups)) { $inc += (Resolve-LBADGroup -Ctx $ctx -Group $g).Dn }
    $exc = @(); foreach ($g in @($Policy.ExcludeGroups)) { $exc += (Resolve-LBADGroup -Ctx $ctx -Group $g).Dn }
    $bases = @($Policy.OUs | Where-Object { $_ }); if (-not $bases.Count) { $bases = @('') }
    $seen = @{}; $out = New-Object System.Collections.ArrayList
    foreach ($b in $bases) {
        $p = @{ Type = $(if ($Policy.Type) { [string]$Policy.Type } else { 'All' }); Server = $srv; Credential = $Credential; MemberOf = $inc; NotMemberOf = $exc }
        if ($b) { $p.SearchBase = $b }
        if ($Policy.NameLike) { $p.NameLike = [string]$Policy.NameLike }
        if ($Policy.IncludeDisabled -eq $true) { $p.IncludeDisabled = $true }
        foreach ($c in @(Find-LBADComputers @p)) { if (-not $seen[$c.Name]) { $seen[$c.Name] = $true; [void]$out.Add($c) } }
    }
    # خودِ سرورِ لاگ‌بوک هرگز ایجنت نمی‌گیرد | never the LogBok server itself
    $me = $env:COMPUTERNAME
    $only = @($Policy.Computers | Where-Object { $_ } | ForEach-Object { ((([string]$_).Trim() -replace '^.*\\', '') -split '\.')[0] -replace '\$$', '' })
    if ($only.Count) { $out = @($out | Where-Object { $only -contains [string]$_.Name }) }
    return @($out | Where-Object { $_.Name -ne $me } | Sort-Object Name)
}

# --- نصبِ موازیِ گروهی | parallel batch push ---------------------------------------------------
function Start-LBAgentBatch {
    param([Parameter(Mandatory)][string]$InstallDir, [Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][object[]]$Computers,
          [string]$Collector, [string]$CredName, [string]$PolicyId, [int]$Parallel = 6)
    Assert-LBRemotePush -StateDir $StateDir
    $runner = Join-Path $InstallDir 'Run-AgentBatch.ps1'
    if (-not (Test-Path $runner)) { throw 'Run-AgentBatch.ps1 not found' }
    $id = 'b' + (Get-Date).ToString('yyyyMMddHHmmss', $script:Inv) + [guid]::NewGuid().ToString('N').Substring(0, 4)
    $items = @()
    foreach ($c in $Computers) {
        $n = [string]$c.Name; if ($n -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { continue }
        $a = [string]$c.Address; if ($a -and $a -notmatch '^[A-Za-z0-9_.\-:]{1,255}$') { $a = '' }
        $items += @{ Name = $n; Address = $a }
        Set-LBAgentStatus -StateDir $StateDir -Name $n -Fields @{ Method = 'push'; Kind = 'Windows'; Address = $a; Step = 'queued'; Ok = $null; Collector = $Collector; Policy = $PolicyId; Message = 'در صفِ نصبِ گروهی | queued (batch)' }
    }
    if (-not $items.Count) { return $null }
    $bd = Join-Path $StateDir 'agents'
    $bf = Join-Path $bd "$id.batch"
    $o = [ordered]@{ Id = $id; PolicyId = $PolicyId; Collector = $Collector; CredName = $CredName; Parallel = [math]::Max(1, [math]::Min(20, $Parallel)); Items = $items; Created = (Get-Date).ToString('o', $script:Inv) }
    [IO.File]::WriteAllText($bf, ($o | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`" -BatchFile `"$bf`"" -WindowStyle Hidden | Out-Null
    return [pscustomobject]@{ Id = $id; Count = $items.Count }
}

# اجرای یک سیاست (کشف + نصب) | run a policy: discover, register as sources, push
function Invoke-LBAgentPolicy {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string]$InstallDir, [Parameter(Mandatory)][string]$StateDir, [switch]$Auto, [switch]$Preview)
    $cred = Get-LBAgentPolicyCred -Policy $Policy -StateDir $StateDir
    $all = @(Get-LBAgentPolicyTargets -Policy $Policy -StateDir $StateDir -Credential $cred)
    $st = @{}; foreach ($x in @(Get-LBAgentStatus -StateDir $StateDir)) { $st[[string]$x.Name] = $x }
    $todo = @(); $skipOk = 0; $skipRecent = 0
    foreach ($c in $all) {
        $s = $st[[string]$c.Name]
        if ($s -and $s.Ok -eq $true -and -not ($Policy.Reinstall -eq $true -and -not $Auto)) { $skipOk++; continue }
        if ($Auto -and $s -and $s.Ok -eq $false) {
            $u = $null; try { $u = [datetime]::Parse([string]$s.Updated, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } catch { }
            if ($u -and $u -gt (Get-Date).AddHours(-6)) { $skipRecent++; continue }   # ناموفقِ اخیر: ۶ ساعت بعد دوباره | retry failed after 6h
        }
        if ($Auto -and $s -and $null -eq $s.Ok -and $s.Step -ne 'waiting') { $skipRecent++; continue }   # هنوز در حالِ نصب | in progress
        $todo += $c
    }
    $res = [ordered]@{ Matched = $all.Count; Installed = $skipOk; Queued = 0; Skipped = $skipRecent; Batch = ''; Computers = @($all | Select-Object -First 500 | ForEach-Object { [ordered]@{ name = $_.Name; address = $_.Address; os = $_.Os; ou = $_.OU; status = $(if ($st[[string]$_.Name]) { [string]$st[[string]$_.Name].Step } else { '' }); ok = $(if ($st[[string]$_.Name]) { $st[[string]$_.Name].Ok } else { $null }) } }) }
    if ($Preview) { return $res }
    if ($todo.Count) {
        # ثبت به‌عنوانِ منبعِ لاگ تا ارتباط و لاگشان پایش شود | register as monitored sources
        try { [void](Import-LBADComputers -Computers $todo -InstallDir $InstallDir -By $(if ($Auto) { 'agent-policy (auto)' } else { 'agent-policy' })) } catch { }
        $b = Start-LBAgentBatch -InstallDir $InstallDir -StateDir $StateDir -Computers $todo -Collector ([string]$Policy.Collector) -CredName $(if ($Policy.CredName) { [string]$Policy.CredName } else { 'ad-deploy' }) -PolicyId ([string]$Policy.Id) -Parallel $(if ($Policy.Parallel) { [int]$Policy.Parallel } else { 6 })
        if ($b) { $res.Queued = $b.Count; $res.Batch = $b.Id }
    }
    $f = @{ LastRun = (Get-Date).ToString('o', $script:Inv); LastResult = @{ Matched = $res.Matched; Installed = $res.Installed; Queued = $res.Queued; Skipped = $res.Skipped } }
    if ($Auto) { $f.LastAutoRun = $f.LastRun }
    Update-LBAgentPolicyField -StateDir $StateDir -Id ([string]$Policy.Id) -Fields $f
    return $res
}

# --- GPO با LDAP + SYSVOL | GPO via LDAP + SYSVOL (no RSAT/GPMC needed) ----------------------
$script:GpoStartup = @'
# ==========================================================================
#  Deploy-LogBokAgent.ps1 — GPO computer startup script (generated by LogBok)
#  Installs or updates the LogBok agent when the package in SYSVOL changes.
#  Log: C:\Windows\Temp\logbok-agent-gpo.log
# ==========================================================================
$ErrorActionPreference = 'Continue'
$src = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'LogBok-Agent'
$log = Join-Path $env:SystemRoot 'Temp\logbok-agent-gpo.log'
function L([string]$m) { try { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date).ToString('s'), $m) } catch { } }
try {
    if (Test-Path 'C:\Scripts\LogBok\engine.flag') { L 'LogBok server on this computer - skipped'; return }
    $want = (Get-Content (Join-Path $src 'version.txt') -Raw).Trim()
    $have = ''
    $aj = Join-Path $env:ProgramData 'Agent\state\agent.json'
    if (Test-Path $aj) { try { $rawA = Get-Content $aj -Raw; if ($rawA.StartsWith('LBENC1:')) { $rawA = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($rawA.Substring(7)), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) }; $have = [string]($rawA | ConvertFrom-Json).PackageStamp } catch { } }
    $tasks = @(Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction SilentlyContinue)
    if ($have -eq $want -and $tasks.Count) { L "up to date ($want)"; return }
    # ایجنتِ نصب‌شده خودش از سرور به‌روز می‌شود؛ پس نسخهٔ برابر/جدیدتر = نصبِ دوباره لازم نیست (جلوگیری از حلقهٔ نصب ↔ به‌روزرسانی)
    # an installed agent self-updates from the server: same or newer version = no reinstall (prevents the install <-> self-update loop)
    $vw = $null; $vh = $null
    try { $vw = [version](($want -split '-')[0]) } catch { }
    try { if ($have) { $vh = [version](($have -split '-')[0]) } } catch { }
    if ($tasks.Count -and $vw -and $vh -and $vh -ge $vw) { L "installed $have (self-updating; package $want) - skipped"; return }
    $tmp = Join-Path $env:SystemRoot 'Temp\LogBok-Agent-Setup'
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    Copy-Item -Path $src -Destination $tmp -Recurse -Force
    $r = & (Join-Path $tmp 'Install-LogBokAgent.ps1') -Unattended
    L ("installed {0}: {1}" -f $want, ($r -join ' '))
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
} catch { L ("ERROR " + $_.Exception.Message) }
'@

function Get-LBGpoStartupPath { param($Ctx, [string]$Guid) return "\\$($Ctx.Fqdn)\SysVol\$($Ctx.Fqdn)\Policies\$Guid\Machine\Scripts\Startup\Deploy-LogBokAgent.ps1" }

function Write-LBUnicodeFile { param([string]$Path, [string]$Text) [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UnicodeEncoding($false, $true))) }

# ساخت/به‌روزرسانیِ GPO | create or update the deployment GPO for a policy
function Publish-LBAgentGpo {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string]$InstallDir, [Parameter(Mandatory)][string]$StateDir, [pscredential]$Credential)
    if (-not $Credential) { $Credential = Get-LBAgentPolicyCred -Policy $Policy -StateDir $StateDir }
    if (-not $Credential) { throw 'برای ساختِ GPO حسابِ Domain Admin لازم است | a Domain Admin credential is required to create the GPO' }
    $ctx = Get-LBADContext -Server ([string]$Policy.Server) -Credential $Credential
    $gp = if ($Policy.Gpo) { $Policy.Gpo } else { @{} }
    $guid = [string]$gp.Guid
    $name = "LogBok Agent Deployment - $($Policy.Name)"
    $polDn = "CN=Policies,CN=System,$($ctx.DomainDN)"
    $gpc = $null
    if ($guid) { try { $gpc = Get-LBADObject -Ctx $ctx -Dn "CN=$guid,$polDn"; [void]$gpc.Properties['displayName'].Value; if (-not $gpc.psbase.Guid) { $gpc = $null } } catch { $gpc = $null } }
    $created = $false
    if (-not $gpc) {
        $guid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
        $parent = Get-LBADObject -Ctx $ctx -Dn $polDn
        $gpc = $parent.psbase.Children.Add("CN=$guid", 'groupPolicyContainer')
        $gpc.Properties['displayName'].Value = $name
        $gpc.Properties['gPCFunctionalityVersion'].Value = 2
        $gpc.Properties['gPCFileSysPath'].Value = "\\$($ctx.Fqdn)\SysVol\$($ctx.Fqdn)\Policies\$guid"
        $gpc.Properties['flags'].Value = 1          # بخشِ User غیرفعال | user configuration disabled
        $gpc.Properties['versionNumber'].Value = 0
        $gpc.CommitChanges()
        foreach ($cn in 'Machine','User') { $ch = $gpc.psbase.Children.Add("CN=$cn", 'container'); $ch.CommitChanges() }
        $created = $true
    }
    # فایل‌ها در SYSVOL | files in SYSVOL (same DC as LDAP)
    $drive = 'LBG' + [guid]::NewGuid().ToString('N').Substring(0, 5)
    New-PSDrive -Name $drive -PSProvider FileSystem -Root "\\$($ctx.DC)\SYSVOL" -Credential $ctx.Credential -ErrorAction Stop | Out-Null
    try {
        $gdir = "$($drive):\$($ctx.Fqdn)\Policies\$guid"
        $startup = Join-Path $gdir 'Machine\Scripts\Startup'
        # .NET (WriteAllText) درایوِ PS را نمی‌شناسد → مسیرِ واقعیِ UNC | .NET cannot use PS drive names → real UNC path (same SMB session)
        $gfs = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($gdir)
        $sfs = Join-Path $gfs 'Machine\Scripts\Startup'
        foreach ($d in $gdir, (Join-Path $gdir 'User'), $startup) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
        $pkgTmp = Join-Path ([IO.Path]::GetTempPath()) ('lbgpo-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        try {
            [void](New-LBAgentFolder -InstallDir $InstallDir -OutDir $pkgTmp -Collector ([string]$Policy.Collector))
            $dst = Join-Path $startup 'LogBok-Agent'
            if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
            Copy-Item -Path $pkgTmp -Destination $dst -Recurse -Force
            $stamp = (Get-Content (Join-Path $pkgTmp 'version.txt') -Raw).Trim()
        } finally { Remove-Item $pkgTmp -Recurse -Force -ErrorAction SilentlyContinue }
        [IO.File]::WriteAllText((Join-Path $sfs 'Deploy-LogBokAgent.ps1'), $script:GpoStartup, (New-Object Text.UTF8Encoding($true)))
        $ps = Get-LBGpoStartupPath -Ctx $ctx -Guid $guid
        Write-LBUnicodeFile -Path (Join-Path $gfs 'Machine\Scripts\scripts.ini') -Text ("`r`n[Startup]`r`n0CmdLine=powershell.exe`r`n0Parameters=-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ps`"`r`n")
        $pref = Join-Path $gdir 'Machine\Preferences\ScheduledTasks'
        if (-not (Test-Path $pref)) { New-Item -ItemType Directory -Path $pref -Force | Out-Null }
        [IO.File]::WriteAllText((Join-Path (Join-Path $gfs 'Machine\Preferences\ScheduledTasks') 'ScheduledTasks.xml'), (New-LBGpoImmediateTaskXml -ScriptUnc $ps), (New-Object Text.UTF8Encoding($false)))
        # نسخه: AD و GPT.INI باید یکی باشند | version must match in AD and GPT.INI
        $ver = 0; try { $ver = [int]$gpc.Properties['versionNumber'].Value } catch { }
        $ver = $ver + 1
        $gpc.Properties['versionNumber'].Value = $ver
        $gpc.Properties['gPCMachineExtensionNames'].Value = $script:GpoCses
        $gpc.Properties['displayName'].Value = $name
        $gpc.CommitChanges()
        [IO.File]::WriteAllText((Join-Path $gfs 'GPT.INI'), ("[General]`r`nVersion={0}`r`ndisplayName={1}`r`n" -f $ver, $name), [Text.Encoding]::ASCII)
    } finally { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }

    # فیلترِ امنیتی | security filtering on the GPO object
    $gpc = Get-LBADObject -Ctx $ctx -Dn "CN=$guid,$polDn"
    $gpc.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
    $sec = $gpc.psbase.ObjectSecurity
    $au = New-Object Security.Principal.SecurityIdentifier('S-1-5-11')
    $read = [DirectoryServices.ActiveDirectoryRights]'ReadProperty, ListChildren, ListObject, GenericRead'
    $inc = @(); foreach ($g in @($Policy.IncludeGroups)) { $inc += Resolve-LBADGroup -Ctx $ctx -Group $g }
    $exc = @(); foreach ($g in @($Policy.ExcludeGroups)) { $exc += Resolve-LBADGroup -Ctx $ctx -Group $g }
    # selected computers: the GPO applies only to these computer accounts
    foreach ($cn in @($Policy.Computers | Where-Object { $_ })) { $inc += Resolve-LBADComputer -Ctx $ctx -Name ([string]$cn) }
    # بازنشانیِ قواعدِ قبلیِ همین گروه‌ها | reset our managed identities
    $sec.PurgeAccessRules($au)
    foreach ($x in @($inc + $exc)) { $sec.PurgeAccessRules($x.Sid) }
    foreach ($old in @($gp.Include + $gp.Exclude | Where-Object { $_ })) { try { $sec.PurgeAccessRules((New-Object Security.Principal.SecurityIdentifier([string]$old))) } catch { } }
    $sec.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($au, $read, 'Allow')))
    if ($inc.Count) {
        foreach ($x in $inc) {
            $sec.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($x.Sid, $read, 'Allow')))
            $sec.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($x.Sid, 'ExtendedRight', 'Allow', $script:ApplyGpRight)))
        }
    } else {
        $sec.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($au, 'ExtendedRight', 'Allow', $script:ApplyGpRight)))
    }
    foreach ($x in $exc) { $sec.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($x.Sid, 'ExtendedRight', 'Deny', $script:ApplyGpRight))) }
    $gpc.CommitChanges()

    # لینک به OUها (یا ریشهٔ دامنه) | link to the OUs (or the domain root)
    $targets = @($Policy.OUs | Where-Object { $_ }); if (-not $targets.Count) { $targets = @($ctx.DomainDN) }
    $linkStr = "[LDAP://cn=$guid,cn=policies,cn=system,$($ctx.DomainDN);0]"
    foreach ($old in @($gp.Links | Where-Object { $_ -and $targets -notcontains $_ })) { Remove-LBGpoLink -Ctx $ctx -Dn $old -Guid $guid }
    foreach ($t in $targets) {
        $o = Get-LBADObject -Ctx $ctx -Dn $t
        $cur = [string]$o.Properties['gPLink'].Value
        if ($cur -notmatch [regex]::Escape("cn=$guid,")) { $o.Properties['gPLink'].Value = ($cur + $linkStr); $o.CommitChanges() }
    }
    $info = @{ Guid = $guid; Name = $name; Domain = $ctx.Fqdn; DC = $ctx.DC; Links = $targets; Stamp = $stamp; Include = @($inc | ForEach-Object { $_.Sid.Value }); Exclude = @($exc | ForEach-Object { $_.Sid.Value })
               Published = (Get-Date).ToString('o', $script:Inv); Version = $ver; Script = $ps }
    Update-LBAgentPolicyField -StateDir $StateDir -Id ([string]$Policy.Id) -Fields @{ Gpo = $info }
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9002 -EntryType Information -Message ("LogBok agent GPO {0} {1} ({2}) linked to {3}" -f $(if ($created) { 'created' } else { 'updated' }), $name, $guid, ($targets -join '; ')) } catch { }
    return [pscustomobject]$info
}
function Remove-LBGpoLink {
    param($Ctx, [string]$Dn, [string]$Guid)
    try {
        $o = Get-LBADObject -Ctx $Ctx -Dn $Dn
        $cur = [string]$o.Properties['gPLink'].Value
        $new = [regex]::Replace($cur, '\[LDAP://cn=' + [regex]::Escape($Guid) + ',[^\]]*\]', '', 'IgnoreCase')
        if ($new -ne $cur) { if ($new) { $o.Properties['gPLink'].Value = $new } else { $o.Properties['gPLink'].Clear() }; $o.CommitChanges() }
    } catch { }
}
# حذفِ کاملِ GPO | remove the GPO completely (links, AD object, SYSVOL folder)
function Remove-LBAgentGpo {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string]$StateDir, [pscredential]$Credential)
    $gp = $Policy.Gpo; if (-not $gp -or -not $gp.Guid) { return $false }
    if (-not $Credential) { $Credential = Get-LBAgentPolicyCred -Policy $Policy -StateDir $StateDir }
    $ctx = Get-LBADContext -Server ([string]$Policy.Server) -Credential $Credential
    foreach ($l in @($gp.Links)) { Remove-LBGpoLink -Ctx $ctx -Dn $l -Guid $gp.Guid }
    try { $o = Get-LBADObject -Ctx $ctx -Dn "CN=$($gp.Guid),CN=Policies,CN=System,$($ctx.DomainDN)"; $o.DeleteTree() } catch { }
    $drive = 'LBG' + [guid]::NewGuid().ToString('N').Substring(0, 5)
    try {
        New-PSDrive -Name $drive -PSProvider FileSystem -Root "\\$($ctx.DC)\SYSVOL" -Credential $ctx.Credential -ErrorAction Stop | Out-Null
        Remove-Item "$($drive):\$($ctx.Fqdn)\Policies\$($gp.Guid)" -Recurse -Force -ErrorAction SilentlyContinue
    } catch { } finally { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }
    Update-LBAgentPolicyField -StateDir $StateDir -Id ([string]$Policy.Id) -Fields @{ Gpo = $null }
    return $true
}

# آمادگی برای استقرار در دامنه | readiness check for AD deployment
function Test-LBAgentDeployReady {
    param([string]$Server, [pscredential]$Credential)
    $r = New-Object System.Collections.ArrayList
    function _a($k, $ok, $d, $fix) { [void]$r.Add([ordered]@{ check = $k; ok = [bool]$ok; detail = $d; fix = $fix }) }
    $ctx = $null
    try { $ctx = Get-LBADContext -Server $Server -Credential $Credential; _a 'ldap' $true ("{0} · DC {1}" -f $ctx.Fqdn, $ctx.DC) '' }
    catch { _a 'ldap' $false $_.Exception.Message 'آدرسِ DC و حسابِ دامنه را وارد کنید | enter the DC address and a domain account'; return $r.ToArray() }
    try {
        $pol = Get-LBADObject -Ctx $ctx -Dn "CN=Policies,CN=System,$($ctx.DomainDN)"
        $pol.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
        $can = $false
        $me = if ($ctx.Credential) { $ctx.Credential.UserName } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
        [void]$pol.psbase.ObjectSecurity
        _a 'policies-container' $true ("CN=Policies readable as {0}" -f $me) ''
    } catch { _a 'policies-container' $false $_.Exception.Message 'حساب باید عضوِ Domain Admins یا Group Policy Creator Owners باشد | the account must be a Domain Admin or Group Policy Creator Owner' }
    $drive = 'LBT' + [guid]::NewGuid().ToString('N').Substring(0, 5)
    try {
        $p = @{ Name = $drive; PSProvider = 'FileSystem'; Root = "\\$($ctx.DC)\SYSVOL"; ErrorAction = 'Stop' }; if ($ctx.Credential) { $p.Credential = $ctx.Credential }
        New-PSDrive @p | Out-Null
        $ok = Test-Path "$($drive):\$($ctx.Fqdn)\Policies"
        _a 'sysvol' $ok ("\\{0}\SYSVOL\{1}\Policies" -f $ctx.DC, $ctx.Fqdn) $(if ($ok) { '' } else { 'دسترسیِ SMB به SYSVOL (TCP 445) لازم است | SMB access to SYSVOL (TCP 445) is required' })
    } catch { _a 'sysvol' $false $_.Exception.Message 'دسترسیِ SMB به SYSVOL (TCP 445) لازم است | SMB access to SYSVOL (TCP 445) is required' }
    finally { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }
    return $r.ToArray()
}

# --- دامنه‌های ذخیره‌شده (چند دامنه) | saved domains, multi-domain (state\ad-domains.json) -----------
function Get-LBADDomainFile { param([string]$StateDir) Join-Path $StateDir 'ad-domains.json' }
function Get-LBADDomains {
    param([Parameter(Mandatory)][string]$StateDir)
    $f = Get-LBADDomainFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @() }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return @($h) }; return @($h | Where-Object { $_ -is [hashtable] }) } catch { return @() }
}
function Save-LBADDomains {
    param([Parameter(Mandatory)][string]$StateDir, [object[]]$Domains)
    $f = Get-LBADDomainFile -StateDir $StateDir; $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Domains) -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
function Get-LBADDomain { param([string]$StateDir, [string]$Id) if (-not $Id) { return $null }; return (Get-LBADDomains -StateDir $StateDir | Where-Object { [string]$_.Id -eq $Id } | Select-Object -First 1) }
function Get-LBADDomainCredName { param([string]$Id) return ('ad-' + $Id) }
# سرور و اعتبارنامهٔ یک دامنهٔ ذخیره‌شده | server + credential of a saved domain
function Get-LBADDomainConn {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Id)
    $d = Get-LBADDomain -StateDir $StateDir -Id $Id
    if (-not $d) { throw "دامنه پیدا نشد | domain not found: $Id" }
    $cr = $null; $f = Join-Path (Join-Path $StateDir 'creds') ((Get-LBADDomainCredName $Id) + '.sec')
    if (Test-Path $f) { $cr = Read-LBCredFile -File $f }
    $srv = if ($d.Server) { [string]$d.Server } elseif ($d.DC) { [string]$d.DC } else { [string]$d.Fqdn }
    return [pscustomobject]@{ Domain = $d; Server = $srv; Credential = $cr; CredName = (Get-LBADDomainCredName $Id) }
}
# آمارِ دامنه | domain inventory counts (computers by type, OUs, users, groups)
function Get-LBADStats {
    param([Parameter(Mandatory)]$Ctx)
    $root = Get-LBADObject -Ctx $Ctx -Dn $Ctx.DomainDN
    $o = [ordered]@{ Computers = 0; Servers = 0; Workstations = 0; DCs = 0; Disabled = 0; Stale = 0; OUs = 0; Users = 0; Groups = 0 }
    $cut = (Get-Date).AddDays(-45).ToFileTime()
    $ds = New-Object DirectoryServices.DirectorySearcher($root, '(objectCategory=computer)')
    $ds.PageSize = 500; foreach ($p in 'name','distinguishedname','memberof','operatingsystem','useraccountcontrol','lastlogontimestamp') { [void]$ds.PropertiesToLoad.Add($p) }
    $map = @{}
    foreach ($r in $ds.FindAll()) {
        $pp = $r.Properties; $o.Computers++
        try {
            $nm = ([string]($pp['name'] | Select-Object -First 1)).ToUpperInvariant(); $dn = [string]($pp['distinguishedname'] | Select-Object -First 1)
            $grp = @(@($pp['memberof']) | ForEach-Object { [string]$_ } | Where-Object { $_ })
            if ($nm) { $map[$nm] = @{ dn = $dn; ou = $(if ($dn -match '^CN=[^,]+,(.+)$') { $Matches[1] } else { '' }); groups = @($grp | ForEach-Object { if ($_ -match '^CN=([^,]+)') { $Matches[1] } }); groupDns = $grp; domain = $Ctx.Fqdn } }
        } catch { }
        $uac = [int]($pp['useraccountcontrol'] | Select-Object -First 1)
        if (($uac -band 2) -ne 0) { $o.Disabled++ }
        if (($uac -band 8192) -ne 0) { $o.DCs++ }
        elseif ([string]($pp['operatingsystem'] | Select-Object -First 1) -match 'Server') { $o.Servers++ } else { $o.Workstations++ }
        $ll = 0L; try { $ll = [long]($pp['lastlogontimestamp'] | Select-Object -First 1) } catch { }
        if ($ll -lt $cut) { $o.Stale++ }
    }
    foreach ($k in @(@('OUs', '(objectCategory=organizationalUnit)'), @('Users', '(&(objectCategory=person)(objectClass=user))'), @('Groups', '(objectCategory=group)'))) {
        $s2 = New-Object DirectoryServices.DirectorySearcher($root, $k[1]); $s2.PageSize = 500; [void]$s2.PropertiesToLoad.Add('name')
        $o[$k[0]] = @($s2.FindAll()).Count
    }
    $o.Map = $map
    return $o
}
# نقشهٔ کامپیوتر → OU/گروه‌ها (برای هدف‌گیریِ سیاست‌ها با OU و گروه) | computer -> OU/groups map (policy targeting by OU/group)
function Get-LBADComputerMapFile { param([string]$StateDir) Join-Path $StateDir 'ad-computers.json' }
function Save-LBADComputerMap {
    param([Parameter(Mandatory)][string]$StateDir, [hashtable]$Map, [string]$Domain)
    $f = Get-LBADComputerMapFile -StateDir $StateDir
    $cur = @{}; if (Test-Path $f) { try { $cur = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if (-not ($cur -is [hashtable])) { $cur = @{} } } catch { $cur = @{} } }
    foreach ($k in @($cur.Keys)) { if ($Domain -and [string]$cur[$k].domain -eq $Domain -and -not $Map.ContainsKey($k)) { $cur.Remove($k) } }   # حذف‌شده‌های همین دامنه | drop stale entries of this domain
    foreach ($k in $Map.Keys) { $cur[$k] = $Map[$k] }
    [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $cur -Depth 6), (New-Object Text.UTF8Encoding($false)))
    return $cur.Count
}
function Get-LBADComputerMap {
    param([Parameter(Mandatory)][string]$StateDir)
    $f = Get-LBADComputerMapFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @{} }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return $h } } catch { }
    return @{}
}
# اتصال، بررسیِ آمادگی، خواندنِ آمار و ذخیره | connect + readiness + inventory, then SAVE the domain and its encrypted credential
function Connect-LBADDomain {
    param([Parameter(Mandatory)][string]$StateDir, [string]$Id, [string]$Server, [pscredential]$Credential)
    $old = $null; if ($Id) { $old = Get-LBADDomain -StateDir $StateDir -Id $Id }
    if ($old -and -not $Credential) { $c0 = Get-LBADDomainConn -StateDir $StateDir -Id $Id; $Credential = $c0.Credential; if (-not $Server) { $Server = $c0.Server } }
    if ($Server -and $Server -notmatch '^[A-Za-z0-9_.\-:]{1,255}$') { throw 'invalid DC address' }
    $checks = @(Test-LBAgentDeployReady -Server $Server -Credential $Credential)
    $ldap = $checks | Where-Object { $_.check -eq 'ldap' } | Select-Object -First 1
    if (-not $ldap -or -not $ldap.ok) { return [pscustomobject]@{ Ok = $false; Domain = $old; Checks = $checks; Error = $(if ($ldap) { [string]$ldap.detail } else { 'ldap' }) } }
    $ctx = Get-LBADContext -Server $Server -Credential $Credential
    $stats = $null; $statErr = ''
    try { $stats = Get-LBADStats -Ctx $ctx } catch { $statErr = $_.Exception.Message }
    $all = @(Get-LBADDomains -StateDir $StateDir)
    if (-not $old) { $old = $all | Where-Object { [string]$_.Fqdn -eq $ctx.Fqdn } | Select-Object -First 1 }   # همان دامنه = به‌روزرسانی | same domain -> update
    $d = if ($old) { $old } else { @{ Id = ('d' + [guid]::NewGuid().ToString('N').Substring(0, 8)); Created = (Get-Date).ToString('o', $script:Inv) } }
    $nb = ''; try { $nb = (($ctx.Fqdn -split '\.')[0]).ToUpperInvariant() } catch { }
    $d.Fqdn = $ctx.Fqdn; $d.DomainDN = $ctx.DomainDN; $d.DC = $ctx.DC; $d.Server = $(if ($Server) { $Server } else { $ctx.DC }); $d.NetBios = $nb
    $d.User = $(if ($ctx.Credential) { [string]$ctx.Credential.UserName } else { '(this server account)' })
    $d.LastCheck = (Get-Date).ToString('o', $script:Inv)
    $d.Ready = -not @($checks | Where-Object { -not $_.ok }).Count
    $d.Checks = @($checks | ForEach-Object { @{ check = $_.check; ok = $_.ok; detail = $_.detail; fix = $_.fix } })
    if ($stats) { $m0 = $stats.Map; $stats.Remove('Map'); $d.Stats = $stats; try { if ($m0) { [void](Save-LBADComputerMap -StateDir $StateDir -Map $m0 -Domain $ctx.Fqdn) } } catch { } }; $d.LastError = $statErr
    if ($ctx.Credential) { [void](Set-LBTargetCredential -Name (Get-LBADDomainCredName $d.Id) -Credential $ctx.Credential -StateDir $StateDir) }
    # سازگاری: نخستین دامنه حسابِ پیش‌فرضِ استقرار هم می‌شود | compat: first domain also becomes the legacy deploy account
    if ($ctx.Credential -and -not @($all | Where-Object { [string]$_.Id -ne [string]$d.Id }).Count) { [void](Set-LBTargetCredential -Name 'ad-deploy' -Credential $ctx.Credential -StateDir $StateDir) }
    Save-LBADDomains -StateDir $StateDir -Domains @(@($all | Where-Object { [string]$_.Id -ne [string]$d.Id }) + $d)
    return [pscustomobject]@{ Ok = $true; Domain = $d; Checks = $checks; Error = '' }
}
function Remove-LBADDomain {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Id)
    $used = @(Get-LBAgentPolicies -StateDir $StateDir | Where-Object { [string]$_.DomainId -eq $Id })
    if ($used.Count) { throw ("این دامنه در سیاستِ «{0}» استفاده شده؛ اول آن را حذف کنید | used by deployment policy '{0}': delete it first" -f $used[0].Name) }
    Save-LBADDomains -StateDir $StateDir -Domains @(Get-LBADDomains -StateDir $StateDir | Where-Object { [string]$_.Id -ne $Id })
    Remove-LBTargetCredential -Name (Get-LBADDomainCredName $Id) -StateDir $StateDir
}

# --- گروه‌های Workgroup (بدونِ دامنه) | saved workgroup groups (state\workgroups.json) --------
#   هر گروه: نامِ دلخواه + یک حسابِ مدیرِ محلیِ مشترک (رمزگذاری‌شده) + محدودهٔ IP و/یا فهرستِ سیستم‌ها.
#   نصب از همان مسیرِ push/batch انجام می‌شود؛ هر سیستم می‌تواند حسابِ اختصاصیِ خودش را هم داشته باشد.
function Get-LBWorkgroupFile { param([string]$StateDir) Join-Path $StateDir 'workgroups.json' }
function Get-LBWorkgroups {
    param([Parameter(Mandatory)][string]$StateDir)
    $f = Get-LBWorkgroupFile -StateDir $StateDir
    if (-not (Test-Path $f)) { return @() }
    try { $h = ConvertTo-LBHashtable ((Get-Content $f -Raw -Encoding UTF8) | ConvertFrom-Json); if ($h -is [hashtable]) { return @($h) }; return @($h | Where-Object { $_ -is [hashtable] }) } catch { return @() }
}
function Save-LBWorkgroups {
    param([Parameter(Mandatory)][string]$StateDir, [object[]]$Groups)
    $f = Get-LBWorkgroupFile -StateDir $StateDir; $tmp = "$f.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject @($Groups) -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $f -Force
}
function Get-LBWorkgroup { param([string]$StateDir, [string]$Id) if (-not $Id) { return $null }; return (Get-LBWorkgroups -StateDir $StateDir | Where-Object { [string]$_.Id -eq $Id } | Select-Object -First 1) }
function Get-LBWorkgroupCredName { param([string]$Id) return ('wg-' + $Id) }
# حسابِ مشترکِ یک گروهِ ذخیره‌شده | the shared credential of a saved workgroup
function Get-LBWorkgroupCred {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Id)
    $f = Join-Path (Join-Path $StateDir 'creds') ((Get-LBWorkgroupCredName $Id) + '.sec')
    if (Test-Path $f) { return (Read-LBCredFile -File $f) }
    return $null
}
# فهرستِ نشانی‌ها از محدودهٔ IP و فهرستِ دستی | expand a range (a.b.c.d-e) and an explicit host list
function Expand-LBWgHosts {
    param([string]$Range, [string[]]$Hosts)
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($h in @($Hosts)) { $x = ([string]$h).Trim(); if ($x -and -not $seen[$x]) { $seen[$x] = $true; [void]$out.Add($x) } }
    $rg = ([string]$Range).Trim()
    if ($rg) {
        foreach ($part in ($rg -split '[,\s]+')) {
            $pp = $part.Trim(); if (-not $pp) { continue }
            if ($pp -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$') {
                $pre = $Matches[1]; $a = [int]$Matches[2]; $b = [int]$Matches[3]
                if ($a -lt 0 -or $b -gt 255 -or $a -gt $b) { continue }
                for ($i = $a; $i -le $b; $i++) { $ip = "$pre.$i"; if (-not $seen[$ip]) { $seen[$ip] = $true; [void]$out.Add($ip) } }
            } elseif ($pp -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$') { if (-not $seen[$pp]) { $seen[$pp] = $true; [void]$out.Add($pp) } }
        }
    }
    return @($out)
}
# آزمونِ یک نشانی: زنده؟ SMB(445)؟ WinRM(5985)؟ نام؟ | probe one address
function Test-LBWgHost {
    param([string]$Address, [int]$TimeoutMs = 700)
    $smb = (Test-LBTcpPort -HostName $Address -Port 445 -TimeoutMs $TimeoutMs).Ok
    $winrm = (Test-LBTcpPort -HostName $Address -Port 5985 -TimeoutMs $TimeoutMs).Ok
    $name = ''
    try { if ($Address -match '^\d{1,3}(\.\d{1,3}){3}$') { $name = [string]([Net.Dns]::GetHostEntry($Address).HostName) } else { $name = $Address } } catch { }
    if ($name -match '\.') { $name = ($name -split '\.')[0] }
    return [pscustomobject]@{ Address = $Address; Alive = ($smb -or $winrm); Smb = $smb; WinRM = $winrm; Name = $name }
}
# اسکنِ گروه + ذخیرهٔ دائمیِ آن و حسابِ مشترکِ رمزگذاری‌شده | scan a workgroup, then persist it + its encrypted shared credential
function Connect-LBWorkgroup {
    param([Parameter(Mandatory)][string]$StateDir, [string]$Id, [string]$Name, [string]$Range, [string[]]$Hosts, [pscredential]$Credential, [switch]$NoScan)
    $all = @(Get-LBWorkgroups -StateDir $StateDir)
    $old = $null; if ($Id) { $old = $all | Where-Object { [string]$_.Id -eq $Id } | Select-Object -First 1 }
    if (-not $Range -and $old) { $Range = [string]$old.Range }
    if (-not $Hosts -and $old) { $Hosts = @(Get-LBArrLocal $old.HostList) }
    $addrs = @(Expand-LBWgHosts -Range $Range -Hosts $Hosts)
    if ($addrs.Count -gt 1024) { throw 'محدوده خیلی بزرگ است (حداکثر ۱۰۲۴ نشانی) | range too large (max 1024 addresses)' }
    $machines = @()
    if (-not $NoScan) {
        foreach ($a in $addrs) { $h = Test-LBWgHost -Address $a; if ($h.Alive) { $machines += @{ name = $h.Name; address = $h.Address; smb = $h.Smb; winrm = $h.WinRM } } }
    } elseif ($old) { $machines = @(Get-LBArrLocal $old.Machines) }
    $g = if ($old) { $old } else { @{ Id = ('w' + [guid]::NewGuid().ToString('N').Substring(0, 8)); Created = (Get-Date).ToString('o', $script:Inv) } }
    if ($Name) { $g.Name = $Name } elseif (-not $g.Name) { $g.Name = 'Workgroup' }
    $g.Range = [string]$Range; $g.HostList = @($Hosts | Where-Object { $_ })
    $g.Machines = @($machines); $g.LastScan = (Get-Date).ToString('o', $script:Inv)
    $withAgent = 0
    $g.Stats = @{ Total = $machines.Count; Smb = @($machines | Where-Object { $_.smb }).Count; WinRM = @($machines | Where-Object { $_.winrm }).Count }
    if ($Credential) { [void](Set-LBTargetCredential -Name (Get-LBWorkgroupCredName $g.Id) -Credential $Credential -StateDir $StateDir) }
    Save-LBWorkgroups -StateDir $StateDir -Groups @(@($all | Where-Object { [string]$_.Id -ne [string]$g.Id }) + $g)
    return [pscustomobject]@{ Ok = $true; Group = $g }
}
function Remove-LBWorkgroup {
    param([Parameter(Mandatory)][string]$StateDir, [Parameter(Mandatory)][string]$Id)
    Save-LBWorkgroups -StateDir $StateDir -Groups @(Get-LBWorkgroups -StateDir $StateDir | Where-Object { [string]$_.Id -ne $Id })
    Remove-LBTargetCredential -Name (Get-LBWorkgroupCredName $Id) -StateDir $StateDir
}
function Get-LBArrLocal { param($v) if ($null -eq $v) { return @() }; if ($v -is [string]) { return @($v) }; return @($v) }

# اجرای خودکارِ سیاست‌ها (از جابِ Connect، هر ۱۵ دقیقه) | scheduled evaluation
function Invoke-LBAgentPoliciesAuto {
    param([Parameter(Mandatory)][string]$InstallDir, [Parameter(Mandatory)][string]$StateDir, [int]$MinMinutes = 60)
    $out = @()
    foreach ($p in @(Get-LBAgentPolicies -StateDir $StateDir)) {
        if ($p.Enabled -eq $false) { continue }
        try {
            # GPO: اگر بسته عوض شده (نشانیِ سرور/نسخه)، فایل‌های SYSVOL به‌روز شوند | refresh GPO package when it changed
            if (($p.Method -eq 'gpo' -or $p.Method -eq 'both') -and $p.Gpo -and $p.Gpo.Guid) {
                $ci = Get-LBCollectorInfo
                $want = Get-LBAgentStamp -InstallDir $InstallDir -CollectorInfo $ci -Collector $(if ($p.Collector) { [string]$p.Collector } else { $ci.Default })
                if ($want -ne [string]$p.Gpo.Stamp) { [void](Publish-LBAgentGpo -Policy $p -InstallDir $InstallDir -StateDir $StateDir); $out += "gpo-refresh:$($p.Name)" }
            }
            if ($p.Auto -eq $true -and ($p.Method -eq 'push' -or $p.Method -eq 'both') -and (Test-LBRemotePushAllowed -StateDir $StateDir)) {
                $last = $null; try { if ($p.LastAutoRun) { $last = [datetime]::Parse([string]$p.LastAutoRun, $script:Inv, [Globalization.DateTimeStyles]::RoundtripKind) } } catch { }
                if (-not $last -or $last -lt (Get-Date).AddMinutes(-$MinMinutes)) {
                    $r = Invoke-LBAgentPolicy -Policy $p -InstallDir $InstallDir -StateDir $StateDir -Auto
                    $out += ("auto:{0} matched={1} queued={2}" -f $p.Name, $r.Matched, $r.Queued)
                }
            }
        } catch {
            Update-LBAgentPolicyField -StateDir $StateDir -Id ([string]$p.Id) -Fields @{ LastError = $_.Exception.Message; LastErrorAt = (Get-Date).ToString('o', $script:Inv) }
            $out += ("error:{0}: {1}" -f $p.Name, $_.Exception.Message)
        }
    }
    try { $out += @(Invoke-LBAgentReconcile -InstallDir $InstallDir -StateDir $StateDir) } catch { }
    return $out
}

# --- آشتیِ حالتِ مطلوب: ایجنتِ مجازِ ساکت را دوباره نصب کن | desired-state reconcile -------------
#  حذف فقط از کنسول مجاز است. اگر ایجنتی که هنوز مجاز است (ادمین از کنسول حذفش نکرده) مدتی
#  گزارش ندهد، سرور از طریقِ سیاستِ استقرار (اعتبارنامهٔ ذخیره‌شده) دوباره نصبش می‌کند — هم
#  ورک‌گروپ هم دامین. اگر ادمین از کنسول حذف/ابطالش کرده باشد، دست نمی‌خورد.
#  The server is the source of truth. An authorized agent that stops reporting and was NOT removed
#  from the console is re-pushed via its deploy policy's stored credentials (workgroup or domain).
#  A host the admin removed (Removed flag / revoked / pending uninstall) is left gone.
function Invoke-LBAgentReconcile {
    param([Parameter(Mandatory)][string]$InstallDir, [Parameter(Mandatory)][string]$StateDir, [int]$SilentMinutes = 20, [int]$RetryMinutes = 60)
    $out = @()
    if (-not (Get-Command Test-LBRemotePushAllowed -ErrorAction SilentlyContinue) -or -not (Test-LBRemotePushAllowed -StateDir $StateDir)) { return $out }
    if (-not (Get-Command Get-LBAgentKeys -ErrorAction SilentlyContinue)) { return $out }
    $keys = @{}; try { $keys = Get-LBAgentKeys -StateDir $StateDir } catch { return $out }
    if (-not ($keys -is [hashtable]) -or -not $keys.Count) { return $out }
    # ماشین‌هایی که ادمین از کنسول دستورِ حذفشان را داده (در صف) هرگز دوباره نصب نشوند
    $pendingUninstall = @{}
    try {
        $aj = Join-Path $StateDir 'agent-actions.json'
        if (Test-Path $aj) { foreach ($a in @(Get-Content $aj -Raw -Encoding UTF8 | ConvertFrom-Json)) { if (([string]$a.Type -eq 'uninstall') -and (@('queued','sent') -contains [string]$a.Status)) { $pendingUninstall[([string]$a.Host).ToUpperInvariant()] = $true } } }
    } catch { }
    $st = @{}; if (Get-Command Get-LBAgentStatus -ErrorAction SilentlyContinue) { try { foreach ($x in @(Get-LBAgentStatus -StateDir $StateDir)) { $st[([string]$x.Name).ToUpperInvariant()] = $x } } catch { } }
    $now = Get-Date
    $rf = Join-Path $StateDir 'agent-reconcile.json'
    $recon = @{}; if (Test-Path $rf) { try { (Get-Content $rf -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $recon[$_.Name] = [string]$_.Value } } catch { } }
    foreach ($h in @($keys.Keys)) {
        $hn = [string]$h; $U = $hn.ToUpperInvariant(); $r = $keys[$h]
        if ([string]$r.Status -eq 'revoked') { continue }          # ادمین ابطال کرده | admin revoked
        if ($r.Removed -eq $true) { continue }                     # ادمین از کنسول حذف کرده | removed via console
        if ($pendingUninstall[$U]) { continue }                    # دستورِ حذف در صف است | uninstall in flight
        $last = ConvertTo-LBDate ([string]$r.LastTs)
        if (-not ($last -is [datetime])) { continue }              # هنوز هیچ‌وقت گزارش نداده | never reported yet
        if ($last -gt $now.AddMinutes(-$SilentMinutes)) { continue }   # هنوز گزارش می‌دهد | still reporting
        $lt = $null; if ($recon[$U]) { $lt = ConvertTo-LBDate $recon[$U] }
        if (($lt -is [datetime]) -and ($lt -gt $now.AddMinutes(-$RetryMinutes))) { continue }   # به‌تازگی تلاش شده | tried recently
        $s = $st[$U]
        if ($s -and ($null -eq $s.Ok) -and (@('queued','installing','uninstalling','waiting') -contains [string]$s.Step)) { continue }   # در حالِ نصب | in progress
        $addr = if ($s -and $s.Address) { [string]$s.Address } elseif ($r.Ip) { [string]$r.Ip } else { $hn }
        $pol = $null; if ($s -and $s.Policy -and (Get-Command Get-LBAgentPolicy -ErrorAction SilentlyContinue)) { try { $pol = Get-LBAgentPolicy -StateDir $StateDir -Id ([string]$s.Policy) } catch { } }
        $recon[$U] = $now.ToString('o', $script:Inv)
        if (-not $pol -or -not ((@('push','both') -contains [string]$pol.Method))) {
            # راهی برای نصبِ خودکار نیست (سیاست/اعتبارنامه نداریم، یا فقط GPO است که خودش بازمی‌گرداند) → فقط هشدار
            try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' }
                  Write-EventLog -LogName Application -Source 'LogBok' -EventId 9020 -EntryType Warning -Message ("AGENT MISSING on {0}: authorized agent has not reported for over {1} min. No push deploy policy/credential is set to auto-reinstall it (GPO machines reinstall on next startup). Reinstall manually or assign a deploy policy." -f $hn, $SilentMinutes) } catch { }
            $out += ("missing-no-policy:{0}" -f $hn); continue
        }
        try {
            $comp = @([pscustomobject]@{ Name = $hn; Address = $addr })
            $b = Start-LBAgentBatch -InstallDir $InstallDir -StateDir $StateDir -Computers $comp -Collector ([string]$pol.Collector) -CredName $(if ($pol.CredName) { [string]$pol.CredName } else { 'ad-deploy' }) -PolicyId ([string]$pol.Id)
            if ($b) {
                $out += ("reinstall:{0}" -f $hn)
                try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' }
                      Write-EventLog -LogName Application -Source 'LogBok' -EventId 9013 -EntryType Information -Message ("AGENT RECONCILE on {0}: authorized agent was missing for over {1} min; reinstall pushed via policy '{2}'." -f $hn, $SilentMinutes, $pol.Name) } catch { }
            }
        } catch { $out += ("reinstall-failed:{0}: {1}" -f $hn, $_.Exception.Message) }
    }
    try { [IO.File]::WriteAllText($rf, (ConvertTo-Json -InputObject $recon), (New-Object Text.UTF8Encoding($false))) } catch { }
    return $out
}

Export-ModuleMember -Function Invoke-LBAgentReconcile, New-LBDE, Get-LBADContext, Get-LBADGroups, Resolve-LBADGroup, Get-LBAgentPolicies, Save-LBAgentPolicies, Get-LBAgentPolicy, Set-LBAgentPolicy, `
    Update-LBAgentPolicyField, Remove-LBAgentPolicy, Get-LBAgentPolicyCred, Get-LBAgentPolicyTargets, Start-LBAgentBatch, Invoke-LBAgentPolicy, `
    Publish-LBAgentGpo, Remove-LBAgentGpo, Remove-LBGpoLink, Test-LBAgentDeployReady, Invoke-LBAgentPoliciesAuto, `
    Get-LBADDomains, Save-LBADDomains, Get-LBADDomain, Get-LBADDomainConn, Get-LBADStats, Connect-LBADDomain, Remove-LBADDomain, Save-LBADComputerMap, Get-LBADComputerMap, `
    Get-LBWorkgroups, Save-LBWorkgroups, Get-LBWorkgroup, Get-LBWorkgroupCred, Get-LBWorkgroupCredName, Expand-LBWgHosts, Test-LBWgHost, Connect-LBWorkgroup, Remove-LBWorkgroup
