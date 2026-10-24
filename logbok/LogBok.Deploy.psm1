# ==========================================================================
#  LogBok.Deploy.psm1 - نصبِ گروهیِ ایجنت روی سیستم‌های سازمان
#
#  سه محیط پشتیبانی می‌شود و در یک فهرستِ واحد می‌توانند ترکیب شوند:
#   - domain    : سیستمِ عضوِ Active Directory (احراز هویت با Kerberos؛
#                 نیازی به گذرواژهٔ هر سیستم نیست)
#   - workgroup : سیستمِ بدونِ دامنه (به گذرواژهٔ Administratorِ محلیِ همان
#                 سیستم نیاز دارد؛ از «گاوصندوقِ اعتبارنامه» خوانده می‌شود)
#
#  روش‌های تحویل | delivery methods:
#   - GPO   : بهترین روش برای دامنه؛ خودِ سیستم‌ها هنگامِ راه‌اندازی خود را
#             پیکربندی می‌کنند. بدونِ گذرواژه، بدونِ push، تا هزاران سیستم.
#   - Push  : کپیِ فایل‌ها از راه دور (admin share) + نصب از راه دور (WinRM).
#             برای workgroup و برای دامنه‌های کوچک.
#
#  مرزِ صادقانه: این نصب فقط روی سیستم‌هایی انجام می‌شود که ادمینِ آن‌ها
#  اعتبارنامهٔ مدیر دارد. از سازوکارهای مستندِ ویندوز استفاده می‌شود
#  (WinRM, admin share, GPO) و هیچ تکنیکِ پنهان‌سازی/دور زدن در کار نیست.
# ==========================================================================

$script:Inv = [Globalization.CultureInfo]::InvariantCulture

# فایل‌هایی که کلاینت (فقط ایجنت) لازم دارد | files an agent needs
$script:AgentFiles = @(
    'config.psd1','policies.psd1','LogBok.Core.psm1','LogBok.Agent.psm1','LogBok.Jobs.psm1',
    'LogBok.License.psm1','LogBok.Lang.psm1','LogBok.Firewall.psm1','LogBok.AntiRansomware.psm1',
    'LogBok.Behavior.psm1','LogBok.Policy.psm1','LogBok.Scanner.psm1','LogBok.Identity.psm1',
    'LogBok.Update.psm1','LogBok.Threat.psm1','LogBok.Traffic.psm1','LogBok.FwGovernance.psm1',
    'LogBok.FIM.psm1','LogBok.Guard.psm1','LogBok.Connect.psm1','Run-Watchdog.ps1','Run-Guard.ps1','Run-Connect.ps1'
)

# ---------------------------------------------------------------------------
#  ۱) گاوصندوقِ اعتبارنامه (فقط روی سرورِ مدیریت، با DPAPIِ همان ادمین)
#     Export-Clixml گذرواژه را با DPAPIِ کاربرِ فعلی رمز می‌کند؛ فقط همان
#     حساب روی همان سرور می‌تواند بازش کند. یک‌بار وارد می‌کنید، بارها استفاده.
# ---------------------------------------------------------------------------
function Get-LBVaultPath { param([string]$InstallDir) Join-Path $InstallDir 'state\deploy-vault.xml' }

function Import-LBVault {
    param([string]$InstallDir)
    $f = Get-LBVaultPath $InstallDir
    if (Test-Path $f) { try { return (Import-Clixml $f) } catch { } }
    return @{}
}
function Save-LBVault {
    param([string]$InstallDir, $Vault)
    $d = Join-Path $InstallDir 'state'
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $Vault | Export-Clixml -Path (Get-LBVaultPath $InstallDir)
}
# ذخیرهٔ یک اعتبارنامه: برای یک سیستمِ خاص یا مشترک (__shared__)
function Set-LBDeployCred {
    param([string]$InstallDir, [string]$Computer = '__shared__', [pscredential]$Credential)
    $v = Import-LBVault $InstallDir
    if (-not ($v -is [hashtable])) { $v = @{} }
    $v[$Computer] = $Credential
    Save-LBVault -InstallDir $InstallDir -Vault $v
}
# خواندنِ اعتبارنامهٔ یک سیستم: اول اختصاصی، بعد مشترک | per-host then shared
function Get-LBDeployCred {
    param([string]$InstallDir, [string]$Computer)
    $v = Import-LBVault $InstallDir
    if ($v -is [hashtable]) {
        if ($Computer -and $v.ContainsKey($Computer) -and $v[$Computer]) { return $v[$Computer] }
        if ($v.ContainsKey('__shared__') -and $v['__shared__']) { return $v['__shared__'] }
    }
    return $null
}

# ---------------------------------------------------------------------------
#  ۲) کشفِ سیستم‌ها | discover targets
# ---------------------------------------------------------------------------
# از Active Directory (بدونِ نیاز به RSAT؛ با [adsisearcher])
function Get-LBAdComputers {
    param([string]$SearchBase)
    $out = New-Object System.Collections.ArrayList
    try {
        $filter = '(&(objectCategory=computer)(operatingSystem=*Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        $searcher = if ($SearchBase) { [adsisearcher]([adsi]"LDAP://$SearchBase", $filter) } else { [adsisearcher]$filter }
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('dnshostname','name','operatingSystem','primaryGroupID')) | Out-Null
        foreach ($r in $searcher.FindAll()) {
            $p = $r.Properties
            $host2 = if ($p['dnshostname'].Count) { [string]$p['dnshostname'][0] } else { [string]$p['name'][0] }
            if (-not $host2) { continue }
            $os = if ($p['operatingSystem'].Count) { [string]$p['operatingSystem'][0] } else { '' }
            $pgid = if ($p['primarygroupid'].Count) { [int]$p['primarygroupid'][0] } else { 0 }
            $role = Get-LBGuessRole -Os $os -PrimaryGroupId $pgid
            [void]$out.Add([pscustomobject]@{ Computer=$host2; Role=$role; Type='domain'; OS=$os })
        }
    } catch { Write-Warning "AD discovery failed: $($_.Exception.Message)" }
    return $out.ToArray()
}
# حدسِ نقش از سیستم‌عاملِ AD | guess the license role
function Get-LBGuessRole {
    param([string]$Os, [int]$PrimaryGroupId = 0)
    if ($PrimaryGroupId -eq 516 -or $PrimaryGroupId -eq 521) { return 'DomainControllers' }  # DC / RODC
    if ($Os -match 'Server') { return 'FileServers' }   # پیش‌فرضِ سرور؛ در CSV قابل‌تصحیح
    return 'Clients'
}
# از محدودهٔ IP (برای محیطِ بدونِ دامنه) | from an IP range
function Get-LBRangeComputers {
    param([string]$Prefix, [int]$From = 1, [int]$To = 254, [string]$Role = 'Clients', [string]$Type = 'workgroup')
    $out = New-Object System.Collections.ArrayList
    for ($i = $From; $i -le $To; $i++) {
        $ip = "$Prefix.$i"
        $ok = $false
        try { $ok = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue } catch {}
        if ($ok) { [void]$out.Add([pscustomobject]@{ Computer=$ip; Role=$Role; Type=$Type; OS='' }) }
    }
    return $out.ToArray()
}
# از فایلِ CSV | from a CSV:  Computer,Role,Type[,Username,Password]
function Get-LBCsvComputers {
    param([string]$Path)
    $out = New-Object System.Collections.ArrayList
    foreach ($row in (Import-Csv -Path $Path)) {
        $c = ([string]$row.Computer).Trim()
        if (-not $c) { continue }
        $role = if ($row.Role) { [string]$row.Role } else { 'Clients' }
        $type = if ($row.Type) { ([string]$row.Type).ToLower() } else { 'domain' }
        if ($type -notin 'domain','workgroup') { $type = 'domain' }
        $o = [pscustomobject]@{ Computer=$c; Role=$role; Type=$type; OS=''; Username=([string]$row.Username); Password=([string]$row.Password) }
        [void]$out.Add($o)
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
#  ۳) اعتبارنامهٔ هر سیستم | resolve each target's credential
#     domain    → $null  (Kerberos با کاربرِ فعلی)
#     workgroup → از CSV، یا از گاوصندوق (اختصاصی/مشترک)
# ---------------------------------------------------------------------------
function Resolve-LBTargetCred {
    param($Target, [string]$InstallDir)
    if ($Target.Type -eq 'domain') { return $null }
    # CSVِ دارای Username/Password
    if ($Target.PSObject.Properties.Name -contains 'Username' -and $Target.Username) {
        $sec = ConvertTo-SecureString ([string]$Target.Password) -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential($Target.Username, $sec)
    }
    return (Get-LBDeployCred -InstallDir $InstallDir -Computer $Target.Computer)
}

# ---------------------------------------------------------------------------
#  ۴) TrustedHosts: برای workgroup لازم است (Kerberos نیست)
#     فقط سیستم‌های هدف افزوده می‌شوند، نه «*».
# ---------------------------------------------------------------------------
function Add-LBTrustedHosts {
    param([string[]]$Computers)
    if (-not $Computers -or $Computers.Count -eq 0) { return }
    $path = 'WSMan:\localhost\Client\TrustedHosts'
    $cur = ''
    try { $cur = (Get-Item $path -ErrorAction SilentlyContinue).Value } catch {}
    $set = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in ($cur -split ',')) { if ($x.Trim()) { [void]$set.Add($x.Trim()) } }
    $added = $false
    foreach ($c in $Computers) { if ($c -and $set.Add($c)) { $added = $true } }
    if ($added) {
        try { Set-Item $path -Value (($set) -join ',') -Force } catch { Write-Warning "TrustedHosts: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
#  ۵) آزمونِ دسترسی و راه‌اندازیِ WinRM در صورت خاموش‌بودن
# ---------------------------------------------------------------------------
function Test-LBWinRm {
    param([string]$Computer, [pscredential]$Credential)
    try {
        if ($Credential) { return [bool](Test-WSMan -ComputerName $Computer -Credential $Credential -Authentication Negotiate -ErrorAction Stop) }
        return [bool](Test-WSMan -ComputerName $Computer -ErrorAction Stop)
    } catch { return $false }
}
# اگر WinRM خاموش باشد، از راهِ WMI/DCOM روشنش می‌کنیم (جایی که RPC باز است)
function Enable-LBRemoting {
    param([string]$Computer, [pscredential]$Credential)
    $cmd = 'cmd.exe /c winrm quickconfig -quiet -force & netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes'
    try {
        $p = @{ Class='Win32_Process'; Name='Create'; ArgumentList=$cmd; ComputerName=$Computer; ErrorAction='Stop' }
        if ($Credential) { $p.Credential = $Credential }
        $r = Invoke-WmiMethod @p
        Start-Sleep -Seconds 6
        return ($r.ReturnValue -eq 0)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
#  ۶) کپیِ فایل‌های ایجنت از راهِ admin share (C$)
# ---------------------------------------------------------------------------
function Copy-LBAgentFiles {
    param([string]$Computer, [string]$SourceDir, [pscredential]$Credential, [string]$RemoteDir = 'C$\ProgramData\Agent')
    $unc = "\\$Computer\$RemoteDir"
    $drive = $null
    try {
        if ($Credential) {
            # برای workgroup با New-PSDrive اعتبارنامه را به SMB می‌دهیم
            $driveName = 'LBDeploy' + ([guid]::NewGuid().ToString('N').Substring(0,6))
            $root = "\\$Computer\C$"
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $root -Credential $Credential -ErrorAction Stop | Out-Null
            $drive = $driveName
            $unc = "$driveName`:\ProgramData\Agent"
        }
        if (-not (Test-Path $unc)) { New-Item -ItemType Directory -Path $unc -Force -ErrorAction Stop | Out-Null }
        foreach ($d in 'state','logs','reports') { $p = Join-Path $unc $d; if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
        $copied = 0
        foreach ($fn in $script:AgentFiles) {
            $src = Join-Path $SourceDir $fn
            if (Test-Path $src) { Copy-Item -Path $src -Destination (Join-Path $unc $fn) -Force -ErrorAction Stop; $copied++ }
        }
        # license.key و engine.flag عمداً به کلاینت نمی‌روند (کلاینت موتور نیست)
        $logo = Join-Path $SourceDir 'logbok-logo.svg'; if (Test-Path $logo) { Copy-Item $logo (Join-Path $unc 'logbok-logo.svg') -Force }
        return $copied
    } finally {
        if ($drive) { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
#  ۷) نصبِ ایجنت از راه دور (WinRM) | remote install
# ---------------------------------------------------------------------------
function Install-LBRemoteAgent {
    param([string]$Computer, [string]$Collector, [pscredential]$Credential, [string]$RemoteDir = 'C:\ProgramData\Agent')
    $sb = {
        param($Collector, $RemoteDir)
        Import-Module (Join-Path $RemoteDir 'LogBok.Agent.psm1') -Force -DisableNameChecking
        Install-LogBokAgent -InstallDir $RemoteDir -Collector $Collector   # ایجنت (نه موتور): فقط واچ‌داگ + تله‌متری
        'OK'
    }
    $p = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($Collector,$RemoteDir); ErrorAction='Stop' }
    if ($Credential) { $p.Credential = $Credential }
    return (Invoke-Command @p)
}

# ---------------------------------------------------------------------------
#  ۸) ارکستراسیونِ نصبِ گروهیِ Push | orchestrate push deployment
#     برای هر سیستم: اعتبارنامه → TrustedHosts (workgroup) → WinRM (یا روشن‌کردنش)
#     → کپیِ فایل → نصب. نتیجهٔ هر سیستم گزارش می‌شود. سقفِ لایسنس اعمال می‌شود.
# ---------------------------------------------------------------------------
function Invoke-LBMassDeploy {
    param(
        [Parameter(Mandatory)]$Targets,
        [Parameter(Mandatory)][string]$SourceDir,
        [string]$Collector,
        [string]$InstallDir = $SourceDir,
        $License,
        [hashtable]$InventoryCount,   # نقش → تعداد نصب‌شده (برای سقف)
        [string[]]$ExistingComputers, # سیستم‌هایی که قبلاً در موجودی‌اند (دوباره شمرده نمی‌شوند)
        [switch]$WhatIf,
        [scriptblock]$Progress
    )
    $existing = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @($ExistingComputers)) { if ($e) { [void]$existing.Add($e) } }
    $results = New-Object System.Collections.ArrayList
    # workgroupها را یک‌جا به TrustedHosts اضافه کن
    $wg = @($Targets | Where-Object { $_.Type -eq 'workgroup' } | ForEach-Object { $_.Computer })
    if ($wg.Count -gt 0 -and -not $WhatIf) { Add-LBTrustedHosts -Computers $wg }
    if (-not $InventoryCount) { $InventoryCount = @{} }

    foreach ($t in $Targets) {
        $res = [pscustomobject]@{ Computer=$t.Computer; Role=$t.Role; Type=$t.Type; Step='start'; Ok=$false; Message='' }
        if ($Progress) { & $Progress $t }
        try {
            $alreadyInstalled = $existing.Contains($t.Computer)
            # سقفِ لایسنس برای این نقش (سیستمِ از قبل نصب‌شده دوباره حساب نمی‌شود)
            if (-not $alreadyInstalled -and $License -and $License.Limits -and $License.Limits.ContainsKey($t.Role)) {
                $used = [int]$InventoryCount[$t.Role]
                if ($used -ge [int]$License.Limits[$t.Role]) {
                    $res.Step='license'; $res.Message = "سقفِ لایسنسِ $($t.Role) پر است ($used/$($License.Limits[$t.Role]))"
                    [void]$results.Add($res); continue
                }
            }
            $cred = Resolve-LBTargetCred -Target $t -InstallDir $InstallDir
            if ($t.Type -eq 'workgroup' -and -not $cred) {
                $res.Step='cred'; $res.Message='اعتبارنامهٔ workgroup موجود نیست (گاوصندوق/CSV)'; [void]$results.Add($res); continue
            }
            if ($WhatIf) {
                $res.Step='whatif'; $res.Ok=$true; $res.Message=$(if($alreadyInstalled){'آماده (نصبِ مجدد/ترمیم)'}else{'آماده برای نصب'})
                if (-not $alreadyInstalled) { if (-not $InventoryCount.ContainsKey($t.Role)) { $InventoryCount[$t.Role]=0 }; $InventoryCount[$t.Role]++ }
                [void]$results.Add($res); continue
            }

            # WinRM؟ اگر نه، روشنش کن
            if (-not (Test-LBWinRm -Computer $t.Computer -Credential $cred)) {
                $res.Step='winrm'
                if (-not (Enable-LBRemoting -Computer $t.Computer -Credential $cred)) {
                    $res.Message='WinRM خاموش است و روشن نشد (RPC/فایروال). با GPO یا دستی WinRM را فعال کنید.'
                    [void]$results.Add($res); continue
                }
            }
            # کپیِ فایل
            $res.Step='copy'
            $n = Copy-LBAgentFiles -Computer $t.Computer -SourceDir $SourceDir -Credential $cred
            if ($n -lt 1) { $res.Message='کپیِ فایل‌ها ناموفق (دسترسیِ admin share؟)'; [void]$results.Add($res); continue }
            # نصب
            $res.Step='install'
            Install-LBRemoteAgent -Computer $t.Computer -Collector $Collector -Credential $cred | Out-Null
            $res.Step='done'; $res.Ok=$true; $res.Message=$(if($alreadyInstalled){"ترمیم/به‌روزرسانی شد ($n فایل)"}else{"نصب شد ($n فایل)"})
            if (-not $alreadyInstalled) { if (-not $InventoryCount.ContainsKey($t.Role)) { $InventoryCount[$t.Role]=0 }; $InventoryCount[$t.Role]++ }
        } catch {
            $res.Message = $_.Exception.Message
        }
        [void]$results.Add($res)
    }
    return $results.ToArray()
}

# ---------------------------------------------------------------------------
#  ۹) روشِ GPO (برای دامنه) — بهترین، بدونِ گذرواژه، بدونِ push
#     یک GPO می‌سازد که:
#      الف) رجیستریِ WEF SubscriptionManager را ست می‌کند (فوروارد لاگ)
#      ب) ScriptBlockLogging را روشن می‌کند
#      ج) یک Startup Script (ماشین) که auditpol + فعال‌سازیِ لاگ‌ها را اجرا می‌کند
#     نیازمندِ ماژولِ GroupPolicy (روی سرورِ دامنه/RSAT).
# ---------------------------------------------------------------------------
function New-LBDeployGpo {
    param(
        [string]$Name = 'LogBok - Client Telemetry',
        [Parameter(Mandatory)][string]$Collector,
        [string]$LinkTo,          # DN برای لینک؛ خالی = ریشهٔ دامنه
        [string]$ConfigScriptSource   # مسیرِ LogBok-ConfigureClient.ps1 (در منبعِ نصب)
    )
    Import-Module GroupPolicy -ErrorAction Stop
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $Name -Comment 'Managed by LogBok deploy' }

    # الف) WEF SubscriptionManager
    $wefKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    Set-GPRegistryValue -Name $Name -Key $wefKey -ValueName '1' -Type String `
        -Value ("Server=http://{0}:5985/wsman/SubscriptionManager/WEC,Refresh=60" -f $Collector) | Out-Null
    # ب) ScriptBlockLogging
    Set-GPRegistryValue -Name $Name -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 | Out-Null
    # ج) Startup script (auditpol + enable operational logs) در SYSVOL این GPO
    $dom = $env:USERDNSDOMAIN
    $gpoId = $gpo.Id.ToString('B').ToUpper()
    $startupDir = "\\$dom\SYSVOL\$dom\Policies\$gpoId\Machine\Scripts\Startup"
    if (-not (Test-Path $startupDir)) { New-Item -ItemType Directory -Path $startupDir -Force | Out-Null }
    if ($ConfigScriptSource -and (Test-Path $ConfigScriptSource)) {
        Copy-Item $ConfigScriptSource -Destination (Join-Path $startupDir 'LogBok-ConfigureClient.ps1') -Force
    }
    # psscripts.ini → اسکریپتِ .ps1 با powershell.exe اجرا می‌شود (scripts.ini فایلِ .ps1 را اجرا نمی‌کند)
    $psIni = "\\$dom\SYSVOL\$dom\Policies\$gpoId\Machine\Scripts\psscripts.ini"
    $iniBody = "[Startup]`r`n0CmdLine=LogBok-ConfigureClient.ps1`r`n0Parameters=`r`n"
    Set-Content -Path $psIni -Value $iniBody -Encoding Unicode -Force
    try { (Get-Item $psIni -Force).Attributes = 'Hidden' } catch {}
    # ثبتِ افزونهٔ Scripts در GPO (gPCMachineExtensionNames)
    $cse = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    try {
        $adGpo = [adsi]("LDAP://CN={0},CN=Policies,CN=System,{1}" -f $gpoId, ([adsi]'LDAP://RootDSE').defaultNamingContext)
        $cur = [string]$adGpo.Properties['gPCMachineExtensionNames'].Value
        if ($cur -notmatch '42B5FAAE') { $adGpo.Properties['gPCMachineExtensionNames'].Value = ($cur + $cse); $adGpo.CommitChanges() }
        # نسخه: واژهٔ «کامپیوتر» (۱۶ بیتِ بالا) باید افزایش یابد، نه واژهٔ کاربر
        $ver = [int]$adGpo.Properties['versionNumber'].Value
        $ver = $ver + 0x10000
        $adGpo.Properties['versionNumber'].Value = $ver
        $adGpo.CommitChanges()
        # هم‌گام‌سازیِ GPT.INI در SYSVOL با نسخهٔ AD (وگرنه GPMC ناسالم گزارش می‌دهد)
        $gptIni = "\\$dom\SYSVOL\$dom\Policies\$gpoId\GPT.INI"
        if (Test-Path $gptIni) {
            $lines = Get-Content $gptIni
            if ($lines -match '^Version=') { $lines = $lines -replace '^Version=.*', "Version=$ver" }
            else { $lines += "Version=$ver" }
            Set-Content -Path $gptIni -Value $lines -Encoding ASCII -Force
        }
    } catch { Write-Warning "Startup-script registration needs manual check in GPMC: $($_.Exception.Message)" }

    # لینک به دامنه/OU — اگر از قبل لینک است، دوباره نساز (بدونِ تکیه بر متنِ خطا)
    if (-not $LinkTo) { $LinkTo = ([adsi]'LDAP://RootDSE').defaultNamingContext }
    $already = $false
    try { $already = [bool]((Get-GPInheritance -Target $LinkTo -ErrorAction Stop).GpoLinks | Where-Object { $_.DisplayName -eq $Name }) } catch {}
    if (-not $already) { New-GPLink -Name $Name -Target $LinkTo -LinkEnabled Yes -ErrorAction Stop | Out-Null }
    return [pscustomobject]@{ Name=$Name; Id=$gpoId; LinkedTo=$LinkTo; Collector=$Collector }
}

Export-ModuleMember -Function Set-LBDeployCred, Get-LBDeployCred, Import-LBVault, `
    Get-LBAdComputers, Get-LBRangeComputers, Get-LBCsvComputers, Get-LBGuessRole, `
    Resolve-LBTargetCred, Add-LBTrustedHosts, Test-LBWinRm, Enable-LBRemoting, `
    Copy-LBAgentFiles, Install-LBRemoteAgent, Invoke-LBMassDeploy, New-LBDeployGpo
