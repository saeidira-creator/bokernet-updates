# ==========================================================================
#  Run-AgentPush.ps1 — نصبِ خودکارِ ایجنت روی یک سیستمِ ویندوزی فقط با نام‌کاربری و گذرواژه
#  (کنسولِ وب آن را در فرایندی جدا اجرا می‌کند تا رابط منتظر نماند)
#  روی سیستمِ مقصد هیچ کاری لازم نیست؛ از کانالِ مدیریتیِ استانداردِ ویندوز استفاده می‌شود:
#    1) WinRM (5985) → به سیستم می‌گوییم نصب‌کننده را از پورتِ 8687ِ سرور بگیرد و اجرا کند
#    2) SMB (445) → یک سرویسِ موقت (مثلِ PsExec) فقط همان فرمان را یک‌بار اجرا و بعد حذف می‌شود
#       445 (اشتراکِ فایل) رایج‌ترین پورتِ باز در شبکه‌های ویندوزی است؛ فقط همین یک پورت کافی است
#    3) اگر هر دو بسته بود ولی RPC/WMI (135) باز بود: با WMI همان فرمان را اجرا می‌کنیم
#  هر سه به‌ترتیب و خودکار امتحان می‌شوند؛ کاربر فقط نام‌کاربری و گذرواژه می‌دهد.
#  هیچ فایلی روی سیستم کپی نمی‌شود؛ خودِ سیستم بسته را فقط از 8687 می‌گیرد.
#  پس از نصب، ایجنت فقط از کلاینت به سرور (8687) وصل می‌شود؛ روی کلاینت پورتی باز نمی‌شود.
#  وضعیتِ هر مرحله به زبانِ ساده در state\agents\<Name>.json نوشته می‌شود.
# ==========================================================================
param([Parameter(Mandatory)][string]$Name, [string]$Address, [string]$Collector, [string]$CredName)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'LogBok.Core.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.Targets.psm1')  -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.AgentPkg.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.AgentIn.psm1')  -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.Deploy.psm1')   -Force -DisableNameChecking
Import-Module (Join-Path $root 'LogBok.Connect.psm1')  -Force -DisableNameChecking
$cfg = Get-LogBokConfig
$sd = Get-LBStateDir -Config $cfg

function St([string]$Step, [string]$Msg, $Ok = $null, [string]$Fix = '') {
    $f = @{ Method = 'push'; Step = $Step; Message = $Msg; Address = $script:addr; Collector = $script:col; Fix = $Fix; Tried = @($script:tried) }
    if ($null -ne $Ok) { $f.Ok = [bool]$Ok } else { $f.Ok = $null }
    Set-LBAgentStatus -StateDir $sd -Name $Name -Fields $f
}
# ترجمهٔ خطا به زبانِ ساده | plain-language reason for an error
function Get-PlainReason([string]$m) {
    if ($m -match 'logon failure|1326|password is incorrect|unknown user name|user name or password') { return 'badpass' }
    if ($m -match 'Access is denied|access denied|0x80070005|UnauthorizedAccess|not a (local )?admin|failed \(5\)') { return 'denied' }
    if ($m -match 'network path was not found|network name cannot be found|failed \((53|1722|1219)\)|RPC server is unavailable|1722|0x800706BA|cannot connect|timed out|WinRM cannot') { return 'closed' }
    return 'other'
}
# اجرای یک فرمان روی سیستمِ دیگر فقط از راهِ SMB (445): نشستِ ADMIN$ + سرویسِ موقتِ یک‌بارمصرف
# run one command on a remote computer over SMB/445 only: ADMIN$ session + a one-shot temporary service (svcctl over named pipe)
function Invoke-LBSmbExec([string]$Target, $Cred, [string]$PsCommand) {
    $drv = 'LBX' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
    $p = @{ Name = $drv; PSProvider = 'FileSystem'; Root = ('\\{0}\ADMIN$' -f $Target); ErrorAction = 'Stop' }
    if ($Cred) { $p.Credential = $Cred }
    New-PSDrive @p | Out-Null       # نشستِ SMB با همین حساب؛ دسترسیِ ADMIN$ یعنی مدیر است | SMB session; ADMIN$ access proves admin rights
    try {
        $svc = 'LogBokSetup' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($PsCommand))
        # cmd فوراً برمی‌گردد و PowerShell جدا ادامه می‌دهد (سرویسِ واقعی نیست) | cmd returns at once; PowerShell keeps running detached
        $bin = '%SystemRoot%\System32\cmd.exe /c start /b powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + $enc
        $unc = '\\' + $Target
        $o = & sc.exe $unc create $svc 'binPath=' $bin 'start=' 'demand' 'DisplayName=' 'LogBok Setup (temporary)' 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('sc create failed ({0}): {1}' -f $LASTEXITCODE, (($o | Out-String).Trim())) }
        try { [void](& sc.exe $unc start $svc 2>&1) } catch { }   # خطای 1053 طبیعی است | error 1053 is expected
        Start-Sleep -Seconds 3
        try { [void](& sc.exe $unc delete $svc 2>&1) } catch { }
    }
    finally { try { Remove-PSDrive -Name $drv -Force -ErrorAction SilentlyContinue } catch { } }
}
# آیا ایجنت پس از شروعِ نصب خودش را معرفی کرد؟ | did the agent check in after we started?
function Wait-Agent([datetime]$Since, [int]$Seconds) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        foreach ($s in @(Get-LBAgentStatus -StateDir $sd)) {
            $match = ([string]$s.Name -ieq $Name) -or ($script:addr -and [string]$s.Address -eq $script:addr)
            if (-not $match) { continue }
            $u = $null; try { $u = [datetime]::Parse([string]$s.Updated, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch { }
            if (-not $u -or $u -lt $Since) { continue }
            if ([string]$s.Step -in 'enrolled', 'approval') { return $s }
        }
        Start-Sleep -Seconds 4
    }
    return $null
}

$t = Get-LBTargetList -StateDir $sd | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
$script:addr = if ($Address) { $Address } elseif ($t -and $t.Address) { [string]$t.Address } else { $Name }
$ci = Get-LBCollectorInfo -Config $cfg
$script:col = if ($Collector) { $Collector } else { $ci.Default }
$script:tried = @()
# پیش‌فرض خاموش؛ فقط اگر مدیر صریحاً روشن کرده باشد | off by default; only when an admin explicitly enabled it
if (-not (Test-LBRemotePushAllowed -StateDir $sd)) {
    St 'failed' 'نصب از راه دور (WinRM/SMB/WMI) برای امنیت خاموش است؛ از «یک خط / فایلِ نصب» یا در دامنه از GPO استفاده کنید | remote push is off for security — use the one-line/install file, or GPO in a domain' $false 'manual'
    return
}
$port = 8687; if ($cfg.Agent -and $cfg.Agent.IngestPort) { $port = [int]$cfg.Agent.IngestPort }
$installed = $false; $how = ''; $lastWhy = ''; $lastMsg = ''
try {
    St 'cred' 'خواندنِ نام‌کاربری و گذرواژه | reading the credential'
    $cred = $null
    $own = Join-Path (Join-Path $sd 'creds') ((Get-LBSafeName $Name) + '.sec')
    if (Test-Path $own) { $cred = Read-LBCredFile -File $own }
    if (-not $cred -and $CredName) { $cred = Get-LBTargetCredential -Computer $CredName -StateDir $sd }
    if (-not $cred) { $cred = Get-LBTargetCredential -Computer $Name -StateDir $sd }
    if (-not $cred -and $script:addr -ne $Name) { $cred = Get-LBTargetCredential -Computer $script:addr -StateDir $sd }
    if (-not $cred -and -not $ci.Domain) { throw 'NOCRED' }
    # نامِ کاربریِ بدونِ دامنه = حسابِ محلیِ همان سیستم (نه سرور) | a bare user name means the target's own local account
    if ($cred -and $cred.UserName -notmatch '[\\@]') { $cred = New-Object Management.Automation.PSCredential(('{0}\{1}' -f $script:addr, $cred.UserName), $cred.Password) }

    # توکنِ ثبت‌نام لازم است تا /install.ps1 را از 8687 بدهد | enrollment token gates the single-port installer
    $enr = Get-LBEnrollInfo -StateDir $sd
    if (-not (Test-LBEnrollValid $enr)) { throw 'NOTOKEN' }
    $tok = (([string]$enr.Token).ToLowerInvariant() -replace '[^0-9a-f]', '')
    # همان خطِ تأییدشده (SHA-256) که در کنسول نشان داده می‌شود | the same SHA-256-verified line the console shows
    $line = Get-LBBootstrapLine -Server $script:col -Port $port -Token $tok -InstallDir $root -Config $cfg
    $psCmd = $line
    $remoteCmd = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($line))

    St 'probe' 'بررسیِ راهِ ورود | checking how we can reach the computer'
    $p5985 = (Test-LBTcpPort -HostName $script:addr -Port 5985 -TimeoutMs 2500).Ok
    $p445  = (Test-LBTcpPort -HostName $script:addr -Port 445  -TimeoutMs 2500).Ok
    $p135  = (Test-LBTcpPort -HostName $script:addr -Port 135  -TimeoutMs 2500).Ok
    if (-not ($p5985 -or $p445 -or $p135)) {
        $alive = $false; try { $alive = [bool](Test-Connection -ComputerName $script:addr -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { }
        throw $(if ($alive) { 'NOPATH' } else { 'OFFLINE' })
    }
    $t0 = (Get-Date).AddSeconds(-2)

    # --- 1) WinRM: به سیستم می‌گوییم بسته را خودش از 8687 بگیرد | tell the computer to pull the package over 8687
    if (-not $installed -and $p5985) {
        try {
            St 'install' 'نصب از راهِ WinRM | installing through WinRM'
            if ($cred) { try { Add-LBTrustedHosts -Computers @($script:addr) } catch { } }
            $sb = { param($l) $ProgressPreference = 'SilentlyContinue'; Invoke-Expression $l }
            $p = @{ ComputerName = $script:addr; ErrorAction = 'Stop'; ArgumentList = @($line); ScriptBlock = $sb }
            if ($cred) { $p.Credential = $cred; $p.Authentication = 'Negotiate' }
            [void](Invoke-Command @p)
            $installed = $true; $how = 'WinRM'; $script:tried += 'winrm:ok'
        } catch { $lastMsg = $_.Exception.Message; $lastWhy = Get-PlainReason $lastMsg; $script:tried += ('winrm:' + $lastWhy) }
    } elseif (-not $p5985) { $script:tried += 'winrm:closed' }

    # --- 2) SMB (445): سرویسِ موقت همان فرمان را اجرا می‌کند | a one-shot service runs the same command
    if (-not $installed -and $p445 -and $lastWhy -ne 'badpass') {
        try {
            St 'install' 'نصب از راهِ اشتراکِ فایل (SMB) | installing through file sharing (SMB)'
            Invoke-LBSmbExec -Target $script:addr -Cred $cred -PsCommand $psCmd
            $installed = $true; $how = 'SMB'; $script:tried += 'smb:ok'
        } catch { $lastMsg = $_.Exception.Message; $lastWhy = Get-PlainReason $lastMsg; $script:tried += ('smb:' + $lastWhy) }
    } elseif (-not $installed -and -not $p445) { $script:tried += 'smb:closed' }

    # --- 3) WMI (RPC 135): همان فرمان را از راهِ Win32_Process اجرا می‌کنیم | run the same command via WMI
    if (-not $installed -and $p135 -and $lastWhy -ne 'badpass') {
        try {
            St 'install' 'نصب از راهِ WMI | installing through WMI (RPC)'
            $wp = @{ Class = 'Win32_Process'; Name = 'Create'; ArgumentList = $remoteCmd; ComputerName = $script:addr; ErrorAction = 'Stop' }
            if ($cred) { $wp.Credential = $cred }
            $r = Invoke-WmiMethod @wp
            if ($r.ReturnValue -eq 0) { $installed = $true; $how = 'WMI'; $script:tried += 'wmi:ok' }
            else { $lastWhy = $(if ($r.ReturnValue -in 2, 3, 8, 9, 21) { 'denied' } else { 'other' }); $lastMsg = ('WMI ReturnValue=' + $r.ReturnValue); $script:tried += ('wmi:' + $lastWhy) }
        } catch { $lastMsg = $_.Exception.Message; $lastWhy = Get-PlainReason $lastMsg; $script:tried += ('wmi:' + $lastWhy) }
    } elseif (-not $installed -and -not $p135) { $script:tried += 'wmi:closed' }

    if (-not $installed) {
        if ($lastWhy -eq 'badpass') { throw 'BADPASS' }
        if ($lastWhy -eq 'denied') { throw 'DENIED' }
        throw 'NOPATH'
    }

    # ثبت در منابع و موجودی | register as a source + inventory
    if (-not $t) { [void](Add-LBTarget -Name $Name -Address $(if ($Address) { $Address } else { '' }) -Kind 'Windows' -Monitor 'agent' -Source 'agent' -By 'agent-push') }
    $invPath = Join-Path $sd 'inventory.json'
    $inv = @(); if (Test-Path $invPath) { try { $inv = @(Get-Content $invPath -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch { } }
    if (-not @($inv | Where-Object { $_.Computer -eq $Name }).Count) { $inv += [pscustomobject]@{ Computer = $Name; Role = 'Workstation'; InstalledAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss') } }
    ConvertTo-Json -InputObject @($inv) -Depth 5 | Set-Content -Path $invPath -Encoding UTF8

    # منتظر می‌مانیم تا خودِ ایجنت وصل شود (نصب چند ثانیه طول می‌کشد) | wait for the agent to check in
    St 'waiting' ('نصب شروع شد (از راهِ {0})؛ منتظرِ اولین ارتباطِ ایجنت… | installing (via {0}); waiting for the agent to connect…' -f $how)
    $seen = Wait-Agent -Since $t0 -Seconds 150
    if ($seen) {
        $okMsg = $(if ([string]$seen.Step -eq 'approval') { 'نصب شد و منتظرِ تأیید در «سیستم‌ها» است | installed — waiting for approval under Computers' } else { 'نصب شد و وصل است | installed and connected' })
        St 'done' $okMsg $true
        Write-LogBokLog -Message ("ایجنت روی {0} نصب شد (via {1}) | agent installed on {0}" -f $Name, $how) -Config $cfg
    }
    else {
        St 'done' ('نصب از راهِ {0} شروع شد؛ ایجنت معمولاً تا ۲ دقیقه در «سیستم‌ها» ظاهر می‌شود | install started via {0}; the agent usually appears under Computers within ~2 min' -f $how) $true
        Write-LogBokLog -Message ("نصبِ ایجنت روی {0} شروع شد (via {1})؛ هنوز وصل نشده | agent install started on {0}, not yet connected" -f $Name, $how) -Config $cfg
    }
    try { [void](Test-LBConnectivity -Config (Get-LogBokConfig) -InstallDir $root -Save -Only @($script:addr)) } catch { }
}
catch {
    $code = $_.Exception.Message
    # پیامِ ساده + راهِ حل، برای کاربرِ تازه‌کار | plain reason + what to do, for a non-expert
    $map = @{
        NOCRED  = @('نام‌کاربری و گذرواژهٔ یک مدیرِ این سیستم را وارد کنید | enter the username and password of an administrator on this computer', 'cred')
        NOTOKEN = @('توکنِ نصب در سرور آماده نیست؛ در «حفاظت ← استقرار» یک‌بار دکمهٔ ساختِ بسته را بزنید | the install token is not ready on the server — build the package once under Protection → Deployment', 'server')
        OFFLINE = @('سیستم روشن یا در شبکه نیست؛ روشن بودن و نامِ درست/IP را بررسی کنید | the computer is off or not on the network — check it is on and the name/IP is right', 'offline')
        NOPATH  = @('سیستم روشن است ولی فایروالِ ویندوزِ آن همهٔ راه‌ها (5985، 445، 135) را بسته است. یک راهِ بی‌دردسر: همان خطِ نصب را یک‌بار روی خودِ سیستم (PowerShell با Run as administrator) اجرا کنید؛ آدرسش در «حفاظت ← استقرار ← یک سیستم» هست. در دامنه، سیاستِ GPO همین کار را خودکار انجام می‌دهد. | the computer is on but its Windows Firewall blocks every channel (5985, 445, 135). Easiest fix: run the one-line install once on the computer itself (PowerShell as administrator) — the line is under Protection → Deployment → One computer. In a domain, the GPO policy does this automatically.', 'manual')
        DENIED  = @('ویندوز اجازه نداد. در دامنه یک حسابِ Domain Admin (مثل YAS\admin) بزنید؛ در Workgroup از خودِ حسابِ داخلیِ «Administrator» استفاده کنید — ویندوز به بقیهٔ حساب‌های مدیرِ محلی از راه دور اجازه نمی‌دهد. | Windows refused. In a domain use a Domain Admin (e.g. YAS\admin); in a workgroup use the built-in "Administrator" account — Windows blocks other local admin accounts remotely.', 'cred')
        BADPASS = @('نام‌کاربری یا گذرواژه درست نیست؛ دوباره وارد کنید | the username or password is wrong — enter it again', 'cred')
    }
    if ($map.ContainsKey($code)) { $m = $map[$code][0]; $fixCode = $map[$code][1] }
    else { $m = ('نصب انجام نشد: {0} | install did not complete' -f $code); $fixCode = 'other' }
    St 'failed' $m $false $fixCode
    Write-LogBokLog -Message ("نصبِ ایجنت روی {0} ناموفق: {1} | agent push failed (tried: {2})" -f $Name, $m, ($script:tried -join ', ')) -Level WARN -Config $cfg
}
