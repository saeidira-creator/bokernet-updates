# ==========================================================================
#  LogBok.Scanner.psm1 - security posture scanner + service health
#  finds each issue and gives it a problem / why-it-matters / fix / remediation,
#  and remediates it itself when allowed.
#  Security-posture scanner: each finding carries Problem / Why / Recommendation
#  / Fix, and can auto-remediate when allowed. Also watches critical services.
#
#  each finding:
#   @{ Id; Severity; Title; Problem; Recommendation; Remediable; Risky; Fix(scriptblock) }
# ==========================================================================

function New-Vuln {
    param($Id,$Severity,$Title,$Problem,$Recommendation,[bool]$Remediable=$false,[bool]$Risky=$false,[scriptblock]$Fix)
    [pscustomobject]@{ Id=$Id; Severity=$Severity; Title=$Title; Problem=$Problem
        Recommendation=$Recommendation; Remediable=$Remediable; Risky=$Risky; Fix=$Fix }
}

# critical services that must be running and automatic (+ role-based)
#  Wecsvc is only needed on the Collector server (Manual on clients) -> added via -Extra
$script:CriticalServices = @('EventLog','Schedule','MpsSvc','WinDefend')

# ------------------- service health monitoring (light, every cycle) -----
#  if a critical service is stopped/non-automatic -> returns it and (with Fix) repairs it.
function Test-LogBokServices {
    param([string[]]$Extra,[switch]$Fix)
    $issues = @()
    $list = @($script:CriticalServices + $Extra) | Where-Object { $_ } | Select-Object -Unique
    foreach ($name in $list) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $startType = (Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue).StartMode
        if ($svc.Status -ne 'Running' -or $startType -eq 'Disabled') {
            $issues += [pscustomobject]@{ Service=$name; Status=$svc.Status; StartMode=$startType }
            if ($Fix) {
                try { Set-Service -Name $name -StartupType Automatic -ErrorAction SilentlyContinue
                      Start-Service -Name $name -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
    return $issues
}

# ----------------------------- full vulnerability scan ----------------------
function Invoke-LogBokScan {
    $f = @()

    # 1) SMBv1 (EternalBlue/WannaCry risk)
    try {
        $smb1 = $null
        try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
        if ($smb1 -eq $true) {
            $f += New-Vuln 'SMB1' 'Critical' 'پروتکل SMBv1 فعال است | SMBv1 enabled' `
                'SMBv1 قدیمی و آسیب‌پذیر است (EternalBlue/WannaCry).' `
                'SMBv1 را غیرفعال کنید؛ ویندوزهای امروزی به آن نیاز ندارند.' $true $true `
                { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue }
        }
    } catch {}

    # 2) Guest account enabled
    try {
        $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=true AND SID like 'S-1-5-%-501'" -ErrorAction SilentlyContinue
        if ($guest -and -not $guest.Disabled) {
            $f += New-Vuln 'GUEST' 'Warning' 'حساب Guest فعال است | Guest account enabled' `
                'حساب مهمان مسیر ورود ناشناس فراهم می‌کند.' 'حساب Guest را غیرفعال کنید.' $true $false `
                { & net user guest /active:no | Out-Null }
        }
    } catch {}

    # 3) RDP with NLA disabled
    try {
        $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdp -eq 0) {
            $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
            if ($nla -ne 1) {
                $f += New-Vuln 'RDP_NLA' 'Warning' 'RDP بدون NLA | RDP without Network Level Auth' `
                    'نبودِ NLA، RDP را در برابر حمله آسیب‌پذیرتر می‌کند.' 'NLA را برای RDP فعال کنید.' $true $false `
                    { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 }
            }
        }
    } catch {}

    # 4) AutoLogon with a stored password
    try {
        $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if ($w.AutoAdminLogon -eq '1' -and $w.DefaultPassword) {
            $f += New-Vuln 'AUTOLOGON' 'Critical' 'ورود خودکار با گذرواژهٔ آشکار | AutoLogon password in registry' `
                'گذرواژه به‌صورت متن ساده در رجیستری ذخیره شده است.' 'AutoLogon را غیرفعال و گذرواژه را حذف کنید.' $true $false `
                { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0'
                  Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue }
        }
    } catch {}

    # 5) unquoted service path (privilege escalation)
    try {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
            # only vulnerable when the exe-path part (up to the first .exe) contains a space
            $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -notmatch '^\s*[A-Za-z]:\\Windows' -and
            $_.PathName -match '^\s*(.*?\.exe)' -and $Matches[1] -match '\s'
        } | ForEach-Object {
            $svcName = $_.Name
            $fix = {
                $p = (Get-CimInstance Win32_Service -Filter "Name='$svcName'").PathName
                # directly in the registry (sc.exe mangled inner quotes on PS 5.1)
                if ($p -and $p -notmatch '^\s*"' -and $p -match '^\s*(.*?\.exe)(.*)$') {
                    $q = '"' + $Matches[1] + '"' + $Matches[2]
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name ImagePath -Value $q -ErrorAction Stop
                }
            }.GetNewClosure()
            $f += New-Vuln ("UNQUOTED:$svcName") 'Warning' ("مسیر بدون‌کوتیشن سرویس $svcName | Unquoted service path: $svcName") `
                'مسیر اجرایی سرویس کوتیشن ندارد و زمینهٔ ربایش را فراهم می‌کند.' 'مسیر اجرایی سرویس را داخل کوتیشن بگذارید.' $true $true $fix
        }
    } catch {}

    # 6) outdated Defender signatures
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusSignatureAge -gt 3) {
            $f += New-Vuln 'DEF_SIG' 'Warning' ("امضای دیفندر {0} روز قدیمی | Defender signatures {0} days old" -f $mp.AntivirusSignatureAge) `
                'پایگاه ویروس به‌روز نیست و شناسایی ضعیف می‌شود.' 'امضاها را به‌روزرسانی کنید.' $true $false `
                { Update-MpSignature -ErrorAction SilentlyContinue }
        }
    } catch {}

    # 7) PowerShell v2 engine (downgrade attack)
    try {
        $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
        if ($v2 -and $v2.State -eq 'Enabled') {
            $f += New-Vuln 'PSV2' 'Warning' 'موتور PowerShell v2 فعال | PowerShell v2 engine enabled' `
                'نسخهٔ ۲ لاگ‌برداری ندارد و برای دور زدن استفاده می‌شود.' 'ویژگی PowerShell v2 را غیرفعال کنید.' $true $true `
                { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue | Out-Null }
        }
    } catch {}

    # 8) critical service health
    foreach ($iss in (Test-LogBokServices)) {
        $sn = $iss.Service
        $f += New-Vuln ("SVC:$sn") 'Critical' ("سرویس حیاتی $sn سالم نیست ($($iss.Status)/$($iss.StartMode)) | Critical service unhealthy") `
            'یک سرویس امنیتی/پایه در حال اجرا یا خودکار نیست.' 'سرویس را روی Automatic بگذارید و اجرا کنید.' $true $false `
            ([scriptblock]::Create("Set-Service -Name '$sn' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name '$sn' -ErrorAction SilentlyContinue"))
    }

    return $f
}

# --------------------------- remediate findings ----------------------------
#  by default only low-risk items are fixed; risky ones require -IncludeRisky.
function Repair-LogBokScan {
    param([Parameter(Mandatory)]$Findings,[switch]$IncludeRisky)
    $fixed = @()
    foreach ($v in @($Findings | Where-Object { $_.Remediable -and $_.Fix })) {
        if ($v.Risky -and -not $IncludeRisky) { continue }
        try { & $v.Fix; $fixed += $v.Id } catch {}
    }
    return $fixed
}

Export-ModuleMember -Function *
