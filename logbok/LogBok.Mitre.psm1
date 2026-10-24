# ==========================================================================
#  LogBok.Mitre.psm1 - نگاشتِ MITRE ATT&CK + میزِ رخداد (Incident/Case)
#  ۱) هر دستهٔ یافته را به تکنیک‌های MITRE ATT&CK برچسب می‌زند.
#  ۲) یافته‌های مرتبط را در «رخداد» گروه می‌کند و وضعیت/واگذاری نگه می‌دارد
#     (incidents.json). حذف‌نشدنی و قابلِ‌پیگیری.
# ==========================================================================

# نگاشتِ دسته → تکنیک‌های MITRE | category → ATT&CK techniques
$script:MitreMap = @{
    Firewall        = @(@{id='T1562.004';n='Impair Defenses: Disable or Modify System Firewall'})
    Defender        = @(@{id='T1562.001';n='Impair Defenses: Disable or Modify Tools'})
    MassFile        = @(@{id='T1485';    n='Data Destruction'})
    ActiveDirectory = @(@{id='T1136';    n='Create Account'},@{id='T1098';n='Account Manipulation'},@{id='T1078';n='Valid Accounts'})
    BruteForce      = @(@{id='T1110';    n='Brute Force'})
    Guard           = @(@{id='T1110';    n='Brute Force (blocked by Login Guard)'},@{id='T1133';n='External Remote Services'})
    SqlLogin        = @(@{id='T1110';    n='Brute Force'},@{id='T1190';n='Exploit Public-Facing Application'})
    IISAttack       = @(@{id='T1190';    n='Exploit Public-Facing Application'})
    FtpAttack       = @(@{id='T1110';    n='Brute Force'})
    ServiceState    = @(@{id='T1489';    n='Service Stop'})
    Tamper          = @(@{id='T1562.001';n='Impair Defenses: Disable or Modify Tools'},@{id='T1489';n='Service Stop'})
    Ransomware      = @(@{id='T1486';    n='Data Encrypted for Impact'})
    Behavior        = @(@{id='T1078';    n='Valid Accounts (anomalous use)'})
    FileSuspicion   = @(@{id='T1204';    n='User Execution'},@{id='T1036';n='Masquerading'})
    Policy          = @(@{id='T1562';    n='Impair Defenses'})
    Vulnerability   = @(@{id='T1203';    n='Exploitation for Client Execution'},@{id='T1068';n='Exploitation for Privilege Escalation'})
    FwGovernance    = @(@{id='T1562.004';n='Impair Defenses: Disable or Modify System Firewall'})
    FtpSuspicion    = @(@{id='T1071';    n='Application Layer Protocol'})
    FIM             = @(@{id='T1565.001';n='Data Manipulation: Stored Data Manipulation'},@{id='T1036';n='Masquerading'})
    Correlation     = @(@{id='T1110';    n='Multi-stage attack pattern'})
    ADAttack        = @(@{id='T1558.003';n='Kerberoasting'},@{id='T1558.004';n='AS-REP Roasting'},@{id='T1003.006';n='DCSync (OS Credential Dumping)'})
    GPO             = @(@{id='T1484.001';n='Group Policy Modification'})
    FileACL         = @(@{id='T1222';    n='File and Directory Permissions Modification'})
    MemberServer    = @(@{id='T1053.005';n='Scheduled Task'},@{id='T1543.003';n='Create or Modify System Service'})
    Network         = @(@{id='T1110';    n='Brute Force (network device)'},@{id='T1602';n='Data from Configuration Repository'})
    AppLog          = @(@{id='T1190';    n='Exploit Public-Facing Application'})
    Custom          = @()   # قواعدِ سفارشیِ کاربر؛ تکنیکِ ثابتی ندارند | user-defined rules
    Connectivity    = @(@{id='T1562.002';n='Impair Defenses: Disable Windows Event Logging (possible)'})
    EndpointHealth  = @(@{id='T1562.001';n='Impair Defenses: Disable or Modify Tools (possible)'})
    AppControl      = @(@{id='T1204.002';n='User Execution: Malicious File (blocked)'})
}

function Get-LBMitre { param([string]$Category)
    if ($script:MitreMap.ContainsKey($Category)) { return $script:MitreMap[$Category] }
    return @()
}

# برچسبِ MITRE را به یافته می‌افزاید (رشتهٔ کوتاه برای نمایش) | tag a finding
function Add-LBMitreTag {
    param([Parameter(ValueFromPipeline)]$Finding)
    process {
        # اگر یافته از قبل برچسبِ MITRE دارد (مثلِ یافته‌های همبسته)، حفظش کن
        $existing = $null
        try { if ($Finding.PSObject.Properties.Name -contains 'Mitre') { $existing = [string]$Finding.Mitre } } catch {}
        if ($existing) { return $Finding }
        $tech = Get-LBMitre -Category $Finding.Category
        $tag = if ($tech.Count) { ($tech | ForEach-Object { $_.id }) -join ', ' } else { '' }
        $Finding | Add-Member -NotePropertyName Mitre -NotePropertyValue $tag -Force
        $Finding
    }
}

# --- میزِ رخداد | incident workbench --------------------------------------
function Get-LBIncidentPath { param($Config) Join-Path $Config.Paths.State 'incidents.json' }

function Get-LBIncidents {
    param($Config)
    $f = Get-LBIncidentPath -Config $Config
    # ForEach-Object آرایهٔ JSON را در PS 5.1 باز می‌کند (وگرنه یک عضوِ تودرتو می‌شد)
    if (Test-Path $f) { try { return @(Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch { return @() } }
    return @()
}
function Save-LBIncidents { param($Config,$Incidents)
    $Incidents | ConvertTo-Json -Depth 6 | Set-Content -Path (Get-LBIncidentPath -Config $Config) -Encoding UTF8
}

# از یافته‌های بحرانی/هشدار، رخداد می‌سازد یا رخدادِ باز را به‌روز می‌کند.
# کلیدِ گروه‌بندی: سیستم + دسته (یک رخدادِ باز برای هر ترکیب).
function Update-LBIncidents {
    param($Config,$Findings)
    $inc = @(Get-LBIncidents -Config $Config)
    $now = (Get-Date).ToString('o')
    $openByKey = @{}
    foreach ($i in $inc) { if ($i.Status -ne 'Closed') { $openByKey["$($i.Machine)|$($i.Category)"] = $i } }

    foreach ($f in @($Findings | Where-Object { $_.Severity -in 'Critical','Warning' })) {
        $key = "$($f.Machine)|$($f.Category)"
        $tech = (Get-LBMitre -Category $f.Category | ForEach-Object { $_.id }) -join ', '
        if ($openByKey.ContainsKey($key)) {
            $i = $openByKey[$key]
            $i.Count = [int]$i.Count + 1
            $i.LastSeen = $now
            if ($f.Title) { $i.Title = $f.Title }   # عنوانِ آخرین رویداد (دوزبانه) | latest event's title
            if ($f.Severity -eq 'Critical') { $i.Severity = 'Critical' }
        } else {
            $newInc = [pscustomobject]@{
                Id='INC-' + (Get-Date).ToString('yyMMdd-HHmmss',[Globalization.CultureInfo]::InvariantCulture) + '-' + ([guid]::NewGuid().ToString('N').Substring(0,6))
                Machine=$f.Machine; Category=$f.Category; Title=$f.Title; Severity=$f.Severity
                Mitre=$tech; Status='Open'; Owner=''; Count=1
                FirstSeen=$now; LastSeen=$now
            }
            $inc += $newInc
            $openByKey[$key] = $newInc
        }
    }
    Save-LBIncidents -Config $Config -Incidents $inc
    return $inc
}

# تغییر وضعیت/واگذاری یک رخداد | set status / owner
function Set-LBIncident {
    param($Config,[Parameter(Mandatory)][string]$Id,[ValidateSet('Open','Investigating','Closed')][string]$Status,[string]$Owner)
    $inc = @(Get-LBIncidents -Config $Config)
    foreach ($i in $inc) { if ($i.Id -eq $Id) {
        if ($Status) { $i.Status = $Status }
        if ($PSBoundParameters.ContainsKey('Owner')) { $i.Owner = $Owner }
    } }
    Save-LBIncidents -Config $Config -Incidents $inc
    return ($inc | Where-Object Id -eq $Id)
}

Export-ModuleMember -Function *
