# ==========================================================================
#  LogBok.Agent.psm1 - install, hardening and self-healing of the agent on the target machine
#  Agent install, hardening and self-healing on target machines.
#
#  honest boundary:
#   the agent installs as a known, documented service/task that is resistant to
#   a normal user (who cannot stop/remove it) and self-heals, but is always
#   removable by an authorized admin and through the console. It uses no
#   "concealment/rootkit/AV-bypass" techniques; doing so would be both
#   malware-like and would get your product quarantined on the customer machine.
#   The agent is a documented, hardened service: resistant to tampering by
#   ordinary users and self-healing, yet always removable by an authorized
#   admin / from the console. No hiding, rootkit or AV-evasion techniques.
# ==========================================================================

$AuditSubs = @(
    '{0CCE9215-69AE-11D9-BED3-505054503030}','{0CCE9217-69AE-11D9-BED3-505054503030}',
    '{0CCE9235-69AE-11D9-BED3-505054503030}','{0CCE9237-69AE-11D9-BED3-505054503030}',
    '{0CCE923F-69AE-11D9-BED3-505054503030}','{0CCE9242-69AE-11D9-BED3-505054503030}',
    '{0CCE921D-69AE-11D9-BED3-505054503030}','{0CCE9223-69AE-11D9-BED3-505054503030}',
    '{0CCE923C-69AE-11D9-BED3-505054503030}',  # Directory Service Changes (5136/5137/5141 - GPO/AD)
    '{0CCE923B-69AE-11D9-BED3-505054503030}',  # Directory Service Access (4662 - DCSync)
    '{0CCE9240-69AE-11D9-BED3-505054503030}',  # Kerberos Service Ticket Ops (4769 - Kerberoasting)
    '{0CCE9227-69AE-11D9-BED3-505054503030}',  # Other Object Access Events (4698/4702 - scheduled tasks)
    '{0CCE9231-69AE-11D9-BED3-505054503030}',  # Authorization Policy Change (4670 - ACL change)
    '{0CCE922B-69AE-11D9-BED3-505054503030}'   # Process Creation (4688)
)

function Register-LogBokEventSource {
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) {
        New-EventLog -LogName Application -Source 'LogBok' -ErrorAction Stop } } catch {}
}

function Write-LogBokTamper {
    param([string]$Message)
    Register-LogBokEventSource
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9001 -EntryType Warning -Message $Message } catch {}
}

# enable auditing and log forwarding to the Collector | audit + WEF forwarding
function Set-LogBokClientTelemetry {
    param([string]$Collector)
    foreach ($g in $AuditSubs) { & auditpol.exe /set /subcategory:"$g" /success:enable /failure:enable | Out-Null }
    & wevtutil.exe sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /e:true 2>$null
    & wevtutil.exe sl "Microsoft-Windows-Windows Defender/Operational" /e:true 2>$null
    & wevtutil.exe sl "Microsoft-Windows-PrintService/Operational" /e:true 2>$null
    # enable PowerShell script-block logging (4104)
    try {
        $psk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-not (Test-Path $psk)) { New-Item -Path $psk -Force | Out-Null }
        New-ItemProperty -Path $psk -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord -Force | Out-Null
    } catch {}
    if ($Collector) {
        & winrm quickconfig -quiet 2>$null
        # add NETWORK SERVICE to the Event Log Readers group by SID (independent of the Windows language)
        try {
            $grp = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-573')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $ns  = (New-Object Security.Principal.SecurityIdentifier('S-1-5-20')).Translate([Security.Principal.NTAccount]).Value
            & net localgroup "$grp" "$ns" /add 2>$null | Out-Null
        } catch { }
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name '1' -Value "Server=http://${Collector}:5985/wsman/SubscriptionManager/WEC,Refresh=60" -PropertyType String -Force | Out-Null
        Restart-Service Wecsvc -ErrorAction SilentlyContinue
    }
}

# is telemetry still intact?
function Test-LogBokClientTelemetry {
    param([string]$Collector)
    $okAudit = $true
    # CSV output; an "Inclusion Setting" column of No Auditing means auditing is off.
    # (previously -notmatch on an array was always true and raised a false Tamper alert every 2 minutes)
    try {
        $csv = @((& auditpol.exe /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r) 2>$null | Where-Object { $_ -and $_.Trim() })
        if ($csv.Count -ge 2) {
            $row = $csv | ConvertFrom-Csv | Select-Object -First 1
            $inc = [string]$row.'Inclusion Setting'
            if (-not $inc) { $inc = [string]($row.PSObject.Properties | Select-Object -Last 2 | Select-Object -First 1).Value }
            if ($inc -match 'No Auditing|بدون') { $okAudit = $false }
        }
    } catch { }
    $okWef = $true
    if ($Collector) {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
        if (-not (Test-Path $key)) { $okWef = $false }
    }
    return ($okAudit -and $okWef)
}

# --- hardening: folder & task ACLs, automatic recovery ---------------------
function Protect-LogBokPath {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        # SYSTEM and Administrators only; normal users have no access at all (no read, no view),
        # so an ordinary user cannot open or read the agent folder and files.
        # by SID so it works on non-English Windows too (group names are localized)
        # only SYSTEM and Administrators; ordinary users get NO access (cannot read or even list the folder)
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    } catch {}
}

# build the agent tasks from the shared job catalog (LogBok.Jobs.psm1)
function Install-LogBokAgentTasks {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [switch]$FullEngine)
    Import-Module (Join-Path $PSScriptRoot 'LogBok.Jobs.psm1') -Force -DisableNameChecking
    $cfgPath = Join-Path $InstallDir 'config.psd1'
    $cfg = if (Test-Path $cfgPath) { Import-PowerShellDataFile $cfgPath } else { @{} }
    $role = if ($FullEngine) { 'Engine' } else { 'Agent' }
    Sync-LBJobs -Config $cfg -InstallDir $InstallDir -Role $role -StartNew | Out-Null
}

# full local agent install on the target machine
function Install-LogBokAgent {
    param([string]$InstallDir='C:\Scripts\LogBok',[string]$Collector,[switch]$FullEngine)
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    foreach ($d in @('state','logs','reports')) { $p = Join-Path $InstallDir $d; if (-not (Test-Path $p)){ New-Item -ItemType Directory -Path $p -Force | Out-Null } }
    Register-LogBokEventSource
    Set-LogBokClientTelemetry -Collector $Collector
    Install-LogBokAgentTasks -InstallDir $InstallDir -FullEngine:$FullEngine
    Protect-LogBokPath $InstallDir
    # installing is not tampering; the installer writes the 9010 info event
}

# authorized agent removal
function Uninstall-LogBokAgent {
    param([string]$InstallDir='C:\Scripts\LogBok',[switch]$KeepFiles)
    # remove every task in the \LogBok\ folder (whatever jobs were created)
    Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction SilentlyContinue | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath '\LogBok\' -Confirm:$false -ErrorAction SilentlyContinue
    }
    try { Remove-NetFirewallRule -DisplayName 'LogBok-Syslog-In' -ErrorAction SilentlyContinue } catch {}
    # the login-guard rules are removed too (otherwise blocked IPs would stay blocked forever)
    try { Import-Module (Join-Path $InstallDir 'LogBok.Guard.psm1') -Force -DisableNameChecking -ErrorAction Stop; Remove-LBGuardRules } catch {}
    try { Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue } catch {}
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $KeepFiles -and (Test-Path $InstallDir)) {
        try { & icacls.exe $InstallDir /reset /T /C | Out-Null } catch {}
        # build folders (Tools with the private key, _Releases, _Backups) are never removed by an agent uninstall
        $keep = @('Tools','_Releases','_Backups')
        $hasKeep = @(Get-ChildItem -Path $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object { $keep -contains $_.Name }).Count -gt 0
        if ($hasKeep) {
            Get-ChildItem -Path $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object { $keep -notcontains $_.Name } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- move an agent from the old folder to ProgramData\Agent ----------------
#  versions before 1.8.2 installed under C:\Scripts\LogBok. Identity (agent.json) and state are moved, tasks are repointed to the new home
#  and the old folder is removed. Never runs on the LogBok server (engine.flag).
#  agents before 1.8.2 lived in C:\Scripts\LogBok. Identity (agent.json) and state move over, tasks are re-pointed,
#  the old folder is removed. Never runs on the LogBok server itself (engine.flag).
function Move-LogBokAgentLegacy {
    param([string]$Legacy = 'C:\Scripts\LogBok', [string]$NewDir = (Join-Path $env:ProgramData 'Agent'))
    $Legacy = $Legacy.TrimEnd('\'); $NewDir = $NewDir.TrimEnd('\')
    if ($Legacy -eq $NewDir) { return 'same folder' }
    if (-not (Test-Path (Join-Path $Legacy 'LogBok.Agent.psm1'))) { return 'nothing to move' }
    if (-not (Test-Path (Join-Path $Legacy 'state\agent.json'))) { return 'not an agent folder - not moved' }
    # any sign of a server or a build copy -> leave it alone
    foreach ($mk in @('engine.flag', 'license.key', 'LogBok.Web.psm1', 'Run-Web.ps1', 'LogBok-Setup.ps1', 'Tools\privatekey.xml')) {
        if (Test-Path (Join-Path $Legacy $mk)) { return "server or build files found ($mk) - not moved" }
    }
    if (Test-Path 'C:\Scripts\LogBok\engine.flag') { return 'LogBok server - not moved' }
    foreach ($d in @($NewDir, (Join-Path $NewDir 'state'), (Join-Path $NewDir 'logs'), (Join-Path $NewDir 'reports'))) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null } }
    $n = 0
    # any copy error stops the whole move (the old folder stays untouched)
    foreach ($f in @(Get-ChildItem -Path $Legacy -File -ErrorAction Stop)) {
        $to = Join-Path $NewDir $f.Name
        if (-not (Test-Path $to)) { Copy-Item -LiteralPath $f.FullName -Destination $to -Force -ErrorAction Stop; $n++ }
    }
    $ls = Join-Path $Legacy 'state'
    foreach ($f in @(Get-ChildItem -Path $ls -Recurse -File -ErrorAction Stop)) {
        $rel = $f.FullName.Substring($ls.Length).TrimStart('\'); $to = Join-Path (Join-Path $NewDir 'state') $rel
        if (-not (Test-Path $to)) { $pd = Split-Path -Parent $to; if (-not (Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force -ErrorAction Stop | Out-Null }; Copy-Item -LiteralPath $f.FullName -Destination $to -Force -ErrorAction Stop; $n++ }
    }
    if (-not (Test-Path (Join-Path $NewDir 'state\agent.json'))) { throw 'identity (agent.json) missing in the new folder - old folder kept' }
    Get-ChildItem -Path $NewDir -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    # tasks to the new home; any failure keeps the old folder
    Import-Module (Join-Path $NewDir 'LogBok.Jobs.psm1') -Force -DisableNameChecking
    $cfgPath = Join-Path $NewDir 'config.psd1'; $cfg = if (Test-Path $cfgPath) { Import-PowerShellDataFile $cfgPath } else { @{} }
    $res = @(Sync-LBJobs -Config $cfg -InstallDir $NewDir -Role 'Agent' -Force)
    $bad = @($res | Where-Object { $_ -and $_.Ok -eq $false })
    if ($bad.Count) { throw ("tasks could not be re-created: " + (@($bad | ForEach-Object { "$($_.Job): $($_.Message)" }) -join '; ')) }
    $still = @(Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction SilentlyContinue | Where-Object { @($_.Actions | Where-Object { [string]$_.Arguments -like ('*"' + $Legacy + '\*') }).Count })
    if ($still.Count) { throw ("tasks still point to the old folder: " + (@($still | ForEach-Object { $_.TaskName }) -join ', ')) }
    $wd = @(Get-ScheduledTask -TaskPath '\LogBok\' -ErrorAction SilentlyContinue | Where-Object { @($_.Actions | Where-Object { [string]$_.Arguments -like ('*"' + $NewDir + '\Run-Watchdog.ps1*') }).Count })
    if (-not $wd.Count) { throw 'watchdog task not found in the new folder - old folder kept' }
    Protect-LogBokPath $NewDir
    try { Add-MpPreference -ExclusionPath $NewDir -ErrorAction SilentlyContinue } catch { }
    try { Remove-MpPreference -ExclusionPath $Legacy -ErrorAction SilentlyContinue } catch { }
    # only agent files and state/logs/reports are removed; unknown files stay
    try { & icacls.exe $Legacy /reset /T /C /Q | Out-Null } catch { }
    foreach ($f in @(Get-ChildItem -Path $Legacy -File -Force -ErrorAction SilentlyContinue)) {
        if (Test-Path (Join-Path $NewDir $f.Name)) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    }
    foreach ($d in @('state', 'logs', 'reports')) { $p = Join-Path $Legacy $d; if (Test-Path $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }
    if (-not @(Get-ChildItem -Path $Legacy -Force -ErrorAction SilentlyContinue).Count) { Remove-Item -LiteralPath $Legacy -Force -ErrorAction SilentlyContinue }
    $par = Split-Path -Parent $Legacy
    if ($par -and (Split-Path -Leaf $par) -eq 'Scripts' -and (Test-Path $par) -and -not @(Get-ChildItem -Path $par -Force -ErrorAction SilentlyContinue).Count) { Remove-Item -LiteralPath $par -Force -ErrorAction SilentlyContinue }
    try { Register-LogBokEventSource; Write-EventLog -LogName Application -Source 'LogBok' -EventId 9013 -EntryType Information -Message ("LogBok agent moved on {0}: {1} -> {2} ({3} files)" -f $env:COMPUTERNAME, $Legacy, $NewDir, $n) } catch { }
    return ("moved to {0} ({1} files)" -f $NewDir, $n)
}
# after a self-update (or from the watchdog), the move runs in a separate process (so the current process can finish from the old folder)
# after a self-update (or from the watchdog) the move runs in a separate process, so the current run can finish from the old folder
function Start-LogBokAgentMove {
    param([string]$InstallDir)
    if (-not $InstallDir) { return $false }
    $InstallDir = $InstallDir.TrimEnd('\')
    # only the known old locations
    $known = @('C:\Scripts\LogBok'); if ($env:ProgramFiles) { $known += (Join-Path $env:ProgramFiles 'BokerNet\LogBok Agent') }
    if (-not ($known | Where-Object { $_ -eq $InstallDir })) { return $false }
    if ((Test-Path (Join-Path $InstallDir 'engine.flag')) -or (Test-Path 'C:\Scripts\LogBok\engine.flag') -or -not (Test-Path (Join-Path $InstallDir 'state\agent.json'))) { return $false }
    $mv = Join-Path $env:TEMP ('lbmv-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
    $script = @"
Start-Sleep -Seconds 20
try { Import-Module '$InstallDir\LogBok.Agent.psm1' -Force -DisableNameChecking; `$r = Move-LogBokAgentLegacy -Legacy '$InstallDir'; Set-Content -Path (Join-Path `$env:ProgramData 'Agent\state\move-result.txt') -Value ([string]`$r) -ErrorAction SilentlyContinue } catch { try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9001 -EntryType Warning -Message ('LogBok agent move failed (old folder kept): ' + `$_.Exception.Message) } catch { } }
try { Remove-Item -LiteralPath '$mv' -Force -ErrorAction SilentlyContinue } catch { }
"@
    Set-Content -LiteralPath $mv -Value $script -Encoding UTF8
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $psExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $mv) -WindowStyle Hidden -WorkingDirectory (Join-Path $env:SystemRoot 'System32')
    return $true
}

# --- the agent follows the server's address --------------------------------
#  every watchdog cycle re-resolves the server name; if the server IP changed, the firewall rule
#  LogBok-Agent-Collector and agent.json are fixed automatically (event 9011). If DNS does not answer,
#  the previous IPs are left untouched.
function Update-LogBokCollectorAccess {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    # the agent opens no inbound port; it only keeps the server address up to date for sending
    # the agent opens no inbound port; it only keeps the server's address current for pushing
    $a = Get-LogBokAgentInfo -InstallDir $InstallDir
    if (-not $a) { return $null }
    if ($a.LegacyRuleRemoved -ne $true) {
        try { Remove-NetFirewallRule -DisplayName 'LogBok-Agent-Collector' -ErrorAction SilentlyContinue } catch { }
        try { Get-NetFirewallRule -Name 'LogBok-Mgmt-Allow-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch { }
        Set-LogBokInfoField $a 'LegacyRuleRemoved' $true; Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a
    }
    $names = @(@($a.CollectorNames) + $a.Collector | Where-Object { $_ -and ([string]$_) -notmatch '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -Unique)
    $live = @()
    foreach ($n in $names) { try { $live += @([Net.Dns]::GetHostAddresses([string]$n) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { } }
    $cur = @(@($a.CollectorIps) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if (-not $live.Count) { return $false }
    $want = @($live | Sort-Object -Unique)
    if (($want -join ',') -eq ($cur -join ',')) { return $false }
    Set-LogBokInfoField $a 'CollectorIps' $want; Set-LogBokInfoField $a 'CollectorCheckedAt' (Get-Date).ToString('o')
    Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a
    Register-LogBokEventSource
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9011 -EntryType Information -Message ("LogBok agent on {0}: server {1} now at {2} (was {3})" -f $env:COMPUTERNAME, $a.Collector, ($want -join ','), ($cur -join ',')) } catch { }
    return $true
}

# --- forward events to the LogBok server (push) ----------------------------
#  every watchdog cycle (2 min): new events from the important logs since the last marker, signed with the org key,
#  compressed and sent to http://<server>:8687/ingest. If the server is unreachable the marker does not advance
#  and the same events are resent next time (no event is lost, up to a 24-hour cap).
$script:FwdLogs = @('Security','System','Application','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PrintService/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script')
# --- crypto & enrollment ---------------------------------------------------
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
function Get-LogBokSha { param([string]$Text) $h = [Security.Cryptography.SHA256]::Create(); try { return $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) } finally { $h.Dispose() } }
function Get-LogBokHmac { param([string]$Key, [byte[]]$Data) $h = New-Object Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($Key)); try { return (-join ($h.ComputeHash($Data) | ForEach-Object { $_.ToString('x2') })) } finally { $h.Dispose() } }
function Protect-LogBokAes {
    param([byte[]]$Key, [byte[]]$Plain)
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $Key; $aes.GenerateIV()
    try { $ct = $aes.CreateEncryptor().TransformFinalBlock($Plain, 0, $Plain.Length); $o = New-Object byte[] (16 + $ct.Length); [Array]::Copy($aes.IV, 0, $o, 0, 16); [Array]::Copy($ct, 0, $o, 16, $ct.Length); return $o } finally { $aes.Dispose() }
}
# encrypt agent data on disk (DPAPI, bound to this machine): a normal user and offline theft cannot read it
# at-rest protection for the agent's own data (DPAPI machine-scope): unreadable to ordinary users and to offline theft
# (SYSTEM/admin on THIS computer can always decrypt — that is unavoidable while the agent runs here)
function Protect-LBAgentBlob {
    param([string]$Plain)
    try { return ('LBENC1:' + [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Plain), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))) }
    catch { return $Plain }   # DPAPI unavailable (non-Windows/dev environment) -> store as-is
}
function Unprotect-LBAgentBlob {
    param([string]$Raw)
    if ($Raw -and $Raw.StartsWith('LBENC1:')) { return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Raw.Substring(7)), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) }
    return $Raw   # backward-compatible: legacy plaintext still loads
}
function Get-LogBokAgentInfo {
    param([string]$InstallDir)
    $f = Join-Path $InstallDir 'state\agent.json'; if (-not (Test-Path $f)) { return $null }
    try { $raw = Get-Content $f -Raw -Encoding UTF8; return ((Unprotect-LBAgentBlob $raw) | ConvertFrom-Json) } catch { return $null }
}
function Save-LogBokAgentInfo {
    param([string]$InstallDir, $Info)
    $f = Join-Path $InstallDir 'state\agent.json'
    $o = [ordered]@{}; foreach ($p in $Info.PSObject.Properties) { $o[$p.Name] = $p.Value }
    Set-Content -Path $f -Value (Protect-LBAgentBlob ($o | ConvertTo-Json -Depth 4)) -Encoding UTF8
    try { & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null } catch { }
}
function Set-LogBokInfoField { param($Info, [string]$Name, $Value) if ($Info.PSObject.Properties.Name -contains $Name) { $Info.$Name = $Value } else { $Info | Add-Member -NotePropertyName $Name -NotePropertyValue $Value } }
function Get-LogBokAgentSecret {
    param($Info)
    if (-not $Info -or -not $Info.SecretEnc) { return $null }
    try { return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([string]$Info.SecretEnc), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) } catch { return $null }
}
function New-LogBokAgentSecret {
    $b = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
    $sec = -join ($b | ForEach-Object { $_.ToString('x2') })
    $enc = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($sec), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
    return @{ Secret = $sec; Enc = $enc }
}
function Get-LogBokServerUrls { param($Info, [string]$Path) $port = if ($Info.IngestPort) { [int]$Info.IngestPort } else { 8687 }; return @(@(@($Info.CollectorNames) + $Info.Collector + @($Info.CollectorIps)) | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { "http://{0}:{1}{2}" -f $_, $port, $Path }) }
function Invoke-LogBokPost {
    param([string[]]$Urls, [string]$SignKey, [byte[]]$Body, [string]$Path, [string]$AgentId)
    $ts = [datetime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $hn = ([string]$env:COMPUTERNAME).ToUpperInvariant()
    $pre = [Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n$Path`n")
    $buf = New-Object byte[] ($pre.Length + $Body.Length); [Array]::Copy($pre, 0, $buf, 0, $pre.Length); [Array]::Copy($Body, 0, $buf, $pre.Length, $Body.Length)
    $sig = Get-LogBokHmac -Key $SignKey -Data $buf
    $last = @{ Ok = $false; Code = 0; Error = 'no server address' }
    foreach ($u in $Urls) {
        try {
            $rq = [Net.HttpWebRequest]::Create($u)
            $rq.Method = 'POST'; $rq.Timeout = 20000; $rq.ReadWriteTimeout = 20000; $rq.ContentType = 'application/octet-stream'; $rq.Proxy = $null
            $rq.Headers.Add('X-LogBok-Host', $hn); $rq.Headers.Add('X-LogBok-Ts', $ts); $rq.Headers.Add('X-LogBok-Sig', $sig)
            if ($AgentId) { $rq.Headers.Add('X-LogBok-Id', $AgentId) }   # stable id survives a rename
            $rq.ContentLength = $Body.Length
            $st = $rq.GetRequestStream(); $st.Write($Body, 0, $Body.Length); $st.Close()
            $rs = $rq.GetResponse(); $code = [int]$rs.StatusCode
            $txt = (New-Object IO.StreamReader($rs.GetResponseStream())).ReadToEnd(); $rs.Close()
            return @{ Ok = ($code -eq 200); Code = $code; Text = $txt; Url = $u; Ts = $ts }
        } catch [Net.WebException] {
            $resp = $_.Exception.Response
            if ($resp) { $code = [int]$resp.StatusCode; $txt = ''; try { $txt = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch { }; return @{ Ok = $false; Code = $code; Text = $txt; Error = $txt; Url = $u } }
            $last = @{ Ok = $false; Code = 0; Error = $_.Exception.Message }
        } catch { $last = @{ Ok = $false; Code = 0; Error = $_.Exception.Message } }
    }
    return $last
}
# enrollment token: plaintext (fresh install) or DPAPI-encrypted (kept for re-enrollment)
function Get-LogBokEnrollToken {
    param($Info)
    if (-not $Info) { return $null }
    if ($Info.EnrollToken) { return [string]$Info.EnrollToken }
    if ($Info.EnrollTokenEnc) { try { return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String([string]$Info.EnrollTokenEnc), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) } catch { } }
    return $null
}
function Protect-LogBokEnrollToken { param([string]$Token) if (-not $Token) { return '' }; try { return [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Token), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)) } catch { return '' } }
# enroll with the package token; the encrypted per-agent secret is sent
function Invoke-LogBokEnroll {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    $a = Get-LogBokAgentInfo -InstallDir $InstallDir
    $tok = Get-LogBokEnrollToken $a
    if (-not $a -or -not $tok) { return @{ Ok = $false; Error = 'no enrollment token (reinstall the agent from the LogBok console)' } }
    if (-not $a.AgentId) { Set-LogBokInfoField $a 'AgentId' ([guid]::NewGuid().ToString()); Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a }
    $sec = Get-LogBokAgentSecret $a
    if (-not $sec) { $n = New-LogBokAgentSecret; $sec = $n.Secret; Set-LogBokInfoField $a 'SecretEnc' $n.Enc; Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a }
    $os = ''; try { $os = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
    $plain = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject ([ordered]@{ secret = $sec; os = $os; version = [string]$a.Version })))
    $body = Protect-LogBokAes -Key (Get-LogBokSha ("{0}|enroll" -f $tok)) -Plain $plain
    $r = Invoke-LogBokPost -Urls (Get-LogBokServerUrls $a '/enroll') -SignKey $tok -Body $body -Path '/enroll' -AgentId ([string]$a.AgentId)
    if ($r.Ok) {
        $st = ''; try { $st = [string]($r.Text | ConvertFrom-Json).status } catch { }
        Set-LogBokInfoField $a 'Enrolled' $true; Set-LogBokInfoField $a 'EnrollStatus' $st; Set-LogBokInfoField $a 'EnrolledAt' (Get-Date).ToString('o')
        # the plaintext token is deleted; the DPAPI copy stays so the agent can re-enroll itself if the server is reinstalled
        # plain token is dropped; a DPAPI-protected copy stays so the agent can re-enroll by itself after a server rebuild
        if (-not $a.EnrollTokenEnc) { $te = Protect-LogBokEnrollToken $tok; if ($te) { Set-LogBokInfoField $a 'EnrollTokenEnc' $te } }
        $a.PSObject.Properties.Remove('EnrollToken')
        Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a
        return @{ Ok = $true; Status = $st }
    }
    return @{ Ok = $false; Error = $(if ($r.Error) { $r.Error } else { "HTTP $($r.Code)" }) }
}
# uninstall code (same as shown in the console)
function Get-LogBokUninstallCode {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    $sec = Get-LogBokAgentSecret (Get-LogBokAgentInfo -InstallDir $InstallDir); if (-not $sec) { return $null }
    $h = Get-LogBokHmac -Key $sec -Data ([Text.Encoding]::UTF8.GetBytes('uninstall:' + ([string]$env:COMPUTERNAME).ToUpperInvariant()))
    return ($h.Substring(0, 12).ToUpperInvariant() -replace '(.{4})(?!$)', '$1-')
}
function Send-LogBokSigned {
    param([string]$InstallDir, $Info, [string]$Path, $Object)
    $sec = Get-LogBokAgentSecret $Info; if (-not $sec) { return @{ Ok = $false; Error = 'agent secret missing' } }
    $json = ConvertTo-Json -InputObject $Object -Depth 8 -Compress
    $ms = New-Object IO.MemoryStream; $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
    $bytes = [Text.Encoding]::UTF8.GetBytes($json); $gz.Write($bytes, 0, $bytes.Length); $gz.Close()
    $body = Protect-LogBokAes -Key (Get-LogBokSha "$sec|enc") -Plain $ms.ToArray()
    return (Invoke-LogBokPost -Urls (Get-LogBokServerUrls $Info $Path) -SignKey $sec -Body $body -Path $Path -AgentId ([string]$Info.AgentId))
}
function Send-LogBokBatch {
    param([string]$InstallDir, $Info, [object[]]$Events)
    $perf = $null; try { $pf = Join-Path $InstallDir 'state\perf.json'; if (Test-Path $pf) { $perf = Get-Content $pf -Raw | ConvertFrom-Json } } catch { }
    return (Send-LogBokSigned -InstallDir $InstallDir -Info $Info -Path '/ingest' -Object ([ordered]@{ v = [string]$Info.Version; e = @($Events); perf = $perf }))
}
# the agent's own noise in the PowerShell log (only when the user is SYSTEM):
#  - script blocks from the agent's own files (the install folder is writable only by SYSTEM/Administrators)
#  - Windows's auto-generated code for CIM cmdlets (CDXML: Defender/NetSecurity) that the agent calls every run
#  on a DC these two exceeded 60 MB/hour; all other PowerShell events are sent as before.
# the agent's own noise in the PowerShell log (only when the user is SYSTEM): script blocks of the agent's own files
# (the install folder is writable only by SYSTEM/Administrators) and Windows-generated CDXML wrappers for CIM cmdlets.
function Test-LogBokSelfNoise {
    param($Event, [string]$Xml, [string]$InstallDir, [hashtable]$Seen)
    $id = [int]$Event.Id
    if ($id -ne 4104 -and $id -ne 4103) { return $false }
    if (-not $Xml -or $Xml -notmatch "UserID='S-1-5-18'") { return $false }
    $dir = $InstallDir.TrimEnd('\') + '\'
    try { $x = [xml]$Xml } catch { return $false }
    $d = @{}; foreach ($n in @($x.Event.EventData.Data)) { if ($n -and $n.Name) { $d[[string]$n.Name] = [string]$n.'#text' } }
    if ($id -eq 4103) {
        $ctx = [string]$d['ContextInfo']
        return ($ctx -and $ctx.IndexOf(('Script Name = ' + $dir), [StringComparison]::OrdinalIgnoreCase) -ge 0)
    }
    $path = [string]$d['Path']; $sb = [string]$d['ScriptBlockId']; $txt = [string]$d['ScriptBlockText']
    if ($path) { return $path.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) }
    if ($sb -and $Seen.ContainsKey($sb)) { return $true }
    if ($txt -match '^\s*#requires -version 3\.0\s+try \{ Microsoft\.PowerShell\.Core\\Set-StrictMode -Off \} catch \{ \}' -and $txt -match '__cmdletization_') {
        if ($sb) { $Seen[$sb] = $true }
        return $true
    }
    return $false
}

# truncate a long XML so the structure (and fields after the script text, like Path) stays intact
# shortens long event XML so it stays well-formed and keeps the fields after the script text (e.g. Path)
function Limit-LogBokXml {
    param([string]$Xml, [int]$Max = 20000)
    if (-not $Xml -or $Xml.Length -le $Max) { return $Xml }
    $m = [regex]::Match($Xml, "(?s)(<Data Name='(?:ScriptBlockText|Payload|ContextInfo)'>)(.*?)(</Data>)")
    if ($m.Success) {
        $keep = $m.Groups[2].Length - ($Xml.Length - $Max) - 40
        if ($keep -gt 200) {
            $t = $m.Groups[2].Value.Substring(0, $keep) -replace '&[#A-Za-z0-9]{0,8}$', ''
            return $Xml.Substring(0, $m.Groups[2].Index) + $t + ' …[truncated]' + $Xml.Substring($m.Groups[3].Index)
        }
    }
    return $Xml.Substring(0, $Max)
}

function Invoke-LogBokForward {
    param([string]$InstallDir = 'C:\Scripts\LogBok', [int]$MaxPerLog = 1000, [int]$FirstMinutes = 120)
    $seenSb = @{}
    $a = Get-LogBokAgentInfo -InstallDir $InstallDir
    if (-not $a) { return $null }
    if ($a.Enrolled -ne $true) {
        $enr = Invoke-LogBokEnroll -InstallDir $InstallDir
        if (-not $enr.Ok) { $res = [ordered]@{ At = (Get-Date).ToString('o'); Sent = 0; Ok = $false; Error = ('enroll: ' + $enr.Error) }; try { ($res | ConvertTo-Json) | Set-Content -Path (Join-Path $InstallDir 'state\forward-last.json') -Encoding UTF8 } catch { }; return $res }
        $a = Get-LogBokAgentInfo -InstallDir $InstallDir
    }
    $bf = Join-Path $InstallDir 'state\forward.json'
    $bm = @{}; if (Test-Path $bf) { try { (Get-Content $bf -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $bm[$_.Name] = $_.Value } } catch { } }
    $sent = 0; $fails = 0; $lastErr = ''
    foreach ($lg in $script:FwdLogs) {
        $mark = $bm[$lg]
        $since = (Get-Date).AddMinutes(-$FirstMinutes); $lastRec = [long]0
        if ($mark) { try { $since = [datetime]::Parse([string]$mark.t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-1); $lastRec = [long]$mark.r } catch { } }
        if ($since -lt (Get-Date).AddHours(-24)) { $since = (Get-Date).AddHours(-24) }
        $ev = @()
        try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $lg; StartTime = $since } -MaxEvents $MaxPerLog -Oldest -ErrorAction Stop) } catch { continue }
        $ev = @($ev | Where-Object { [long]$_.RecordId -gt $lastRec -or ([long]$_.RecordId -lt $lastRec - 100000000) })
        if (-not $ev.Count) { continue }
        for ($i = 0; $i -lt $ev.Count; $i += 400) {
            $chunk = @($ev[$i..([math]::Min($i + 399, $ev.Count - 1))])
            $items = @(foreach ($e in $chunk) {
                $xml = ''; try { $xml = $e.ToXml() } catch { }
                if (Test-LogBokSelfNoise -Event $e -Xml $xml -InstallDir $InstallDir -Seen $seenSb) { continue }
                $msg = ''; try { $msg = [string]$e.Message } catch { }
                [ordered]@{ l = $lg; i = [int]$e.Id; t = $e.TimeCreated.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture); r = [long]$e.RecordId
                            p = [string]$e.ProviderName; v = [string]$e.LevelDisplayName; m = [string]$e.MachineName
                            s = $msg.Substring(0, [math]::Min(4000, $msg.Length)); x = (Limit-LogBokXml $xml 20000) }
            })
            $r = @{ Ok = $true }
            if ($items.Count) { $r = Send-LogBokBatch -InstallDir $InstallDir -Info $a -Events $items }
            if (-not $r.Ok) { $fails++; $lastErr = $(if ($r.Error) { $r.Error } else { "HTTP $($r.Code)" }); if ($r.Code -eq 401 -and $r.Text -match 'reenroll') { Set-LogBokInfoField $a 'Enrolled' $false; Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a }; break }
            $lastE = $chunk[-1]
            $bm[$lg] = @{ t = $lastE.TimeCreated.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture); r = [long]$lastE.RecordId }
            $sent += $items.Count
            Start-Sleep -Milliseconds 200   # gentle pacing; do not load the network and disk
        }
        if ($fails) { break }
    }
    # control heartbeat (always): health/inventory/results up, policy/command/update down
    # the heartbeat goes out EVERY cycle, also after a failed event batch, and carries that error, so the server
    # always sees the computer as online and learns why events are not arriving
    $c = $null; try { $c = Invoke-LogBokControl -InstallDir $InstallDir -Info $a -FwdError $lastErr } catch { $c = @{ Ok = $false; Error = $_.Exception.Message } }; if (-not $c.Ok) { $fails++; $lastErr = (($lastErr + ' | heartbeat: ' + [string]$c.Error).Trim(' |')) }
    try { ($bm | ConvertTo-Json -Depth 4) | Set-Content -Path $bf -Encoding UTF8 } catch { }
    $res = [ordered]@{ At = (Get-Date).ToString('o'); Sent = $sent; Ok = (-not $fails); Error = $lastErr }
    try { ($res | ConvertTo-Json) | Set-Content -Path (Join-Path $InstallDir 'state\forward-last.json') -Encoding UTF8 } catch { }
    return $res
}

# --- inventory & health ----------------------------------------------------
function Get-LogBokInventory {
    $o = [ordered]@{ at = (Get-Date).ToString('o') }
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $o.os = [ordered]@{ n = [string]$os.Caption; v = [string]$os.Version; b = [string]$os.BuildNumber; arch = [string]$os.OSArchitecture; inst = $(if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') } else { '' }); boot = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { '' }) } } catch { }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $o.hw = [ordered]@{ mf = [string]$cs.Manufacturer; model = [string]$cs.Model; ramGB = [math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1); domain = [string]$cs.Domain; joined = [bool]$cs.PartOfDomain; user = [string]$cs.UserName } } catch { }
    try { $o.hw.serial = [string](Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber } catch { }
    try { $o.cpu = @(Get-CimInstance Win32_Processor -ErrorAction Stop | ForEach-Object { [ordered]@{ n = ([string]$_.Name).Trim(); cores = [int]$_.NumberOfCores; lp = [int]$_.NumberOfLogicalProcessors } }) } catch { }
    try { $o.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object { [ordered]@{ d = [string]$_.DeviceID; sizeGB = [math]::Round([double]$_.Size / 1GB, 1); freeGB = [math]::Round([double]$_.FreeSpace / 1GB, 1); fs = [string]$_.FileSystem } }) } catch { }
    try { $o.net = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object { [ordered]@{ n = [string]$_.Description; mac = [string]$_.MACAddress; ip = @($_.IPAddress | Where-Object { $_ -match '^\d+\.' }); gw = @($_.DefaultIPGateway); dns = @($_.DNSServerSearchOrder); dhcp = [bool]$_.DHCPEnabled } }) } catch { }
    # software from the registry (not Win32_Product, which is slow and problematic)
    $sw = New-Object System.Collections.ArrayList; $seen = @{}
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    try { foreach ($k in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) { $paths += "Registry::HKEY_USERS\$($k.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" } } catch { }
    foreach ($p in $paths) {
        foreach ($i in @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue)) {
            $n = [string]$i.DisplayName; if (-not $n -or $i.SystemComponent -eq 1 -or $i.ParentKeyName) { continue }
            $key = "$n|$($i.DisplayVersion)"; if ($seen[$key]) { continue }; $seen[$key] = $true
            [void]$sw.Add([ordered]@{ n = $n; v = [string]$i.DisplayVersion; p = [string]$i.Publisher; d = [string]$i.InstallDate })
        }
    }
    $o.software = @($sw | Sort-Object { $_.n })
    # programs with live network connections (for "per-application internet control")
    try { $o.netapps = @(Get-LogBokNetApps) } catch { }
    try { $o.hotfix = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object { [ordered]@{ id = [string]$_.HotFixID; on = $(if ($_.InstalledOn) { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } else { '' }) } }) } catch { }
    try {
        $gn = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]("WinNT://./$gn,group")
        $o.admins = @($g.psbase.Invoke('Members') | ForEach-Object { ([string]$_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null)) -replace '^WinNT://', '' -replace '/', '\' })
    } catch { }
    return $o
}
# processes with network connections: name, path, connection count, internet vs LAN
function Test-LogBokPrivateIp {
    param([string]$Ip)
    if (-not $Ip -or $Ip -eq '0.0.0.0' -or $Ip -eq '::' -or $Ip -match '^(127\.|::1$|169\.254\.|fe80:|10\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    if ($Ip -match '^(224\.|239\.|255\.|ff)') { return $true }
    return $false
}
function Get-LogBokNetApps {
    $by = @{}
    $conns = @(); try { $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop) } catch { }
    foreach ($c in $conns) {
        $pid0 = [int]$c.OwningProcess; if ($pid0 -le 4) { continue }
        if (-not $by.ContainsKey($pid0)) { $by[$pid0] = @{ c = 0; inet = 0; remotes = @{} } }
        $by[$pid0].c++
        $ra = [string]$c.RemoteAddress
        if (-not (Test-LogBokPrivateIp $ra)) { $by[$pid0].inet++; if ($by[$pid0].remotes.Count -lt 5) { $by[$pid0].remotes[$ra] = [int]$c.RemotePort } }
    }
    $udp = @(); try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { [int]$_.OwningProcess -gt 4 }) } catch { }
    foreach ($u in $udp) { $pid0 = [int]$u.OwningProcess; if (-not $by.ContainsKey($pid0)) { $by[$pid0] = @{ c = 0; inet = 0; remotes = @{}; udp = $true } } }
    $out = @{}
    foreach ($pid0 in @($by.Keys)) {
        $pr = $null; try { $pr = Get-Process -Id $pid0 -ErrorAction Stop } catch { continue }
        $path = ''; try { $path = [string]$pr.Path } catch { }
        $exe = $(if ($path) { [IO.Path]::GetFileName($path) } else { $pr.ProcessName + '.exe' })
        $k = $exe.ToLowerInvariant()
        if (-not $out.ContainsKey($k)) { $out[$k] = [ordered]@{ n = $exe; p = $path; c = 0; inet = 0; r = @(); u = '' } }
        $out[$k].c += [int]$by[$pid0].c; $out[$k].inet += [int]$by[$pid0].inet
        foreach ($rk in @($by[$pid0].remotes.Keys)) { if (@($out[$k].r).Count -lt 5 -and @($out[$k].r) -notcontains $rk) { $out[$k].r += $rk } }
        if (-not $out[$k].u) { try { $own = (Get-CimInstance Win32_Process -Filter "ProcessId=$pid0" -ErrorAction Stop).GetOwner(); if ($own.User) { $out[$k].u = ("{0}\{1}" -f $own.Domain, $own.User) } } catch { } }
    }
    return @($out.Values | Sort-Object { -$_.inet }, { $_.n })
}
function Get-LogBokHealth {
    param([string]$InstallDir = 'C:\Scripts\LogBok')
    $h = [ordered]@{ at = (Get-Date).ToString('o') }
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $h.uptimeH = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1); $h.memFreePct = [math]::Round(100 * [double]$os.FreePhysicalMemory / [double]$os.TotalVisibleMemorySize, 0) } catch { }
    try { $h.cpu = [int](@(Get-CimInstance Win32_Processor -ErrorAction Stop | Measure-Object LoadPercentage -Average).Average) } catch { }
    try { $c = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop; $h.cFreePct = [math]::Round(100 * [double]$c.FreeSpace / [double]$c.Size, 0); $h.cFreeGB = [math]::Round([double]$c.FreeSpace / 1GB, 1) } catch { }
    try { $m = Get-MpComputerStatus -ErrorAction Stop; $h.av = [ordered]@{ on = [bool]$m.AMServiceEnabled; rt = [bool]$m.RealTimeProtectionEnabled; sigAge = [int]$m.AntivirusSignatureAge; scanAge = [int]$m.QuickScanAge } } catch { $h.av = $null }
    try { $h.fw = [ordered]@{}; foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) { $h.fw[[string]$p.Name] = [bool]$p.Enabled } } catch { }
    $h.rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    try { $h.user = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch { }
    try { $bl = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection'); $h.bitlocker = $(switch ([int]$bl) { 1 { 'on' } 3 { 'on' } 5 { 'on' } 2 { 'off' } 6 { 'off' } default { '' } }) } catch { }
    try { $h.isolated = Test-Path (Join-Path $InstallDir 'state\isolation.json') } catch { }
    return $h
}

# --- per-application internet control --------------------------------------
$script:PublicV4 = @('0.0.0.1-9.255.255.255','11.0.0.0-100.63.255.255','100.128.0.0-126.255.255.255','128.0.0.0-169.253.255.255','169.255.0.0-172.15.255.255','172.32.0.0-192.167.255.255','192.169.0.0-223.255.255.255','2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
function Resolve-LogBokProgram {
    param([string]$Spec, [hashtable]$Cache)
    if ($Spec -match '\\') { return @([Environment]::ExpandEnvironmentVariables($Spec)) }
    $c = $Cache[$Spec.ToLowerInvariant()]
    if ($c -and $c.at -and ([datetime]::Parse([string]$c.at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) -gt (Get-Date).AddHours(-6))) { return @($c.paths) }
    $found = New-Object System.Collections.ArrayList
    try { foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Split-Path $_.Path -Leaf) -eq $Spec } | ForEach-Object { $_.Path })) { if ($found -notcontains $p) { [void]$found.Add($p) } } } catch { }
    $roots = @(@{ P = $env:ProgramFiles; D = 4 }, @{ P = ${env:ProgramFiles(x86)}; D = 4 }, @{ P = $env:ProgramData; D = 3 })
    $ud = Join-Path ([string]$env:SystemDrive + '\') 'Users'
    $uds = @(); if ($env:SystemDrive -and (Test-Path -LiteralPath $ud)) { try { $uds = @(Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue) } catch { } }
    foreach ($u in $uds) { $roots += @{ P = (Join-Path $u.FullName 'AppData\Local'); D = 4 }; $roots += @{ P = (Join-Path $u.FullName 'AppData\Roaming'); D = 3 } }
    foreach ($r in $roots) {
        if (-not $r.P -or -not (Test-Path $r.P)) { continue }
        try { foreach ($f in @(Get-ChildItem -Path $r.P -Filter $Spec -File -Recurse -Depth $r.D -ErrorAction SilentlyContinue)) { if ($found -notcontains $f.FullName) { [void]$found.Add($f.FullName) } } } catch { }
    }
    $Cache[$Spec.ToLowerInvariant()] = @{ at = (Get-Date).ToString('o'); paths = @($found) }
    return @($found)
}
function Test-LogBokInWindow {
    param($Schedule)
    if (-not $Schedule -or $Schedule.Enabled -ne $true) { return $true }
    $now = Get-Date
    if (@($Schedule.Days).Count -and @($Schedule.Days) -notcontains $now.DayOfWeek.ToString()) { return $false }
    $m = $now.Hour * 60 + $now.Minute
    $a = [int]([string]$Schedule.Start).Split(':')[0] * 60 + [int]([string]$Schedule.Start).Split(':')[1]
    $b = [int]([string]$Schedule.End).Split(':')[0] * 60 + [int]([string]$Schedule.End).Split(':')[1]
    if ($a -le $b) { return ($m -ge $a -and $m -lt $b) } else { return ($m -ge $a -or $m -lt $b) }
}
# resolve a user/group name to a SID (for the firewall LocalUser filter)
function Resolve-LogBokPrincipalSid {
    param([string]$Name)
    $n = ([string]$Name).Trim()
    if (-not $n) { return $null }
    if ($n -match '^S-1-[0-9-]+$') { return $n }
    try { return (New-Object Security.Principal.NTAccount($n)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
    $wk = @{ 'everyone' = 'S-1-1-0'; 'authenticated users' = 'S-1-5-11'; 'users' = 'S-1-5-32-545'; 'administrators' = 'S-1-5-32-544'; 'guests' = 'S-1-5-32-546' }
    $k = $n.ToLowerInvariant() -replace '^.*\\', ''
    if ($wk.ContainsKey($k)) { return $wk[$k] }
    return $null
}
# build a LocalUser SDDL: for specific users/groups only, or for everyone except an excepted group
function New-LogBokLocalUserSddl {
    param([string[]]$Users, [string[]]$Except, [ref]$Unresolved)
    $allow = @(); foreach ($u in @($Users)) { $s = Resolve-LogBokPrincipalSid $u; if ($s) { $allow += $s } elseif ($Unresolved) { $Unresolved.Value += [string]$u } }
    $deny = @();  foreach ($u in @($Except)) { $s = Resolve-LogBokPrincipalSid $u; if ($s) { $deny += $s } elseif ($Unresolved) { $Unresolved.Value += [string]$u } }
    if (-not $allow.Count -and -not $deny.Count) { return '' }
    if (-not $allow.Count) { $allow = @('S-1-1-0') }   # everyone, minus the excepted principals
    $d = ''
    foreach ($s in ($deny | Select-Object -Unique)) { $d += "(D;;CC;;;$s)" }    # deny ACEs first (conventional DACL order)
    foreach ($s in ($allow | Select-Object -Unique)) { $d += "(A;;CC;;;$s)" }
    return "O:LSD:$d"
}
function Set-LogBokAppBlocks {
    param([string]$InstallDir, [object[]]$Blocks, [switch]$Force)
    Import-LogBokCore $InstallDir
    $sf = Join-Path $InstallDir 'state\appblock-state.json'
    $st = @{ rules = @{}; cache = @{}; rev = '' }
    if (Test-Path $sf) { try { $st = ConvertTo-LBHashtable (Get-Content $sf -Raw | ConvertFrom-Json); if (-not $st.rules) { $st.rules = @{} }; if (-not $st.cache) { $st.cache = @{} } } catch { } }
    $want = @{}; $status = @(); $errors = @()
    foreach ($b in @($Blocks)) {
        $on = Test-LogBokInWindow $b.schedule
        $users = @(@($b.users) | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $except = @(@($b.except) | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $unres = @(); $sddl = New-LogBokLocalUserSddl -Users $users -Except $except -Unresolved ([ref]$unres)
        foreach ($u in ($unres | Select-Object -Unique)) { $errors += ("user/group not found on this computer: {0} (policy {1})" -f $u, $b.name) }
        $uscope = (($users | Sort-Object) -join ';') + '|' + (($except | Sort-Object) -join ';')
        foreach ($spec in @($b.programs)) {
            $paths = @(Resolve-LogBokProgram -Spec ([string]$spec) -Cache $st.cache)
            $status += [ordered]@{ policy = [string]$b.id; program = [string]$spec; paths = $paths; active = $on; users = $users; except = $except }
            foreach ($p in $paths) {
                $sha = [Security.Cryptography.SHA1]::Create(); $hx = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(("{0}|{1}|{2}|{3}" -f $b.id, $p.ToLowerInvariant(), $b.scope, $uscope))) | Select-Object -First 5 | ForEach-Object { $_.ToString('x2') })
                $want["LogBok-AppBlock-$($b.id)-$hx"] = @{ path = $p; scope = [string]$b.scope; on = $on; name = [string]$b.name; sddl = $sddl }
            }
        }
    }
    $sig = ((@($want.Keys) | Sort-Object) -join ',') + '|' + ((@($want.Keys) | Sort-Object | ForEach-Object { [string]$want[$_].on }) -join '')
    if ($Force -or $sig -ne [string]$st.rev) {
        $have = @{}
        try { foreach ($r in @(Get-NetFirewallRule -Group 'LogBok App Control' -ErrorAction SilentlyContinue)) { $have[[string]$r.DisplayName] = $r } } catch { }
        foreach ($n in @($have.Keys)) { if (-not $want.ContainsKey($n)) { try { Remove-NetFirewallRule -Name $have[$n].Name -ErrorAction Stop } catch { $errors += "remove $n : $($_.Exception.Message)" } } }
        foreach ($n in @($want.Keys)) {
            $w = $want[$n]; $en = $(if ($w.on) { 'True' } else { 'False' })
            try {
                if ($have.ContainsKey($n)) { Set-NetFirewallRule -Name $have[$n].Name -Enabled $en -ErrorAction Stop }
                else {
                    $ra = if ($w.scope -eq 'all') { 'Any' } else { $script:PublicV4 }
                    $np = @{ DisplayName = $n; Group = 'LogBok App Control'; Description = ("LogBok: internet blocked for {0} (policy {1})" -f $w.path, $w.name); Direction = 'Outbound'; Action = 'Block'; Program = $w.path; RemoteAddress = $ra; Profile = 'Any'; Enabled = $en; ErrorAction = 'Stop' }
                    if ($w.sddl) { $np.LocalUser = [string]$w.sddl }   # scope to specific users/groups
                    New-NetFirewallRule @np | Out-Null
                }
            } catch { $errors += "$($w.path): $($_.Exception.Message)" }
        }
        if (-not $errors.Count) { $st.rev = $sig }
    }
    try { (ConvertTo-Json -InputObject $st -Depth 6) | Set-Content -Path $sf -Encoding UTF8 } catch { }
    return [ordered]@{ rules = $want.Count; items = $status; errors = $errors }
}
function Import-LogBokCore { param([string]$InstallDir) if (-not (Get-Command Set-LBSetting -ErrorAction SilentlyContinue)) { Import-Module (Join-Path $InstallDir 'LogBok.Core.psm1') -DisableNameChecking -Global -ErrorAction Stop } }

# --- app removal (uninstall) enforced by policy ------------------------------
#  Runs each policy cycle, so an app that is reinstalled is removed again, and
#  a running instance is closed. Known tokens 'OneDrive' and 'Copilot' get the
#  correct per-app removal; any other token is treated as an app name and is
#  removed as a Store app and/or via its classic uninstall string.
# Remove an app's per-user traces so a later login can't bring it back: Run/Startup
# entries and scheduled tasks for EVERY profile (logged-in, logged-out, and the
# Default profile that new users are cloned from), plus leftover per-profile folders.
function Remove-LBUserTraces {
    param([string[]]$RunNames = @(), [string[]]$TaskLike = @(), [string[]]$FolderLeaf = @())
    foreach ($pat in @($TaskLike)) {
        try { Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like $pat } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }
    if (@($RunNames).Count) {
        $profiles = @()
        try { foreach ($p in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) { $pp = [string](Get-ItemProperty $p.PSPath -ErrorAction SilentlyContinue).ProfileImagePath; if ($pp -and (Test-Path (Join-Path $pp 'NTUSER.DAT'))) { $profiles += @{ Sid = $p.PSChildName; Dir = $pp } } } } catch { }
        $defDir = Join-Path $env:SystemDrive 'Users\Default'
        if (Test-Path (Join-Path $defDir 'NTUSER.DAT')) { $profiles += @{ Sid = 'LBDEFAULT'; Dir = $defDir } }
        $loaded = @{}; foreach ($k in (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue)) { $loaded[$k.PSChildName] = $true }
        foreach ($pr in $profiles) {
            $sid = [string]$pr.Sid; $temp = $false
            if (-not $loaded.ContainsKey($sid)) { try { & reg.exe load "HKU\$sid" (Join-Path $pr.Dir 'NTUSER.DAT') 2>&1 | Out-Null; $temp = $true } catch { continue } }
            try {
                foreach ($sub in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
                    $rk = "Registry::HKEY_USERS\$sid\$sub"
                    if (Test-Path $rk) { foreach ($vn in @((Get-Item $rk -ErrorAction SilentlyContinue).Property)) { foreach ($nm in @($RunNames)) { if ($vn -like $nm) { Remove-ItemProperty $rk -Name $vn -ErrorAction SilentlyContinue } } } }
                }
            } catch { } finally { if ($temp) { [gc]::Collect(); Start-Sleep -Milliseconds 120; & reg.exe unload "HKU\$sid" 2>&1 | Out-Null } }
        }
    }
    foreach ($leaf in @($FolderLeaf)) {
        foreach ($u in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
            $fp = Join-Path $u.FullName $leaf; if (Test-Path $fp) { try { Remove-Item $fp -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
        }
    }
}
function Remove-LBOneDriveApp {
    Get-Process -Name OneDrive, FileCoAuth, FileSyncHelper, OneDriveStandaloneUpdater -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($s in @("$env:SystemRoot\SysWOW64\OneDriveSetup.exe", "$env:SystemRoot\System32\OneDriveSetup.exe")) { if (Test-Path $s) { Start-Process $s '/uninstall' -Wait -ErrorAction SilentlyContinue } }
    # machine policy stops sync now and for every future user
    try { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Force | Out-Null; New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' -Value 1 -PropertyType DWord -Force | Out-Null } catch { }
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue
    Remove-LBUserTraces -RunNames @('OneDrive', 'OneDriveSetup') -TaskLike @('*OneDrive*') -FolderLeaf @('AppData\Local\Microsoft\OneDrive')
}
function Remove-LBCopilotApp {
    Get-Process -Name Copilot, CopilotNative, ai -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # -AllUsers removes it for every user; provisioned removal stops new users getting it
    foreach ($pat in @('*Microsoft.Copilot*', '*Windows.Ai.Copilot*', '*Microsoft.Windows.Ai.Copilot*')) { Get-AppxPackage -AllUsers $pat -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
    try { Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Copilot*' } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null } } catch { }
    try { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Force | Out-Null; New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' -Value 1 -PropertyType DWord -Force | Out-Null } catch { }
    Remove-LBUserTraces -RunNames @('*Copilot*') -TaskLike @('*Copilot*')
}
function Remove-LBClassicApp {
    param([string]$Like)
    $hit = $false
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($rt in $roots) {
        foreach ($k in @(Get-ItemProperty $rt -ErrorAction SilentlyContinue)) {
            $dn = [string]$k.DisplayName; if (-not $dn -or $dn -notlike "*$Like*") { continue }
            $u = [string]$k.QuietUninstallString; if (-not $u) { $u = [string]$k.UninstallString }
            if (-not $u) { continue }
            if ($u -notmatch '/quiet|/qn|/silent' -and $u -match 'msiexec') { $u = $u -replace '/I', '/X'; $u = "$u /qn /norestart" }
            try { Start-Process 'cmd.exe' ('/c ' + $u) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue; $hit = $true } catch { }
        }
    }
    return $hit
}
function Set-LogBokAppRemovals {
    param([string]$InstallDir, [object[]]$Items)
    $out = [ordered]@{ at = (Get-Date).ToString('o'); items = @(); errors = @() }
    foreach ($it in @($Items)) {
        foreach ($spec in @($it.programs)) {
            $name = ([string]$spec).Trim(); if (-not $name) { continue }
            $key = $name.ToLowerInvariant(); $removed = $false
            try {
                if ($key -eq 'onedrive') { Remove-LBOneDriveApp; $removed = $true }
                elseif ($key -eq 'copilot') { Remove-LBCopilotApp; $removed = $true }
                else {
                    $base = [IO.Path]::GetFileNameWithoutExtension($name)
                    Get-Process -Name $base -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    $appx = @(Get-AppxPackage -AllUsers "*$name*" -ErrorAction SilentlyContinue); if ($appx.Count) { $appx | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue; $removed = $true }
                    try { Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$name*" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null } } catch { }
                    if (Remove-LBClassicApp -Like $name) { $removed = $true }
                    Remove-LBUserTraces -RunNames @("*$base*") -TaskLike @("*$base*")
                }
                $out.items += [ordered]@{ policy = [string]$it.id; program = $name; removed = $removed }
            }
            catch { $out.errors += ("{0}: {1}" -f $name, $_.Exception.Message) }
        }
    }
    return $out
}
# desired state for Windows services (startup type + running state), set by policy
function Set-LogBokServices {
    param([string]$InstallDir, [object[]]$Items)
    $out = [ordered]@{ at = (Get-Date).ToString('o'); items = @(); errors = @() }
    foreach ($it in @($Items)) {
        $name = ([string]$it.name).Trim(); if (-not $name) { continue }
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { $out.errors += "service not found: $name"; $out.items += [ordered]@{ name = $name; found = $false }; continue }
        $startup = ([string]$it.startup).ToLowerInvariant(); $state = ([string]$it.state).ToLowerInvariant()
        try {
            if ($startup -eq 'disabled') { Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue }
            elseif ($startup -eq 'manual') { Set-Service -Name $name -StartupType Manual -ErrorAction SilentlyContinue }
            elseif ($startup -eq 'auto') { Set-Service -Name $name -StartupType Automatic -ErrorAction SilentlyContinue }
            elseif ($startup -eq 'delayed') { & sc.exe config $name start= delayed-auto 2>&1 | Out-Null }
            if ($state -eq 'running') { if ($startup -ne 'disabled') { Start-Service -Name $name -ErrorAction SilentlyContinue } }
            elseif ($state -eq 'stopped') { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
            $sv2 = Get-Service -Name $name -ErrorAction SilentlyContinue
            $out.items += [ordered]@{ name = $name; found = $true; status = [string]$sv2.Status; startup = [string]$sv2.StartType }
        }
        catch { $out.errors += ("{0}: {1}" -f $name, $_.Exception.Message) }
    }
    return $out
}
# this computer's login-guard profile
function Set-LogBokGuardProfile {
    param([string]$InstallDir, $Guard)
    Import-LogBokCore $InstallDir
    $sd = Join-Path $InstallDir 'state'
    $ov = Get-LBSettingsOverlay -StateDir $sd
    $bk = Join-Path $sd 'guard-prepolicy.json'
    if ($Guard) {
        # previous manual settings are kept so they can be restored when the policy is removed
        if (-not (Test-Path $bk) -and -not ($ov.Guard -and $ov.Guard.__policy)) { try { [IO.File]::WriteAllText($bk, (ConvertTo-Json -InputObject @{ Guard = $ov.Guard; Jobs = $(if ($ov.Jobs -and $ov.Jobs.ContainsKey('Guard')) { $ov.Jobs.Guard } else { $null }) } -Depth 8), (New-Object Text.UTF8Encoding($false))) } catch { } }
        $s = ConvertTo-LBHashtable $Guard.settings
        $s['__policy'] = [string]$Guard.id
        [void](Set-LBSetting -Path 'Guard' -Value $s -StateDir $sd)
        if ($s.Enabled -eq $false) { [void](Set-LBSetting -Path 'Jobs.Guard' -Value $false -StateDir $sd) } elseif ($ov.Jobs -and $ov.Jobs.ContainsKey('Guard')) { [void](Set-LBSetting -Path 'Jobs.Guard' -Remove -StateDir $sd) }
        return [ordered]@{ id = [string]$Guard.id; name = [string]$Guard.name; enabled = ($s.Enabled -ne $false) }
    }
    if ($ov.Guard -and $ov.Guard.__policy) {
        $prev = $null; if (Test-Path $bk) { try { $prev = ConvertTo-LBHashtable (Get-Content $bk -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { } }
        if ($prev -and $prev.Guard) { [void](Set-LBSetting -Path 'Guard' -Value $prev.Guard -StateDir $sd) } else { [void](Set-LBSetting -Path 'Guard' -Remove -StateDir $sd) }
        if ($prev -and $null -ne $prev.Jobs) { [void](Set-LBSetting -Path 'Jobs.Guard' -Value ([bool]$prev.Jobs) -StateDir $sd) } elseif ($ov.Jobs -and $ov.Jobs.ContainsKey('Guard')) { [void](Set-LBSetting -Path 'Jobs.Guard' -Remove -StateDir $sd) }
    }
    Remove-Item $bk -Force -ErrorAction SilentlyContinue
    return $null
}
function Invoke-LogBokPolicy {
    param([string]$InstallDir, $Policy)
    $res = [ordered]@{ rev = [string]$Policy.rev; at = (Get-Date).ToString('o') }
    try { $res.appblock = Set-LogBokAppBlocks -InstallDir $InstallDir -Blocks @($Policy.appBlocks) -Force } catch { $res.appblock = @{ errors = @($_.Exception.Message) } }
    try { $res.appremove = Set-LogBokAppRemovals -InstallDir $InstallDir -Items @($Policy.appRemoves) } catch { $res.appremove = @{ errors = @($_.Exception.Message) } }
    try { $res.services = Set-LogBokServices -InstallDir $InstallDir -Items @($Policy.services) } catch { $res.services = @{ errors = @($_.Exception.Message) } }
    try { $res.guard = Set-LogBokGuardProfile -InstallDir $InstallDir -Guard $Policy.guard } catch { $res.guardError = $_.Exception.Message }
    try { $res.applaunch = Set-LogBokAppLaunch -InstallDir $InstallDir -Policy $Policy.appLaunch } catch { $res.applaunch = @{ errors = @($_.Exception.Message) } }
    # enforced hardening: re-check and auto-fix the items
    $res.harden = @($Policy.harden | Where-Object { $_ })
    if ($res.harden.Count) { try { Set-Content (Join-Path $InstallDir 'state\posture-due.flag') '1' } catch { } }
    $res.patch = $(if ($Policy.patch) { [string]$Policy.patch.name } else { '' })
    try { (ConvertTo-Json -InputObject ([ordered]@{ policy = $Policy; status = $res }) -Depth 8) | Set-Content -Path (Join-Path $InstallDir 'state\policy.json') -Encoding UTF8 } catch { }
    return $res
}



# --- application execution control (pattern: Application Control in Endpoint Central) ---
#  based on Windows AppLocker. block mode = Enforce, warn/audit mode = AuditOnly (the program runs but
#  event 8003/8004 is logged; in warn the user is also notified). Two modes: a blocklist
#  or an allowlist. Nothing is hidden; the policy is visible to the admin via Get-AppLockerPolicy.
#  on editions without AppLocker (Home) it falls back automatically to Software Restriction Policies.
$script:LBAppLockerColl = @('Exe', 'Msi', 'Script')
$script:LBAllowBaseline = @(
    @{ id = '921cc481-6e17-4653-8f75-050b80acca20'; name = 'All files under Program Files'; path = '%PROGRAMFILES%\*' }
    @{ id = 'a61c8b2c-a319-4cd0-9690-d2177cad7b51'; name = 'All files under Windows'; path = '%WINDIR%\*' }
)
function Get-LBNewGuid { return [guid]::NewGuid().ToString() }
function Test-LBAppLockerAvailable {
    try { return [bool](Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue) } catch { return $false }
}
# one AppLocker path rule
function New-LBAppLockerPathRule {
    param([string]$Path, [string]$Action, [string]$Sid, [string]$Label)
    $xp = [Security.SecurityElement]::Escape($Path)
    $nm = [Security.SecurityElement]::Escape($Label)
    $tpl = '<FilePathRule Id="{0}" Name="{1}" Description="managed by LogBok" UserOrGroupSid="{2}" Action="{3}"><Conditions><FilePathCondition Path="{4}" /></Conditions></FilePathRule>'
    return ($tpl -f (Get-LBNewGuid), $nm, $Sid, $Action, $xp)
}
# an AppLocker rule from a program spec (filename or full path)
function New-LBAppLockerRule {
    param([string]$Spec, [string]$Action, [string]$Sid = 'S-1-1-0')
    $p = ([string]$Spec).Trim()
    if (-not $p) { return '' }
    $path = if ($p -eq '*') { '*' } elseif ($p -notmatch '[\\/]') { '*\' + $p } else { [Environment]::ExpandEnvironmentVariables($p) }
    return (New-LBAppLockerPathRule -Path $path -Action $Action -Sid $Sid -Label ("LogBok: {0} {1}" -f $Action, $p))
}
function New-LogBokAppLockerXml {
    param($Policy)
    $enf = if ([string]$Policy.mode -eq 'block') { 'Enabled' } else { 'AuditOnly' }
    $list = if ([string]$Policy.list -eq 'allowlist') { 'allowlist' } else { 'blocklist' }
    $specs = @(@($Policy.programs) | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<AppLockerPolicy Version="1">')
    foreach ($coll in $script:LBAppLockerColl) {
        [void]$sb.Append(('<RuleCollection Type="{0}" EnforcementMode="{1}">' -f $coll, $enf))
        if ($coll -eq 'Exe' -and $list -eq 'allowlist') {
            # listed programs + Windows itself only; admins unrestricted to avoid lockout | allowlist + baseline + admins
            foreach ($b in $script:LBAllowBaseline) { [void]$sb.Append((New-LBAppLockerPathRule -Path $b.path -Action 'Allow' -Sid 'S-1-1-0' -Label ("LogBok baseline: " + $b.name))) }
            [void]$sb.Append((New-LBAppLockerPathRule -Path '*' -Action 'Allow' -Sid 'S-1-5-32-544' -Label 'LogBok: administrators'))
            foreach ($s in $specs) { [void]$sb.Append((New-LBAppLockerRule -Spec $s -Action 'Allow')) }
        } else {
            # allow all, deny the listed programs
            [void]$sb.Append((New-LBAppLockerRule -Spec '*' -Action 'Allow'))
            foreach ($s in $specs) { if ($coll -eq 'Exe' -or $s -match '\.(msi|ps1|bat|cmd|vbs|js)$') { [void]$sb.Append((New-LBAppLockerRule -Spec $s -Action 'Deny')) } }
        }
        [void]$sb.Append('</RuleCollection>')
    }
    [void]$sb.Append('</AppLockerPolicy>')
    return $sb.ToString()
}
# an SRP-equivalent policy for editions without AppLocker (block/blocklist only)
function Set-LBAppLaunchSrp {
    param([string]$Programs, $Specs, [switch]$Clear)
    $root = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    $paths = $root + '\0\Paths'
    if (Test-Path $paths) { foreach ($k in @(Get-ChildItem $paths -ErrorAction SilentlyContinue)) { $d = (Get-ItemProperty $k.PSPath -Name Description -ErrorAction SilentlyContinue).Description; if ($d -eq 'LogBok') { Remove-Item $k.PSPath -Recurse -Force -ErrorAction SilentlyContinue } } }
    if ($Clear) { return }
    if (-not (Test-Path $root)) { New-Item -Path $root -Force | Out-Null }
    Set-ItemProperty -Path $root -Name 'DefaultLevel' -Value 0x40000 -Type DWord -Force    # Unrestricted by default
    Set-ItemProperty -Path $root -Name 'TransparentEnabled' -Value 1 -Type DWord -Force
    if (-not (Test-Path $paths)) { New-Item -Path $paths -Force | Out-Null }
    foreach ($s in @($Specs)) {
        $val = if ($s -match '[\\/]') { [Environment]::ExpandEnvironmentVariables([string]$s) } else { [string]$s }
        $kp = $paths + '\' + ([guid]::NewGuid().ToString('B'))
        New-Item -Path $kp -Force | Out-Null
        Set-ItemProperty -Path $kp -Name 'SaferFlags' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $kp -Name 'ItemData' -Value $val -Type ExpandString -Force
        Set-ItemProperty -Path $kp -Name 'Description' -Value 'LogBok' -Type String -Force
        Set-ItemProperty -Path $kp -Name 'ItemSize' -Value 0 -Type DWord -Force
    }
}
function Set-LogBokAppLaunch {
    param([string]$InstallDir, $Policy)
    $sd = Join-Path $InstallDir 'state'
    $sf = Join-Path $sd 'applaunch-state.json'
    $prev = $null; if (Test-Path $sf) { try { $prev = Get-Content $sf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    $result = [ordered]@{ at = (Get-Date).ToString('o'); engine = ''; mode = ''; list = ''; count = 0; errors = @() }
    $useAL = Test-LBAppLockerAvailable
    if (-not $Policy) {
        # clear policy
        if ($prev -and [string]$prev.engine -eq 'applocker') { try { Clear-LBAppLockerLogBok } catch { $result.errors += [string]$_.Exception.Message } }
        elseif ($prev -and [string]$prev.engine -eq 'srp') { try { Set-LBAppLaunchSrp -Clear } catch { $result.errors += [string]$_.Exception.Message } }
        Remove-Item $sf -Force -ErrorAction SilentlyContinue
        return [ordered]@{ at = $result.at; engine = 'none'; count = 0; errors = $result.errors }
    }
    $result.mode = [string]$Policy.mode; $result.list = [string]$Policy.list
    $specs = @(@($Policy.programs) | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $result.count = $specs.Count
    if ($useAL) {
        $result.engine = 'applocker'
        try {
            try { $svc = Get-Service AppIDSvc -ErrorAction Stop; if ($svc.StartType -eq 'Disabled') { Set-Service AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue }; if ($svc.Status -ne 'Running') { Start-Service AppIDSvc -ErrorAction SilentlyContinue } } catch { }
            $xml = New-LogBokAppLockerXml -Policy $Policy
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ('LogBok-AL-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.xml')
            [IO.File]::WriteAllText($tmp, $xml, (New-Object Text.UTF8Encoding($false)))
            Set-AppLockerPolicy -XmlPolicy $tmp -ErrorAction Stop
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        } catch { $result.engine = ''; $result.errors += 'AppLocker: ' + $_.Exception.Message }
    }
    if ($result.engine -ne 'applocker') {
        # SRP fallback supports block/blocklist only
        if ([string]$Policy.mode -eq 'block' -and [string]$Policy.list -ne 'allowlist') {
            try { Set-LBAppLaunchSrp -Specs $specs; $result.engine = 'srp' } catch { $result.errors += 'SRP: ' + $_.Exception.Message }
        } elseif (-not $result.errors.Count) { $result.errors += 'AppLocker not available on this Windows edition; only block+blocklist is supported here' }
    }
    try { (ConvertTo-Json -InputObject $result -Depth 5) | Set-Content -Path $sf -Encoding UTF8 } catch { }
    return $result
}
function Clear-LBAppLockerLogBok {
    # remove only LogBok rules from the current policy (the admin's manual rules stay)
    $cur = $null; try { $cur = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop } catch { }
    $keepColl = @()
    if ($cur) {
        try {
            $doc = [xml]$cur
            foreach ($rc in @($doc.AppLockerPolicy.RuleCollection)) {
                $kept = @($rc.ChildNodes | Where-Object { [string]$_.Description -ne 'managed by LogBok' })
                $inner = ($kept | ForEach-Object { $_.OuterXml }) -join ''
                $keepColl += ('<RuleCollection Type="{0}" EnforcementMode="{1}">{2}</RuleCollection>' -f $rc.Type, $(if ($inner) { $rc.EnforcementMode } else { 'NotConfigured' }), $inner)
            }
        } catch { }
    }
    $xml = '<AppLockerPolicy Version="1">' + ($keepColl -join '') + '</AppLockerPolicy>'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('LogBok-AL-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.xml')
    [IO.File]::WriteAllText($tmp, $xml, (New-Object Text.UTF8Encoding($false)))
    Set-AppLockerPolicy -XmlPolicy $tmp -ErrorAction Stop
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
# in warn mode: read AppLocker events (8003 allowed-but-audited, 8004 blocked) and notify the user
function Invoke-LogBokAppLaunchWarn {
    param([string]$InstallDir, $Policy)
    if (-not $Policy -or [string]$Policy.mode -ne 'warn') { return }
    $sd = Join-Path $InstallDir 'state'; $wf = Join-Path $sd 'applaunch-warn.txt'
    $last = 0; if (Test-Path $wf) { try { $last = [long]((Get-Content $wf -Raw).Trim()) } catch { } }
    $max = $last
    $evts = @(); try { $evts = @(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 40 -ErrorAction Stop | Where-Object { $_.Id -in 8003, 8004 -and [long]$_.RecordId -gt $last }) } catch { return }
    $msgTxt = if ([string]$Policy.warnText) { [string]$Policy.warnText } else { 'این برنامه طبقِ سیاستِ سازمان مجاز نیست و استفاده از آن گزارش می‌شود. | This program is not permitted by company policy; its use is reported.' }
    foreach ($e in @($evts | Sort-Object RecordId)) {
        if ([long]$e.RecordId -gt $max) { $max = [long]$e.RecordId }
        $file = ''; try { $file = Split-Path -Leaf ([string]$e.Properties[0].Value) } catch { }
        try { & "$env:SystemRoot\System32\msg.exe" '*' /TIME:30 ("LogBok: {0}`n{1}" -f $file, $msgTxt) 2>$null } catch { }
    }
    if ($max -gt $last) { Set-Content -Path $wf -Value $max }
}

# --- security configuration assessment (pattern: Security Configuration Management in Endpoint Central / CIS) ---
#  security posture: read-only checks; only the whitelisted fixes below can be applied, each a documented
#  Windows setting. Every check is cheap (registry / built-in cmdlets) and runs at most once a day.
function Get-LogBokRegValue { param([string]$Path, [string]$Name) try { $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $null } }
function Get-LogBokNetAccounts {
    $o = @{}
    try { foreach ($l in @(& net.exe accounts 2>$null)) { if ($l -match '^\s*Minimum password length[^:]*:\s*(\S+)') { $o.MinLen = $Matches[1] }; if ($l -match '^\s*Lockout threshold[^:]*:\s*(\S+)') { $o.Lockout = $Matches[1] } } } catch { }
    return $o
}
$script:PostureDefs = @(
    @{ id = 'fw-on'; sev = 'high'; fa = 'فایروالِ ویندوز در همهٔ پروفایل‌ها روشن باشد'; en = 'Windows Firewall on for all profiles'; fixFa = 'روشن‌کردنِ فایروال'; fixEn = 'Turn the firewall on' }
    @{ id = 'av-rt'; sev = 'high'; fa = 'محافظتِ آنیِ Defender روشن باشد'; en = 'Defender real-time protection on'; fixFa = 'روشن‌کردنِ محافظتِ آنی'; fixEn = 'Turn real-time protection on' }
    @{ id = 'av-sig'; sev = 'medium'; fa = 'امضای آنتی‌ویروس به‌روز باشد (حداکثر ۳ روز)'; en = 'Antivirus signatures up to date (max 3 days)'; fixFa = 'به‌روزرسانیِ امضا'; fixEn = 'Update signatures' }
    @{ id = 'smb1'; sev = 'high'; fa = 'پروتکلِ قدیمیِ SMBv1 خاموش باشد'; en = 'Legacy SMBv1 disabled'; fixFa = 'خاموش‌کردنِ SMBv1'; fixEn = 'Disable SMBv1' }
    @{ id = 'rdp-nla'; sev = 'high'; fa = 'اگر ریموت‌دسکتاپ باز است، NLA اجباری باشد'; en = 'If Remote Desktop is on, NLA is required'; fixFa = 'اجباری‌کردنِ NLA'; fixEn = 'Require NLA' }
    @{ id = 'uac'; sev = 'high'; fa = 'UAC روشن باشد'; en = 'UAC enabled'; fixFa = 'روشن‌کردنِ UAC (پس از ری‌استارت)'; fixEn = 'Enable UAC (after restart)' }
    @{ id = 'guest'; sev = 'medium'; fa = 'حسابِ Guest غیرفعال باشد'; en = 'Guest account disabled'; fixFa = 'غیرفعال‌کردنِ Guest'; fixEn = 'Disable Guest' }
    @{ id = 'autorun'; sev = 'medium'; fa = 'اجرای خودکارِ فلش و CD خاموش باشد'; en = 'AutoRun disabled for all drives'; fixFa = 'خاموش‌کردنِ AutoRun'; fixEn = 'Disable AutoRun' }
    @{ id = 'wdigest'; sev = 'high'; fa = 'WDigest رمزِ متنی را در حافظه نگه ندارد'; en = 'WDigest does not keep clear-text passwords'; fixFa = 'خاموش‌کردنِ WDigest'; fixEn = 'Disable WDigest credential caching' }
    @{ id = 'lsa-ppl'; sev = 'medium'; fa = 'محافظتِ LSA روشن باشد (ضدِ سرقتِ رمز از حافظه)'; en = 'LSA protection on (credential theft defence)'; fixFa = 'روشن‌کردنِ محافظتِ LSA (پس از ری‌استارت)'; fixEn = 'Enable LSA protection (after restart)' }
    @{ id = 'ntlm'; sev = 'medium'; fa = 'فقط NTLMv2 فرستاده شود'; en = 'Send NTLMv2 only'; fixFa = 'تنظیمِ LmCompatibilityLevel روی 3'; fixEn = 'Set LmCompatibilityLevel to 3' }
    @{ id = 'llmnr'; sev = 'low'; fa = 'LLMNR خاموش باشد (ضدِ جعلِ نام در شبکه)'; en = 'LLMNR disabled (name-spoofing defence)'; fixFa = 'خاموش‌کردنِ LLMNR'; fixEn = 'Disable LLMNR' }
    @{ id = 'anon'; sev = 'low'; fa = 'فهرست‌کردنِ ناشناسِ حساب‌ها ممنوع باشد'; en = 'No anonymous enumeration of accounts'; fixFa = 'محدودکردنِ دسترسیِ ناشناس'; fixEn = 'Restrict anonymous access' }
    @{ id = 'ps2'; sev = 'medium'; fa = 'موتورِ قدیمیِ PowerShell 2 حذف باشد'; en = 'Legacy PowerShell 2.0 engine removed'; fixFa = 'حذفِ PowerShell 2.0'; fixEn = 'Remove PowerShell 2.0' }
    @{ id = 'screenlock'; sev = 'low'; fa = 'قفلِ خودکارِ صفحه پس از حداکثر ۱۵ دقیقه'; en = 'Automatic screen lock after at most 15 minutes'; fixFa = 'تنظیمِ قفلِ خودکار روی ۱۵ دقیقه'; fixEn = 'Set automatic lock to 15 minutes' }
    @{ id = 'pwlen'; sev = 'medium'; fa = 'حداقلِ طولِ رمز ۸ کاراکتر (سیستم‌های خارج از دامنه)'; en = 'Minimum password length 8 (non-domain computers)'; fixFa = 'تنظیمِ حداقلِ طولِ رمز'; fixEn = 'Set minimum password length' }
    @{ id = 'lockout'; sev = 'medium'; fa = 'قفل‌شدنِ حساب پس از تلاش‌های ناموفق (سیستم‌های خارج از دامنه)'; en = 'Account lockout after failed attempts (non-domain computers)'; fixFa = 'تنظیمِ قفلِ حساب پس از ۱۰ تلاش'; fixEn = 'Lock accounts after 10 failures' }
    @{ id = 'wuauserv'; sev = 'high'; fa = 'سرویسِ Windows Update غیرفعال نباشد'; en = 'Windows Update service not disabled'; fixFa = 'فعال‌کردنِ سرویسِ Windows Update'; fixEn = 'Re-enable Windows Update service' }
    @{ id = 'audit-logon'; sev = 'medium'; fa = 'ممیزیِ ورودِ موفق و ناموفق روشن باشد'; en = 'Logon success/failure auditing on'; fixFa = 'روشن‌کردنِ ممیزیِ ورود'; fixEn = 'Enable logon auditing' }
    @{ id = 'bitlocker'; sev = 'medium'; fa = 'درایوِ ویندوز با BitLocker رمزگذاری شده باشد'; en = 'System drive encrypted with BitLocker'; fixFa = 'BitLocker را با ذخیرهٔ کلیدِ بازیابی دستی روشن کنید'; fixEn = 'Enable BitLocker manually and store the recovery key' }
    @{ id = 'admins'; sev = 'low'; fa = 'تعدادِ مدیرانِ محلی کم باشد (حداکثر ۳)'; en = 'Few local administrators (max 3)'; fixFa = 'اعضای غیرضروری را از Administrators حذف کنید'; fixEn = 'Remove unnecessary members of Administrators' }
)
$script:PostureFixable = @('fw-on', 'av-rt', 'av-sig', 'smb1', 'rdp-nla', 'uac', 'guest', 'autorun', 'wdigest', 'lsa-ppl', 'ntlm', 'llmnr', 'anon', 'ps2', 'screenlock', 'pwlen', 'lockout', 'wuauserv', 'audit-logon')
function Test-LogBokPostureCheck {
    param([string]$Id)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $domain = $false; try { $domain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
    switch ($Id) {
        'fw-on'   { $off = @(); try { $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name }) } catch { return @{ ok = $null; val = 'n/a' } }; return @{ ok = (-not $off.Count); val = $(if ($off.Count) { 'off: ' + ($off -join ',') } else { 'on' }) } }
        'av-rt'   { try { $m = Get-MpComputerStatus -ErrorAction Stop; return @{ ok = [bool]$m.RealTimeProtectionEnabled; val = $(if ($m.RealTimeProtectionEnabled) { 'on' } else { 'off' }) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'av-sig'  { try { $m = Get-MpComputerStatus -ErrorAction Stop; return @{ ok = ([int]$m.AntivirusSignatureAge -le 3); val = ('{0} d' -f $m.AntivirusSignatureAge) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'smb1'    { try { $v = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol; return @{ ok = (-not $v); val = $(if ($v) { 'enabled' } else { 'disabled' }) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'rdp-nla' { $deny = Get-LogBokRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'; if ($deny -ne 0) { return @{ ok = $true; val = 'RDP off' } }; $n = Get-LogBokRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'; return @{ ok = ($n -eq 1); val = $(if ($n -eq 1) { 'NLA on' } else { 'NLA off' }) } }
        'uac'     { $v = Get-LogBokRegValue $pol 'EnableLUA'; return @{ ok = ($v -ne 0); val = [string]$v } }
        'guest'   { try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like 'S-1-5-*-501' } | Select-Object -First 1; if (-not $g) { return @{ ok = $true; val = 'none' } }; return @{ ok = (-not $g.Enabled); val = $(if ($g.Enabled) { 'enabled' } else { 'disabled' }) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'autorun' { $v = Get-LogBokRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'; return @{ ok = ($v -eq 255); val = [string]$v } }
        'wdigest' { $v = Get-LogBokRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'; return @{ ok = ($v -ne 1); val = [string]$v } }
        'lsa-ppl' { $v = Get-LogBokRegValue $lsa 'RunAsPPL'; return @{ ok = ($v -in 1, 2); val = [string]$v } }
        'ntlm'    { $v = Get-LogBokRegValue $lsa 'LmCompatibilityLevel'; if ($null -eq $v) { $v = 3 }; return @{ ok = ([int]$v -ge 3); val = [string]$v } }
        'llmnr'   { $v = Get-LogBokRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'; return @{ ok = ($v -eq 0); val = $(if ($v -eq 0) { 'off' } else { 'on' }) } }
        'anon'    { $a = Get-LogBokRegValue $lsa 'RestrictAnonymousSAM'; $b = Get-LogBokRegValue $lsa 'RestrictAnonymous'; return @{ ok = ($a -ne 0 -and $b -ge 1); val = ('SAM={0} RA={1}' -f $a, $b) } }
        'ps2'     { $v = Get-LogBokRegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion'; return @{ ok = (-not $v); val = $(if ($v) { 'installed' } else { 'removed' }) } }
        'screenlock' { $v = Get-LogBokRegValue $pol 'InactivityTimeoutSecs'; return @{ ok = ($v -and [int]$v -gt 0 -and [int]$v -le 900); val = $(if ($v) { '{0} s' -f $v } else { 'not set' }) } }
        'pwlen'   { if ($domain) { return @{ ok = $true; val = 'domain policy' } }; $n = Get-LogBokNetAccounts; $l = 0; [void][int]::TryParse([string]$n.MinLen, [ref]$l); return @{ ok = ($l -ge 8); val = [string]$n.MinLen } }
        'lockout' { if ($domain) { return @{ ok = $true; val = 'domain policy' } }; $n = Get-LogBokNetAccounts; $l = 0; [void][int]::TryParse([string]$n.Lockout, [ref]$l); return @{ ok = ($l -gt 0); val = [string]$n.Lockout } }
        'wuauserv'{ try { $s = Get-Service wuauserv -ErrorAction Stop; return @{ ok = ([string]$s.StartType -ne 'Disabled'); val = [string]$s.StartType } } catch { return @{ ok = $null; val = 'n/a' } } }
        'audit-logon' { try { $o = @(& auditpol.exe /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' 2>$null) -join ' '; $ok = ($o -match 'Success and Failure'); return @{ ok = $ok; val = $(if ($ok) { 'success+failure' } else { 'incomplete' }) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'bitlocker' { try { $bl = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection'); if ($null -eq $bl) { return @{ ok = $null; val = 'n/a' } }; $on = ([int]$bl -in 1, 3, 5); return @{ ok = $on; val = $(if ($on) { 'on' } else { 'off' }) } } catch { return @{ ok = $null; val = 'n/a' } } }
        'admins'  { try { $gn = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]; $n = @(([ADSI]("WinNT://./$gn,group")).psbase.Invoke('Members')).Count; return @{ ok = ($n -le 3); val = [string]$n } } catch { return @{ ok = $null; val = 'n/a' } } }
    }
    return @{ ok = $null; val = '' }
}
function Get-LogBokPosture {
    $w = @{ high = 10; medium = 5; low = 2 }; $tot = 0; $got = 0
    $checks = foreach ($d in $script:PostureDefs) {
        $r = @{ ok = $null; val = '' }; try { $r = Test-LogBokPostureCheck -Id $d.id } catch { }
        if ($null -ne $r.ok) { $tot += $w[$d.sev]; if ($r.ok) { $got += $w[$d.sev] } }
        [ordered]@{ id = $d.id; ok = $r.ok; val = [string]$r.val; sev = $d.sev; fa = $d.fa; en = $d.en; fixFa = $d.fixFa; fixEn = $d.fixEn; fix = ($script:PostureFixable -contains $d.id) }
    }
    return [ordered]@{ at = (Get-Date).ToString('o'); score = $(if ($tot) { [int][math]::Round(100 * $got / $tot) } else { 0 }); checks = @($checks) }
}
function Repair-LogBokPostureItem {
    param([string]$Id)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $setReg = { param($p, $n, $v) if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; Set-ItemProperty -Path $p -Name $n -Value $v -Type DWord -Force }
    switch ($Id) {
        'fw-on'   { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop }
        'av-rt'   { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
        'av-sig'  { Update-MpSignature -ErrorAction Stop }
        'smb1'    { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop }
        'rdp-nla' { & $setReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 }
        'uac'     { & $setReg $pol 'EnableLUA' 1 }
        'guest'   { Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' } | Disable-LocalUser -ErrorAction Stop }
        'autorun' { & $setReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 }
        'wdigest' { & $setReg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }
        'lsa-ppl' { & $setReg $lsa 'RunAsPPL' 1 }
        'ntlm'    { & $setReg $lsa 'LmCompatibilityLevel' 3 }
        'llmnr'   { & $setReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
        'anon'    { & $setReg $lsa 'RestrictAnonymousSAM' 1; & $setReg $lsa 'RestrictAnonymous' 1 }
        'ps2'     { if (Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) { try { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null } catch { if (Get-Command Uninstall-WindowsFeature -ErrorAction SilentlyContinue) { Uninstall-WindowsFeature PowerShell-V2 -ErrorAction Stop | Out-Null } else { throw } } } }
        'screenlock' { & $setReg $pol 'InactivityTimeoutSecs' 900 }
        'pwlen'   { & net.exe accounts /minpwlen:8 | Out-Null }
        'lockout' { & net.exe accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15 | Out-Null }
        'wuauserv'{ Set-Service wuauserv -StartupType Manual -ErrorAction Stop }
        'audit-logon' { & auditpol.exe /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null }
        default   { throw "not fixable: $Id" }
    }
}
function Repair-LogBokPosture {
    param([string[]]$Ids)
    $out = @()
    foreach ($i in @($Ids | Where-Object { $script:PostureFixable -contains $_ } | Select-Object -Unique)) {
        try { Repair-LogBokPostureItem -Id $i; $out += "$i ok" } catch { $out += "$i failed: $($_.Exception.Message)" }
    }
    return ($out -join '; ')
}

# --- Windows update management (pattern: Patch Management in Endpoint Central) ---
#  Windows Update Agent (COM) runs in a separate hidden, low-priority process so the agent cycle never waits.
#  result: state\patches.json (list of missing updates + last install). Sent with the next heartbeat.
function Get-LogBokPatchLock { param([string]$InstallDir) return (Join-Path $InstallDir 'state\patch-running.flag') }
function Test-LogBokPatchBusy {
    param([string]$InstallDir)
    $f = Get-LogBokPatchLock $InstallDir
    if (-not (Test-Path $f)) { return $false }
    if ((Get-Item $f).LastWriteTime -lt (Get-Date).AddHours(-3)) { Remove-Item $f -Force -ErrorAction SilentlyContinue; return $false }
    return $true
}
function Start-LogBokPatchJob {
    param([string]$InstallDir, [ValidateSet('scan', 'install')][string]$Mode = 'scan', [ValidateSet('security', 'all')][string]$Scope = 'security', [ValidateSet('never', 'if-needed')][string]$Reboot = 'never', [string]$ActionId = '')
    if (Test-LogBokPatchBusy $InstallDir) { return 'busy' }
    Set-Content -Path (Get-LogBokPatchLock $InstallDir) -Value (Get-Date).ToString('o')
    $mod = Join-Path $InstallDir 'LogBok.Agent.psm1'
    $cmd = "`$p=[Diagnostics.Process]::GetCurrentProcess(); `$p.PriorityClass='BelowNormal'; Import-Module '$mod' -DisableNameChecking; Invoke-LogBokPatchWork -InstallDir '$InstallDir' -Mode '$Mode' -Scope '$Scope' -Reboot '$Reboot' -ActionId '$ActionId'"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    try { Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc" -WindowStyle Hidden -ErrorAction Stop }
    catch { Remove-Item (Get-LogBokPatchLock $InstallDir) -Force -ErrorAction SilentlyContinue; throw }
    return 'started'
}
function Test-LogBokPatchInScope {
    param($Update, [string]$Scope)
    if ($Scope -eq 'all') { return $true }
    if ([string]$Update.MsrcSeverity) { return $true }
    foreach ($c in @($Update.Categories)) { if ([string]$c.Name -in 'Security Updates', 'Critical Updates', 'Definition Updates', 'Update Rollups') { return $true } }
    return $false
}
function Invoke-LogBokPatchWork {
    param([string]$InstallDir, [string]$Mode = 'scan', [string]$Scope = 'security', [string]$Reboot = 'never', [string]$ActionId = '')
    $pf = Join-Path (Join-Path $InstallDir 'state') 'patches.json'
    $prev = $null; if (Test-Path $pf) { try { $prev = Get-Content $pf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    $res = [ordered]@{ at = (Get-Date).ToString('o'); missing = @(); error = ''; lastInstall = $(if ($prev) { $prev.lastInstall } else { $null }) }
    try {
        $ses = New-Object -ComObject Microsoft.Update.Session
        $ses.ClientApplicationID = 'LogBok'
        $sr = $ses.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $list = @(); foreach ($u in $sr.Updates) { $list += $u }
        if ($Mode -eq 'install') {
            $col = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $list) { if (Test-LogBokPatchInScope $u $Scope) { if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }; [void]$col.Add($u) } }
            $inst = [ordered]@{ at = (Get-Date).ToString('o'); scope = $Scope; count = $col.Count; ok = 0; failed = 0; rebootRequired = $false; actionId = $ActionId; error = '' }
            if ($col.Count) {
                $dl = $ses.CreateUpdateDownloader(); $dl.Updates = $col; [void]$dl.Download()
                $ins = $ses.CreateUpdateInstaller(); $ins.Updates = $col
                $ir = $ins.Install()
                for ($i = 0; $i -lt $col.Count; $i++) { $rc = $ir.GetUpdateResult($i).ResultCode; if ($rc -eq 2 -or $rc -eq 3) { $inst.ok++ } else { $inst.failed++ } }
                $inst.rebootRequired = [bool]$ir.RebootRequired
            }
            $res.lastInstall = $inst
            try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9014 -EntryType Information -Message ("LogBok: {0} update(s) installed, {1} failed (scope {2}); reboot required: {3}" -f $inst.ok, $inst.failed, $Scope, $inst.rebootRequired) } catch { }
            if ($inst.rebootRequired -and $Reboot -eq 'if-needed') { & shutdown.exe /r /t 900 /c 'Windows updates were installed by IT (LogBok). The computer restarts in 15 minutes; please save your work.' /d p:2:17 | Out-Null }
            $sr = $ses.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            $list = @(); foreach ($u in $sr.Updates) { $list += $u }
        }
        $res.missing = @(foreach ($u in $list) {
            $kb = ''; try { $kb = (@($u.KBArticleIDs) | ForEach-Object { 'KB' + $_ }) -join ',' } catch { }
            [ordered]@{ kb = $kb; title = [string]$u.Title; sev = $(if ($u.MsrcSeverity) { [string]$u.MsrcSeverity } else { (@($u.Categories) | Select-Object -First 1 | ForEach-Object { [string]$_.Name }) }); date = $(try { ([datetime]$u.LastDeploymentChangeTime).ToString('yyyy-MM-dd') } catch { '' }); reboot = ([int]$u.InstallationBehavior.RebootBehavior -gt 0); security = (Test-LogBokPatchInScope $u 'security'); sizeMB = [math]::Round([double]$u.MaxDownloadSize / 1MB, 0) }
        })
    } catch { $res.error = $_.Exception.Message }
    try { [IO.File]::WriteAllText($pf, (ConvertTo-Json -InputObject $res -Depth 5), (New-Object Text.UTF8Encoding($false))) } catch { }
    if ($ActionId) {
        $arf = Join-Path $InstallDir 'state\action-results.json'; $cur = @()
        if (Test-Path $arf) { try { $cur = @((Get-Content $arf -Raw | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_ }) } catch { } }
        $msg = if ($res.error) { 'Windows Update: ' + $res.error } elseif ($Mode -eq 'install') { '{0} installed, {1} failed, reboot required: {2}' -f $res.lastInstall.ok, $res.lastInstall.failed, $res.lastInstall.rebootRequired } else { '{0} missing update(s)' -f @($res.missing).Count }
        $cur += [ordered]@{ id = $ActionId; ok = (-not $res.error); out = $msg }
        try { (ConvertTo-Json -InputObject @($cur) -Depth 4) | Set-Content -Path $arf -Encoding UTF8 } catch { }
    }
    Remove-Item (Get-LogBokPatchLock $InstallDir) -Force -ErrorAction SilentlyContinue
}
# maintenance window for automatic install (from policy)
function Invoke-LogBokPatchPolicy {
    param([string]$InstallDir, $Patch)
    if (-not $Patch -or $Patch.enabled -eq $false) { return }
    $now = Get-Date
    if (@($Patch.days).Count -and @($Patch.days) -notcontains $now.DayOfWeek.ToString()) { return }
    $h = [int]$Patch.hour; if ($now.Hour -lt $h -or $now.Hour -ge ($h + 3)) { return }
    $mf = Join-Path $InstallDir 'state\patch-auto-last.txt'
    if ((Test-Path $mf) -and ((Get-Content $mf -Raw).Trim() -eq $now.ToString('yyyy-MM-dd'))) { return }
    if ((Start-LogBokPatchJob -InstallDir $InstallDir -Mode install -Scope $(if ($Patch.scope -eq 'all') { 'all' } else { 'security' }) -Reboot $(if ($Patch.reboot -eq 'if-needed') { 'if-needed' } else { 'never' })) -eq 'started') { Set-Content -Path $mf -Value $now.ToString('yyyy-MM-dd') }
}

# --- move to a new server (planned migration) ------------------------------
#  the new addresses are probed first (/ping); if none answer, nothing is changed so the agent is not left stranded.
#  the new addresses are probed first; if none answers, nothing changes so the agent is never stranded
function Set-LogBokServerAddress {
    param([string]$InstallDir, [string[]]$Names = @(), [string[]]$Ips = @(), [int]$Port = 0)
    $a = Get-LogBokAgentInfo -InstallDir $InstallDir
    if (-not $a) { throw 'agent.json missing' }
    $names = @($Names | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[A-Za-z0-9_.\-]{1,255}$' } | Select-Object -Unique)
    $ips = @($Ips | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique)
    if (-not $names.Count -and -not $ips.Count) { throw 'no new server address given' }
    $port = if ($Port -gt 0 -and $Port -lt 65536) { $Port } elseif ($a.IngestPort) { [int]$a.IngestPort } else { 8687 }
    foreach ($n in $names) { try { $ips += @([Net.Dns]::GetHostAddresses($n) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { } }
    $ips = @($ips | Select-Object -Unique)
    $alive = $false
    foreach ($h in @($names + $ips)) {
        try { $rq = [Net.HttpWebRequest]::Create(("http://{0}:{1}/ping" -f $h, $port)); $rq.Method = 'GET'; $rq.Timeout = 8000; $rq.Proxy = $null; $rs = $rq.GetResponse(); $rs.Close(); $alive = $true; break } catch { }
    }
    if (-not $alive) { throw ("new server not reachable on port {0} ({1}) - address NOT changed" -f $port, (@($names + $ips) -join ', ')) }
    $old = [string]$a.Collector
    Set-LogBokInfoField $a 'Collector' $(if ($names.Count) { $names[0] } else { $ips[0] })
    Set-LogBokInfoField $a 'CollectorNames' $names; Set-LogBokInfoField $a 'CollectorIps' $ips; Set-LogBokInfoField $a 'IngestPort' $port
    Set-LogBokInfoField $a 'CollectorCheckedAt' (Get-Date).ToString('o')
    Save-LogBokAgentInfo -InstallDir $InstallDir -Info $a
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9012 -EntryType Information -Message ("LogBok agent on {0}: server moved from {1} to {2}" -f $env:COMPUTERNAME, $old, $a.Collector) } catch { }
    return @{ ok = $true; out = ("server address changed to {0} (port {1})" -f $a.Collector, $port) }
}

# --- console actions (whitelisted types only) ------------------------------
function Invoke-LogBokAction {
    param([string]$InstallDir, $Action, $Info)
    $t = [string]$Action.type; $a = $Action.args
    try {
        switch ($t) {
            'inventory'       { Set-Content -Path (Join-Path $InstallDir 'state\inventory-due.flag') -Value '1'; return @{ ok = $true; out = 'inventory will be sent now' } }
            'sync-policy'     { $pf = Join-Path $InstallDir 'state\policy.json'; if (Test-Path $pf) { Remove-Item $pf -Force }; return @{ ok = $true; out = 'policy will be re-applied' } }
            'defender-scan'   { Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList '-NoProfile -WindowStyle Hidden -Command Start-MpScan -ScanType QuickScan' -WindowStyle Hidden; return @{ ok = $true; out = 'Defender quick scan started' } }
            'defender-update' { Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList '-NoProfile -WindowStyle Hidden -Command Update-MpSignature' -WindowStyle Hidden; return @{ ok = $true; out = 'Defender signature update started' } }
            'isolate'         { if (-not @($Info.CollectorIps).Count) { throw 'server IP unknown - isolation refused (the agent would lose contact)' }; Import-LogBokCore $InstallDir; Import-Module (Join-Path $InstallDir 'LogBok.Firewall.psm1') -Force -DisableNameChecking; $ip = @($Info.CollectorIps)[0]; Invoke-LogBokIsolate -AllowIp $ip -InstallDir $InstallDir; return @{ ok = $true; out = "isolated (only $ip allowed)" } }
            'unisolate'       { Import-Module (Join-Path $InstallDir 'LogBok.Firewall.psm1') -Force -DisableNameChecking; Restore-LogBokIsolate -InstallDir $InstallDir; return @{ ok = $true; out = 'isolation lifted' } }
            'kill-process'    { $n = [string]$a.name; if ($n -notmatch '^[A-Za-z0-9_.\- ]{1,80}$') { throw 'invalid name' }; $ps = @(Get-Process -Name $n -ErrorAction SilentlyContinue); $ps | Stop-Process -Force -ErrorAction SilentlyContinue; return @{ ok = $true; out = ("{0} process(es) stopped" -f $ps.Count) } }
            'block-ip'        { Import-LogBokCore $InstallDir; Import-Module (Join-Path $InstallDir 'LogBok.Guard.psm1') -Force -DisableNameChecking; [void](Add-LBGuardManualBlock -InstallDir $InstallDir -Ip ([string]$a.ip) -Minutes ([int]$a.minutes)); return @{ ok = $true; out = "blocked $($a.ip)" } }
            'unblock-ip'      { Import-LogBokCore $InstallDir; Import-Module (Join-Path $InstallDir 'LogBok.Guard.psm1') -Force -DisableNameChecking; [void](Remove-LBGuardBlocks -InstallDir $InstallDir -Ip @([string]$a.ip) -ResetHistory); return @{ ok = $true; out = "unblocked $($a.ip)" } }
            'reboot'          { $sec = [math]::Max(60, [int]$a.minutes * 60); $msg = ([string]$a.message); if (-not $msg) { $msg = 'Restart requested by IT (LogBok)' }; & shutdown.exe /r /t $sec /c $msg /d p:4:1 | Out-Null; return @{ ok = $true; out = "restart in $([int]($sec / 60)) min" } }
            'update-agent'    { return @{ ok = $true; out = 'update requested' } }
            'uninstall'       {
                # self-uninstall: a separate remover is created from System32 so that, after reporting the result, it removes the agent completely
                # self-uninstall: a separate cleaner launched from System32 removes the agent after we report back
                $clean = Join-Path $env:TEMP ('lbrm-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
                $script = @"
Start-Sleep -Seconds 12
try { Import-Module '$InstallDir\LogBok.Agent.psm1' -Force -DisableNameChecking; Uninstall-LogBokAgent -InstallDir '$InstallDir' } catch { }
try { Remove-Item -LiteralPath '$clean' -Force -ErrorAction SilentlyContinue } catch { }
"@
                Set-Content -LiteralPath $clean -Value $script -Encoding UTF8
                $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                Start-Process -FilePath $psExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $clean) -WindowStyle Hidden -WorkingDirectory (Join-Path $env:SystemRoot 'System32')
                return @{ ok = $true; out = 'uninstall scheduled; the agent removes itself shortly' }
            }
            'logoff-session'  { Import-Module (Join-Path $InstallDir 'LogBok.Sessions.psm1') -DisableNameChecking; return @{ ok = $true; out = (Invoke-LBSessionAction -Id ([int]$a.id) -Action logoff) } }
            'disconnect-session' { Import-Module (Join-Path $InstallDir 'LogBok.Sessions.psm1') -DisableNameChecking; return @{ ok = $true; out = (Invoke-LBSessionAction -Id ([int]$a.id) -Action disconnect) } }
            'message-session' { Import-Module (Join-Path $InstallDir 'LogBok.Sessions.psm1') -DisableNameChecking; return @{ ok = $true; out = (Invoke-LBSessionAction -Id ([int]$a.id) -Action message -Text ([string]$a.text)) } }
            'set-server'      { return (Set-LogBokServerAddress -InstallDir $InstallDir -Names @($a.names) -Ips @($a.ips) -Port ([int]$a.port)) }
            'posture-scan'    { Set-Content -Path (Join-Path $InstallDir 'state\posture-due.flag') -Value '1'; return @{ ok = $true; out = 'security check will run now' } }
            'fix-posture'     { $o = Repair-LogBokPosture -Ids @($a.checks); Set-Content -Path (Join-Path $InstallDir 'state\posture-due.flag') -Value '1'; return @{ ok = ($o -notmatch 'failed'); out = $o } }
            'patch-scan'      { $r = Start-LogBokPatchJob -InstallDir $InstallDir -Mode scan -ActionId ([string]$Action.id); return @{ ok = ($r -eq 'started'); out = $(if ($r -eq 'busy') { 'Windows Update is already running' } else { 'scan started in the background' }) } }
            'install-updates' { $r = Start-LogBokPatchJob -InstallDir $InstallDir -Mode install -Scope $(if ([string]$a.scope -eq 'all') { 'all' } else { 'security' }) -Reboot $(if ([string]$a.reboot -eq 'if-needed') { 'if-needed' } else { 'never' }) -ActionId ([string]$Action.id); return @{ ok = ($r -eq 'started'); out = $(if ($r -eq 'busy') { 'Windows Update is already running' } else { 'installation started in the background' }) } }
            default           { return @{ ok = $false; out = "unknown action $t" } }
        }
    } catch { return @{ ok = $false; out = $_.Exception.Message } }
}

# --- verified agent self-update --------------------------------------------
function Get-LogBokPayloadHash {
    param($Manifest)
    $lines = [string[]]@($Manifest.files.PSObject.Properties | Where-Object { $_.Name -like 'files/*' } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ((-join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)) } finally { $h.Dispose() }
}
function Test-LogBokPackage {
    param([string]$Dir, [string]$Thumbprint)
    $man = Get-Content (Join-Path $Dir 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $sha = [Security.Cryptography.SHA256]::Create()
    foreach ($p in $man.files.PSObject.Properties) {
        $fp = Join-Path $Dir $p.Name
        if (-not (Test-Path -LiteralPath $fp)) { throw "missing $($p.Name)" }
        if ((-join ($sha.ComputeHash([IO.File]::ReadAllBytes($fp)) | ForEach-Object { $_.ToString('x2') })) -ne [string]$p.Value) { throw "hash mismatch $($p.Name)" }
    }
    if ($Thumbprint) {
        foreach ($f in (Get-ChildItem -Path $Dir -Recurse -Include *.ps1, *.psm1 -File)) {
            $sg = Get-AuthenticodeSignature -FilePath $f.FullName
            if (-not $sg.SignerCertificate -or $sg.Status -eq 'HashMismatch' -or $sg.SignerCertificate.Thumbprint -ne $Thumbprint) { throw "signature mismatch $($f.Name) (signed by another certificate)" }
        }
    }
    return $man
}
function Invoke-LogBokAgentSelfUpdate {
    param([string]$InstallDir, $Info)
    $sec = Get-LogBokAgentSecret $Info; if (-not $sec) { throw 'agent secret missing' }
    $ts = [datetime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $hn = ([string]$env:COMPUTERNAME).ToUpperInvariant()
    $body = Protect-LogBokAes -Key (Get-LogBokSha "$sec|enc") -Plain ([Text.Encoding]::UTF8.GetBytes('{}'))
    $pre = [Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n/update`n"); $buf = New-Object byte[] ($pre.Length + $body.Length); [Array]::Copy($pre, 0, $buf, 0, $pre.Length); [Array]::Copy($body, 0, $buf, $pre.Length, $body.Length)
    $sig = Get-LogBokHmac -Key $sec -Data $buf
    $data = $null; $rsig = ''
    foreach ($u in (Get-LogBokServerUrls $Info '/update')) {
        try {
            $rq = [Net.HttpWebRequest]::Create($u); $rq.Method = 'POST'; $rq.Timeout = 60000; $rq.ReadWriteTimeout = 60000; $rq.Proxy = $null
            $rq.Headers.Add('X-LogBok-Host', $hn); $rq.Headers.Add('X-LogBok-Ts', $ts); $rq.Headers.Add('X-LogBok-Sig', $sig); if ($Info.AgentId) { $rq.Headers.Add('X-LogBok-Id', [string]$Info.AgentId) }; $rq.ContentLength = $body.Length
            $st = $rq.GetRequestStream(); $st.Write($body, 0, $body.Length); $st.Close()
            $rs = $rq.GetResponse(); $rsig = [string]$rs.Headers['X-LogBok-Sig']; $ms = New-Object IO.MemoryStream; $rs.GetResponseStream().CopyTo($ms); $rs.Close(); $data = $ms.ToArray(); break
        } catch { }
    }
    if (-not $data) { throw 'server unreachable for update' }
    $rp = [Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n/update-resp`n"); $rb = New-Object byte[] ($rp.Length + $data.Length); [Array]::Copy($rp, 0, $rb, 0, $rp.Length); [Array]::Copy($data, 0, $rb, $rp.Length, $data.Length)
    if ((Get-LogBokHmac -Key $sec -Data $rb) -ne $rsig.ToLowerInvariant()) { throw 'update signature invalid - ignored' }
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = (Get-LogBokSha "$sec|upd"); $iv = New-Object byte[] 16; [Array]::Copy($data, 0, $iv, 0, 16); $aes.IV = $iv
    $zip = $aes.CreateDecryptor().TransformFinalBlock($data, 16, $data.Length - 16); $aes.Dispose()
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('LogBok-Update-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    try {
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $tmp 'u.zip'), $zip)
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $tmp 'u.zip'), (Join-Path $tmp 'x'))
        $pkg = Join-Path (Join-Path $tmp 'x') 'LogBok-Agent'
        $man = Test-LogBokPackage -Dir $pkg -Thumbprint ([string]$Info.SignerThumbprint)
        $n = 0
        foreach ($f in (Get-ChildItem -Path (Join-Path $pkg 'files') -File)) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $InstallDir $f.Name) -Force; $n++ }
        Set-LogBokInfoField $Info 'PayloadHash' (Get-LogBokPayloadHash $man); Set-LogBokInfoField $Info 'PackageStamp' ([string]$man.stamp); Set-LogBokInfoField $Info 'UpdatedAt' (Get-Date).ToString('o')
        # keep the version reported to the console in step (the old version used to be shown after a self-update)
        $nv = ([string]$man.stamp -split '-')[0]; if ($nv -match '^\d+(\.\d+){1,3}$') { Set-LogBokInfoField $Info 'Version' $nv }
        Save-LogBokAgentInfo -InstallDir $InstallDir -Info $Info
        try { Install-LogBokAgentTasks -InstallDir $InstallDir } catch { }
        Register-LogBokEventSource
        try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9013 -EntryType Information -Message ("LogBok agent updated on {0} to {1} ({2} files, verified)" -f $env:COMPUTERNAME, $man.stamp, $n) } catch { }
        # an agent in the old folder moves itself to ProgramData\Agent
        $mvMsg = ''; try { if (Start-LogBokAgentMove -InstallDir $InstallDir) { $mvMsg = '; moving to ' + (Join-Path $env:ProgramData 'Agent') } } catch { }
        return "updated to $($man.stamp) ($n files)$mvMsg"
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# --- control heartbeat: reports up, commands down --------------------------
function Invoke-LogBokControl {
    param([string]$InstallDir, $Info, [string]$FwdError = '')
    $sd = Join-Path $InstallDir 'state'
    $body = [ordered]@{ v = [string]$Info.Version; e = @(); ctl = 1; ph = [string]$Info.PayloadHash }
    if ($FwdError) { $body.fe = $FwdError.Substring(0, [math]::Min(500, $FwdError.Length)) }
    # live sessions (console/RDP) on every heartbeat
    try { $sm = Join-Path $InstallDir 'LogBok.Sessions.psm1'; if (Test-Path $sm) { if (-not (Get-Command Get-LBLiveSessions -ErrorAction SilentlyContinue)) { Import-Module $sm -DisableNameChecking -ErrorAction Stop }; $body.sess = @(Get-LBLiveSessions); $body.sessAt = (Get-Date).ToString('o') } } catch { }
    $sendPat = $false
    try { $pf = Join-Path $sd 'perf.json'; if (Test-Path $pf) { $body.perf = Get-Content $pf -Raw | ConvertFrom-Json } } catch { }
    # health every 10 min, inventory daily or on request
    $hf = Join-Path $sd 'health-last.txt'; $due = $true; if (Test-Path $hf) { $due = ((Get-Item $hf).LastWriteTime -lt (Get-Date).AddMinutes(-10)) }
    if ($due) { try { $body.health = Get-LogBokHealth -InstallDir $InstallDir; Set-Content $hf (Get-Date).ToString('o') } catch { } }
    $if = Join-Path $sd 'inventory-last.txt'; $flag = Join-Path $sd 'inventory-due.flag'
    $idue = (Test-Path $flag) -or -not (Test-Path $if) -or ((Get-Item $if -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Date).AddHours(-12))
    if ($idue) { try { $body.inv = Get-LogBokInventory; Set-Content $if (Get-Date).ToString('o'); Remove-Item $flag -Force -ErrorAction SilentlyContinue } catch { } }
    $pol = $null; $pjf = Join-Path $sd 'policy.json'
    if (Test-Path $pjf) { try { $pol = Get-Content $pjf -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    if ($pol) { $body.pr = [string]$pol.status.rev; $body.ps = $pol.status }
    # posture daily or on demand; enforced hardening from policy
    $pfl = Join-Path $sd 'posture-due.flag'; $plf = Join-Path $sd 'posture-last.txt'
    if ((Test-Path $pfl) -or -not (Test-Path $plf) -or ((Get-Item $plf -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Date).AddHours(-24))) {
        try {
            $post = Get-LogBokPosture
            $need = @(); if ($pol -and @($pol.policy.harden).Count) { $hl = @($pol.policy.harden); $need = @($post.checks | Where-Object { $_.ok -eq $false -and $_.fix -and $hl -contains $_.id } | ForEach-Object { $_.id }) }
            if ($need.Count) { $post.enforced = Repair-LogBokPosture -Ids $need; $post2 = Get-LogBokPosture; $post2.enforced = $post.enforced; $post = $post2 }
            $body.post = $post; Set-Content $plf (Get-Date).ToString('o'); Remove-Item $pfl -Force -ErrorAction SilentlyContinue
        } catch { }
    }
    # Windows updates: daily background scan, send the fresh result
    $ptf = Join-Path $sd 'patches.json'; $pts = Join-Path $sd 'patches-sent.txt'
    if (-not (Test-Path $ptf) -or ((Get-Item $ptf).LastWriteTime -lt (Get-Date).AddHours(-24))) { try { [void](Start-LogBokPatchJob -InstallDir $InstallDir -Mode scan) } catch { } }
    if ((Test-Path $ptf) -and (-not (Test-Path $pts) -or (Get-Item $ptf).LastWriteTime -gt (Get-Item $pts).LastWriteTime)) { try { $body.pat = Get-Content $ptf -Raw -Encoding UTF8 | ConvertFrom-Json; $sendPat = $true } catch { } }
    if ($pol -and $pol.policy.patch) { try { Invoke-LogBokPatchPolicy -InstallDir $InstallDir -Patch $pol.policy.patch } catch { } }
    $arf = Join-Path $sd 'action-results.json'; $pending = @()
    if (Test-Path $arf) { try { $pending = @((Get-Content $arf -Raw | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_ }) } catch { } }
    if ($pending.Count) { $body.ar = $pending }
    $r = Send-LogBokSigned -InstallDir $InstallDir -Info $Info -Path '/ingest' -Object $body
    if (-not $r.Ok) { return @{ Ok = $false; Error = $(if ($r.Error) { $r.Error } else { "HTTP $($r.Code)" }) } }
    if ($pending.Count) { Remove-Item $arf -Force -ErrorAction SilentlyContinue }
    if ($sendPat) { Set-Content $pts (Get-Date).ToString('o') }
    $out = @{ Ok = $true; Applied = @() }
    $j = $null; try { $j = $r.Text | ConvertFrom-Json } catch { }
    if ($j -and $j.x) {
        $sec = Get-LogBokAgentSecret $Info
        $ts = [string]$r.Ts; $hn = ([string]$env:COMPUTERNAME).ToUpperInvariant()
        if ((Get-LogBokHmac -Key $sec -Data ([Text.Encoding]::UTF8.GetBytes("$ts`n$hn`n$($j.x)"))) -ne [string]$j.xs) { return @{ Ok = $false; Error = 'directive signature invalid - ignored' } }
        $raw = [Convert]::FromBase64String([string]$j.x)
        $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = (Get-LogBokSha "$sec|resp"); $iv = New-Object byte[] 16; [Array]::Copy($raw, 0, $iv, 0, 16); $aes.IV = $iv
        $gzb = $aes.CreateDecryptor().TransformFinalBlock($raw, 16, $raw.Length - 16); $aes.Dispose()
        $gz = New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(, $gzb)), [IO.Compression.CompressionMode]::Decompress); $sr = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
        $d = $sr.ReadToEnd() | ConvertFrom-Json; $sr.Dispose()
        $results = @()
        # 1) agent self-update first (the first contact after downtime is here too); inventory/state are resent afterwards
        # 1) self-update FIRST (also the first contact after the computer was off); then re-send inventory/posture with the new code
        if ($d.update) {
            $u = $null; try { $u = Invoke-LogBokAgentSelfUpdate -InstallDir $InstallDir -Info $Info; $ok = $true } catch { $u = $_.Exception.Message; $ok = $false }
            foreach ($act in @($d.acts | Where-Object { $_.type -eq 'update-agent' })) { $results += [ordered]@{ id = [string]$act.id; ok = $ok; out = [string]$u } }
            if ($ok) { foreach ($fl in 'inventory-due.flag','posture-due.flag') { try { Set-Content -Path (Join-Path $sd $fl) -Value '1' } catch { } } }
            $out.Applied += 'update'
        }
        if ($d.pol) { [void](Invoke-LogBokPolicy -InstallDir $InstallDir -Policy $d.pol); $out.Applied += 'policy' }
        foreach ($act in @($d.acts)) { if ($act -and [string]$act.type -ne 'update-agent') { $res = Invoke-LogBokAction -InstallDir $InstallDir -Action $act -Info $Info; $results += [ordered]@{ id = [string]$act.id; ok = [bool]$res.ok; out = [string]$res.out } } }
        if ($results.Count) {
            $cur = @(); if (Test-Path $arf) { try { $cur = @((Get-Content $arf -Raw | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_ }) } catch { } }
            (ConvertTo-Json -InputObject @($cur + $results) -Depth 4) | Set-Content -Path $arf -Encoding UTF8; $out.Applied += 'actions' }
    }
    # schedule the app rules each cycle (no cost when nothing changed)
    if ($out.Applied -notcontains 'policy' -and $pol -and @($pol.policy.appBlocks).Count) { try { [void](Set-LogBokAppBlocks -InstallDir $InstallDir -Blocks @($pol.policy.appBlocks)) } catch { } }
    # app-launch warn mode: notify users of new attempts
    if ($pol -and $pol.policy.appLaunch -and [string]$pol.policy.appLaunch.mode -eq 'warn') { try { Invoke-LogBokAppLaunchWarn -InstallDir $InstallDir -Policy $pol.policy.appLaunch } catch { } }
    return $out
}

Export-ModuleMember -Function *
