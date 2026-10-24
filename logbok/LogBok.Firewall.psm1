# ==========================================================================
#  LogBok.Firewall.psm1 - per-app internet control + toggle firewall and
#  antivirus + emergency isolation. All rules are created with the "LogBok-"
#  prefix so they are manageable/removable from the console, and every change is logged/emailed.
#  Per-app internet control, AV/Firewall toggle, emergency isolation.
#  Every rule is prefixed "LogBok-" so it is manageable/removable from the
#  console, and every change is audited by the monitor.
# ==========================================================================

function Write-LogBokAction { param([string]$Message)
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9002 -EntryType Information -Message $Message } catch {}
}

# --- block an app from the internet ---
function Block-LogBokApp {
    param([Parameter(Mandatory)][string]$Path,[string]$Name)
    if (-not $Name) { $Name = [IO.Path]::GetFileNameWithoutExtension($Path) }
    $rn = "LogBok-Block-$Name"
    foreach ($dir in 'Outbound','Inbound') {
        try {
            New-NetFirewallRule -DisplayName "$rn-$dir" -Direction $dir -Program $Path -Action Block -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        } catch {
            # netsh fallback for older Windows
            $nd = if ($dir -eq 'Inbound') { 'in' } else { 'out' }
            & netsh advfirewall firewall add rule name="$rn-$dir" dir=$nd action=block program="$Path" enable=yes | Out-Null
        }
    }
    Write-LogBokAction "Blocked internet for app: $Path"
    return $rn
}

function Unblock-LogBokApp {
    param([string]$Name,[string]$Path)
    if (-not $Name -and $Path) { $Name = [IO.Path]::GetFileNameWithoutExtension($Path) }
    if (-not $Name) { throw 'نامِ برنامه خالی است | empty app name' }   # otherwise all blocks would be removed
    foreach ($d in 'Outbound','Inbound') {
        Get-NetFirewallRule -DisplayName "LogBok-Block-$Name-$d" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    Write-LogBokAction "Unblocked app: $Name"
}

function Get-LogBokAppBlocks {
    Get-NetFirewallRule -DisplayName 'LogBok-Block-*' -ErrorAction SilentlyContinue |
        Select-Object DisplayName,Direction,Enabled
}

# --- toggle Windows Firewall (logged) ---
function Set-LogBokFirewall {
    param([Parameter(Mandatory)][bool]$Enabled, [string]$InstallDir='C:\Scripts\LogBok')
    # before enabling the firewall, the always-open management rules are created so WinRM/RDP/WEF are not cut off
    if ($Enabled) {
        if (Test-Path (Join-Path $InstallDir 'engine.flag')) { try { Import-Module (Join-Path $InstallDir 'LogBok.Connect.psm1') -Force -DisableNameChecking -ErrorAction Stop; [void](Assert-LBMgmtAllow -InstallDir $InstallDir) } catch { } }
    }
    $state = if ($Enabled) {'on'} else {'off'}
    & netsh advfirewall set allprofiles state $state | Out-Null
    Write-LogBokAction "Windows Firewall set to $state by LogBok console"
}

# --- toggle Defender real-time protection (logged) ---
function Set-LogBokDefenderRealtime {
    param([Parameter(Mandatory)][bool]$Enabled)
    try { Set-MpPreference -DisableRealtimeMonitoring (-not $Enabled) -ErrorAction Stop } catch {}
    $s = if ($Enabled) {'enabled'} else {'disabled'}
    Write-LogBokAction "Defender real-time protection $s by LogBok console"
}

# --- emergency isolation: cut all internet except the Collector connection ---
#  for ransomware/attack response. Reverted with Restore.
#  changing the default to block is not enough because existing Allow rules (RDP, SMB, WinRM...)
#  still work; so all active Allow rules are temporarily disabled and their list
#  is saved so Restore brings back exactly those.
function Get-LBIsolationFile { param([string]$InstallDir='C:\Scripts\LogBok') Join-Path $InstallDir 'state\isolation.json' }
function Invoke-LogBokIsolate {
    param([string]$AllowIp, [string]$InstallDir='C:\Scripts\LogBok')   # management server IP that must stay open
    $f = Get-LBIsolationFile $InstallDir
    $disabled = @()
    if (-not (Test-Path $f)) {   # isolating twice must not corrupt the original list
        try {
            $rules = @(Get-NetFirewallRule -Enabled True -Action Allow -ErrorAction Stop | Where-Object { $_.DisplayName -notlike 'LogBok-*' })
            foreach ($r in $rules) {
                try { Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop; $disabled += $r.Name } catch { }   # GPO rules cannot be changed
            }
        } catch { }
        try {
            $dir = Split-Path $f -Parent; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            @{ Time=(Get-Date).ToString('o',[Globalization.CultureInfo]::InvariantCulture); Rules=$disabled } | ConvertTo-Json | Set-Content -Path $f -Encoding UTF8
        } catch { }
    }
    & netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    if ($AllowIp) {
        New-NetFirewallRule -DisplayName 'LogBok-Allow-Collector' -Direction Outbound -RemoteAddress $AllowIp -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName 'LogBok-Allow-Collector-In' -Direction Inbound -RemoteAddress $AllowIp -Action Allow -Enabled True -ErrorAction SilentlyContinue | Out-Null
    }
    Write-LogBokAction "HOST ISOLATED by LogBok (allow=$AllowIp; temporarily disabled allow-rules=$($disabled.Count))"
}

function Restore-LogBokIsolate {
    param([string]$InstallDir='C:\Scripts\LogBok')
    & netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
    try { Import-Module (Join-Path $InstallDir 'LogBok.Connect.psm1') -Force -DisableNameChecking -ErrorAction Stop; [void](Assert-LBMgmtAllow -InstallDir $InstallDir) } catch { }
    $f = Get-LBIsolationFile $InstallDir
    if (Test-Path $f) {
        try {
            $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($n in @($j.Rules)) { if ($n) { try { Enable-NetFirewallRule -Name $n -ErrorAction Stop } catch {} } }
            Remove-Item $f -Force
        } catch { }
    }
    Get-NetFirewallRule -DisplayName 'LogBok-Allow-Collector*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-LogBokAction "Host isolation lifted by LogBok"
}

Export-ModuleMember -Function *
