# ==========================================================================
#  LogBok.Identity.psm1 - local users & services management
#  Local users & services management (admin operations, all logged).
#  every operation writes event 9008, which goes to the Collector.
# ==========================================================================

function Write-LogBokAdmin { param([string]$Message)
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('LogBok')) { New-EventLog -LogName Application -Source 'LogBok' } } catch {}
    try { Write-EventLog -LogName Application -Source 'LogBok' -EventId 9008 -EntryType Information -Message $Message } catch {}
}

# -------------------------- local users -----------------------------------
function Get-LogBokLocalUsers {
    $users = @()
    try {
        $users = Get-LocalUser | Select-Object Name,Enabled,LastLogon,
            @{n='PasswordExpires';e={$_.PasswordExpires}},@{n='Description';e={$_.Description}}
    } catch {
        # old Windows without the LocalAccounts module -> WMI
        $users = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=true" |
            Select-Object Name,@{n='Enabled';e={-not $_.Disabled}},@{n='LastLogon';e={$null}},
                @{n='PasswordExpires';e={$null}},Description
    }
    return $users
}

function Set-LogBokUserPassword {
    param([Parameter(Mandatory)][string]$User,[Parameter(Mandatory)][securestring]$Password)
    try { Set-LocalUser -Name $User -Password $Password -ErrorAction Stop }
    catch {
        # avoid net user (password would appear on the command line and in process logs) -> ADSI
        $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        try {
            $u = [ADSI]"WinNT://./$User,user"
            $u.SetPassword([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
            $u.SetInfo()
        } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    Write-LogBokAdmin "Password set for local user '$User'"
}

function Enable-LogBokUser  { param([string]$User)
    try { Enable-LocalUser -Name $User -ErrorAction Stop } catch { & net user $User /active:yes | Out-Null }
    Write-LogBokAdmin "Local user '$User' enabled" }
function Disable-LogBokUser { param([string]$User)
    try { Disable-LocalUser -Name $User -ErrorAction Stop } catch { & net user $User /active:no | Out-Null }
    Write-LogBokAdmin "Local user '$User' disabled" }
function Unlock-LogBokUser  { param([string]$User)
    # only the lock is cleared; a deliberately disabled account is not re-enabled
    try { $u = [ADSI]"WinNT://./$User,user"; $u.IsAccountLocked = $false; $u.SetInfo() } catch {}
    Write-LogBokAdmin "Local user '$User' unlock requested" }

# -------------------------- services --------------------------------------
function Get-LogBokServiceList {
    Get-Service | Select-Object Name,DisplayName,Status,
        @{n='StartType';e={ (Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue).StartMode }}
}
function Start-LogBokService  { param([string]$Name) Start-Service -Name $Name -ErrorAction SilentlyContinue; Write-LogBokAdmin "Service '$Name' started" }
function Stop-LogBokService   { param([string]$Name) Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue; Write-LogBokAdmin "Service '$Name' stopped" }
function Enable-LogBokService { param([string]$Name) Set-Service   -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue; Write-LogBokAdmin "Service '$Name' set Automatic" }
function Disable-LogBokService{ param([string]$Name) Set-Service   -Name $Name -StartupType Disabled  -ErrorAction SilentlyContinue; Write-LogBokAdmin "Service '$Name' set Disabled" }

Export-ModuleMember -Function *
